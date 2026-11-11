"""Request pipeline (Section 4). Implemented: steps 1 to 3 and 5 to 12 (11 is a stand-in), plus the
size cap, labeling and fingerprinting of step 14, and the audit.

Step 4 (pins), the injection scan of step 14 and the approval queue of step 11 arrive in Phases 5 and 6;
each is added at the marked place so the order stays exactly as in the guide.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from firewall import (
    audit,
    content,
    destinations,
    flow,
    grants,
    inspect_args,
    limits,
    paths,
    pinning,
    policy,
    ratelimit,
    redact,
    scan_output,
    sessions,
)
from firewall.config import PolicyConfig
from firewall.models import Verdict
from firewall.registry import Registry
from firewall.store import Store

STATUS_CODES = {"expired": "GRANT_EXPIRED", "revoked": "GRANT_REVOKED", "exhausted": "GRANT_EXHAUSTED"}
CLEANUP_EVERY_S = 60.0
# denies that say nothing about the agent misbehaving on a valid grant do not count toward suspension
NOT_COUNTED = {"NO_GRANT", "GRANT_EXPIRED", "GRANT_REVOKED", "GRANT_EXHAUSTED", "TOO_MANY_SESSIONS",
               "GRANT_SUSPENDED", "FIREWALL_ERROR"}


class Engine:
    def __init__(self, store: Store, policy: PolicyConfig, mode: str | None = None,
                 upstream_timeouts: dict[str, float] | None = None, registry: Registry | None = None,
                 known_tools: set[str] | None = None, path_base: Path | None = None):
        self.store = store
        self.policy = policy
        self.mode = mode or policy.defaults.mode
        self.upstream_timeouts = upstream_timeouts or {}
        self.registry = registry
        # tools the upstreams really provide (discovered at startup); None means "trust the registry"
        self.known_tools = known_tools
        # directory the upstream tools treat as their working directory; relative paths resolve against it
        self.path_base = Path(path_base) if path_base is not None else Path.cwd()
        self._warned: set[str] = set()
        self._last_cleanup = 0.0

    # ---------------- verdict helpers ----------------
    def deny(self, code: str, detail: str = "", grant_id: str | None = None) -> Verdict:
        return Verdict("deny", [code], detail={"message": detail} if detail else {}, grant_id=grant_id)

    def blocks(self, v: Verdict) -> bool:
        """Does this verdict stop the call? Monitor mode lets everything through except FIREWALL_ERROR
        (fail closed: if the firewall itself broke, the call is never forwarded)."""
        if v.action == "allow":
            return False
        return self.mode == "enforce" or v.code == "FIREWALL_ERROR"

    def agent_message(self, v: Verdict) -> str:
        """Generic text only: reason code and event id, no matched rule or pattern (no oracle)."""
        return f"Blocked by firewall. code={v.code} event={v.event_id}"

    def _audit_verdict(self, v: Verdict) -> str:
        if v.action == "allow":
            return "allow"
        if self.blocks(v):
            return v.action
        return "would_deny" if v.action == "deny" else "would_require_approval"

    # ---------------- pipeline ----------------
    async def check_call(self, session_id: str, token: str | None, tool: str, args: dict) -> Verdict:
        v = await self._pipeline(session_id, token, tool, args)
        await self._after_decision(v)
        return v

    async def _after_decision(self, v: Verdict) -> None:
        """F08 circuit breaker: consecutive hard denies on one grant suspend it (enforce mode only).
        An allowed call resets the streak (done in step 12)."""
        if v.grant_id is None or v.action != "deny" or self.mode != "enforce" or v.code in NOT_COUNTED:
            return
        new = await sessions.update_state(self.store, v.grant_id, denied_delta=1)
        if new["denied_streak"] >= self.policy.defaults.suspend_after_denies and not new["suspended"]:
            await sessions.update_state(self.store, v.grant_id, suspended=True)
            await self.audit_system("ALERT: grant suspended after consecutive denied calls",
                                    {"grant_id": v.grant_id, "reason_code": "GRANT_SUSPENDED"})

    async def _pipeline(self, session_id: str, token: str | None, tool: str, args: dict) -> Verdict:
        await self._maybe_cleanup()
        cfg = self.policy.defaults
        # Step 1: resolve grant (F02, F06, F34)
        grant = await grants.resolve(self.store, token)
        if grant is None:
            return self.deny("NO_GRANT")
        if grant.status != "active":
            return self.deny(STATUS_CODES[grant.status], grant_id=grant.id)
        if not await sessions.touch_session(self.store, session_id, grant):
            return self.deny("TOO_MANY_SESSIONS", grant_id=grant.id)
        # Step 2: grant state (F08)
        state = await sessions.load_state(self.store, grant.id)
        if state.suspended:
            return self.deny("GRANT_SUSPENDED", grant_id=grant.id)
        # Step 3: surface check (F01, F05). Unknown means not registered or not provided by any upstream.
        meta = self.registry.meta(tool) if self.registry else None
        if self.registry is not None and (
                meta is None or (self.known_tools is not None and tool not in self.known_tools)):
            return self.deny("UNKNOWN_TOOL", f"tool {tool!r} is not registered", grant.id)
        # Step 4: pin state (F04). A changed or quarantined tool stays blocked until an operator approves it.
        pin = await self.store.get_pin(tool)
        if pin is not None and pin["state"] == "changed":
            return self.deny("TOOL_PINNED_CHANGED", "tool definition changed since it was pinned", grant.id)
        if pin is not None and pin["state"] == "quarantined":
            return self.deny("TOOL_POISONED", "tool definition looks poisoned", grant.id)
        # Step 5: grant scope (F06)
        if tool not in grant.allowed_tools:
            return self.deny("TOOL_NOT_GRANTED", f"tool {tool!r} is not in the grant", grant.id)
        # Step 6: rate and loop limits (F08)
        v = await ratelimit.check_rate(self.store, grant.id, tool, args, cfg)
        if v is not None:
            v.grant_id = grant.id
            return v
        # Step 7: size limits on arguments (F33)
        v = limits.check_arg_limits(args)
        if v is not None:
            v.grant_id = grant.id
            return v
        approval_reasons: list[str] = []
        rule_id: str | None = None
        info: dict = {}
        is_sink = meta is not None and "sink" in meta.labels
        if meta is not None:
            # Step 8: argument inspection: secrets and PII (F09), paths and commands (F10), destinations (F11)
            secrets = inspect_args.find_secrets(args)
            if secrets and (is_sink or tool not in self.policy.secrets_allowed_tools):
                return Verdict("deny", ["SECRET_IN_ARGS"], grant_id=grant.id, detail={
                    "matches": [{"kind": m.kind, "masked": m.masked, "path": m.path} for m in secrets]})
            # the recipient itself is not "PII in the message": leave the destination argument out
            pii = inspect_args.find_pii({k: v for k, v in args.items() if k != meta.dest_arg}) if is_sink else []
            for check in (lambda: paths.check_paths(meta, args, grant, self.path_base),
                          lambda: destinations.check_destination(meta, args, grant)):
                v = check()
                if v is not None:
                    v.grant_id = grant.id
                    return v
            if pii:
                # PII in a sink call needs approval unless the destination is in the grant. Reaching this point
                # means the destination check passed, i.e. it is in the grant, so no approval is added.
                info["pii"] = [{"kind": m.kind, "masked": m.masked, "path": m.path} for m in pii]
            # Step 9: flow check (F12) and trifecta rule (F13), sink calls only
            state = await sessions.load_state(self.store, grant.id)  # fresh: labels may have changed since step 2
            if is_sink:
                eg = await flow.evaluate_egress(self.store, grant.id, tool, args, self.policy.allow_flows)
                if eg.verdict is not None:
                    eg.verdict.grant_id = grant.id
                    return eg.verdict
                if eg.declassified:
                    info["declassified"] = eg.declassified  # allow_flows used; recorded in the audit row
                if cfg.trifecta_mode != "off" and ({"private", "untrusted"} <= state.labels or state.suspicious):
                    if cfg.trifecta_mode == "block":
                        return Verdict("deny", ["POLICY_DENY"], rule_id="trifecta", grant_id=grant.id,
                                       detail={"reason": "private and untrusted data seen before a sink call"})
                    approval_reasons.append("TRIFECTA_APPROVAL")
                await flow.record_egress(self.store, grant.id, eg.buffer_entries)
            # Step 10: policy rules (F07). A rule may deny or add an approval requirement, never allow.
            pv = policy.evaluate(self.policy.rules, meta, state, args)
            if pv is not None:
                pv.grant_id = grant.id
                if pv.action == "deny":
                    return pv
                approval_reasons.extend(pv.reason_codes)
                rule_id = pv.rule_id
        # An operator can also demand approval for specific tools on a grant (GRANT_APPROVAL)
        if tool in grant.approval_required_for:
            approval_reasons.append("GRANT_APPROVAL")
        # Step 11: approval. The queue and wait flow arrive in Phase 6; until then a call that needs
        # approval is simply held back (fail closed in enforce mode).
        if approval_reasons:
            return Verdict("require_approval", list(dict.fromkeys(approval_reasons)), rule_id=rule_id,
                           grant_id=grant.id, detail=info)
        # Step 12: reserve one unit of budget atomically (F06)
        if not await grants.reserve_budget(self.store, grant.id):
            return self.deny("GRANT_EXHAUSTED", grant_id=grant.id)
        await sessions.update_state(self.store, grant.id, incr_calls=1, denied_reset=True)
        return Verdict("allow", grant_id=grant.id, detail=info)

    async def check_result(self, session_id: str, token: str | None, tool: str, result: Any,
                           grant_id: str | None = None, upstream_ms: float | None = None,
                           latency_ms: float | None = None) -> Any:
        """Step 14, in this order: size cap (F33), binary content (F40), injection scan and quarantine (F14),
        labeling and fingerprinting (F12), redaction (F15), audit. Any exception propagates, and the middleware
        then withholds the result (fail closed): a result we could not record must not be released."""
        cfg = self.policy.defaults
        meta = self.registry.meta(tool) if self.registry else None
        tool_labels = set(meta.labels) if meta else set()
        labels = {x for x in tool_labels if x in ("private", "untrusted")}
        result, truncated = limits.cap_result(result)

        enforce = self.mode == "enforce"
        if "untrusted" in labels and cfg.block_binary_from_untrusted and content.has_binary(result):
            if grant_id is not None:
                await sessions.update_state(self.store, grant_id, add_labels=labels)
            if not enforce:  # monitor mode records what it would have done and lets the result through
                await self.audit_result(session_id, grant_id, tool, "would_deny", "BINARY_BLOCKED", upstream_ms,
                                        latency_ms, {"monitor": True})
                return result
            ev = await self.audit_result(session_id, grant_id, tool, "deny", "BINARY_BLOCKED", upstream_ms, latency_ms)
            return self._replacement(
                result, f"[Firewall] Content from {tool} withheld: binary content from an untrusted tool. "
                        f"code=BINARY_BLOCKED event={ev}")

        scan_info: dict | None = None
        if meta is not None and ("untrusted" in labels or cfg.scan_all):
            texts = content.extract_text(result)
            score, families = scan_output.injection_score_many(texts) if texts else (0.0, [])
            if score >= cfg.injection_flag_threshold:
                scan_info = {"score": score, "families": families, "snippet": scan_output.snippet("\n".join(texts))}
                if grant_id is not None:  # the grant has now seen suspicious content (F13 gets stricter)
                    await sessions.update_state(self.store, grant_id, add_labels=labels, suspicious=True)
                if score >= cfg.injection_block_threshold and enforce:
                    ev = await self.audit_result(session_id, grant_id, tool, "quarantine", "INJECTION_QUARANTINE",
                                                 upstream_ms, latency_ms, scan_info)
                    return self._replacement(
                        result, f"[Firewall] Content from {tool} withheld: possible prompt injection. "
                                f"code=INJECTION_QUARANTINE event={ev}")

        if grant_id is not None and labels:
            await sessions.update_state(self.store, grant_id, add_labels=labels)  # label first, then fingerprint
        if grant_id is not None and "private" in labels:
            for text in content.extract_text(result):
                await flow.register_private(self.store, grant_id, tool, text)
            if cfg.redact_private_secrets:  # fingerprints above were taken from the original text
                result = content.map_result_strings(result, redact.redact)

        if scan_info is not None:
            if not enforce and scan_info["score"] >= cfg.injection_block_threshold:
                scan_info = {**scan_info, "monitor": True, "would_quarantine": True}
            await self.audit_result(session_id, grant_id, tool, "flag", None, upstream_ms, latency_ms, scan_info)
        else:
            await self.audit_result(session_id, grant_id, tool, "flag" if truncated else "allow",
                                    "RESULT_TRUNCATED" if truncated else None, upstream_ms, latency_ms)
        return result

    @staticmethod
    def _replacement(result: Any, message: str) -> Any:
        """A result that carries only `message`. The shape of any structured content is kept (string leaves
        replaced), because clients validate it against the tool's output schema."""
        from mcp_types import TextContent

        update: dict[str, Any] = {"content": [TextContent(type="text", text=message)]}
        structured = getattr(result, "structured_content", None)
        if structured is not None:
            update["structured_content"] = content.map_strings(structured, lambda _s: message)
        return result.model_copy(update=update)

    async def observe_tools(self, tools: list) -> list:
        """F04: compare live tool definitions with their pins; audit every change and every poisoned tool."""
        names = {t.name for t in tools}
        known = names | (self.registry.names() if self.registry else set())
        reviewed = self.registry.reviewed_map() if self.registry else {}
        events = []
        for t in tools:
            ev = await pinning.observe(self.store, t, known, reviewed)
            if ev.transition in ("changed", "poisoned"):
                code = "TOOL_PINNED_CHANGED" if ev.transition == "changed" else "TOOL_POISONED"
                await audit.write(self.store, {
                    "phase": "system", "verdict": "quarantine", "tool": t.name, "reason_code": code,
                    "detail": {"old_hash": ev.old_hash, "new_hash": ev.new_hash, "reasons": ev.reasons,
                               "message": "ALERT: " + code}, "mode": self.mode})
            events.append(ev)
        return events

    async def filter_tools(self, session_id: str, token: str | None, tools: list) -> list:
        """F03 and F04: pin every live definition first, then return only the tools in the caller's grant that
        are not changed or quarantined. No valid active grant means an empty list. Monitor mode shows the whole
        catalog (it records, it does not restrict). Any error hides everything."""
        try:
            await self.observe_tools(tools)
            if self.mode != "enforce":
                return tools
            grant = await grants.resolve(self.store, token)
            if grant is None or grant.status != "active":
                return []
            state = await sessions.load_state(self.store, grant.id)
            if state.suspended:
                return []
            allowed = set(grant.allowed_tools)
            blocked = {p["tool"] for p in await self.store.list_pins() if p["state"] in pinning.BLOCKING_STATES}
            return [t for t in tools if t.name in allowed and t.name not in blocked
                    and (self.registry is None or self.registry.has(t.name))]
        except Exception:  # noqa: BLE001 - fail closed
            return [] if self.mode == "enforce" else tools
    # ---------------- audit ----------------
    async def audit_call(self, session_id: str, token: str | None, tool: str, args: dict, verdict: Verdict,
                         latency_ms: float | None = None) -> None:
        """One row per decision. Sets verdict.event_id. The token is never written."""
        detail = dict(verdict.detail)
        if verdict.action != "allow" and not self.blocks(verdict):
            detail["monitor"] = True
        row_id = await audit.write(self.store, {
            "session_id": session_id, "grant_id": verdict.grant_id, "tool": tool,
            "args_masked": audit.mask(args), "args_hash": audit.args_hash(args), "phase": "call",
            "verdict": self._audit_verdict(verdict), "reason_code": verdict.code, "rule_id": verdict.rule_id,
            "detail": {**detail, "reason_codes": verdict.reason_codes}, "latency_ms": latency_ms, "mode": self.mode,
        })
        verdict.event_id = f"ev_{row_id}"

    async def audit_result(self, session_id: str, grant_id: str | None, tool: str, verdict: str,
                           reason_code: str | None, upstream_ms: float | None, latency_ms: float | None,
                           detail: dict | None = None) -> str:
        row_id = await audit.write(self.store, {
            "session_id": session_id, "grant_id": grant_id, "tool": tool, "phase": "result",
            "verdict": verdict, "reason_code": reason_code, "detail": detail or {},
            "latency_ms": latency_ms, "upstream_ms": upstream_ms, "mode": self.mode,
        })
        return f"ev_{row_id}"

    async def audit_system(self, message: str, detail: dict | None = None, *, verdict: str = "flag",
                           reason_code: str | None = None) -> None:
        await audit.write(self.store, {
            "phase": "system", "verdict": verdict, "reason_code": reason_code,
            "detail": {"message": message, **(detail or {})}, "mode": self.mode,
        })

    async def warn_once(self, key: str, message: str) -> None:
        """One WARN audit row per process and key (F02)."""
        if key not in self._warned:
            self._warned.add(key)
            await self.audit_system(message)

    async def warn_default_session(self) -> None:
        await self.warn_once("default-session", "WARN: no MCP session id available, using default-session")
    async def _maybe_cleanup(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup >= CLEANUP_EVERY_S:
            self._last_cleanup = now
            await sessions.cleanup(self.store)
