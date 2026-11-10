"""Request pipeline (Section 4). Phase 2 implements steps 1, 2, 12 and the audit hooks.

Steps 3 to 11 and the result scanning of step 14 arrive in Phases 3 to 6; each is added at
the marked place so the order stays exactly as in the guide.
"""
from __future__ import annotations

import time
from typing import Any

from firewall import audit, grants, sessions
from firewall.config import PolicyConfig
from firewall.models import Verdict
from firewall.store import Store

STATUS_CODES = {"expired": "GRANT_EXPIRED", "revoked": "GRANT_REVOKED", "exhausted": "GRANT_EXHAUSTED"}
CLEANUP_EVERY_S = 60.0


class Engine:
    def __init__(self, store: Store, policy: PolicyConfig, mode: str | None = None,
                 upstream_timeouts: dict[str, float] | None = None):
        self.store = store
        self.policy = policy
        self.mode = mode or policy.defaults.mode
        self.upstream_timeouts = upstream_timeouts or {}
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
        await self._maybe_cleanup()
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
        # Steps 3-11: surface, pin, scope, limits, inspection, flow, policy, approval (Phases 3-6)
        # Step 12: reserve one unit of budget atomically (F06)
        if not await grants.reserve_budget(self.store, grant.id):
            return self.deny("GRANT_EXHAUSTED", grant_id=grant.id)
        await sessions.update_state(self.store, grant.id, incr_calls=1)
        return Verdict("allow", grant_id=grant.id)

    async def check_result(self, session_id: str, token: str | None, tool: str, result: Any,
                           grant_id: str | None = None, upstream_ms: float | None = None,
                           latency_ms: float | None = None) -> Any:
        """Step 14. Phase 2: audit only; scanning, labeling and redaction come in Phases 4 and 5."""
        await self.audit_result(session_id, grant_id, tool, "allow", None, upstream_ms, latency_ms)
        return result

    async def filter_tools(self, session_id: str, token: str | None, tools: list) -> list:
        """F03 catalog filtering arrives in Phase 3; Phase 2 passes the catalog through."""
        return tools

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

    async def audit_system(self, message: str, detail: dict | None = None) -> None:
        await audit.write(self.store, {
            "phase": "system", "verdict": "flag", "detail": {"message": message, **(detail or {})}, "mode": self.mode,
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
