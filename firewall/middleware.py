"""FastMCP middleware: the choke point for every request (Section 12, verified against fastmcp 4.1.6)."""
from __future__ import annotations

import asyncio
import hashlib
import time

import anyio
from fastmcp.exceptions import MCPError, PromptError, ResourceError, ToolError
from fastmcp.server.dependencies import get_http_headers, get_http_request
from fastmcp.server.middleware import Middleware

from firewall.engine import Engine

FALLBACK_SESSION = "default-session"


def _is_transport_failure(exc: BaseException) -> bool:
    """True when the upstream itself broke (connection closed, process died), as opposed to the
    upstream tool reporting an ordinary error. Walks the cause chain because the proxy wraps
    transport errors in ToolError."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (MCPError, OSError, anyio.ClosedResourceError, anyio.BrokenResourceError, EOFError)):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class FirewallMiddleware(Middleware):
    def __init__(self, engine: Engine):
        self.engine = engine

    # ---------------- request identity ----------------
    async def _sid(self, context) -> str:
        """Session identity (F02). Verified against fastmcp 4.1.6: handshake-era clients (Client(mode="legacy"),
        the official MCP SDKs today) send a stable mcp-session-id header. 2026-07-28 era clients have no session
        at all (every request is its own connection and ctx.session_id changes per request), so those are
        identified by client address plus user agent. State never depends on this: it belongs to the grant."""
        try:
            headers = get_http_headers(include={"mcp-session-id"}) or {}
            if headers.get("mcp-session-id"):
                return headers["mcp-session-id"]
            req = get_http_request()
        except Exception:  # noqa: BLE001 - not an HTTP request (stdio or in-memory)
            await self.engine.warn_default_session()
            return FALLBACK_SESSION
        host = req.client.host if req.client else "unknown"
        digest = hashlib.sha256(f"{host}|{req.headers.get('user-agent', '')}".encode()).hexdigest()[:12]
        await self.engine.warn_once(
            "stateless-era", "WARN: client has no MCP session; identified by client address and user agent")
        return f"stateless:{digest}"
    def _token(self, context) -> str | None:
        token = (get_http_headers() or {}).get("x-task-grant")
        if token:
            return token
        try:  # fallback (F02): query parameter on the connection URL
            return get_http_request().query_params.get("task_grant")
        except Exception:  # noqa: BLE001
            return None

    # ---------------- tools ----------------
    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        return await self.engine.filter_tools(await self._sid(context), self._token(context), list(tools))

    async def on_call_tool(self, context, call_next):
        eng = self.engine
        sid, token = await self._sid(context), self._token(context)
        name = context.message.name
        args = context.message.arguments or {}

        t0 = time.perf_counter()
        try:
            verdict = await eng.check_call(sid, token, name, args)
        except Exception as exc:  # noqa: BLE001 - fail closed
            verdict = eng.deny("FIREWALL_ERROR", repr(exc))
        latency_ms = (time.perf_counter() - t0) * 1000
        try:
            await eng.audit_call(sid, token, name, args, verdict, latency_ms)
        except Exception as exc:
            raise ToolError("Blocked by firewall. code=FIREWALL_ERROR event=ev_none") from exc
        if eng.blocks(verdict):
            raise ToolError(eng.agent_message(verdict))

        upstream = name.split("_", 1)[0]
        timeout = eng.upstream_timeouts.get(upstream, 30.0)
        t1 = time.perf_counter()
        try:
            result = await asyncio.wait_for(call_next(context), timeout)
        except TimeoutError:
            ev = await eng.audit_result(sid, verdict.grant_id, name, "deny", "UPSTREAM_TIMEOUT",
                                        (time.perf_counter() - t1) * 1000, None)
            raise ToolError(f"Upstream failed. code=UPSTREAM_TIMEOUT event={ev}") from None
        except ToolError as exc:
            if _is_transport_failure(exc):
                ev = await eng.audit_result(sid, verdict.grant_id, name, "deny", "UPSTREAM_ERROR",
                                            (time.perf_counter() - t1) * 1000, None, {"error": "transport"})
                raise ToolError(f"Upstream failed. code=UPSTREAM_ERROR event={ev}") from None
            # the upstream tool itself reported an error; pass it on, audited
            await eng.audit_result(sid, verdict.grant_id, name, "allow", None,
                                   (time.perf_counter() - t1) * 1000, None, {"tool_error": True})
            raise
        except Exception as exc:  # noqa: BLE001 - upstream unreachable or crashed; never retried
            ev = await eng.audit_result(sid, verdict.grant_id, name, "deny", "UPSTREAM_ERROR",
                                        (time.perf_counter() - t1) * 1000, None, {"error": type(exc).__name__})
            raise ToolError(f"Upstream failed. code=UPSTREAM_ERROR event={ev}") from None
        upstream_ms = (time.perf_counter() - t1) * 1000

        out = await eng.check_result(sid, token, name, result, verdict.grant_id, upstream_ms, None)
        return out

    # ---------------- resources and prompts (F01: disabled by default) ----------------
    async def _surface_blocked(self, context, what: str) -> None:
        eng = self.engine
        sid = await self._sid(context)
        ev = await eng.audit_result(sid, None, what, "deny", "RESOURCES_DISABLED", None, None)
        return ev

    async def on_list_resources(self, context, call_next):
        if self.engine.policy.defaults.allow_resources:
            return await call_next(context)
        return []

    async def on_list_resource_templates(self, context, call_next):
        if self.engine.policy.defaults.allow_resources:
            return await call_next(context)
        return []

    async def on_list_prompts(self, context, call_next):
        if self.engine.policy.defaults.allow_resources:
            return await call_next(context)
        return []

    async def on_read_resource(self, context, call_next):
        if self.engine.policy.defaults.allow_resources:
            return await call_next(context)
        ev = await self._surface_blocked(context, "resources/read")
        raise ResourceError(f"Blocked by firewall. code=RESOURCES_DISABLED event={ev}")

    async def on_get_prompt(self, context, call_next):
        if self.engine.policy.defaults.allow_resources:
            return await call_next(context)
        ev = await self._surface_blocked(context, "prompts/get")
        raise PromptError(f"Blocked by firewall. code=RESOURCES_DISABLED event={ev}")
