"""Gateway server (F01): one namespaced FastMCP proxy over all upstreams, served over streamable HTTP.

Run with: uv run python -m firewall.server
Env: FW_DB_PATH, FW_GATEWAY_PORT (8800), FW_MODE, FW_ALLOW_MONITOR.
"""
from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn
from fastmcp import FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import ProxyClient

from firewall.config import PolicyConfig, ToolsConfig, Upstream, load_policy, load_tools, load_upstreams
from firewall.engine import Engine
from firewall.middleware import FirewallMiddleware
from firewall.registry import Registry
from firewall.store import Store

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationRefused(Exception):
    """The gateway refuses to start (fail closed)."""


def transport_for(u: Upstream, env_extra: dict[str, str] | None = None):
    if u.transport == "http":
        return StreamableHttpTransport(u.url)
    command = sys.executable if u.command == "python" else u.command
    args = [str(ROOT / a) if a.endswith(".py") else a for a in u.args]
    env = {**os.environ, "PYTHONUNBUFFERED": "1", **(env_extra or {}), **u.env}
    return StdioTransport(command=command, args=args, env=env, cwd=str(ROOT), keep_alive=True)


def resolve_mode(policy: PolicyConfig, mode: str | None = None) -> str:
    """F38 part: monitor mode needs FW_ALLOW_MONITOR=1 so the system is never left unprotected by accident."""
    chosen = mode or os.environ.get("FW_MODE") or policy.defaults.mode
    if chosen not in ("enforce", "monitor"):
        raise ConfigurationRefused(f"FW_MODE must be enforce or monitor, got {chosen!r}")
    if chosen == "monitor" and os.environ.get("FW_ALLOW_MONITOR") != "1" and mode is None:
        raise ConfigurationRefused("monitor mode requires FW_ALLOW_MONITOR=1")
    return chosen


@dataclass
class Gateway:
    mcp: FastMCP
    engine: Engine
    store: Store
    transports: list = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    port: int = 0
    _server: uvicorn.Server | None = None
    _task: asyncio.Task | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> None:
        app = self.mcp.http_app()
        import socket
        if port == 0:  # pick a free port
            with socket.socket() as s:
                s.bind((host, 0))
                port = s.getsockname()[1]
        self.port = port
        self._server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="error"))
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(200):
            if self._server.started:
                return
            if self._task.done():
                self._task.result()
            await asyncio.sleep(0.05)
        raise RuntimeError("gateway did not start")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
            if self._task:
                await self._task
        for t in self.transports:
            try:
                await t.close()
            except Exception as exc:  # noqa: BLE001 - shutdown must continue for the other transports
                print(f"warning: closing upstream transport failed: {exc!r}", file=sys.stderr)
        await self.store.close()


def _blocking_client(transport, upstream: str, engine: Engine) -> ProxyClient:
    """F39: the proxy would relay server-initiated sampling, elicitation and roots requests from an upstream
    to the agent, which makes them an injection and exfiltration channel. Refuse them and record each attempt."""

    async def sampling(messages, params, context):
        await engine.audit_system(f"upstream {upstream!r} asked the client for model sampling", verdict="deny",
                                  reason_code="UPSTREAM_REQUEST_BLOCKED")
        raise PermissionError("Blocked by firewall. code=UPSTREAM_REQUEST_BLOCKED")

    async def elicitation(message, response_type, params, context):
        await engine.audit_system(f"upstream {upstream!r} asked the user for input", verdict="deny",
                                  reason_code="UPSTREAM_REQUEST_BLOCKED")
        return ElicitResult(action="decline")

    return ProxyClient(transport, sampling_handler=sampling, elicitation_handler=elicitation, roots=[])


async def build_gateway(*, db_path: str, upstreams: list[Upstream] | None = None,
                        policy: PolicyConfig | None = None, mode: str | None = None,
                        env_extra: dict[str, str] | None = None, tools: ToolsConfig | None = None,
                        path_base: str | Path | None = None) -> Gateway:
    policy = policy or load_policy(ROOT / "policy.yaml")
    tools = tools or load_tools(ROOT / "tools.yaml")
    upstreams = upstreams if upstreams is not None else [
        u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.enabled]
    registry = Registry(tools)
    mode = resolve_mode(policy, mode)
    store = await Store(db_path).open()
    engine = Engine(store, policy, mode, {u.name: u.timeout_s for u in upstreams}, registry=registry,
                    path_base=path_base or os.environ.get("FW_PATH_BASE") or Path.cwd())
    mcp = FastMCP("agent-firewall", middleware=[FirewallMiddleware(engine)])
    transports = []
    for u in upstreams:
        t = transport_for(u, env_extra)
        transports.append(t)
        mcp.mount(create_proxy(_blocking_client(t, u.name, engine)), namespace=u.name)
    gw = Gateway(mcp, engine, store, transports)
    try:
        # Startup discovery: real, namespaced tool names (Section 11), validated against tools.yaml (F05).
        live = list(await mcp.list_tools(run_middleware=False))
        gw.tool_names = sorted(t.name for t in live)
        missing, gw.warnings = registry.validate_discovery(gw.tool_names)
        if missing:
            raise ConfigurationRefused(
                "tools provided by upstreams but missing from tools.yaml: " + ", ".join(missing)
                + ". Review each one and add it with reviewed: true (labels and risk decide how it is handled).")
        engine.known_tools = set(gw.tool_names)
        await engine.observe_tools(live)  # first sight: pin every tool (F04) and scan it for poisoning
        if gw.warnings:
            await engine.audit_system("startup warnings", {"warnings": gw.warnings})
    except BaseException:
        await gw.stop()  # do not leave upstream processes or the database open on a refused start
        raise
    return gw


async def amain() -> None:
    db = os.environ.get("FW_DB_PATH", "./fw.db")
    port = int(os.environ.get("FW_GATEWAY_PORT", "8800"))
    try:
        gw = await build_gateway(db_path=db)
    except ConfigurationRefused as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    await gw.start(port=port)
    for w in gw.warnings:
        print(f"WARNING: {w}", file=sys.stderr, flush=True)
    print(f"gateway listening on {gw.url}  mode={gw.engine.mode}  tools={gw.tool_names}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await gw.stop()


if __name__ == "__main__":
    asyncio.run(amain())

