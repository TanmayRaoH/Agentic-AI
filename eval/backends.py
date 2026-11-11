"""Backends the scripted attacker talks to. Phase 1: unprotected (straight to the upstreams)."""
from __future__ import annotations

import os
import re
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Self

from fastmcp.client import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from eval.attacker import CallOutcome
from eval.scenario import Scenario
from firewall.config import Upstream, load_upstreams

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "eval" / "runtime"
WORLD = RUNTIME / "world"
LOGS = RUNTIME / "logs"

# Which upstream a malicious variant replaces
VARIANT_REPLACES = {"poisoned": "web", "rugpull": "web", "schema": "web", "shadow": "fs"}


def upstream_specs(scn: Scenario) -> list[Upstream]:
    specs = load_upstreams(ROOT / "upstreams.yaml").upstreams
    if scn.variant:
        target = VARIANT_REPLACES[scn.variant]
        for u in specs:
            if u.name == target:
                u.args = ["demo/servers/rugpull_server.py"]
                u.env = {**u.env, "RUGPULL_MODE": scn.variant}
    return [u for u in specs if u.enabled]


def needed_servers(scn: Scenario) -> set[str]:
    names = {s.call for s in scn.steps if s.call} | {s.if_visible for s in scn.steps if s.if_visible}
    return {n.split("_", 1)[0] for n in names}


def server_env(extra: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    env.update({"FW_WORLD": str(WORLD), "FW_LOG_DIR": str(LOGS), "PYTHONUNBUFFERED": "1"})
    env.update(extra)
    return env


def stdio_transport(u: Upstream) -> StdioTransport:
    command = sys.executable if u.command == "python" else u.command
    args = [str(ROOT / a) if a.endswith(".py") else a for a in u.args]
    return StdioTransport(command=command, args=args, env=server_env(u.env), cwd=str(ROOT))


_CODE = re.compile(r"code=([A-Z_]+)")


class UnprotectedBackend:
    """Connects directly to each needed upstream. Tool names get the upstream name as prefix."""

    def __init__(self, scn: Scenario):
        self.scn = scn
        self._stack = AsyncExitStack()
        self._clients: dict[str, Client] = {}
        self._owner: dict[str, tuple[str, str]] = {}  # prefixed name -> (upstream, raw name)

    async def __aenter__(self) -> Self:
        wanted = needed_servers(self.scn)
        for u in upstream_specs(self.scn):
            if u.name not in wanted:
                continue
            client = Client(stdio_transport(u))
            await self._stack.enter_async_context(client)
            self._clients[u.name] = client
        return self

    async def __aexit__(self, *exc) -> None:
        await self._stack.aclose()

    async def visible_tools(self) -> set[str]:
        self._owner.clear()
        for name, client in self._clients.items():
            for t in await client.list_tools():
                self._owner[f"{name}_{t.name}"] = (name, t.name)
        return set(self._owner)

    async def call(self, name: str, args: dict) -> CallOutcome:
        if name not in self._owner:  # not listed: unprotected mode still lets the agent try
            await self.visible_tools()
        if name not in self._owner:
            return CallOutcome(f"unknown tool {name}", is_error=True)
        server, raw = self._owner[name]
        try:
            res = await self._clients[server].call_tool(raw, args, raise_on_error=False)
        except Exception as exc:  # noqa: BLE001  (transport or validation failure)
            return CallOutcome(f"error: {exc}", is_error=True)
        text = "\n".join(getattr(c, "text", "") for c in res.content)
        m = _CODE.search(text)
        return CallOutcome(text, is_error=bool(res.is_error), code=m.group(1) if m else None)

    async def detections(self) -> set[str]:
        return set()



class GatewayBackend:
    """Talks to the firewall gateway over streamable HTTP with the scenario's grant token."""

    def __init__(self, scn: Scenario, url: str, token: str, store=None, grant_id: str | None = None):
        self.scn = scn
        self._store = store
        self._grant_id = grant_id
        self._client = Client(StreamableHttpTransport(url, headers={"X-Task-Grant": token}), mode="legacy")

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.__aexit__(*exc)

    async def visible_tools(self) -> set[str]:
        return {t.name for t in await self._client.list_tools()}

    async def call(self, name: str, args: dict) -> CallOutcome:
        try:
            res = await self._client.call_tool(name, args, raise_on_error=False, timeout=130)
        except Exception as exc:  # noqa: BLE001 - transport or validation failure
            return CallOutcome(f"error: {exc}", is_error=True)
        text = "\n".join(getattr(c, "text", "") for c in res.content)
        m = _CODE.search(text)
        return CallOutcome(text, is_error=bool(res.is_error), code=m.group(1) if m else None)

    async def detections(self) -> set[str]:
        """What the firewall itself reported about this grant: result scans (F14). A quarantine also counts as
        flagged. This is the firewall's own signal, which is what a detection scenario is about."""
        if self._store is None or self._grant_id is None:
            return set()
        found: set[str] = set()
        for row in await self._store.query_audit(grant_id=self._grant_id, phase="result", limit=5000):
            if row["verdict"] == "quarantine":
                found |= {"quarantined", "flagged"}
            elif row["verdict"] == "flag" and "families" in (row["detail"] or ""):
                found.add("flagged")
        return found
