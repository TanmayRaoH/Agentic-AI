import shutil
from pathlib import Path

import pytest_asyncio
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from firewall.config import (
    Defaults,
    PolicyConfig,
    ToolEntry,
    Upstream,
    load_policy,
    load_tools,
    load_upstreams,
)
from firewall.server import build_gateway

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_WORLD = ROOT / "eval" / "fixtures" / "world"


def relaxed_policy(**overrides) -> PolicyConfig:
    """The shipped policy, but with rate and loop limits high enough that tests which repeat calls are not
    affected. Tests of those limits pass their own values."""
    pol = load_policy(ROOT / "policy.yaml")
    d = {**pol.defaults.model_dump(), "rate_limit_per_min": 100000, "rate_burst": 100000, "loop_threshold": 100000,
         **overrides}
    return PolicyConfig(defaults=Defaults(**d), rules=pol.rules, allow_flows=pol.allow_flows,
                        secrets_allowed_tools=pol.secrets_allowed_tools)


@pytest_asyncio.fixture
async def make_gateway(tmp_path):
    """Factory: start an in-process gateway over a chosen set of demo upstreams."""
    started = []

    async def _make(names=(), mode="enforce", extra: tuple[Upstream, ...] = (), tools_cfg=None, policy=None):
        world, logs = tmp_path / "world", tmp_path / "logs"
        if not world.exists():
            shutil.copytree(FIXTURE_WORLD, world)
        logs.mkdir(exist_ok=True)
        specs = [u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.name in names] + list(extra)
        tools = tools_cfg or load_tools(ROOT / "tools.yaml")
        for t in ("crash_ok", "crash_boom", "crash_slow", "crash_ask_sampling", "crash_ask_user"):  # tools of the test-only misbehaving upstream
            tools.tools[t] = ToolEntry(labels=[], risk="low", reviewed=True)
        gw = await build_gateway(
            db_path=str(tmp_path / f"fw{len(started)}.db"), upstreams=specs, mode=mode, tools=tools, path_base=world, policy=policy or relaxed_policy(),
            env_extra={"FW_WORLD": str(world), "FW_LOG_DIR": str(logs)},
        )
        await gw.start()
        started.append(gw)
        return gw, logs

    yield _make
    for gw in started:
        await gw.stop()


def client_for(gw, token, legacy=True):
    """legacy=True: handshake-era client with a stable mcp-session-id (official SDKs today).
    legacy=False: fastmcp 4 default, a 2026-07-28 era client with no session at all."""
    headers = {"X-Task-Grant": token} if token else {}
    return Client(StreamableHttpTransport(gw.url, headers=headers), mode="legacy" if legacy else "auto")


def crashy_upstream(timeout_s: float = 30.0) -> Upstream:
    return Upstream(name="crash", transport="stdio", command="python", timeout_s=timeout_s,
                    args=[str(ROOT / "tests" / "helpers" / "crashy_server.py")])
