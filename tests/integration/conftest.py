import shutil
from pathlib import Path

import pytest_asyncio
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from firewall.config import Upstream, load_upstreams
from firewall.server import build_gateway

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_WORLD = ROOT / "eval" / "fixtures" / "world"


@pytest_asyncio.fixture
async def make_gateway(tmp_path):
    """Factory: start an in-process gateway over a chosen set of demo upstreams."""
    started = []

    async def _make(names=(), mode="enforce", extra: tuple[Upstream, ...] = ()):
        world, logs = tmp_path / "world", tmp_path / "logs"
        if not world.exists():
            shutil.copytree(FIXTURE_WORLD, world)
        logs.mkdir(exist_ok=True)
        specs = [u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.name in names] + list(extra)
        gw = await build_gateway(
            db_path=str(tmp_path / f"fw{len(started)}.db"), upstreams=specs, mode=mode,
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
