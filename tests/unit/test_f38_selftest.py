"""F38: startup self-test and monitor-mode safety."""
from pathlib import Path

import httpx
import pytest

from firewall import destinations, flow, inspect_args, paths, scan_output, selftest
from firewall.admin_api import create_admin_app
from firewall.config import load_policy, load_tools
from firewall.registry import Registry
from firewall.server import ConfigurationRefused, build_gateway, resolve_mode
from firewall.store import Store

ROOT = Path(__file__).resolve().parents[2]
POLICY = load_policy(ROOT / "policy.yaml")
TOKEN = "admin-token-0123456789"


async def test_f38_a_healthy_install_passes_every_check():
    assert await selftest.run(POLICY) == []


def _break_flow(mp):
    async def blind(*a, **k):
        return flow.EgressResult(verdict=None) if hasattr(flow, "EgressResult") else None
    mp.setattr(flow, "evaluate_egress", blind)


@pytest.mark.parametrize("name, patch", [
    ("flow engine", _break_flow),
    ("injection scanner", lambda mp: mp.setattr(scan_output, "injection_score", lambda text: (0.0, []))),
    ("secret detector", lambda mp: mp.setattr(inspect_args, "scan_secrets", lambda text: [])),
    ("destination check", lambda mp: mp.setattr(destinations, "check_destination", lambda *a, **k: None)),
    ("path check", lambda mp: mp.setattr(paths, "check_paths", lambda *a, **k: None)),
])
async def test_f38_a_disabled_detector_is_reported_by_name(monkeypatch, name, patch):
    patch(monkeypatch)
    failures = await selftest.run(POLICY)
    assert any(f.startswith(name) for f in failures), failures


async def test_f38_a_detector_that_is_too_eager_is_also_a_failure(monkeypatch):
    monkeypatch.setattr(scan_output, "injection_score", lambda text: (1.0, ["x"]))
    assert any("harmless" in f for f in await selftest.run(POLICY))


async def test_f38_a_check_that_crashes_counts_as_failed(monkeypatch):
    def boom(text):
        raise RuntimeError("broken")
    monkeypatch.setattr(inspect_args, "scan_secrets", boom)
    failures = await selftest.run(POLICY)
    assert any("secret detector" in f and "crashed" in f for f in failures)


async def test_f38_the_gateway_refuses_to_start_when_a_detector_is_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_output, "injection_score", lambda text: (0.0, []))
    with pytest.raises(ConfigurationRefused, match="self-test"):
        await build_gateway(db_path=str(tmp_path / "g.db"), upstreams=[], mode="enforce")
    assert not (tmp_path / "g.db").exists()  # refused before touching the database


def test_f38_monitor_mode_needs_the_explicit_flag(monkeypatch):
    monkeypatch.setenv("FW_MODE", "monitor")
    monkeypatch.delenv("FW_ALLOW_MONITOR", raising=False)
    with pytest.raises(ConfigurationRefused, match="FW_ALLOW_MONITOR=1"):
        resolve_mode(POLICY)
    monkeypatch.setenv("FW_ALLOW_MONITOR", "0")
    with pytest.raises(ConfigurationRefused):
        resolve_mode(POLICY)
    monkeypatch.setenv("FW_ALLOW_MONITOR", "1")
    assert resolve_mode(POLICY) == "monitor"


def test_f38_enforce_needs_no_flag_and_junk_modes_are_refused(monkeypatch):
    monkeypatch.delenv("FW_ALLOW_MONITOR", raising=False)
    monkeypatch.setenv("FW_MODE", "enforce")
    assert resolve_mode(POLICY) == "enforce"
    monkeypatch.setenv("FW_MODE", "off")
    with pytest.raises(ConfigurationRefused, match="enforce or monitor"):
        resolve_mode(POLICY)


async def _health(tmp_path, mode, name="h.db"):
    store = await Store(tmp_path / name).open()
    try:
        if mode:
            await store.set_runtime("mode", mode, "2026-01-01T00:00:00Z")
        app = create_admin_app(store, Registry(load_tools(ROOT / "tools.yaml")), POLICY, TOKEN)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://admin") as c:
            return (await c.get("/health", headers={"X-Admin-Token": TOKEN})).json()
    finally:
        await store.close()


async def test_f38_health_shows_the_banner_only_while_the_gateway_runs_in_monitor_mode(tmp_path):
    assert (await _health(tmp_path, "monitor"))["monitor_banner"] is True
    h = await _health(tmp_path, "enforce", "h2.db")
    assert h["monitor_banner"] is False and h["mode"] == "enforce"
