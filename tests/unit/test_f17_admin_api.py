"""Admin API (F17) and credential hygiene (F34)."""
import asyncio
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from firewall import grants
from firewall.admin_api import AdminConfigError, LoginLimiter, create_admin_app
from firewall.config import load_policy, load_tools
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "admin-token-0123456789"
H = {"X-Admin-Token": TOKEN}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest_asyncio.fixture
async def api(tmp_path):
    store = await Store(tmp_path / "a.db").open()
    clock = Clock()
    app = create_admin_app(store, Registry(load_tools(ROOT / "tools.yaml")), load_policy(ROOT / "policy.yaml"),
                           TOKEN, limiter=LoginLimiter(clock), version="abc123")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://admin") as c:
        yield c, store, clock
    await store.close()


GRANT = {"task": "demo", "allowed_tools": ["notes_read"], "allowed_destinations": [], "max_calls": 5}


@pytest.mark.parametrize("short", [None, "", "short", "x" * 15])
def test_f17_refuses_to_start_without_a_strong_admin_token(short):
    with pytest.raises(AdminConfigError, match="16"):
        create_admin_app(None, None, None, short)


ROUTES = [("GET", "/health"), ("GET", "/grants"), ("POST", "/grants"), ("GET", "/grants/g_x"),
          ("DELETE", "/grants/g_x"), ("POST", "/grants/g_x/resume"), ("GET", "/approvals"),
          ("POST", "/approvals/a/decision"), ("POST", "/policy/test"), ("GET", "/audit")]


@pytest.mark.parametrize("method, path", ROUTES)
async def test_f17_missing_or_wrong_token_is_401_on_every_route(api, method, path):
    c, store, _ = api
    body = {} if method == "POST" else None
    assert (await c.request(method, path, json=body)).status_code == 401
    assert (await c.request(method, path, headers={"X-Admin-Token": "wrong-token-value"}, json=body)).status_code == 401
    assert await store.list_grants() == []  # nothing was created or changed

async def test_f34_five_failures_lock_out_for_60_seconds_even_for_the_right_token(api):
    c, _, clock = api
    for _ in range(4):
        assert (await c.get("/grants", headers={"X-Admin-Token": "nope"})).status_code == 401
    assert (await c.get("/grants", headers=H)).status_code == 200  # a success resets the streak
    for _ in range(5):
        assert (await c.get("/grants", headers={"X-Admin-Token": "nope"})).status_code == 401
    r = await c.get("/grants", headers=H)
    assert r.status_code == 429 and r.json()["detail"]["error"] == "ADMIN_LOCKOUT"
    clock.t += 59
    assert (await c.get("/grants", headers=H)).status_code == 429
    clock.t += 2
    assert (await c.get("/grants", headers=H)).status_code == 200


async def test_f34_failures_older_than_a_minute_do_not_count(api):
    c, _, clock = api
    for _ in range(4):
        await c.get("/grants", headers={"X-Admin-Token": "nope"})
    clock.t += 61
    await c.get("/grants", headers={"X-Admin-Token": "nope"})
    assert (await c.get("/grants", headers=H)).status_code == 200


async def test_f17_health_reports_mode_and_config_version(api):
    c, _, _ = api
    body = (await c.get("/health", headers=H)).json()
    assert body["status"] == "ok" and body["mode"] == "enforce" and body["monitor_banner"] is False
    assert body["config_version"] == "abc123"
    assert body["approvals_enabled"] is False and body["selftest"] is None  # nothing has registered a gateway yet


async def test_f06_create_list_get_revoke_flow_and_token_shown_once(api):
    c, store, _ = api
    r = await c.post("/grants", headers=H, json=GRANT)
    assert r.status_code == 201
    created = r.json()
    token = created["token"]
    assert token.startswith("fwg_") and created["token_prefix"] == token[:8]
    gid = created["id"]
    listed = (await c.get("/grants", headers=H)).json()
    one = (await c.get(f"/grants/{gid}", headers=H)).json()
    assert [g["id"] for g in listed] == [gid]
    assert token not in json.dumps(listed) and token not in json.dumps(one)
    assert one["state"]["suspended"] is False and one["status"] == "active"
    assert (await grants.resolve(store, token)).id == gid
    rv = await c.delete(f"/grants/{gid}", headers=H)
    assert rv.status_code == 200 and rv.json()["status"] == "revoked"
    assert (await grants.resolve(store, token)).status == "revoked"
    assert (await c.delete(f"/grants/{gid}", headers=H)).status_code == 200  # idempotent
    assert (await c.delete("/grants/g_nope", headers=H)).status_code == 404
    assert (await c.get("/grants/g_nope", headers=H)).status_code == 404


@pytest.mark.parametrize("body, needle", [
    ({**GRANT, "allowed_tools": ["nope_tool"]}, "nope_tool"),
    ({**GRANT, "allowed_tools": ["fs_delete_file"]}, "allow_critical"),
    ({**GRANT, "max_calls": 500}, "max_calls"),
    ({**GRANT, "ttl_seconds": 999999}, "ttl_seconds"),
    ({**GRANT, "max_sessions": 9}, "max_sessions"),
    ({**GRANT, "allowed_tools": []}, "at least one"),
])
async def test_f06_invalid_grants_are_rejected_with_a_clear_message(api, body, needle):
    c, _, _ = api
    r = await c.post("/grants", headers=H, json=body)
    assert r.status_code == 422 and needle in json.dumps(r.json())


async def test_f06_critical_tool_allowed_with_explicit_flag(api):
    c, _, _ = api
    r = await c.post("/grants", headers=H, json={**GRANT, "allowed_tools": ["fs_delete_file"], "allow_critical": True})
    assert r.status_code == 201


async def test_f17_unknown_fields_are_rejected(api):
    c, _, _ = api
    r = await c.post("/grants", headers=H, json={**GRANT, "created_by": "agent", "status": "active"})
    assert r.status_code == 422


async def test_f17_every_mutating_endpoint_writes_an_audit_row_with_the_operator(api):
    c, store, _ = api
    gid = (await c.post("/grants", headers=H, json=GRANT)).json()["id"]
    await c.post(f"/grants/{gid}/resume", headers=H)
    await c.delete(f"/grants/{gid}", headers=H)
    await store.insert_approval({"id": "ap_1", "grant_id": gid, "tool": "mail_send_email", "args_hash": "h",
                                 "created_at": iso(utcnow()), "expires_at": iso(utcnow().replace(year=2099))})
    await c.post("/approvals/ap_1/decision", headers=H, json={"decision": "deny"})
    rows = await store.query_audit(phase="admin", limit=20)
    assert sorted(r["tool"] for r in rows) == sorted([
        "POST /grants", "POST /grants/resume", "DELETE /grants", "POST /approvals/decision"])
    assert all(json.loads(r["detail"])["operator"] == "operator" for r in rows)
    assert not any("fwg_" in r["detail"] for r in rows)  # no token material in audit


async def test_f08_resume_clears_suspension(api):
    from firewall import sessions

    c, store, _ = api
    gid = (await c.post("/grants", headers=H, json=GRANT)).json()["id"]
    await sessions.update_state(store, gid, suspended=True, denied_streak=5)
    assert (await c.get(f"/grants/{gid}", headers=H)).json()["state"]["suspended"] is True
    assert (await c.post(f"/grants/{gid}/resume", headers=H)).status_code == 200
    st = (await c.get(f"/grants/{gid}", headers=H)).json()["state"]
    assert st["suspended"] is False and st["denied_streak"] == 0
    assert (await c.post("/grants/g_nope/resume", headers=H)).status_code == 404


async def _approval(store, aid="ap_1", gid="g_1", expires="2099-01-01T00:00:00+00:00"):
    await store.insert_approval({"id": aid, "grant_id": gid, "tool": "mail_send_email", "args_hash": "h",
                                 "args_encrypted": b"secret-bytes", "reason_codes": ["TRIFECTA_APPROVAL"], "destination": "docs.example.com",
                                 "created_at": iso(utcnow()), "expires_at": expires})


async def test_f16_list_and_decide_approvals(api):
    c, store, _ = api
    await _approval(store)
    pending = (await c.get("/approvals?status=pending", headers=H)).json()
    assert [a["id"] for a in pending] == ["ap_1"] and "args_encrypted" not in pending[0]
    r = await c.post("/approvals/ap_1/decision", headers=H, json={"decision": "approve", "scope": "destination"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert (await c.get("/approvals?status=pending", headers=H)).json() == []
    row = (await c.get("/approvals?status=approved", headers=H)).json()[0]
    assert row["decided_by"] == "operator" and row["approval_scope"] == "destination"
    # pending arguments are deleted as soon as the decision is made
    assert (await store._all("SELECT args_encrypted FROM approvals WHERE id='ap_1'"))[0]["args_encrypted"] is None


async def test_f37_second_decision_on_the_same_approval_is_409(api):
    c, store, _ = api
    await _approval(store)
    first = await c.post("/approvals/ap_1/decision", headers=H, json={"decision": "approve"})
    second = await c.post("/approvals/ap_1/decision", headers=H, json={"decision": "deny"})
    assert (first.status_code, second.status_code) == (200, 409)
    assert (await c.get("/approvals?status=approved", headers=H)).json()[0]["status"] == "approved"


async def test_f37_concurrent_decisions_exactly_one_wins(api):
    c, store, _ = api
    await _approval(store)
    rs = await asyncio.gather(*[
        c.post("/approvals/ap_1/decision", headers=H, json={"decision": "approve" if i % 2 else "deny"})
        for i in range(10)])
    assert sorted(r.status_code for r in rs) == [200] + [409] * 9


async def test_f16_unknown_and_expired_approvals(api):
    c, store, _ = api
    assert (await c.post("/approvals/nope/decision", headers=H, json={"decision": "approve"})).status_code == 404
    await _approval(store, "ap_old", expires="2000-01-01T00:00:00+00:00")
    r = await c.post("/approvals/ap_old/decision", headers=H, json={"decision": "approve"})
    assert r.status_code == 409 and "expired" in json.dumps(r.json())
    assert (await c.get("/approvals?status=expired", headers=H)).json()[0]["id"] == "ap_old"
    assert (await c.post("/approvals/x/decision", headers=H, json={"decision": "maybe"})).status_code == 422


async def test_f07_policy_dry_run_executes_nothing_and_reports_the_rule(api):
    c, store, _ = api
    r = await c.post("/policy/test", headers=H, json={"tool": "fs_delete_file", "args": {"path": "./sandbox/out/a"}})
    assert r.json() == {"verdict": "require_approval", "reason_codes": ["POLICY_APPROVAL"], "rule_id": "rule_0"}
    r = await c.post("/policy/test", headers=H, json={"tool": "mail_send_email", "labels_seen": ["private", "untrusted"]})
    assert r.json()["rule_id"] == "rule_1"
    r = await c.post("/policy/test", headers=H, json={"tool": "mail_send_email", "labels_seen": ["private"]})
    assert r.json()["verdict"] == "allow" and r.json()["rule_id"] is None
    assert (await c.post("/policy/test", headers=H, json={"tool": "nope"})).status_code == 404
    assert await store.query_audit(limit=10) == []  # a dry run leaves no trace and spends nothing


async def test_f17_audit_endpoint_filters(api):
    c, store, _ = api
    gid = (await c.post("/grants", headers=H, json=GRANT)).json()["id"]
    rows = (await c.get(f"/audit?grant={gid}&limit=5", headers=H)).json()
    assert len(rows) == 1 and rows[0]["phase"] == "admin"
    assert (await c.get("/audit?grant=g_other", headers=H)).json() == []


async def test_f04_pins_endpoints_list_and_approve(api):
    c, store, _ = api
    await store.observe_pin("web", "web_fetch", "h1", "Fetch a page.", [], "2026-01-01T00:00:00+00:00")
    await store.observe_pin("web", "web_fetch", "h2", "Fetch a page. <IMPORTANT>x</IMPORTANT>", ["hidden-instruction tag"],
                            "2026-01-02T00:00:00+00:00")
    await store.observe_pin("fs", "fs_read_flle", "h3", "Read.", ["name shadows the reserved name 'read_file'"],
                            "2026-01-01T00:00:00+00:00")
    pins = {p["tool"]: p for p in (await c.get("/pins", headers=H)).json()}
    assert pins["web_fetch"]["state"] == "changed" and pins["web_fetch"]["reasons"] == ["hidden-instruction tag"]
    assert pins["web_fetch"]["new_hash"] == "h2" and "IMPORTANT" in pins["web_fetch"]["new_snapshot"]
    assert pins["fs_read_flle"]["state"] == "quarantined"
    r = await c.post("/pins/web/web_fetch/approve", headers=H)
    assert r.status_code == 200 and r.json()["state"] == "approved_change"
    after = {p["tool"]: p for p in (await c.get("/pins", headers=H)).json()}
    assert after["web_fetch"]["state"] == "approved_change" and after["web_fetch"]["hash"] == "h2"
    assert (await c.post("/pins/web/nope/approve", headers=H)).status_code == 404
    admin_rows = [r for r in await store.query_audit(phase="admin", limit=10) if r["tool"] == "POST /pins/approve"]
    assert len(admin_rows) == 1 and "web_fetch" in admin_rows[0]["detail"]


async def test_f04_pins_endpoints_need_the_admin_token(api):
    c, _, _ = api
    assert (await c.get("/pins")).status_code == 401
    assert (await c.post("/pins/web/web_fetch/approve")).status_code == 401
