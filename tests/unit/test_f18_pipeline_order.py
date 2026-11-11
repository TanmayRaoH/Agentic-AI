"""Engine pipeline ordering and verdicts for steps 1 to 5, 10, 11, 12 (T18)."""
from pathlib import Path

import pytest_asyncio

from firewall import grants, sessions
from firewall.config import PolicyConfig, load_policy, load_tools
from firewall.engine import Engine
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[2]
UNKNOWN = "totally_unknown_tool"


@pytest_asyncio.fixture
async def env(tmp_path):
    store = await Store(tmp_path / "t.db").open()
    reg = Registry(load_tools(ROOT / "tools.yaml"))

    def make(mode="enforce", policy=None):
        return Engine(store, policy or load_policy(ROOT / "policy.yaml"), mode, registry=reg,
                      known_tools=reg.names(),
                      path_base=ROOT / "eval" / "fixtures" / "world")

    yield store, reg, make
    await store.close()


async def _grant(store, reg, tools=("notes_read",), **extra):
    return await grants.create_grant(store, {"task": "t", "allowed_tools": list(tools), **extra}, registry=reg)


async def test_f18_no_grant_reports_no_grant_before_anything_else(env):
    store, reg, make = env
    eng = make()
    for token in (None, "", "fwg_not_a_real_token"):
        v = await eng.check_call("s1", token, UNKNOWN, {})
        assert v.code == "NO_GRANT" and v.action == "deny"
        v = await eng.check_call("s1", token, "fs_delete_file", {})  # even a real, dangerous tool
        assert v.code == "NO_GRANT"


async def test_f18_grant_state_checks_come_before_the_tool_checks(env):
    store, reg, make = env
    eng = make()
    g, tok = await _grant(store, reg)
    await store.set_grant_expiry(g.id, "2000-01-01T00:00:00+00:00")
    assert (await eng.check_call("s", tok, UNKNOWN, {})).code == "GRANT_EXPIRED"

    g2, tok2 = await _grant(store, reg)
    await grants.revoke(store, g2.id)
    assert (await eng.check_call("s", tok2, UNKNOWN, {})).code == "GRANT_REVOKED"

    g3, tok3 = await _grant(store, reg, max_calls=1)
    assert (await eng.check_call("s", tok3, "notes_read", {"note_id": 1})).action == "allow"
    assert (await eng.check_call("s", tok3, UNKNOWN, {})).code == "GRANT_EXHAUSTED"

    g4, tok4 = await _grant(store, reg)
    await sessions.update_state(store, g4.id, suspended=True)
    assert (await eng.check_call("s", tok4, UNKNOWN, {})).code == "GRANT_SUSPENDED"
    await grants.resume(store, g4.id)
    assert (await eng.check_call("s", tok4, UNKNOWN, {})).code == "UNKNOWN_TOOL"


async def test_f18_unknown_tool_then_scope_then_allow(env):
    store, reg, make = env
    eng = make()
    g, tok = await _grant(store, reg, tools=("notes_read",))
    assert (await eng.check_call("s", tok, UNKNOWN, {})).code == "UNKNOWN_TOOL"
    v = await eng.check_call("s", tok, "mail_send_email", {})  # real tool, not in this grant
    assert v.code == "TOOL_NOT_GRANTED" and v.grant_id == g.id
    v = await eng.check_call("s", tok, "notes_read", {"note_id": 2})
    assert v.action == "allow" and v.reason_codes == []


async def test_f18_registered_tool_that_no_upstream_provides_is_unknown(env):
    store, reg, make = env
    eng = make()
    eng.known_tools = {"notes_read"}  # fs_read_file is registered but not discovered
    g, tok = await _grant(store, reg, tools=("notes_read", "fs_read_file"))
    assert (await eng.check_call("s", tok, "fs_read_file", {})).code == "UNKNOWN_TOOL"


async def test_f18_denied_calls_do_not_spend_budget(env):
    store, reg, make = env
    eng = make()
    g, tok = await _grant(store, reg, max_calls=3)
    await eng.check_call("s", tok, UNKNOWN, {})
    await eng.check_call("s", tok, "mail_send_email", {})
    assert (await grants.get_grant(store, g.id)).used_calls == 0
    await eng.check_call("s", tok, "notes_read", {})
    assert (await grants.get_grant(store, g.id)).used_calls == 1


async def test_f07_policy_deny_wins_and_cannot_be_turned_into_allow(env):
    store, reg, make = env
    pol = PolicyConfig.model_validate({"rules": [{"match": {"tool": "notes_*"}, "action": "deny", "id": "no-notes"}]})
    eng = make(policy=pol)
    g, tok = await _grant(store, reg)
    v = await eng.check_call("s", tok, "notes_read", {})
    assert v.code == "POLICY_DENY" and v.rule_id == "no-notes"
    assert (await grants.get_grant(store, g.id)).used_calls == 0


async def test_f07_policy_cannot_allow_what_the_grant_does_not_list(env):
    store, reg, make = env
    eng = make(policy=PolicyConfig())  # no rules at all
    g, tok = await _grant(store, reg)
    assert (await eng.check_call("s", tok, "mail_send_email", {})).code == "TOOL_NOT_GRANTED"


async def test_f07_critical_risk_requires_approval_and_is_held_back_without_a_queue(env):
    store, reg, make = env
    eng = make()
    g, tok = await _grant(store, reg, tools=("fs_delete_file",), allow_critical=True, allowed_paths=["./sandbox"])
    v = await eng.check_call("s", tok, "fs_delete_file", {"path": "./sandbox/out/x"})
    assert v.action == "require_approval" and v.reason_codes == ["POLICY_APPROVAL"]
    assert eng.blocks(v)  # no approval flow yet: fail closed
    assert (await grants.get_grant(store, g.id)).used_calls == 0


async def test_f13_grant_approval_required_for_adds_grant_approval(env):
    store, reg, make = env
    eng = make()
    g, tok = await _grant(store, reg, tools=("notes_read",), approval_required_for=["notes_read"])
    v = await eng.check_call("s", tok, "notes_read", {})
    assert v.action == "require_approval" and v.reason_codes == ["GRANT_APPROVAL"]


async def test_f07_labels_seen_rule_uses_grant_state(env):
    store, reg, make = env
    eng = make(policy=PolicyConfig.model_validate({"defaults": {"trifecta_mode": "off"}, "rules": [
        {"match": {"tool": "mail_*", "labels_seen": ["private", "untrusted"]}, "action": "require_approval"}]}))
    g, tok = await _grant(store, reg, tools=("mail_send_email",), allowed_destinations=["docs.example.com"])
    mail = {"to": "a@docs.example.com", "subject": "s", "body": "hello team"}
    assert (await eng.check_call("s", tok, "mail_send_email", mail)).action == "allow"
    await sessions.update_state(store, g.id, add_labels={"private", "untrusted"})
    v = await eng.check_call("s", tok, "mail_send_email", {**mail, "body": "another body"})
    assert v.action == "require_approval" and v.reason_codes == ["POLICY_APPROVAL"] and v.rule_id == "rule_0"

async def test_f07_monitor_mode_records_would_deny_and_does_not_block(env):
    store, reg, make = env
    eng = make(mode="monitor")
    g, tok = await _grant(store, reg)
    v = await eng.check_call("s", tok, "mail_send_email", {})
    assert v.code == "TOOL_NOT_GRANTED" and not eng.blocks(v)
    await eng.audit_call("s", tok, "mail_send_email", {}, v)
    row = (await store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "would_deny" and row["reason_code"] == "TOOL_NOT_GRANTED"
    assert v.event_id == f"ev_{row['id']}"


async def test_f03_filter_tools_only_shows_the_grant(env):
    store, reg, make = env
    eng = make()

    class T:
        def __init__(self, name):
            self.name = name

    catalog = [T(n) for n in ("notes_read", "mail_send_email", "fs_read_file", "web_fetch")]
    _, a = await _grant(store, reg, tools=("notes_read", "fs_read_file"))
    _, b = await _grant(store, reg, tools=("mail_send_email",))
    assert {t.name for t in await eng.filter_tools("s", a, catalog)} == {"notes_read", "fs_read_file"}
    assert {t.name for t in await eng.filter_tools("s", b, catalog)} == {"mail_send_email"}
    assert await eng.filter_tools("s", None, catalog) == []
    assert await eng.filter_tools("s", "fwg_bogus", catalog) == []


async def test_f03_filter_hides_everything_for_inactive_grants(env):
    store, reg, make = env
    eng = make()

    class T:
        name = "notes_read"

    g, tok = await _grant(store, reg)
    assert len(await eng.filter_tools("s", tok, [T()])) == 1
    await grants.revoke(store, g.id)
    assert await eng.filter_tools("s", tok, [T()]) == []
    g2, tok2 = await _grant(store, reg)
    await store.set_grant_expiry(g2.id, iso(utcnow()))
    assert await eng.filter_tools("s", tok2, [T()]) == []


async def test_f03_filter_fails_closed_on_internal_error(env):
    store, reg, make = env
    eng = make()
    await store.close()  # every query will now raise

    class T:
        name = "notes_read"

    assert await eng.filter_tools("s", "fwg_whatever", [T()]) == []
    await store.open()  # reopen so the fixture teardown works
