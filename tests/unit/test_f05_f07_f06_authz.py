"""Unit tests for the registry (F05), policy engine (F07) and grant rules (F06)."""
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from pydantic import ValidationError

from firewall import grants, policy
from firewall.config import ConfigError, PolicyConfig, ToolsConfig, load_tools
from firewall.models import GrantState
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def registry():
    return Registry(load_tools(ROOT / "tools.yaml"))


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await Store(tmp_path / "t.db").open()
    yield s
    await s.close()


# ---------------- F05 registry ----------------
def test_f05_unreviewed_tool_gets_restrictive_labels_and_a_warning():
    reg = Registry(ToolsConfig.model_validate({"tools": {
        "a_safe": {"labels": [], "reviewed": True, "risk": "low"},
        "b_new": {"labels": [], "risk": "low", "dest_arg": "to"},  # not reviewed
    }}))
    assert reg.meta("a_safe").labels == []
    assert reg.meta("b_new").labels == ["private", "untrusted", "sink"]
    assert reg.meta("b_new").reviewed is False
    missing, warnings = reg.validate_discovery(["a_safe", "b_new"])
    assert missing == []
    assert any("b_new" in w and "not reviewed" in w for w in warnings)
    assert not any("a_safe" in w for w in warnings)


def test_f05_discovered_but_unlisted_tools_are_reported_by_name(registry):
    missing, _ = registry.validate_discovery(["notes_read", "evil_new_tool", "another_one"])
    assert missing == ["another_one", "evil_new_tool"]


def test_f05_listed_but_not_discovered_is_only_a_warning(registry):
    missing, warnings = registry.validate_discovery(["notes_read"])
    assert missing == []
    assert any("fs_read_file" in w for w in warnings)


def test_f05_unknown_tool_has_no_meta(registry):
    assert registry.meta("nope") is None and not registry.has("nope")


@pytest.mark.parametrize("entry, needle", [
    ({"labels": ["sink"], "risk": "high"}, "dest_arg"),
    ({"arg_kinds": {"p": "path"}}, "path_roots"),
    ({"labels": ["secret"]}, "labels"),
    ({"risk": "extreme"}, "risk"),
])
def test_f05_each_validation_failure_names_the_tool(tmp_path, entry, needle):
    p = tmp_path / "tools.yaml"
    import yaml

    p.write_text(yaml.safe_dump({"tools": {"my_tool": entry}}))
    with pytest.raises(ConfigError) as e:
        load_tools(p)
    assert "my_tool" in str(e.value) and needle in str(e.value)


# ---------------- F07 policy ----------------
def _rules(*rules):
    return PolicyConfig.model_validate({"rules": list(rules)}).rules


def _meta(registry, name):
    return registry.meta(name)


def test_f07_no_rules_means_none(registry):
    assert policy.evaluate([], _meta(registry, "notes_read"), GrantState("g"), {}) is None


def test_f07_first_match_wins_and_rule_order_matters(registry):
    deny_first = _rules({"match": {"tool": "mail_*"}, "action": "deny", "id": "d"},
                        {"match": {"tool": "mail_*"}, "action": "require_approval"})
    v = policy.evaluate(deny_first, _meta(registry, "mail_send_email"), GrantState("g"), {})
    assert v.action == "deny" and v.reason_codes == ["POLICY_DENY"] and v.rule_id == "d"
    approve_first = _rules({"match": {"tool": "mail_*"}, "action": "require_approval"},
                           {"match": {"tool": "mail_*"}, "action": "deny"})
    v = policy.evaluate(approve_first, _meta(registry, "mail_send_email"), GrantState("g"), {})
    assert v.action == "require_approval" and v.reason_codes == ["POLICY_APPROVAL"] and v.rule_id == "rule_0"


def test_f07_glob_and_risk_and_labels(registry):
    r = _rules({"match": {"tool": "fs_*", "risk": ["critical"]}, "action": "require_approval"})
    assert policy.evaluate(r, _meta(registry, "fs_delete_file"), GrantState("g"), {}) is not None
    assert policy.evaluate(r, _meta(registry, "fs_read_file"), GrantState("g"), {}) is None  # risk low
    assert policy.evaluate(r, _meta(registry, "notes_read"), GrantState("g"), {}) is None  # glob
    by_label = _rules({"match": {"labels": ["sink", "untrusted"]}, "action": "deny"})
    assert policy.evaluate(by_label, _meta(registry, "web_fetch"), GrantState("g"), {}) is not None
    assert policy.evaluate(by_label, _meta(registry, "notes_read"), GrantState("g"), {}) is None


def test_f07_labels_seen_requires_all(registry):
    r = _rules({"match": {"tool": "mail_*", "labels_seen": ["private", "untrusted"]}, "action": "require_approval"})
    m = _meta(registry, "mail_send_email")
    assert policy.evaluate(r, m, GrantState("g", labels={"private"}), {}) is None
    assert policy.evaluate(r, m, GrantState("g", labels=set()), {}) is None
    assert policy.evaluate(r, m, GrantState("g", labels={"private", "untrusted"}), {}) is not None


def test_f07_arg_regex(registry):
    r = _rules({"match": {"tool": "mail_*", "arg_regex": {"to": r"@evil\.example$"}}, "action": "deny"})
    m = _meta(registry, "mail_send_email")
    assert policy.evaluate(r, m, GrantState("g"), {"to": "x@evil.example"}) is not None
    assert policy.evaluate(r, m, GrantState("g"), {"to": "x@good.example"}) is None
    assert policy.evaluate(r, m, GrantState("g"), {}) is None  # argument absent


def test_f07_time_window_local_hours_including_wrap(registry):
    m = _meta(registry, "notes_read")
    day = _rules({"match": {"time_window": "9-17"}, "action": "deny"})
    assert policy.evaluate(day, m, GrantState("g"), {}, now=datetime(2026, 1, 1, 10)) is not None
    assert policy.evaluate(day, m, GrantState("g"), {}, now=datetime(2026, 1, 1, 17)) is None
    night = _rules({"match": {"time_window": "22-6"}, "action": "deny"})
    assert policy.evaluate(night, m, GrantState("g"), {}, now=datetime(2026, 1, 1, 23)) is not None
    assert policy.evaluate(night, m, GrantState("g"), {}, now=datetime(2026, 1, 1, 3)) is not None
    assert policy.evaluate(night, m, GrantState("g"), {}, now=datetime(2026, 1, 1, 12)) is None


@pytest.mark.parametrize("bad", [{"arg_regex": {"a": "("}}, {"time_window": "25-26"}, {"time_window": "noon"}])
def test_f23_invalid_rule_conditions_are_rejected_at_load(bad):
    with pytest.raises(Exception, match="arg_regex|time_window"):
        PolicyConfig.model_validate({"rules": [{"match": bad, "action": "deny"}]})


def test_f07_a_rule_can_never_allow():
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"rules": [{"match": {}, "action": "allow"}]})


# ---------------- F06 grants ----------------
GOOD = {"task": "t", "allowed_tools": ["notes_read"]}


@pytest.mark.parametrize("override", [
    {"ttl_seconds": 24 * 3600 + 1}, {"ttl_seconds": 0}, {"max_calls": 201}, {"max_calls": 0},
    {"max_sessions": 6}, {"max_sessions": 0}, {"allowed_tools": []}, {"allowed_tools": "notes_read"},
    {"max_calls": "30"}, {"max_calls": True},
])
async def test_f06_creation_limits_are_enforced(store, registry, override):
    with pytest.raises(grants.GrantError):
        await grants.create_grant(store, {**GOOD, **override}, registry=registry)


async def test_f06_limit_edges_are_allowed_and_defaults_apply(store, registry):
    g, _ = await grants.create_grant(store, {**GOOD, "ttl_seconds": 86400, "max_calls": 200, "max_sessions": 5},
                                     registry=registry)
    assert (g.max_calls, g.max_sessions) == (200, 5)
    d, _ = await grants.create_grant(store, GOOD, registry=registry)
    assert (d.max_calls, d.max_sessions) == (30, 2)
    ttl = datetime.fromisoformat(d.expires_at) - datetime.fromisoformat(d.created_at)
    assert ttl == timedelta(hours=1)


async def test_f06_grant_naming_a_tool_outside_the_registry_is_rejected(store, registry):
    with pytest.raises(grants.GrantError, match="does_not_exist"):
        await grants.create_grant(store, {**GOOD, "allowed_tools": ["notes_read", "does_not_exist"]}, registry=registry)
    with pytest.raises(grants.GrantError, match="nope"):
        await grants.create_grant(store, {**GOOD, "approval_required_for": ["nope"]}, registry=registry)


async def test_f06_critical_tools_need_allow_critical(store, registry):
    spec = {**GOOD, "allowed_tools": ["fs_delete_file"]}
    with pytest.raises(grants.GrantError, match="allow_critical"):
        await grants.create_grant(store, spec, registry=registry)
    g, _ = await grants.create_grant(store, {**spec, "allow_critical": True}, registry=registry)
    assert g.allowed_tools == ["fs_delete_file"]


async def test_f06_expiry_boundary(store):
    g, tok = await grants.create_grant(store, GOOD)
    assert (await grants.resolve(store, tok)).status == "active"
    await store.set_grant_expiry(g.id, iso(utcnow() + timedelta(seconds=30)))
    assert (await grants.resolve(store, tok)).status == "active"
    await store.set_grant_expiry(g.id, iso(utcnow() - timedelta(seconds=1)))
    assert (await grants.resolve(store, tok)).status == "expired"
    assert not await grants.reserve_budget(store, g.id)  # an expired grant can never spend budget


async def test_f06_revocation_takes_effect_on_next_resolve_and_is_idempotent(store):
    g, tok = await grants.create_grant(store, GOOD)
    assert await grants.revoke(store, g.id) is True
    assert (await grants.resolve(store, tok)).status == "revoked"
    assert not await grants.reserve_budget(store, g.id)
    assert await grants.revoke(store, g.id) is False  # already revoked


async def test_f06_exhaustion(store):
    g, tok = await grants.create_grant(store, {**GOOD, "max_calls": 2})
    assert await grants.reserve_budget(store, g.id) and await grants.reserve_budget(store, g.id)
    assert not await grants.reserve_budget(store, g.id)
    assert (await grants.resolve(store, tok)).status == "exhausted"
