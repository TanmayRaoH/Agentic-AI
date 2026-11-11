"""Approval queue (F16): blocking mode, deferred mode, single use, scopes, encryption and previews."""
import asyncio
import json
from datetime import timedelta
from pathlib import Path

import pytest
import pytest_asyncio

from firewall import approvals, audit, flow, grants, sessions
from firewall.approvals import ApprovalCrypto, ApprovalKeyError
from firewall.config import Defaults, PolicyConfig, load_policy, load_tools
from firewall.engine import Engine
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[2]
WORLD = ROOT / "eval" / "fixtures" / "world"
KEY = "unit-test-approval-key-0123"
PRIV = "The quarterly hiring plan covers eight new engineers in Berlin and three designers in Lisbon this year."
TRI = {"TRIFECTA_APPROVAL", "POLICY_APPROVAL"}  # shipped policy.yaml also has a mail_* approval rule
MAIL = {"to": "team@docs.example.com", "subject": "status", "body": "Quarterly numbers look fine to me."}
TOOLS = ("notes_read", "web_fetch", "mail_send_email", "fs_read_file", "notes_write")


@pytest_asyncio.fixture
async def env(tmp_path):
    store = await Store(tmp_path / "t.db").open()
    reg = Registry(load_tools(ROOT / "tools.yaml"))
    crypto = ApprovalCrypto(KEY)

    def make(mode="enforce", approval_mode="block", timeout=1, ttl=900, secrets_allowed_tools=None, **extra) -> Engine:
        pol = load_policy(ROOT / "policy.yaml")
        d = {**pol.defaults.model_dump(), "rate_limit_per_min": 100000, "rate_burst": 100000, "loop_threshold": 1000,
             "approval_mode": approval_mode, "approval_timeout_s": timeout, "approval_pending_ttl_s": ttl, **extra}
        policy = PolicyConfig(defaults=Defaults(**d), rules=pol.rules, allow_flows=pol.allow_flows,
                              secrets_allowed_tools=secrets_allowed_tools or pol.secrets_allowed_tools)
        return Engine(store, policy, mode, registry=reg, known_tools=reg.names(), path_base=WORLD, approval_crypto=crypto)

    async def grant(tools=TOOLS, taint=True, **kw):
        g, tok = await grants.create_grant(
            store, {"task": "t", "allowed_tools": list(tools), "allowed_destinations": ["docs.example.com", "other.example.com"],
                    "allowed_paths": ["./sandbox"], **kw}, registry=reg)
        if taint:
            await sessions.update_state(store, g.id, add_labels={"private", "untrusted"})
        return g, tok

    yield store, make, grant, crypto
    await store.close()


async def pending(store, n=1, wait_s=3.0):
    for _ in range(int(wait_s / 0.02)):
        rows = await store.list_approvals("pending", with_args=True)
        if len(rows) >= n:
            return rows
        await asyncio.sleep(0.02)
    raise AssertionError(f"expected {n} pending approvals, found {len(await store.list_approvals())}")


async def decide(store, approval_id, decision="approve", scope="once"):
    return await store.decide_approval(approval_id, decision, scope, "operator", iso(utcnow()))


async def raw_args(store, approval_id):
    return (await store._all("SELECT args_encrypted FROM approvals WHERE id=?", (approval_id,)))[0]["args_encrypted"]


# ---------------- key handling and encryption ----------------
@pytest.mark.parametrize("bad", [None, "", "short", "x" * 15])
def test_f16_the_approval_key_must_be_set_and_long_enough(bad):
    with pytest.raises(ApprovalKeyError, match="16"):
        ApprovalCrypto(bad)


def test_f16_arguments_are_encrypted_and_a_wrong_key_cannot_read_them():
    c1, c2 = ApprovalCrypto(KEY), ApprovalCrypto("a-completely-different-key-9")
    blob = c1.encrypt({"body": "very private text"})
    assert b"very private" not in blob
    assert c1.decrypt(blob) == {"body": "very private text"}
    assert c2.decrypt(blob) is None
    assert c1.decrypt(b"garbage") is None


# ---------------- blocking mode ----------------
async def test_f16_approve_resumes_and_forwards_exactly_once(env):
    store, make, grant, _ = env
    eng = make(timeout=5)
    g, tok = await grant()
    task = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    assert set(json.loads(row["reason_codes"])) == TRI and row["destination"] == "docs.example.com"
    assert not task.done()  # the call is held open while the operator decides
    assert (await grants.get_grant(store, g.id)).used_calls == 0  # nothing is spent while waiting
    assert await decide(store, row["id"]) == "ok"
    v = await task
    assert v.action == "allow" and v.detail["approval_id"] == row["id"]
    assert (await grants.get_grant(store, g.id)).used_calls == 1
    done = await store.get_approval(row["id"])
    assert done["status"] == "approved" and done["used"] == 1 and done["decided_by"] == "operator"


async def test_f16_deny_returns_approval_denied_and_spends_nothing(env):
    store, make, grant, _ = env
    eng = make(timeout=5)
    g, tok = await grant()
    task = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    await decide(store, row["id"], "deny")
    v = await task
    assert v.action == "deny" and v.code == "APPROVAL_DENIED" and set(v.reason_codes[1:]) == TRI
    assert (await grants.get_grant(store, g.id)).used_calls == 0
    assert eng.blocks(v)


async def test_f16_timeout_denies_and_deletes_the_stored_arguments(env):
    store, make, grant, _ = env
    eng = make(timeout=1)
    g, tok = await grant()
    start = asyncio.get_running_loop().time()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    waited = asyncio.get_running_loop().time() - start
    assert v.code == "APPROVAL_TIMEOUT" and 0.9 <= waited < 3
    row = (await store.list_approvals(with_args=True))[0]
    assert row["status"] == "expired" and row["args_encrypted"] is None
    assert (await grants.get_grant(store, g.id)).used_calls == 0
    assert await decide(store, row["id"]) == "conflict"  # too late: the call has already been refused


async def test_f16_a_replay_with_changed_arguments_needs_a_new_approval(env):
    store, make, grant, _ = env
    eng = make(timeout=1)
    g, tok = await grant()
    first = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    await decide(store, row["id"])
    assert (await first).action == "allow"
    changed = {**MAIL, "body": "Quarterly numbers look fine to me!!"}  # one character different
    v = await eng.check_call("s", tok, "mail_send_email", changed)
    assert v.code == "APPROVAL_TIMEOUT"
    assert len(await store.list_approvals()) == 2


async def test_f16_an_approval_can_be_used_only_once(env):
    store, make, grant, _ = env
    eng = make(timeout=1)
    g, tok = await grant()
    first = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    await decide(store, row["id"])
    assert (await first).action == "allow"
    second = await eng.check_call("s", tok, "mail_send_email", MAIL)  # identical call
    assert second.code == "APPROVAL_TIMEOUT"
    assert (await grants.get_grant(store, g.id)).used_calls == 1


async def test_f16_an_approval_expires_120_seconds_after_it_was_given(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    approval_id = v.detail["approval_id"]
    await decide(store, approval_id)
    old = iso(utcnow() - timedelta(seconds=approvals.MAX_AGE_S + 5))
    await store._run("UPDATE approvals SET decided_at=? WHERE id=?", (old, approval_id))
    again = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert again.code == "APPROVAL_PENDING" and again.detail["approval_id"] != approval_id  # a fresh request


async def test_f16_an_approval_for_another_tool_or_grant_is_not_usable(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g1, t1 = await grant()
    g2, t2 = await grant()
    v = await eng.check_call("s", t1, "mail_send_email", MAIL)
    await decide(store, v.detail["approval_id"])
    other_grant = await eng.check_call("s2", t2, "mail_send_email", MAIL)
    assert other_grant.code == "APPROVAL_PENDING"
    assert (await eng.check_call("s", t1, "mail_send_email", MAIL)).action == "allow"  # the right grant can use it


# ---------------- hard denies are never approvable ----------------
@pytest.mark.parametrize("label, args, tool, code", [
    ("exfil", {**MAIL, "body": PRIV}, "mail_send_email", "EXFIL_FLOW"),
    ("secret", {**MAIL, "body": "key AKIAIOSFODNN7EXAMPLE"}, "mail_send_email", "SECRET_IN_ARGS"),
    ("destination", {**MAIL, "to": "x@evil.example"}, "mail_send_email", "DEST_NOT_ALLOWED"),
    ("oversize", {**MAIL, "body": "A" * 100_000}, "mail_send_email", "ARG_TOO_LARGE"),
    ("not-granted", MAIL, "fs_read_file", "PATH_VIOLATION"),
])
async def test_f16_an_approval_cannot_override_a_hard_deny(env, label, args, tool, code):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant(tools=TOOLS)
    await flow.register_private(store, g.id, "notes_read", PRIV)
    if label == "not-granted":
        args = {"path": "../../etc/passwd"}
    v = await eng.check_call("s", tok, tool, args)
    assert v.action == "deny" and v.code == code, (label, v.code)
    assert await store.list_approvals() == []  # a hard deny never even creates an approval request


async def test_f16_an_earlier_approval_does_not_unlock_a_later_hard_deny(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    await flow.register_private(store, g.id, "notes_read", PRIV)
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    await decide(store, v.detail["approval_id"], scope="destination")  # approved for this destination for the whole grant
    leak = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": PRIV})
    assert leak.code == "EXFIL_FLOW"
    secret = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": "AKIAIOSFODNN7EXAMPLE"})
    assert secret.code == "SECRET_IN_ARGS"


# ---------------- scope: destination ----------------
async def test_f16_destination_scope_covers_later_calls_to_the_same_destination_only(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    first = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert await decide(store, first.detail["approval_id"], scope="destination") == "ok"
    for body in ("A different message.", "And another one entirely.", "A third note for the team."):
        assert (await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": body})).action == "allow"
    elsewhere = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "to": "someone@other.example.com"})
    assert elsewhere.code == "APPROVAL_PENDING"  # another destination still needs its own approval
    other_grant, other_tok = await grant()
    assert (await eng.check_call("s", other_tok, "mail_send_email", MAIL)).code == "APPROVAL_PENDING"


async def test_f16_scope_destination_needs_a_destination(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant(approval_required_for=["notes_write"])
    v = await eng.check_call("s", tok, "notes_write", {"note_id": 4, "text": "plain"})
    assert v.code == "APPROVAL_PENDING"
    assert await decide(store, v.detail["approval_id"], scope="destination") == "no_destination"
    assert await decide(store, v.detail["approval_id"], scope="once") == "ok"


# ---------------- concurrency ----------------
async def test_f16_identical_concurrent_requests_share_one_row_and_only_one_may_use_it(env):
    store, make, grant, _ = env
    eng = make(timeout=3)
    g, tok = await grant()
    tasks = [asyncio.create_task(eng.check_call(f"s{i}", tok, "mail_send_email", MAIL)) for i in range(2)]
    (row,) = await pending(store)
    await asyncio.sleep(0.3)
    assert len(await store.list_approvals()) == 1  # no duplicate row for the identical request
    await decide(store, row["id"])
    results = await asyncio.gather(*tasks)
    assert sorted(v.action for v in results) == ["allow", "deny"]
    loser = next(v for v in results if v.action == "deny")
    assert loser.code in ("APPROVAL_DENIED", "APPROVAL_TIMEOUT")
    assert (await grants.get_grant(store, g.id)).used_calls == 1


async def test_f16_cancelling_a_waiting_call_expires_its_row_and_deletes_the_arguments(env):
    store, make, grant, _ = env
    eng = make(timeout=30)
    g, tok = await grant()
    task = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    done = (await store.list_approvals(with_args=True))[0]
    assert done["id"] == row["id"] and done["status"] == "expired" and done["args_encrypted"] is None


async def test_f16_the_second_decision_on_an_approval_is_a_conflict(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    results = await asyncio.gather(*[decide(store, v.detail["approval_id"], "approve" if i % 2 else "deny") for i in range(8)])
    assert sorted(results) == ["conflict"] * 7 + ["ok"]


# ---------------- encrypted arguments and preview ----------------
async def test_f16_pending_arguments_are_encrypted_at_rest_and_deleted_when_decided(env):
    store, make, grant, crypto = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    body = "Highly confidential quarterly narrative that must not sit in the database in clear text."
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": body})
    approval_id = v.detail["approval_id"]
    blob = await raw_args(store, approval_id)
    assert blob and b"confidential" not in blob and body not in str(await store._all("SELECT * FROM approvals"))
    assert crypto.decrypt(blob)["body"] == body
    await decide(store, approval_id)
    assert await raw_args(store, approval_id) is None  # deleted the moment it is decided


async def test_f16_expired_pending_rows_lose_their_arguments(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer", ttl=1)
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    await asyncio.sleep(1.2)
    assert await store.sweep_expired_approvals(iso(utcnow())) == 1
    row = await store.get_approval(v.detail["approval_id"], with_args=True)
    assert row["status"] == "expired" and row["args_encrypted"] is None
    assert await decide(store, row["id"]) == "conflict"


async def test_f16_the_preview_shows_content_destination_reasons_and_private_matches(env):
    store, make, grant, crypto = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    await flow.register_private(store, g.id, "notes_read", PRIV)
    # shares a 20+ character run with the private text, below the 3-fingerprint bar for a hard deny
    body = "Hiring news: new engineers in the pipeline, details to follow."
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": body})
    assert v.code == "APPROVAL_PENDING", v.reason_codes
    (row,) = await store.list_approvals("pending", with_args=True)
    p = approvals.preview(crypto, row)
    assert p["tool"] == "mail_send_email" and p["destination"] == "docs.example.com"
    assert set(p["reasons"]) == TRI and p["preview_available"] and body in p["preview"]
    assert p["private_matches"] >= 1 and len(p["preview"]) <= 500


async def test_f16_the_preview_is_cut_at_500_characters_and_masks_secrets(env):
    store, make, grant, crypto = env
    eng = make(approval_mode="defer", secrets_allowed_tools=["notes_write"])
    g, tok = await grant(approval_required_for=["notes_write"])
    eng.policy.secrets_allowed_tools = ["notes_write"]
    text = "AKIAIOSFODNN7EXAMPLE " + "filler " * 200
    v = await eng.check_call("s", tok, "notes_write", {"note_id": 5, "text": text})
    assert v.code == "APPROVAL_PENDING"
    (row,) = await store.list_approvals("pending", with_args=True)
    p = approvals.preview(crypto, row)
    assert len(p["preview"]) == 500 and "AKIAIOSFODNN7EXAMPLE" not in p["preview"] and "[aws_access_key_id#" in p["preview"]


async def test_f16_the_preview_is_unavailable_without_the_key_or_after_the_decision(env):
    store, make, grant, crypto = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    (row,) = await store.list_approvals("pending", with_args=True)
    assert approvals.preview(None, row)["preview_available"] is False
    assert approvals.preview(ApprovalCrypto("another-key-another-key"), row)["preview_available"] is False
    await decide(store, v.detail["approval_id"])
    decided = await store.get_approval(v.detail["approval_id"], with_args=True)
    assert approvals.preview(crypto, decided)["preview_available"] is False


# ---------------- deferred mode ----------------
async def test_f16_deferred_mode_returns_immediately_with_the_approval_id(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    start = asyncio.get_running_loop().time()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert asyncio.get_running_loop().time() - start < 0.5
    assert v.action == "deny" and v.code == "APPROVAL_PENDING" and set(v.reason_codes[1:]) == TRI
    await eng.audit_call("s", tok, "mail_send_email", MAIL, v)
    message = eng.agent_message(v)
    assert v.detail["approval_id"] in message and "APPROVAL_PENDING" in message and "Retry the identical call" in message
    assert (await grants.get_grant(store, g.id)).used_calls == 0


async def test_f16_deferred_retry_flow_pending_then_approved_then_used_up(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    first = await eng.check_call("s", tok, "mail_send_email", MAIL)
    again = await eng.check_call("s", tok, "mail_send_email", MAIL)  # still pending: no new row
    assert again.detail["approval_id"] == first.detail["approval_id"] and len(await store.list_approvals()) == 1
    await decide(store, first.detail["approval_id"])
    retry = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert retry.action == "allow" and retry.detail["approval_id"] == first.detail["approval_id"]
    after = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert after.code == "APPROVAL_PENDING" and after.detail["approval_id"] != first.detail["approval_id"]


async def test_f16_deferred_denial_is_delivered_once_then_a_new_request_is_possible(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    first = await eng.check_call("s", tok, "mail_send_email", MAIL)
    await decide(store, first.detail["approval_id"], "deny")
    denied = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert denied.code == "APPROVAL_DENIED" and denied.detail["approval_id"] == first.detail["approval_id"]
    fresh = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert fresh.code == "APPROVAL_PENDING" and fresh.detail["approval_id"] != first.detail["approval_id"]


async def test_f16_deferred_changed_arguments_open_a_new_request(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    a = await eng.check_call("s", tok, "mail_send_email", MAIL)
    await decide(store, a.detail["approval_id"])
    b = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "subject": "other subject"})
    assert b.code == "APPROVAL_PENDING" and b.detail["approval_id"] != a.detail["approval_id"]


async def test_f16_a_deferred_request_that_expired_is_replaced_by_a_new_one(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer", ttl=1)
    g, tok = await grant()
    a = await eng.check_call("s", tok, "mail_send_email", MAIL)
    await asyncio.sleep(1.2)
    b = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert b.code == "APPROVAL_PENDING" and b.detail["approval_id"] != a.detail["approval_id"]


# ---------------- other approval reasons and modes ----------------
async def test_f16_every_approval_type_reason_goes_through_the_queue(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant(tools=("fs_delete_file", "notes_write", "mail_send_email"), taint=False,
                         approval_required_for=["notes_write"], allow_critical=True)
    crit = await eng.check_call("s", tok, "fs_delete_file", {"path": "./sandbox/out/.keep"})
    grant_level = await eng.check_call("s", tok, "notes_write", {"note_id": 3, "text": "x"})
    assert crit.reason_codes == ["APPROVAL_PENDING", "POLICY_APPROVAL"]
    assert grant_level.reason_codes == ["APPROVAL_PENDING", "GRANT_APPROVAL"]
    await sessions.update_state(store, g.id, add_labels={"private", "untrusted"})
    both = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert set(both.reason_codes[1:]) == {"TRIFECTA_APPROVAL", "POLICY_APPROVAL"}


async def test_f16_without_an_approval_key_the_call_is_held_back_with_its_reason(env):
    store, make, grant, _ = env
    eng = make()
    eng.approval_crypto = None
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert v.action == "require_approval" and set(v.reason_codes) == TRI and eng.blocks(v)
    assert await store.list_approvals() == []


async def test_f16_monitor_mode_records_would_require_approval_forwards_and_spends_budget(env):
    store, make, grant, _ = env
    eng = make(mode="monitor")
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert v.action == "require_approval" and not eng.blocks(v)
    await eng.audit_call("s", tok, "mail_send_email", MAIL, v)
    assert (await store.query_audit(phase="call", limit=1))[0]["verdict"] == "would_require_approval"
    assert await store.list_approvals() == []
    assert (await grants.get_grant(store, g.id)).used_calls == 1  # the forwarded call spends budget


async def test_f16_approval_outcomes_do_not_count_toward_the_denied_streak(env):
    store, make, grant, _ = env
    eng = make(approval_mode="defer")
    g, tok = await grant()
    for i in range(7):
        v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "subject": f"s{i}"})
        assert v.code == "APPROVAL_PENDING"
    state = await sessions.load_state(store, g.id)
    assert state.denied_streak == 0 and not state.suspended


async def test_f16_the_audit_trail_records_the_decision_path(env):
    store, make, grant, _ = env
    eng = make(timeout=5)
    g, tok = await grant()
    task = asyncio.create_task(eng.check_call("s", tok, "mail_send_email", MAIL))
    (row,) = await pending(store)
    await decide(store, row["id"])
    v = await task
    await eng.audit_call("s", tok, "mail_send_email", MAIL, v)
    audited = (await store.query_audit(phase="call", limit=1))[0]
    assert audited["verdict"] == "allow" and row["id"] in audited["detail"]
    assert "Quarterly numbers" not in json.dumps(await store.query_audit(limit=50))  # arguments are never stored raw
    assert (await audit.verify_chain(store))["ok"]
