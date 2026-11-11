"""Trifecta rule (F13), rate/loop limits and circuit breaker (F08), and the Phase 4 pipeline steps 6 to 9."""
import asyncio
from pathlib import Path

import pytest_asyncio
from fastmcp.tools import ToolResult

from firewall import grants, ratelimit, sessions
from firewall.config import Defaults, PolicyConfig, load_policy, load_tools
from firewall.engine import Engine
from firewall.registry import Registry
from firewall.store import Store

ROOT = Path(__file__).resolve().parents[2]
WORLD = ROOT / "eval" / "fixtures" / "world"
NOTE = "Admin notes: the production database password is CANARY-7f3a91. Rotate it quarterly please."
PRIV = "The quarterly hiring plan covers eight new engineers in Berlin and three designers in Lisbon this year."
MAIL = {"to": "team@docs.example.com", "subject": "status", "body": "The launch is on schedule."}


@pytest_asyncio.fixture
async def env(tmp_path):
    store = await Store(tmp_path / "t.db").open()
    reg = Registry(load_tools(ROOT / "tools.yaml"))

    def make(mode="enforce", **defaults):
        pol = load_policy(ROOT / "policy.yaml")
        pol = PolicyConfig(defaults=Defaults(**{**pol.defaults.model_dump(), "rate_limit_per_min": 100000,
                                                "rate_burst": 100000, "loop_threshold": 1000, **defaults}),
                           rules=pol.rules, allow_flows=pol.allow_flows, secrets_allowed_tools=pol.secrets_allowed_tools)
        return Engine(store, pol, mode, registry=reg, known_tools=reg.names(), path_base=WORLD)

    async def grant(tools=("notes_read", "web_fetch", "mail_send_email", "fs_read_file", "fs_write_file"), **kw):
        g, tok = await grants.create_grant(
            store, {"task": "t", "allowed_tools": list(tools), "allowed_destinations": ["docs.example.com"],
                    "allowed_paths": ["./sandbox"], **kw}, registry=reg)
        return g, tok

    yield store, make, grant
    await store.close()


async def result_of(eng, tool, text, gid, sid="s"):
    return await eng.check_result(sid, None, tool, ToolResult(content=text), gid)


# ---------------- F13 trifecta ----------------
async def test_f13_private_plus_untrusted_makes_a_sink_call_need_approval(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await result_of(eng, "notes_read", NOTE, g.id)
    await result_of(eng, "web_fetch", "Some page text from the internet.", g.id)
    assert (await sessions.load_state(store, g.id)).labels == {"private", "untrusted"}
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)  # allowed destination, no verbatim overlap
    assert v.action == "require_approval" and "TRIFECTA_APPROVAL" in v.reason_codes
    assert eng.blocks(v)


async def test_f13_without_the_untrusted_label_no_approval_is_needed(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await result_of(eng, "notes_read", NOTE, g.id)
    assert (await eng.check_call("s", tok, "mail_send_email", MAIL)).action == "allow"


async def test_f13_without_the_private_label_no_approval_is_needed(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await result_of(eng, "web_fetch", "page", g.id)
    assert (await eng.check_call("s", tok, "mail_send_email", MAIL)).action == "allow"


async def test_f13_non_sink_calls_are_never_held_by_the_trifecta_rule(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await sessions.update_state(store, g.id, add_labels={"private", "untrusted"})
    assert (await eng.check_call("s", tok, "fs_read_file", {"path": "./sandbox/docs/a.txt"})).action == "allow"


async def test_f13_a_second_session_on_the_same_grant_still_triggers_it(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant(max_sessions=2)
    await result_of(eng, "notes_read", NOTE, g.id, sid="session-1")
    await result_of(eng, "web_fetch", "page", g.id, sid="session-1")
    v = await eng.check_call("session-2", tok, "mail_send_email", MAIL)
    assert v.action == "require_approval" and "TRIFECTA_APPROVAL" in v.reason_codes


async def test_f13_suspicious_grant_needs_approval_even_without_private_data(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await sessions.update_state(store, g.id, suspicious=True)
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert v.action == "require_approval" and "TRIFECTA_APPROVAL" in v.reason_codes


async def test_f13_block_mode_is_a_hard_deny_and_off_mode_disables_it(env):
    store, make, grant = env
    g, tok = await grant()
    await sessions.update_state(store, g.id, add_labels={"private", "untrusted"})
    blocked = await make(trifecta_mode="block").check_call("s", tok, "mail_send_email", MAIL)
    assert blocked.action == "deny" and blocked.reason_codes == ["POLICY_DENY"] and blocked.rule_id == "trifecta"
    off = make(trifecta_mode="off", )
    off.policy.rules = []  # the default policy also has a labels_seen rule; this isolates the trifecta switch
    assert (await off.check_call("s", tok, "mail_send_email", MAIL)).action == "allow"


async def test_f13_grant_approval_required_for_applies_even_without_labels(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant(approval_required_for=["mail_send_email"])
    v = await eng.check_call("s", tok, "mail_send_email", MAIL)
    assert v.action == "require_approval" and v.reason_codes == ["GRANT_APPROVAL"]


async def test_f13_hard_denies_win_over_approval_requirements(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await result_of(eng, "notes_read", PRIV, g.id)
    await result_of(eng, "web_fetch", "page", g.id)
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": PRIV})  # exfil AND trifecta
    assert v.action == "deny" and v.reason_codes == ["EXFIL_FLOW"]
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "to": "x@evil.example"})
    assert v.action == "deny" and v.reason_codes == ["DEST_NOT_ALLOWED"]


# ---------------- pipeline steps 7 to 9 ----------------
async def test_f33_oversized_arguments_are_denied_before_anything_is_inspected(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": "A" * 100_000})
    assert v.reason_codes == ["ARG_TOO_LARGE"]
    assert (await grants.get_grant(store, g.id)).used_calls == 0


async def test_f09_secret_in_sink_args_is_a_hard_deny(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": "key AKIAIOSFODNN7EXAMPLE"})
    assert v.reason_codes == ["SECRET_IN_ARGS"]
    m = v.detail["matches"][0]
    assert m["kind"] == "aws_access_key_id" and "AKIAIOSFODNN7EXAMPLE" not in str(v.detail)


async def test_f09_secret_in_non_sink_args_is_denied_unless_the_tool_is_allowed(env):
    store, make, grant = env
    g, tok = await grant()
    args = {"path": "./sandbox/out/x.txt", "content": "CANARY-7f3a91"}
    assert make().policy.secrets_allowed_tools == []
    assert (await make().check_call("s", tok, "fs_write_file", args)).reason_codes == ["SECRET_IN_ARGS"]
    eng = make()
    eng.policy.secrets_allowed_tools = ["fs_write_file"]
    assert (await eng.check_call("s", tok, "fs_write_file", args)).action == "allow"
    # but a sink never gets the exemption
    eng.policy.secrets_allowed_tools = ["mail_send_email"]
    assert (await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": "CANARY-7f3a91"})).reason_codes == [
        "SECRET_IN_ARGS"]


async def test_f09_pii_to_an_allowed_destination_is_recorded_for_the_operator_but_not_blocked(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": "Call Jane at +1 415 555 0134"})
    assert v.action == "allow" and [p["kind"] for p in v.detail["pii"]] == ["phone"]  # the recipient is not counted
    assert "415" not in str(v.detail["pii"])


async def test_f10_path_and_destination_checks_run_in_the_pipeline(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    assert (await eng.check_call("s", tok, "fs_read_file", {"path": "./sandbox/../etc/passwd"})).reason_codes == [
        "PATH_VIOLATION"]
    assert (await eng.check_call("s", tok, "web_fetch", {"url": "https://attacker.example/x"})).reason_codes == [
        "DEST_NOT_ALLOWED"]
    assert (await eng.check_call("s", tok, "fs_write_file", {"path": "./outside/target.txt", "content": "x"})
            ).reason_codes == ["PATH_VIOLATION"]


async def test_f12_end_to_end_label_then_fingerprint_then_block(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    await result_of(eng, "notes_read", PRIV, g.id)
    v = await eng.check_call("s", tok, "web_fetch", {"url": "https://docs.example.com/search?q=" + PRIV[:60].replace(" ", "%20")})
    assert v.reason_codes == ["EXFIL_FLOW"]
    benign = await eng.check_call("s", tok, "web_fetch", {"url": "https://docs.example.com/guide"})
    assert benign.action == "allow"


async def test_f12_declassification_is_audited_in_the_verdict(env):
    store, make, grant = env
    eng = make()
    eng.policy.allow_flows = PolicyConfig.model_validate({"allow_flows": [{"from": "notes_*", "to": "mail_*"}]}).allow_flows
    g, tok = await grant()
    await result_of(eng, "notes_read", PRIV, g.id)
    v = await eng.check_call("s", tok, "mail_send_email", {**MAIL, "body": PRIV})
    assert v.action == "allow" and v.detail["declassified"] == ["notes_read"]
    await eng.audit_call("s", tok, "mail_send_email", MAIL, v)
    row = (await store.query_audit(phase="call", limit=1))[0]
    assert "declassified" in row["detail"]


async def test_f12_result_handling_labels_even_when_a_tool_is_unreviewed(env):
    store, make, grant = env
    eng = make()
    eng.registry = Registry(PolicyConfig and load_tools(ROOT / "tools.yaml"))
    eng.registry._tools["notes_read"].reviewed = False  # unreviewed: private + untrusted + sink
    g, tok = await grant()
    await result_of(eng, "notes_read", NOTE, g.id)
    assert (await sessions.load_state(store, g.id)).labels == {"private", "untrusted"}


async def test_f33_oversized_results_are_truncated_and_flagged(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    out = await result_of(eng, "fs_read_file", "Z" * 300_000, g.id)
    assert out.content[0].text.endswith("code=RESULT_TRUNCATED")
    row = (await store.query_audit(phase="result", limit=1))[0]
    assert row["verdict"] == "flag" and row["reason_code"] == "RESULT_TRUNCATED"


# ---------------- F08 ----------------
CFG = Defaults(rate_limit_per_min=30, rate_burst=10, loop_threshold=3, loop_window_s=60)


def test_f08_token_bucket_burst_then_refill():
    rate, loop, codes = {}, {}, []
    for i in range(12):
        rate, loop, code = ratelimit.decide(rate, loop, 1000.0, f"k{i}", CFG)  # 12 different calls in one instant
        codes.append(code)
    assert codes == [None] * 10 + ["RATE_LIMIT"] * 2
    rate, loop, code = ratelimit.decide(rate, loop, 1001.9, "n1", CFG)  # 1.9 s * 0.5 per s = 0.95 token: not yet
    assert code == "RATE_LIMIT"
    rate, loop, code = ratelimit.decide(rate, loop, 1002.0, "n2", CFG)  # 2 s since the start of refill: one token
    assert code is None
    rate, loop, code = ratelimit.decide(rate, loop, 1002.0, "n3", CFG)
    assert code == "RATE_LIMIT"


def test_f08_bucket_never_exceeds_the_burst_size():
    rate, loop, _ = ratelimit.decide({}, {}, 0.0, "a", CFG)
    rate, loop, _ = ratelimit.decide(rate, loop, 3600.0, "b", CFG)  # an hour of refill
    assert rate["tokens"] <= CFG.rate_burst


def test_f08_identical_calls_trip_the_loop_breaker_on_the_third_within_a_minute():
    rate, loop, codes = {}, {}, []
    for t in (0.0, 10.0, 20.0):
        rate, loop, code = ratelimit.decide(rate, loop, t, "same", CFG)
        codes.append(code)
    assert codes == [None, None, "LOOP_DETECTED"]
    rate, loop, code = ratelimit.decide(rate, loop, 30.0, "different", CFG)
    assert code is None
    rate, loop, code = ratelimit.decide(rate, loop, 31.0, "same", CFG)
    assert code == "LOOP_DETECTED"  # the denied attempt counted too


def test_f08_loop_window_expires():
    rate, loop = {}, {}
    for t in (0.0, 10.0):
        rate, loop, _ = ratelimit.decide(rate, loop, t, "same", CFG)
    rate, loop, code = ratelimit.decide(rate, loop, 100.0, "same", CFG)  # the first two are > 60 s old
    assert code is None


async def test_f08_limits_are_per_grant_and_survive_new_sessions(env):
    store, make, grant = env
    eng = make(rate_limit_per_min=30, rate_burst=3, loop_threshold=1000)
    g1, t1 = await grant()
    g2, t2 = await grant()
    codes = [(await eng.check_call("s0" if i % 2 else "s1", t1, "notes_read", {"note_id": i})).code for i in range(5)]  # alternating sessions
    assert codes == [None, None, None, "RATE_LIMIT", "RATE_LIMIT"]
    assert (await eng.check_call("s9", t2, "notes_read", {"note_id": 1})).action == "allow"  # another grant is unaffected


async def test_f08_loop_breaker_through_the_engine(env):
    store, make, grant = env
    eng = make(loop_threshold=3)
    g, tok = await grant()
    codes = [(await eng.check_call("s", tok, "notes_read", {"note_id": 2})).code for _ in range(4)]
    assert codes == [None, None, "LOOP_DETECTED", "LOOP_DETECTED"]


async def test_f08_concurrent_calls_cannot_overspend_the_bucket(env):
    store, make, grant = env
    eng = make(rate_limit_per_min=1, rate_burst=5, loop_threshold=1000)
    g, tok = await grant()
    vs = await asyncio.gather(*[eng.check_call("s", tok, "notes_read", {"note_id": i}) for i in range(20)])
    assert sum(v.action == "allow" for v in vs) == 5


async def test_f08_five_consecutive_denies_suspend_the_grant_and_resume_restores_it(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    for i in range(4):
        assert (await eng.check_call("s", tok, "web_fetch", {"url": f"https://evil{i}.example/"})).code == "DEST_NOT_ALLOWED"
    assert not (await sessions.load_state(store, g.id)).suspended
    await eng.check_call("s", tok, "web_fetch", {"url": "https://evil5.example/"})  # fifth in a row
    st = await sessions.load_state(store, g.id)
    assert st.suspended and st.denied_streak == 5
    assert (await eng.check_call("s", tok, "notes_read", {"note_id": 2})).code == "GRANT_SUSPENDED"
    alerts = [r for r in await store.query_audit(phase="system", limit=20) if "suspended" in r["detail"]]
    assert len(alerts) == 1 and "GRANT_SUSPENDED" in alerts[0]["detail"]
    assert await grants.resume(store, g.id)
    assert (await eng.check_call("s", tok, "notes_read", {"note_id": 2})).action == "allow"


async def test_f08_an_allowed_call_resets_the_denied_streak(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant()
    for i in range(4):
        await eng.check_call("s", tok, "web_fetch", {"url": f"https://evil{i}.example/"})
    assert (await eng.check_call("s", tok, "notes_read", {"note_id": 2})).action == "allow"
    assert (await sessions.load_state(store, g.id)).denied_streak == 0
    for i in range(4):
        await eng.check_call("s", tok, "web_fetch", {"url": f"https://evil{i}.example/"})
    assert not (await sessions.load_state(store, g.id)).suspended


async def test_f08_monitor_mode_never_suspends(env):
    store, make, grant = env
    eng = make(mode="monitor")
    g, tok = await grant()
    for i in range(8):
        await eng.check_call("s", tok, "web_fetch", {"url": f"https://evil{i}.example/"})
    st = await sessions.load_state(store, g.id)
    assert not st.suspended and st.denied_streak == 0


async def test_f08_approval_requirements_and_grant_level_denies_do_not_count(env):
    store, make, grant = env
    eng = make()
    g, tok = await grant(approval_required_for=["notes_read"])
    for _ in range(7):
        assert (await eng.check_call("s", tok, "notes_read", {"note_id": 2})).action == "require_approval"
    assert not (await sessions.load_state(store, g.id)).suspended
