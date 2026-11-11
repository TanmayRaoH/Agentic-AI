"""Data-flow engine (F12): normalization, fingerprints, decoding, egress matching, chunking, caps."""
import base64
import codecs
from urllib.parse import quote

import pytest
import pytest_asyncio

from firewall import flow, grants
from firewall.config import AllowFlow
from firewall.store import Store

NOTE = ("Admin notes: the production database password is CANARY-7f3a91. "
        "Rotate it quarterly and never share it outside the infrastructure team.")
CANARY = "CANARY-7f3a91"


@pytest_asyncio.fixture
async def env(tmp_path):
    store = await Store(tmp_path / "f.db").open()
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"]})
    yield store, g.id
    await store.close()


async def private(env, text=NOTE, tool="notes_read"):
    store, gid = env
    await flow.register_private(store, gid, tool, text)


async def egress(env, args, tool="mail_send_email", allow_flows=None):
    store, gid = env
    r = await flow.evaluate_egress(store, gid, tool, args, allow_flows)
    if r.verdict is None:
        await flow.record_egress(store, gid, r.buffer_entries)
    return r.verdict


# ---------------- normalization and fingerprints ----------------
def test_f12_flow_normal_form():
    assert flow.flow_normal("C A N-A-R-Y_7F3a91!") == "canary7f3a91"
    assert flow.flow_normal("ＣＡＮＡＲＹ７ｆ３ａ９１") == "canary7f3a91"  # NFKC
    assert flow.flow_normal("CAN\u200bARY\u200d-7f\ufeff3a91") == "canary7f3a91"  # zero-width removed
    assert flow.flow_normal("") == "" and flow.flow_normal("!!! ---") == ""
    assert flow.flow_normal("Ünïcode ß 123") == flow.flow_normal("ünïcode ß 123")


def test_f12_fingerprints_are_stable_and_ignore_formatting():
    a = flow.fingerprints(NOTE)
    assert a and a == flow.fingerprints(NOTE)
    assert a == flow.fingerprints(NOTE.upper())
    assert a == flow.fingerprints(" ".join(NOTE))  # spaces between every character
    assert flow.fingerprints("too short") == set()
    assert len(a) < len(flow.flow_normal(NOTE))  # winnowing keeps a subset


def test_f12_shared_substring_shares_fingerprints():
    shared = flow.fingerprints(NOTE) & flow.fingerprints("Unrelated start. " + NOTE[:80] + " unrelated end.")
    assert len(shared) >= flow.FP_THRESHOLD
    assert len(flow.fingerprints(NOTE) & flow.fingerprints("A completely different sentence about lunch plans.")) == 0


def test_f12_rolling_hash_finds_tokens_and_rejects_collisions():
    rec = flow.token_record("canary7f3a91")
    tokens = [{"source_tool": "notes_read", "token_hash": rec[0], "length": rec[1], "poly": rec[2]}]
    assert flow.find_exact("xxcanary7f3a91yy", tokens) == {"notes_read"}
    assert flow.find_exact("canary7f3a9", tokens) == set()
    assert flow.find_exact("canary7f3a92", tokens) == set()
    forged = [{**tokens[0], "token_hash": "0" * 32}]  # same rolling hash, wrong real hash
    assert flow.find_exact("canary7f3a91", forged) == set()


# ---------------- decoding ----------------
def test_f12_candidates_cover_the_documented_encodings():
    secret = "the secret payload text"
    for encoded in (
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),  # padding repaired
        secret.encode().hex(),
        quote(secret, safe=""),
        secret[::-1],
        codecs.encode(secret, "rot13"),
    ):
        assert secret in flow.candidates(encoded), encoded
    assert secret in flow.candidates(f"prefix https://x.example/c?d={base64.b64encode(secret.encode()).decode()}&z=1")
    assert secret in flow.candidates(base64.b64encode(secret.encode().hex().encode()).decode())  # two layers


def test_f12_garbage_does_not_break_decoding():
    for junk in ("", "%", "%zz%41", "=" * 40, "A" * 17, "\x00\x01\x02", "💥" * 30, "ff" * 3):
        assert flow.candidates(junk)[0] == junk


# ---------------- egress ----------------
SEND = {"to": "team@docs.example.com", "subject": "report"}


@pytest.mark.parametrize("name, transform", [
    ("plain", lambda s: s),
    ("base64", lambda s: base64.b64encode(s.encode()).decode()),
    ("base64_urlsafe_nopad", lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")),
    ("hex", lambda s: s.encode().hex()),
    ("hex_upper", lambda s: s.encode().hex().upper()),
    ("url_encoded", lambda s: quote(s, safe="")),
    ("double_url_encoded", lambda s: quote(quote(s, safe=""), safe="")),
    ("reversed", lambda s: s[::-1]),
    ("rot13", lambda s: codecs.encode(s, "rot13")),
    ("spaced", lambda s: " ".join(s)),
    ("dashed_every_4", lambda s: "-".join(s[i : i + 4] for i in range(0, len(s), 4))),
    ("mixed_case", lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))),
    ("zero_width", lambda s: "\u200b".join(s)),
    ("punctuation_noise", lambda s: ".,;".join(s)),
    ("b64_of_hex", lambda s: base64.b64encode(s.encode().hex().encode()).decode()),
    ("hex_of_b64", lambda s: base64.b64encode(s.encode()).decode().encode().hex()),
    ("embedded_in_url", lambda s: "https://docs.example.com/c?d=" + base64.b64encode(s.encode()).decode()),
    ("embedded_in_prose", lambda s: "Hello team, please see below:\n\n" + s + "\n\nThanks!"),
])
async def test_f12_whole_note_is_caught_in_every_encoding(env, name, transform):
    await private(env)
    v = await egress(env, {**SEND, "body": transform(NOTE)})
    assert v is not None and v.reason_codes == ["EXFIL_FLOW"], name


@pytest.mark.parametrize("name, transform", [
    ("plain", lambda s: s),
    ("base64", lambda s: base64.b64encode(s.encode()).decode()),
    ("hex", lambda s: s.encode().hex()),
    ("url_encoded", lambda s: quote(s, safe="")),
    ("reversed", lambda s: s[::-1]),
    ("spaced", lambda s: " ".join(s)),
    ("dashed_every_4", lambda s: "-".join(s[i : i + 4] for i in range(0, len(s), 4))),
    ("mixed_case", lambda s: s.lower()),
    ("b64_of_hex", lambda s: base64.b64encode(s.encode().hex().encode()).decode()),
])
async def test_f12_the_bare_canary_secret_is_caught_in_every_encoding(env, name, transform):
    await private(env)
    v = await egress(env, {**SEND, "body": transform(CANARY)})
    assert v is not None and v.reason_codes == ["EXFIL_FLOW"], name
    assert v.detail["exact_token_match"] is True


async def test_f12_a_benign_summary_with_no_overlap_passes(env):
    await private(env)
    for body in ("Team lunch is on Friday at noon, please bring the slides.",
                 "Status: the launch is on schedule and costs are flat.",
                 "The password policy review is scheduled for next quarter.",  # shares words, not 12-char runs
                 "Rotate credentials regularly.", ""):
        assert await egress(env, {**SEND, "body": body}) is None, body


async def test_f12_partial_leak_of_long_text_is_caught_by_fingerprint_overlap(env):
    await private(env)
    v = await egress(env, {**SEND, "body": "FYI: " + NOTE[10:75]})
    assert v is not None and v.detail["fingerprint_overlap"] >= flow.FP_THRESHOLD


async def test_f12_a_short_fragment_is_not_enough(env):
    await private(env)
    assert await egress(env, {**SEND, "body": "never share it outside"}) is None  # 18 chars: under the overlap bar


async def test_f12_secret_split_across_two_arguments_of_one_call(env):
    await private(env)
    v = await egress(env, {**SEND, "subject": "CANARY-", "body": "7f3a91"})
    assert v is not None and v.reason_codes == ["EXFIL_FLOW"]


async def test_f12_chunks_over_two_calls_are_caught_by_the_egress_buffer(env):
    await private(env)
    assert await egress(env, {**SEND, "body": "CANARY"}) is None  # first half alone is harmless
    v = await egress(env, {**SEND, "body": "-7f3a91"})  # second half completes it
    assert v is not None and v.reason_codes == ["EXFIL_FLOW"]


async def test_f12_three_slices_over_three_calls(env):
    await private(env)
    assert await egress(env, {**SEND, "body": "CANAR"}) is None
    assert await egress(env, {**SEND, "body": "Y-7f3"}) is None
    assert (await egress(env, {**SEND, "body": "a91"})).reason_codes == ["EXFIL_FLOW"]


async def test_f12_chunks_in_hex_over_two_calls(env):
    await private(env)
    assert await egress(env, {**SEND, "body": b"CANARY".hex()}) is None
    assert (await egress(env, {**SEND, "body": b"-7f3a91".hex()})).reason_codes == ["EXFIL_FLOW"]


async def test_f12_chunks_of_the_long_text_over_two_calls(env):
    await private(env)
    half = len(NOTE) // 2
    first = await egress(env, {**SEND, "body": NOTE[:half]})
    second = await egress(env, {**SEND, "body": NOTE[half:]})
    assert first is not None or second is not None  # the second half joins the buffer and completes the overlap


async def test_f12_buffer_keeps_only_the_last_4kb(env):
    store, gid = env
    await private(env)
    await egress(env, {**SEND, "body": "CANARY"})
    for i in range(30):  # push ~6 KB of unrelated text through the buffer
        await egress(env, {**SEND, "body": f"filler number {i} " + "lorem ipsum dolor sit amet " * 8})
    assert sum(len(t) for _, t in await store.get_egress_entries(gid)) <= flow.EGRESS_BUFFER
    assert await egress(env, {**SEND, "body": "-7f3a91"}) is None  # the first half has scrolled out of the window


async def test_f12_nothing_registered_means_nothing_to_match(env):
    assert await egress(env, {**SEND, "body": NOTE}) is None


async def test_f12_data_is_isolated_per_grant(env, tmp_path):
    store, gid = env
    other, _ = await grants.create_grant(store, {"allowed_tools": ["x"]})
    await flow.register_private(store, gid, "notes_read", NOTE)
    r = await flow.evaluate_egress(store, other.id, "mail_send_email", {**SEND, "body": NOTE})
    assert r.verdict is None
    r = await flow.evaluate_egress(store, gid, "mail_send_email", {**SEND, "body": NOTE})
    assert r.verdict is not None


async def test_f12_short_private_values_become_exact_tokens_and_tiny_ones_are_ignored(env):
    store, gid = env
    await private(env, "hunter2hunter2")  # 14 chars: an exact token
    await private(env, "abc123")  # 6 chars: ignored
    assert (await egress(env, {**SEND, "body": "my pw is H-U-N-T-E-R-2-H-U-N-T-E-R-2"})).reason_codes == ["EXFIL_FLOW"]
    assert await egress(env, {**SEND, "body": "abc123 is fine to send"}) is None
    assert await store.fingerprint_count(gid) == 0


async def test_f12_secrets_inside_private_results_are_registered_even_when_short(env):
    # the result is long text, but the key inside it must also be matchable on its own
    long_text = "Deployment notes. " * 5 + "key AKIAIOSFODNN7EXAMPLE end"
    await private(env, long_text, tool="fs_read_file")
    v = await egress(env, {**SEND, "body": "x" + base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()})
    assert v is not None and v.detail["sources"] == ["fs_read_file"]


async def test_f12_fingerprint_cap_keeps_the_most_recent(env, monkeypatch):
    store, gid = env
    monkeypatch.setattr(flow, "FP_CAP", 40)
    first = "Alpha briefing covers quarterly revenue figures, regional hiring plans and the budget for next year."
    last = "Omega briefing lists the data migration timetable, vendor contracts and the rollback procedure."
    await private(env, first)
    for i in range(8):
        await private(env, f"Filler {i} " + f"unrelated private sentence number {i} goes here " * 3)
    await private(env, last)
    assert await store.fingerprint_count(gid) <= 40
    assert await egress(env, {**SEND, "body": last}) is not None  # newest data is still protected
    assert await egress(env, {**SEND, "body": first}) is None  # oldest data was evicted


async def test_f12_allow_flows_declassifies_named_pairs_only(env):
    await private(env, tool="notes_read")
    flows = [AllowFlow(**{"from": "notes_*", "to": "mail_*"})]
    store, gid = env
    r = await flow.evaluate_egress(store, gid, "mail_send_email", {**SEND, "body": NOTE}, flows)
    assert r.verdict is None and r.declassified == ["notes_read"]
    r = await flow.evaluate_egress(store, gid, "web_fetch", {"url": "https://docs.example.com/?q=" + quote(NOTE)}, flows)
    assert r.verdict is not None  # different sink: not declassified
    await private(env, "Other private file content that is long enough to fingerprint properly.", tool="fs_read_file")
    r = await flow.evaluate_egress(
        store, gid, "mail_send_email",
        {**SEND, "body": NOTE + " Other private file content that is long enough to fingerprint properly."}, flows)
    assert r.verdict is not None and "fs_read_file" in r.verdict.detail["sources"]  # one uncovered source blocks


async def test_f12_non_string_arguments_are_ignored(env):
    await private(env)
    assert await egress(env, {"count": 5, "flags": [True, None], "to": "a@docs.example.com"}) is None


async def test_f12_state_survives_a_new_store_connection(env, tmp_path):
    store, gid = env
    await private(env)
    s2 = await Store(store.path).open()  # a second process or a restart sees the same data
    try:
        r = await flow.evaluate_egress(s2, gid, "mail_send_email", {**SEND, "body": CANARY})
        assert r.verdict is not None
    finally:
        await s2.close()


async def test_f12_stored_fingerprints_contain_no_raw_text(env):
    store, gid = env
    await private(env)
    dump = str(await store._all("SELECT * FROM fingerprints")) + str(await store._all("SELECT * FROM exact_tokens"))
    assert "CANARY" not in dump and "7f3a91" not in dump and "production" not in dump.lower()


async def test_f12_glued_prefix_does_not_break_base64_alignment(env):
    await private(env)
    for glued in ('x', 'xy', 'xyz', 'id'):
        v = await egress(env, {**SEND, 'body': glued + base64.b64encode(CANARY.encode()).decode()})
        assert v is not None and v.reason_codes == ['EXFIL_FLOW'], glued


async def test_f12_junk_blobs_cannot_push_the_real_payload_out(env):
    await private(env)
    junk = ' '.join(['Zm9vYmFyYmF6cXV4'] * 80)
    v = await egress(env, {**SEND, 'body': junk + ' ' + base64.b64encode(CANARY.encode()).decode()})
    assert v is not None and v.reason_codes == ['EXFIL_FLOW']


async def test_f12_ordinary_prose_does_not_trigger_on_words_that_look_like_base64(env):
    await private(env)
    prose = 'Please review the infrastructure documentation regarding authentication and authorization procedures.'
    assert await egress(env, {**SEND, 'body': prose}) is None
