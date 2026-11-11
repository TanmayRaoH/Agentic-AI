"""Size limits (F33) and secret / PII detection (F09), including linear-time behavior on 1 MB input."""
import time

import pytest
from fastmcp.tools import ToolResult

from firewall import flow, limits
from firewall.inspect_args import find_pii, find_secrets, luhn_ok, scan_pii, scan_secrets

MB = 1024 * 1024


# ---------------- F33 argument limits ----------------
def test_f33_normal_arguments_pass():
    assert limits.check_arg_limits({"a": "x", "b": [1, 2, {"c": "d"}], "n": 3}) is None
    assert limits.check_arg_limits({}) is None


@pytest.mark.parametrize("args, limit", [
    ({"s": "x" * (limits.MAX_STRING_CHARS + 1)}, "string_chars"),
    ({"l": list(range(limits.MAX_LIST_ITEMS + 1))}, "list_items"),
    ({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": "too deep"}}}}}}}}}, "depth"),
    ({f"k{i}": "x" * 30_000 for i in range(4)}, "json_bytes"),
])
def test_f33_violations_deny_with_arg_too_large(args, limit):
    v = limits.check_arg_limits(args)
    assert v.action == "deny" and v.reason_codes == ["ARG_TOO_LARGE"] and v.detail["limit"] == limit


def test_f33_boundaries_are_inclusive():
    assert limits.check_arg_limits({"s": "x" * limits.MAX_STRING_CHARS}) is None
    assert limits.check_arg_limits({"l": list(range(limits.MAX_LIST_ITEMS))}) is None
    deep = "leaf"
    for _ in range(limits.MAX_DEPTH):
        deep = {"k": deep}
    assert limits.check_arg_limits(deep) is None  # 8 nested objects are allowed
    assert limits.check_arg_limits({"k": deep}) is not None  # 9 are not


def test_f33_hostile_input_is_rejected_fast():
    start = time.perf_counter()
    assert limits.check_arg_limits({"s": "x" * MB}) is not None
    nested: object = "x"
    for _ in range(100_000):
        nested = [nested]
    assert limits.check_arg_limits({"n": nested}) is not None  # no recursion error, stops at depth 9
    assert limits.check_arg_limits({"l": [["a"] * 400] * 400}) is not None  # 160k items but only 500 per list... size cap
    assert time.perf_counter() - start < 0.5


def test_f33_result_cap_truncates_and_marks():
    big = "A" * (limits.MAX_RESULT_BYTES + 5000)
    r = ToolResult(content=big)
    out, truncated = limits.cap_result(r)
    assert truncated
    text = out.content[0].text
    assert len(text.encode()) <= limits.MAX_RESULT_BYTES + 200
    assert text.endswith("code=RESULT_TRUNCATED")


def test_f33_result_under_cap_is_untouched():
    r = ToolResult(content="small")
    out, truncated = limits.cap_result(r)
    assert out is r and not truncated


def test_f33_result_cap_applies_across_blocks_and_keeps_small_structured_content():
    from mcp_types import TextContent

    blocks = [TextContent(type="text", text="B" * 200_000), TextContent(type="text", text="C" * 200_000)]
    r = ToolResult(content=blocks, structured_content={"copy": "D" * 10})
    out, truncated = limits.cap_result(r)
    assert truncated and sum(len(b.text.encode()) for b in out.content) <= limits.MAX_RESULT_BYTES + 200
    assert out.content[0].text == "B" * 200_000 and "C" * 100 in out.content[1].text
    assert out.structured_content == {"copy": "D" * 10}


def test_f33_oversized_structured_content_is_trimmed_but_keeps_its_shape():
    huge = "S" * 400_000
    r = ToolResult(content="ok", structured_content={"result": huge, "n": 3, "list": [huge, "x"]})
    out, truncated = limits.cap_result(r)
    assert truncated and set(out.structured_content) == {"result", "n", "list"}
    assert out.structured_content["n"] == 3
    leaves = [out.structured_content["result"], *out.structured_content["list"]]
    assert sum(len(s.encode()) for s in leaves) <= limits.MAX_RESULT_BYTES + 400
    assert out.structured_content["result"].endswith("code=RESULT_TRUNCATED")


# ---------------- F33 decoder caps ----------------
def test_f33_decoders_stop_after_two_layers():
    import base64

    secret = "the private payload text"
    one = base64.b64encode(secret.encode()).decode()
    two = base64.b64encode(one.encode()).decode()
    three = base64.b64encode(two.encode()).decode()
    assert secret in flow.candidates(two)
    assert secret not in flow.candidates(three)


def test_f33_decoder_output_is_capped_at_1mb():
    import base64

    blob = base64.b64encode(b"a" * (3 * MB)).decode()
    cands = flow.candidates(blob)
    assert sum(len(c) for c in cands) <= flow.MAX_DECODED_TOTAL + len(blob) + 10
    assert len(cands) <= flow.MAX_CANDIDATES


# ---------------- F09 secrets ----------------
GH = "ghp_" + "a1B2c3D4e5" * 3
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.mark.parametrize("kind, text", [
    ("aws_access_key_id", "id=AKIAIOSFODNN7EXAMPLE end"),
    ("private_key_block", "-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
    ("private_key_block", "-----BEGIN PRIVATE KEY-----"),
    ("github_token", f"token {GH}"),
    ("slack_token", "xoxb-1234567890-abcdefghij"),
    ("bearer_token", "Authorization: Bearer abcdefghijklmnop1234567890"),
    ("jwt", f"jwt {JWT}"),
    ("api_key_assignment", "api_key = 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z'"),
    ("api_key_assignment", 'SECRET: "0123456789abcdefABCDEF0123456789"'),
    ("canary", "the password is CANARY-7f3a91 ok"),
])
def test_f09_each_secret_detector_has_a_positive_case(kind, text):
    assert kind in {k for k, _ in scan_secrets(text)}


@pytest.mark.parametrize("text", [
    "AKIA is a prefix", "AKIAIOSFODNN7EXAMP", "akiaiosfodnn7example",  # too short / wrong case
    "ghp_short", "xox is not a token", "Bearer short", "eyJhbGci.too.short",
    "api_key = 'plainwordsonlyplainwordsonlyplainwords'",  # no digits: not mixed
    "api_key = '12345678901234567890123456789012345'",  # no letters
    "password: hunter2", "the canary in the coal mine", "CANARY- alone", "-----BEGIN CERTIFICATE-----",
])
def test_f09_secret_detectors_have_negative_cases(text):
    assert scan_secrets(text) == []


def test_f09_nested_arguments_and_paths_and_masking():
    args = {"to": "a@b.example", "body": {"parts": ["fine", f"key {GH}"], "n": 5}, "meta": [{"x": "CANARY-7f3a91"}]}
    found = find_secrets(args)
    assert {m.kind for m in found} == {"github_token", "canary"}
    assert {m.path for m in found} == {"body.parts[1]", "meta[0].x"}
    for m in found:
        assert GH not in m.masked and "7f3a91" not in m.masked
        assert len(m.masked) < 20


def test_f09_unicode_is_normalized_before_matching():
    fullwidth = "ＣＡＮＡＲＹ－７ｆ３ａ９１"  # fullwidth letters and hyphen
    assert [k for k, _ in scan_secrets(fullwidth)] == ["canary"]


def test_f09_returns_nothing_for_non_string_values():
    assert find_secrets({"a": 1, "b": None, "c": [True, 2.5]}) == []


# ---------------- F09 PII ----------------
def test_f09_pii_positive_cases():
    kinds = {k for k, _ in scan_pii("Jane jane.roe@docs.example.com +1 415 555 0134 card 4111 1111 1111 1111 id 123456789012")}
    assert kinds == {"email", "phone", "card_number", "national_id"}


@pytest.mark.parametrize("text", [
    "4111 1111 1111 1112",  # fails Luhn
    "1234567812345678",  # fails Luhn
    "meet at 12:30 on 2026-11-08", "version 1.2.3.4", "no at sign here", "user@localhost", "a@b",
    "order 12345", "1234567890",  # a bare digit run is not treated as a phone number
])
def test_f09_pii_negative_cases_including_luhn_failures(text):
    assert scan_pii(text) == []


def test_f09_card_is_not_also_reported_as_national_id_or_phone():
    kinds = [k for k, _ in scan_pii("pay 4111 1111 1111 1111 now")]
    assert kinds == ["card_number"]


def test_f09_luhn():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")


def test_f09_find_pii_masks_values():
    found = find_pii({"body": "mail jane.roe@docs.example.com"})
    assert found[0].kind == "email" and "jane.roe@docs" not in found[0].masked


# ---------------- F33 linear-time safety on 1 MB inputs ----------------
HOSTILE = {
    "plain_a": "a" * MB,
    "digits": "1" * MB,
    "digit_space": "1 " * (MB // 2),
    "at_signs": "@" * MB,
    "email_like": "a" * (MB // 2) + "@" + "b" * (MB // 2 - 1),
    "dots": "a." * (MB // 2),
    "eyj": "eyJ" * (MB // 3),
    "eyj_dots": "eyJa.eyJb." * (MB // 10),
    "akia": "AKIA" * (MB // 4),
    "ghp": "ghp_" * (MB // 4),
    "xox": "xoxb-" * (MB // 5),
    "bearer": "Bearer " * (MB // 7),
    "bearer_spaces": "Bearer" + " " * MB,
    "assign": "token=" * (MB // 6),
    "assign_spaces": "token" + " " * MB + "=",
    "begin": "-----BEGIN " * (MB // 11),
    "canary": "CANARY-" * (MB // 7),
    "dash_digits": "1-" * (MB // 2),
    "mixed": ("ab12-_./+= " * 100_000)[:MB],
    "percent": "%41" * (MB // 3),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_f33_detectors_finish_1mb_inputs_under_200ms(name):
    text = HOSTILE[name]
    runs = []
    for _ in range(3):  # best of three: a timing test should measure the code, not a busy machine
        start = time.perf_counter()
        scan_secrets(text)
        scan_pii(text)
        runs.append(time.perf_counter() - start)
    assert min(runs) < 0.2, f"{name}: {min(runs):.3f}s"


@pytest.mark.parametrize("name", ["plain_a", "dots", "mixed", "digit_space"])
def test_f33_flow_normal_is_fast_on_1mb(name):
    runs = []
    for _ in range(3):
        start = time.perf_counter()
        flow.flow_normal(HOSTILE[name])
        runs.append(time.perf_counter() - start)
    assert min(runs) < 0.2
