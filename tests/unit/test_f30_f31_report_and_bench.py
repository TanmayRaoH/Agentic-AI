"""F28 held-out set shape, F30 report generator and F31 benchmark helpers."""
import json

import pytest

from eval import bench, report
from eval.scenario import EVAL_DIR, load_scenarios

HELDOUT = EVAL_DIR / "attacks" / "heldout"
DEV = EVAL_DIR / "attacks" / "dev"


# ---------------- F28 / Section 9: the held-out set ----------------
def test_f28_the_held_out_set_has_enough_scenarios_and_cited_sources():
    scenarios = load_scenarios(HELDOUT)
    assert len(scenarios) >= 10
    assert all(s.set == "heldout" for s in scenarios)
    assert sum(1 for s in scenarios if s.source.startswith(("AgentDojo", "EchoLeak", "Unicode Tags", "Indirect prompt",
                                                            "ChatInject", "Tool poisoning"))) >= 5
    assert all(s.source for s in scenarios)  # every scenario says where it comes from


def test_f28_dev_and_held_out_are_disjoint_and_marked_correctly():
    dev, held = load_scenarios(DEV), load_scenarios(HELDOUT)
    assert not {s.id for s in dev} & {s.id for s in held}
    assert all(s.set == "dev" for s in dev)
    assert {s.type for s in held} == {"prevention", "detection"}


def test_f28_the_held_out_pages_exist_in_the_demo_web_server():
    import sys

    sys.path.insert(0, str(EVAL_DIR.parent / "demo" / "servers"))
    try:
        import common
    finally:
        sys.path.pop(0)
    for s in load_scenarios(HELDOUT):
        for step in s.steps:
            url = step.args.get("url", "") if step.call == "web_fetch" else ""
            if "/community/ho-" in url:
                assert common.fetch_page(url) != "404 Not Found", s.id
    tags = common.fetch_page("https://docs.example.com/community/ho-tags")
    assert any(0xE0000 <= ord(c) <= 0xE007F for c in tags)  # really encoded with Unicode Tag characters


# ---------------- F31 helpers ----------------
def test_f31_percentiles_use_nearest_rank():
    values = list(range(1, 101))
    assert bench.percentile(values, 50) == 50
    assert bench.percentile(values, 95) == 95
    assert bench.percentile(values, 99) == 99
    assert bench.percentile([], 50) is None
    assert bench.percentile([7.0], 99) == 7.0


def test_f31_the_workload_never_repeats_a_call_more_than_the_loop_breaker_allows():
    web = bench.workload("web", 100)
    assert len({json.dumps(a, sort_keys=True) for _, a in web}) == 100
    files = bench.workload("files", 100)
    assert {t for t, _ in files} == {"notes_read", "fs_read_file", "fs_list_files"}


# ---------------- F30 report ----------------
def step(i, tool, is_error=False, code=None):
    return {"i": i, "kind": "call", "tool": tool, "is_error": is_error, "code": code, "text": ""}


def res(sid, kind, success, typ="prevention", set_="dev", gateway_only=False, category="A", steps=None, flaky=False):
    return {"id": sid, "category": category, "kind": kind, "type": typ, "set": set_, "gateway_only": gateway_only,
            "majority_success": success, "nondeterministic": flaky,
            "runs": [{"success": success, "steps": steps or [step(0, "notes_read")]}]}


META = {"fastmcp": "9.9.9", "python": "3.14.0", "platform": "Windows", "git_commit": "abc1234", "date": "2026-01-01",
        "reps": 3}


def write(tmp, name, mode, results):
    (tmp / name).write_text(json.dumps({"mode": mode, "meta": META, "summary": {}, "results": results}), encoding="utf-8")


@pytest.fixture
def results_dir(tmp_path):
    held_gap = next(s for s in load_scenarios(HELDOUT) if s.known_gap and s.type == "prevention")
    write(tmp_path, "final-unprotected.json", "unprotected", [
        res("A01-x", "attack", True), res(held_gap.id, "attack", True, set_="heldout"),
        res("F01-x", "attack", False, "detection", category="F"), res("BN01-x", "benign", True, category="BEN")])
    write(tmp_path, "final-monitor.json", "monitor", [
        res("A01-x", "attack", True), res(held_gap.id, "attack", True, set_="heldout"),
        res("BN01-x", "benign", True, category="BEN")])
    write(tmp_path, "final-enforce.json", "enforce", [
        res("A01-x", "attack", False, steps=[step(0, "notes_read"), step(1, "mail_send_email", True, "EXFIL_FLOW")]),
        res(held_gap.id, "attack", True, set_="heldout"),
        res("D04-x", "attack", False, gateway_only=True, category="D"),
        res("F01-x", "attack", True, "detection", category="F"),
        res("BN01-x", "benign", True, category="BEN", steps=[step(0, "notes_read"), step(1, "notes_read")]),
        res("BN02-x", "benign", False, category="BEN",
            steps=[step(0, "fs_list_files"), step(1, "fs_list_files", True, "RATE_LIMIT")], flaky=True)])
    write(tmp_path, "heldout-before-freeze-enforce.json", "enforce", [res(held_gap.id, "attack", True, set_="heldout")])
    return tmp_path, held_gap


def test_f30_the_report_has_every_required_section(results_dir):
    tmp, _ = results_dir
    text = report.build(tmp)
    for heading in ("## Environment", "## Headline", "## Per-category results", "## Detection scenarios",
                    "## Gateway-only control tests", "## Attacks that still succeed", "## Benign calls wrongly blocked",
                    "## Reason codes", "## Repeatability", "## Held-out set: before and after the tuning freeze",
                    "## Latency", "## Limitations"):
        assert heading in text, heading
    assert "fastmcp 9.9.9" in text and "abc1234" in text and "Python 3.14.0" in text


def test_f30_rates_follow_the_stated_definitions(results_dir):
    tmp, _ = results_dir
    text = report.build(tmp)
    assert "| 1/1 = 100% | 1/1 = 100% | **1/1 = 100%** |" in text  # held-out attack success: the one scenario gets through
    assert "| 1/1 = 100% | 0/1 = 0% |" in text.replace("**", "") or "0/1 = 0%" in text  # dev: 1 of 1 unprotected, 0 of 1 enforce
    assert "False-positive call rate" in text and "1/4 = 25%" in text  # 1 of the 4 benign calls was denied
    assert "Benign task success | 1/1 = 100% | 1/1 = 100% | 1/2 = 50%" in text
    assert "1/1 = 100% in enforce mode" in text  # detection scenario F01 detected
    assert "Held in enforce mode: 1/1 = 100%" in text  # the gateway-only control held


def test_f30_controls_and_detections_are_not_counted_as_attack_success(results_dir):
    tmp, _ = results_dir
    data = json.loads((tmp / "final-enforce.json").read_text())
    assert report.attack_rate(data, "dev") == "0/1 = 0%"  # D04 (control) and F01 (detection) are excluded
    assert report.control_rate(data, "dev") == "1/1 = 100%"
    assert report.detection_rate(data, "dev") == "1/1 = 100%"


def test_f30_surviving_attacks_come_with_their_explanation(results_dir):
    tmp, gap = results_dir
    text = report.build(tmp)
    section = text.split("## Attacks that still succeed")[1].split("## Benign")[0]
    assert gap.id in section and gap.known_gap in section


def test_f30_wrongly_blocked_benign_calls_and_reason_codes_are_listed(results_dir):
    tmp, _ = results_dir
    text = report.build(tmp)
    assert "BN02-x step 1 (fs_list_files): RATE_LIMIT" in text
    assert "| EXFIL_FLOW | 1 |" in text and "| RATE_LIMIT | 1 |" in text
    assert "Scenarios whose repetitions disagreed: BN02-x" in text


def test_f30_the_held_out_comparison_reports_changes_between_runs(results_dir):
    tmp, gap = results_dir
    assert "outcome changed between the two runs: none" in report.build(tmp)
    write(tmp, "heldout-before-freeze-enforce.json", "enforce", [res(gap.id, "attack", False, set_="heldout")])
    assert f"outcome changed between the two runs: {gap.id}" in report.build(tmp)


def test_f30_a_missing_optional_input_is_reported_not_fatal(results_dir):
    tmp, _ = results_dir
    (tmp / "heldout-before-freeze-enforce.json").unlink()
    text = report.build(tmp)
    assert "pre-freeze run was not found" in text and "has not been run" in text


def test_f30_the_limitations_name_the_known_gaps(results_dir):
    text = report.build(results_dir[0])
    limits = text.split("## Limitations")[1].lower()
    for needle in ("scripted", "heuristic", "paraphrase", "reply", "tamper-evident", "agentdojo", "same author"):
        assert needle in limits, needle


def test_f30_latency_section_renders_all_paths():
    lat = {"calls_per_path": 200, "warmup_calls": 20, "paths": {
        "direct": {"end_to_end_ms": {"n": 200, "p50": 3.0, "p95": 4.0, "p99": 5.0}},
        "enforce/scanner-on": {"end_to_end_ms": {"n": 200, "p50": 15.0, "p95": 20.0, "p99": 30.0},
                               "firewall_overhead_ms": {"n": 200, "p50": 6.0, "p95": 9.0, "p99": 12.0},
                               "added_end_to_end_p50_ms": 12.0}}}
    text = "\n".join(report.latency_section(lat))
    assert "| direct | 3.0 |" in text and "| enforce/scanner-on | 15.0 | 20.0 | 30.0 | 12.0 | 6.0 | 9.0 | 12.0 |" in text


def test_f30_main_refuses_to_run_without_results(tmp_path):
    with pytest.raises(SystemExit):
        import sys
        old = sys.argv
        sys.argv = ["report", "--results", str(tmp_path), "--out", str(tmp_path / "r.md")]
        try:
            report.main()
        finally:
            sys.argv = old
