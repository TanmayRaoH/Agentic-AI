"""Report generator (F30): reads the result files of one evaluation and writes eval/report.md.

Inputs (eval/results/):
  final-unprotected.json, final-monitor.json, final-enforce.json   dev and held-out sets, same code version
  heldout-before-freeze-*.json                                     the held-out run made before the tuning freeze
  final-latency.json                                               optional, from eval.bench
Nothing here decides success: every outcome was computed by the runner from upstream logs, sink logs and files.

Usage: uv run python -m eval.report
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from eval.scenario import EVAL_DIR, default_dirs, load_scenarios

RESULTS = EVAL_DIR / "results"
MODES = ("unprotected", "monitor", "enforce")


def load(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def pct(a: int, b: int) -> str:
    return f"{a}/{b} = {a / b:.0%}" if b else "n/a"


def is_prevention(r: dict) -> bool:
    return r["kind"] == "attack" and r["type"] == "prevention" and not r["gateway_only"]


def is_control(r: dict) -> bool:
    return r["kind"] == "attack" and r["type"] == "prevention" and r["gateway_only"]


def is_detection(r: dict) -> bool:
    return r["kind"] == "attack" and r["type"] == "detection"


def pick(data: dict | None, set_name: str, pred) -> list[dict]:
    return [r for r in (data or {}).get("results", []) if r["set"] == set_name and pred(r)]


def attack_rate(data: dict | None, set_name: str) -> str:
    rows = pick(data, set_name, is_prevention)
    return pct(sum(r["majority_success"] for r in rows), len(rows)) if data else "not run"


def detection_rate(data: dict | None, set_name: str) -> str:
    rows = pick(data, set_name, is_detection)
    return pct(sum(r["majority_success"] for r in rows), len(rows)) if data else "not run"


def control_rate(data: dict | None, set_name: str) -> str:
    rows = pick(data, set_name, is_control)
    return pct(sum(not r["majority_success"] for r in rows), len(rows)) if data else "not run"


def benign_stats(data: dict | None, known: dict[str, str] | None = None) -> tuple[str, str, list[str]]:
    rows = [r for r in (data or {}).get("results", []) if r["kind"] == "benign"]
    if not data or not rows:
        return "not run", "not run", []
    ok = sum(r["majority_success"] for r in rows)
    calls = denied = 0
    wrong: list[str] = []
    for r in rows:
        steps = r["runs"][0]["steps"]  # the first repetition is representative; repeated runs are checked for flakiness
        for s in steps:
            if s["kind"] != "call":
                continue
            calls += 1
            if s["is_error"]:
                denied += 1
                why = f". {known[r['id']]}" if known and r["id"] in known and not any(
                    w.startswith(r["id"]) for w in wrong) else ""
                wrong.append(f"{r['id']} step {s['i']} ({s['tool']}): {s['code'] or 'error'}{why}")
    return pct(ok, len(rows)), pct(denied, calls), wrong


def category_table(data_by_mode: dict[str, dict | None], set_name: str) -> list[str]:
    cats = sorted({r["category"] for m in data_by_mode.values() for r in pick(m, set_name, is_prevention)})
    if not cats:
        return ["_no prevention scenarios in this set_", ""]
    lines = ["| Category | Scenarios | Unprotected | Monitor | Enforce |", "|---|---|---|---|---|"]
    for c in cats:
        cells = []
        total = 0
        for mode in MODES:
            rows = [r for r in pick(data_by_mode[mode], set_name, is_prevention) if r["category"] == c]
            total = max(total, len(rows))
            cells.append(f"{sum(r['majority_success'] for r in rows)}/{len(rows)}" if data_by_mode[mode] else "n/a")
        lines.append(f"| {c} | {total} | " + " | ".join(cells) + " |")
    return lines + [""]


def describe(known: dict[str, str], scenario_id: str) -> str:
    return known.get(scenario_id) or "no explanation recorded"


def latency_section(lat: dict | None) -> list[str]:
    if not lat:
        return ["_The latency benchmark has not been run (`uv run python -m eval.bench`)._", ""]
    lines = [f"{lat['calls_per_path']} measured calls per path after a warm-up of {lat['warmup_calls']} calls; times in "
             "milliseconds. Firewall overhead is the `latency_ms` of the call row plus that of the result row in the audit "
             "table (upstream time excluded). The call row covers the pipeline up to the forward and the result row covers "
             "result handling; neither includes the time to write its own audit row, so the end-to-end column is the "
             "complete cost.", "",
             "| Path | End-to-end p50 | p95 | p99 | Added end-to-end p50 | Firewall overhead p50 | p95 | p99 |",
             "|---|---|---|---|---|---|---|---|"]
    for label, p in lat["paths"].items():
        e = p["end_to_end_ms"]
        o = p.get("firewall_overhead_ms") or {}
        lines.append(f"| {label} | {e['p50']} | {e['p95']} | {e['p99']} | {p.get('added_end_to_end_p50_ms', '-')} | "
                     f"{o.get('p50', '-')} | {o.get('p95', '-')} | {o.get('p99', '-')} |")
    return lines + [""]


def build(results_dir: Path) -> str:
    final = {m: load(results_dir / f"final-{m}.json") for m in MODES}
    before = {m: load(results_dir / f"heldout-before-freeze-{m}.json") for m in ("unprotected", "enforce")}
    lat = load(results_dir / "final-latency.json")
    scenarios = {s.id: s for s in load_scenarios(*default_dirs(include_heldout=True))}
    known = {sid: s.known_gap for sid, s in scenarios.items() if s.known_gap}
    sources = {sid: s.source for sid, s in scenarios.items() if s.source}
    enf, unp = final["enforce"], final["unprotected"]
    n_dev = sum(1 for s in scenarios.values() if s.set == "dev" and s.kind == "attack")
    n_benign = sum(1 for s in scenarios.values() if s.kind == "benign")
    meta = (enf or unp or {}).get("meta", {})
    out: list[str] = ["# Agent Firewall: evaluation report", ""]

    out += ["## Environment", "",
            f"- fastmcp {meta.get('fastmcp', '?')}, Python {meta.get('python', '?')} on {meta.get('platform', '?')}",
            f"- code version: git {meta.get('git_commit', '?')}",
            f"- run date: {meta.get('date', '?')}; {meta.get('reps', '?')} repetitions per scenario, majority outcome reported",
            f"- scenarios: {sum(1 for s in scenarios.values() if s.set == 'dev' and s.kind == 'attack')} dev attacks, "
            f"{sum(1 for s in scenarios.values() if s.set == 'heldout')} held-out attacks, "
            f"{sum(1 for s in scenarios.values() if s.kind == 'benign')} benign tasks", ""]

    b_ok, b_fp, b_wrong = benign_stats(enf, known)
    ub_ok, _, _ = benign_stats(unp)
    mon_ok, _, _ = benign_stats(final["monitor"])
    out += ["## Headline", "",
            "| Measure | Unprotected | Monitor (logs only) | Enforce |", "|---|---|---|---|",
            f"| **Attack success, held-out set** (prevention scenarios) | {attack_rate(unp, 'heldout')} | "
            f"{attack_rate(final['monitor'], 'heldout')} | **{attack_rate(enf, 'heldout')}** |",
            f"| Attack success, dev set (secondary, tuned against) | {attack_rate(unp, 'dev')} | "
            f"{attack_rate(final['monitor'], 'dev')} | {attack_rate(enf, 'dev')} |",
            f"| Detection rate, held-out set (flagged or quarantined) | {detection_rate(unp, 'heldout')} | "
            f"{detection_rate(final['monitor'], 'heldout')} | {detection_rate(enf, 'heldout')} |",
            f"| Detection rate, dev set | {detection_rate(unp, 'dev')} | {detection_rate(final['monitor'], 'dev')} | "
            f"{detection_rate(enf, 'dev')} |",
            f"| Gateway-only controls held | {control_rate(unp, 'dev')} | {control_rate(final['monitor'], 'dev')} | "
            f"{control_rate(enf, 'dev')} |",
            f"| Benign task success | {ub_ok} | {mon_ok} | {b_ok} |",
            f"| False-positive call rate (benign calls denied or quarantined) | n/a | n/a | {b_fp} |", ""]
    if lat:
        e = lat["paths"].get("enforce/scanner-on", {})
        if e:
            out += [f"Latency added by the gateway in enforce mode with the scanner on: about "
                    f"{e['added_end_to_end_p50_ms']} ms at the median end to end (firewall overhead p50 "
                    f"{e['firewall_overhead_ms']['p50']} ms, p95 {e['firewall_overhead_ms']['p95']} ms). Details below.", ""]
    out += ["Definitions: attack success = prevention scenarios (not gateway_only) that reached ground-truth success divided "
            "by all such scenarios; detection rate = detection scenarios flagged or quarantined by the firewall; "
            "benign task success = benign scenarios reaching the expected end state; false-positive call rate = benign "
            "calls denied or quarantined divided by all benign calls. Ground truth comes from upstream execution logs, "
            "sink logs and sandbox files, never from the firewall's own verdicts (except detection scenarios, which are "
            "about what the firewall reported).", "",
            "A monitor-mode attack that 'succeeds' is expected: monitor mode logs and forwards everything.", ""]

    out += ["## Per-category results (prevention scenarios: succeeded / total)", "", "### Held-out set", ""]
    out += category_table(final, "heldout") + ["### Dev set", ""] + category_table(final, "dev")

    out += ["## Detection scenarios (reported as detection rates, not attack success)", ""]
    for set_name in ("dev", "heldout"):
        rows = pick(enf, set_name, is_detection)
        if not rows:
            continue
        out += [f"**{set_name}**: {detection_rate(enf, set_name)} in enforce mode", ""]
        for r in rows:
            mark = "detected" if r["majority_success"] else "missed"
            why = "" if r["majority_success"] else f" ({describe(known, r['id'])})"
            out.append(f"- {r['id']}: {mark}{why}")
        out.append("")

    out += ["## Gateway-only control tests", ""]
    ctl = pick(enf, "dev", is_control) + pick(enf, "heldout", is_control)
    if ctl:
        out += [f"Held in enforce mode: {pct(sum(not r['majority_success'] for r in ctl), len(ctl))}. These scenarios mean "
                "nothing without a gateway (expiry, budget, size limits), so they are excluded from the attack success rate.",
                ""] + [f"- {r['id']}: {'held' if not r['majority_success'] else 'NOT held'}" for r in ctl] + [""]

    out += ["## Attacks that still succeed in enforce mode", ""]
    for set_name in ("heldout", "dev"):
        rows = [r for r in pick(enf, set_name, is_prevention) if r["majority_success"]]
        out.append(f"**{set_name}**: " + ("none" if not rows else ""))
        out += [f"- {r['id']}: {describe(known, r['id'])}" for r in rows]
        out.append("")

    out += ["## Benign calls wrongly blocked (enforce mode)", ""]
    out += [f"- {w}" for w in b_wrong] if b_wrong else ["None. Every call of every benign scenario was forwarded "
                                                        "(scenarios marked auto_approve were held until the scripted operator approved them)."]
    failed = [r["id"] for r in (enf or {}).get("results", []) if r["kind"] == "benign" and not r["majority_success"]]
    out += ["", "Benign scenarios that did not reach the expected end state: " + (", ".join(failed) or "none"), ""]
    out += [f"This is a measured false positive, not a tuning target: the limit is the specified default. {known[i]}"
            for i in failed if i in known]
    out += [""] if any(i in known for i in failed) else []

    hist: Counter = Counter()
    for r in (enf or {}).get("results", []):
        for s in r["runs"][0]["steps"]:
            if s["code"]:
                hist[s["code"]] += 1
    out += ["## Reason codes seen by the agent (enforce mode, first repetition of each scenario)", ""]
    out += ["| Code | Count |", "|---|---|"] + [f"| {c} | {n} |" for c, n in hist.most_common()] + [""]

    flaky = sorted({r["id"] for d in final.values() for r in (d or {}).get("results", []) if r["nondeterministic"]})
    out += ["## Repeatability", "", "Scenarios whose repetitions disagreed: " + (", ".join(flaky) if flaky else "none") + ".", ""]

    out += ["## Held-out set: before and after the tuning freeze", ""]
    if before["enforce"] and enf:
        old = {r["id"]: r["majority_success"] for r in before["enforce"]["results"]}
        new = {r["id"]: r["majority_success"] for r in enf["results"] if r["set"] == "heldout"}
        changed = sorted(i for i in new if old.get(i) != new[i])
        out += [f"First run (before the freeze, code {before['enforce'].get('meta', {}).get('git_commit', 'version not recorded: the run predates the metadata block')}): attack success "
                f"{attack_rate(before['enforce'], 'heldout')}, detection {detection_rate(before['enforce'], 'heldout')}.",
                f"Final run (code {meta.get('git_commit', '?')}): attack success {attack_rate(enf, 'heldout')}, "
                f"detection {detection_rate(enf, 'heldout')}.",
                "Scenarios whose outcome changed between the two runs: " + (", ".join(changed) if changed else "none") + ".",
                "No detector, pattern or threshold was changed in response to a held-out result. The engine change between "
                "the two runs is that result handling now records its own latency in the audit rows.", ""]
    else:
        out += ["_The pre-freeze run was not found._", ""]

    out += ["## Latency (F31)", ""] + latency_section(lat)

    out += ["## Where the held-out scenarios come from", ""]
    out += [f"- {sid}: {src}" for sid, src in sorted(sources.items())] + [""]

    out += ["## Limitations", "",
            "- The attacker is scripted and not adaptive: it replays fixed steps and never reacts to a refusal, so the "
            "numbers say how the firewall handles known attack shapes, not how a determined adversary would fare. "
            "A real hijacked model could try many variants.",
            "- Detection of hostile content is heuristic. The held-out set shows its limits (see the missed detection "
            "scenarios above); the dev corpora were used for tuning, so dev numbers are optimistic.",
            "- The held-out scenarios were written by the same author who built the detectors, adapted from published "
            "examples. They were not run against the detectors before they were written, and no detector was tuned on "
            "their results, but they are not independent of the author's mindset. Only six are adapted from cited "
            "published attacks; the rest are standard weakness classes (SSRF, traversal, encoding) or written for this set.",
            "- Flow tracking matches text. Paraphrase, summaries, spelled-out values, lookalike characters and "
            "character-by-character leaks beyond the 4 KB egress buffer evade fingerprints. The trifecta rule only "
            "covers paraphrase once the grant has seen both private and untrusted data.",
            "- Leaks through the agent's own reply, rendered markdown images in the final answer, timing channels and a "
            "compromised host are out of scope (see docs/threat-model.md).",
            "- The audit hash chain is tamper-evident, not tamper-proof: someone who can rewrite the database and the "
            "checkpoint file can recompute it.",
            f"- Scenario counts are below the guide's targets: {n_dev} of the 34 dev attacks (category H is not built) and "
            f"{n_benign} of the 15 benign scenarios (no mid-task reconnect and no structured-content result). Rates over "
            "small counts move a lot with a single scenario.",
            "- Latency was measured on one developer machine with local stdio upstreams and a local SQLite file; "
            "absolute numbers will differ elsewhere. The end-to-end figure includes the extra HTTP hop through the "
            "gateway and its audit writes; the firewall-overhead figure covers only the checks themselves.",
            "- AgentDojo itself was not run; it is future work.", ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--out", type=Path, default=EVAL_DIR / "report.md")
    args = ap.parse_args()
    if not (args.results / "final-enforce.json").exists():
        raise SystemExit("no final-enforce.json: run `make eval` first")
    args.out.write_text(build(args.results), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
