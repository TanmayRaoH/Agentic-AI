"""Evaluation runner (F29). Phase 1: unprotected mode only.

Usage: uv run python -m eval.runner --modes unprotected [--sets dev] [--reps 3] [--only A02]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import time
from collections import defaultdict
from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from eval.attacker import run_steps
from eval.backends import LOGS, RUNTIME, UnprotectedBackend
from eval.ground_truth import FIXTURE_WORLD, WORLD, eval_cond
from eval.scenario import EVAL_DIR, Scenario, default_dirs, load_scenarios

console = Console()


def reset_environment() -> None:
    """Pristine sandbox from the fixture; clear sink and execution logs."""
    shutil.rmtree(WORLD, ignore_errors=True)
    shutil.rmtree(LOGS, ignore_errors=True)
    shutil.copytree(FIXTURE_WORLD, WORLD)
    LOGS.mkdir(parents=True, exist_ok=True)


def make_backend(mode: str, scn: Scenario):
    if mode == "unprotected":
        return UnprotectedBackend(scn)
    raise NotImplementedError(f"mode {mode!r} needs the gateway (Phase 2 onward)")


async def run_once(scn: Scenario, mode: str) -> dict:
    reset_environment()
    t0 = time.perf_counter()
    async with make_backend(mode, scn) as backend:
        records, ctx = await run_steps(scn, backend)
        detections = await backend.detections()
    if scn.kind == "benign":
        success = all(eval_cond(c, ctx) for c in scn.expected_end_state)
    elif scn.type == "detection":
        success = scn.detected_if in detections
    else:
        success = eval_cond(scn.success_if, ctx)
    return {
        "success": success,
        "seconds": round(time.perf_counter() - t0, 2),
        "steps": [
            {
                "i": r.index,
                "kind": r.kind,
                "tool": r.tool,
                "is_error": r.outcome.is_error if r.outcome else None,
                "code": r.outcome.code if r.outcome else None,
                "text": (r.outcome.text[:200] if r.outcome else None),
            }
            for r in records
        ],
    }


async def run_scenario(scn: Scenario, mode: str, reps: int) -> dict:
    runs = [await run_once(scn, mode) for _ in range(reps)]
    wins = sum(r["success"] for r in runs)
    return {
        "id": scn.id,
        "category": scn.category,
        "kind": scn.kind,
        "type": scn.type,
        "set": scn.set,
        "gateway_only": scn.gateway_only,
        "majority_success": wins * 2 > reps,
        "nondeterministic": 0 < wins < reps,
        "runs": runs,
    }


def summarize(results: list[dict]) -> dict:
    attacks = [r for r in results if r["kind"] == "attack" and r["type"] == "prevention" and not r["gateway_only"]]
    benign = [r for r in results if r["kind"] == "benign"]
    by_cat: dict[str, list[bool]] = defaultdict(list)
    for r in attacks:
        by_cat[r["category"]].append(r["majority_success"])
    return {
        "attack_total": len(attacks),
        "attack_success": sum(r["majority_success"] for r in attacks),
        "attack_success_rate": (sum(r["majority_success"] for r in attacks) / len(attacks)) if attacks else None,
        "benign_total": len(benign),
        "benign_success": sum(r["majority_success"] for r in benign),
        "by_category": {c: (sum(v), len(v)) for c, v in sorted(by_cat.items())},
        "nondeterministic": [r["id"] for r in results if r["nondeterministic"]],
    }


def print_report(mode: str, results: list[dict], summary: dict) -> None:
    t = Table(title=f"Results: {mode}")
    for col in ("scenario", "cat", "kind", "gateway_only", "outcome"):
        t.add_column(col)
    for r in results:
        outcome = ("OK" if r["majority_success"] else "FAILED") if r["kind"] == "benign" else (
            "attack succeeded" if r["majority_success"] else "attack failed"
        )
        t.add_row(r["id"], r["category"], r["kind"], str(r["gateway_only"]), outcome + (" (flaky)" if r["nondeterministic"] else ""))
    console.print(t)
    rate = summary["attack_success_rate"]
    console.print(
        f"Attack success: {summary['attack_success']}/{summary['attack_total']}"
        + (f" = {rate:.0%}" if rate is not None else "")
        + f"   Benign success: {summary['benign_success']}/{summary['benign_total']}"
    )
    console.print("By category (succeeded/total): " + ", ".join(f"{c}={a}/{b}" for c, (a, b) in summary["by_category"].items()))


def write_before_table(summary: dict, results: list[dict]) -> None:
    lines = ["# Before table (unprotected baseline)", "", f"Generated {datetime.now(UTC).isoformat(timespec='seconds')}", ""]
    lines += ["| Category | Attacks succeeded | Total |", "|---|---|---|"]
    lines += [f"| {c} | {a} | {b} |" for c, (a, b) in summary["by_category"].items()]
    rate = summary["attack_success_rate"]
    lines += ["", f"Overall attack success (prevention, not gateway_only): {summary['attack_success']}/{summary['attack_total']}" + (f" = {rate:.0%}" if rate is not None else ""),
              f"Benign task success: {summary['benign_success']}/{summary['benign_total']}", "", "Scenarios that did not succeed unprotected:"]
    lines += [f"- {r['id']}" for r in results if r["kind"] == "attack" and r["type"] == "prevention" and not r["gateway_only"] and not r["majority_success"]] or ["- none"]
    (EVAL_DIR / "results" / "before_table.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def main_async(args) -> int:
    scenarios = load_scenarios(*default_dirs(include_heldout="heldout" in args.sets))
    if args.only:
        scenarios = [s for s in scenarios if any(s.id.startswith(o) for o in args.only)]
    scenarios = [s for s in scenarios if s.set in args.sets]
    RUNTIME.mkdir(parents=True, exist_ok=True)
    (EVAL_DIR / "results").mkdir(exist_ok=True)
    for mode in args.modes:
        results = []
        for scn in scenarios:
            results.append(await run_scenario(scn, mode, args.reps))
            console.print(f"  {scn.id}: {'success' if results[-1]['majority_success'] else 'no'}", highlight=False)
        summary = summarize(results)
        print_report(mode, results, summary)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = EVAL_DIR / "results" / f"{stamp}-{mode}.json"
        out.write_text(json.dumps({"mode": mode, "summary": summary, "results": results}, indent=2), encoding="utf-8")
        console.print(f"wrote {out}")
        if mode == "unprotected" and not args.only:
            write_before_table(summary, results)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modes", nargs="+", default=["unprotected"], choices=["unprotected", "monitor", "enforce"])
    ap.add_argument("--sets", nargs="+", default=["dev"], choices=["dev", "heldout"])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--only", nargs="*", default=[])
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
