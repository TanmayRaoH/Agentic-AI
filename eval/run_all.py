"""One command that reproduces the whole evaluation: baseline table, all modes on both sets, latency, report.

    uv run python -m eval.run_all [--reps 3] [--quick]

Writes eval/results/final-{unprotected,monitor,enforce}.json, final-latency.json, before_table.md and eval/report.md.
The held-out run made before the tuning freeze is kept separately as eval/results/heldout-before-freeze-*.json and is
never overwritten by this command.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def step(*args: str) -> None:
    print("\n$ python -m " + " ".join(args), flush=True)
    subprocess.run([sys.executable, "-m", *args], check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--quick", action="store_true", help="shortened run for CI: 1 repetition, 40 latency calls")
    args = ap.parse_args()
    reps = 1 if args.quick else args.reps
    step("eval.runner", "--modes", "unprotected", "--sets", "dev", "--reps", str(reps))  # before_table.md
    step("eval.runner", "--modes", "unprotected", "monitor", "enforce", "--sets", "dev", "heldout",
         "--reps", str(reps), "--tag", "final")
    step("eval.bench", *(["--calls", "40", "--warmup", "10"] if args.quick else []))
    step("eval.report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
