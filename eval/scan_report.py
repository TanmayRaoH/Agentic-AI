"""Measures the output injection scanner (F14) on the dev corpora: detection of known injection samples and the
false-positive rate on benign pages. The report generator (Phase 7) includes these numbers.

Usage: uv run python -m eval.scan_report
"""
from __future__ import annotations

import json
from pathlib import Path

from firewall.scan_output import injection_score

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "injection"
BLOCK, FLAG = 0.8, 0.4


def level(score: float) -> str:
    return "quarantine" if score >= BLOCK else "flag" if score >= FLAG else "pass"


def measure(positives_file: str = "positives_dev.json", benign_file: str = "benign_pages.json") -> dict:
    positives = json.loads((FIXTURES / positives_file).read_text(encoding="utf-8"))
    benign = json.loads((FIXTURES / benign_file).read_text(encoding="utf-8"))
    pos = [(p["id"], p["expect"], *injection_score(p["text"])) for p in positives]
    ben = [(b["id"], b.get("known_fp", False), *injection_score(b["text"])) for b in benign]
    return {
        "positives": len(pos),
        "detected": sum(level(s) != "pass" for _, _, s, _ in pos),
        "quarantined": sum(level(s) == "quarantine" for _, _, s, _ in pos),
        "missed": [i for i, _, s, _ in pos if level(s) == "pass"],
        "benign": len(ben),
        "benign_quarantined": [(i, s, f) for i, _, s, f in ben if level(s) == "quarantine"],
        "benign_flagged": [(i, s, f) for i, _, s, f in ben if level(s) == "flag"],
    }


def to_markdown(m: dict) -> str:
    fp_q = len(m["benign_quarantined"])
    fp_f = len(m["benign_flagged"])
    lines = [
        "# Output injection scanner (F14): dev-corpus measurement", "",
        f"- Known injection samples: {m['positives']}; flagged or quarantined: {m['detected']}; quarantined: {m['quarantined']}.",
        f"- Missed: {m['missed'] or 'none'}",
        (f"- Benign pages: {m['benign']}; quarantined (false positives): {fp_q} = {fp_q / m['benign']:.1%}; "
         f"flagged only: {fp_f} = {fp_f / m['benign']:.1%}."),
        "", "Benign pages quarantined:", *[f"- {i}: score {s}, families {f}" for i, s, f in m["benign_quarantined"]],
        "", "Benign pages flagged:", *[f"- {i}: score {s}, families {f}" for i, s, f in m["benign_flagged"]],
        "",
        ("These corpora were used while tuning the weights, so the numbers are optimistic; the held-out set "
         "(Phase 7) is the honest measurement."),
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    result = measure()
    out = Path(__file__).resolve().parent / "results" / "injection_scan_report.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(to_markdown(result), encoding="utf-8")
    print(to_markdown(result))
