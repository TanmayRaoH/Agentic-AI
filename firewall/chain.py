"""Audit hash chain (F20, Tier 2).

Every audit row stores the hash of the previous row and its own hash, which covers all of its fields
and the previous hash. Editing or removing a row breaks the chain from that point on. The chain is
tamper-EVIDENT, not tamper-proof: someone who can rewrite the whole database can recompute every hash.
The head hash is therefore also appended to a separate checkpoint file (see audit.write_checkpoint).
"""
from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64
FIELDS = ("id", "ts", "session_id", "grant_id", "tool", "args_masked", "args_hash", "phase", "verdict",
          "reason_code", "rule_id", "detail", "latency_ms", "upstream_ms", "mode")


def compute_hash(row: dict, prev_hash: str) -> str:
    """row holds the values exactly as stored in the table (JSON columns as their text)."""
    payload = json.dumps([row[k] for k in FIELDS] + [prev_hash], separators=(",", ":"), ensure_ascii=False,
                         default=str)
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()
