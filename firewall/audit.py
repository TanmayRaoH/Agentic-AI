"""Audit log (F20). Append-only. Never stores raw arguments or full tokens.

Interface change vs Section 5.1: functions take the Store as first argument (no global state).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from typing import Any

from firewall import chain
from firewall.store import Store, iso, utcnow


def _short_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:8]


def mask_value(v: Any) -> Any:
    """Strings become 'first 4 chars + length + short hash'. Phase 4 (F09) refines this to
    mask only detected secrets and keep short harmless values readable."""
    if isinstance(v, str):
        return f"{v[:4]}...[{len(v)} chars #{_short_hash(v)}]"
    if isinstance(v, dict):
        return {k: mask_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [mask_value(x) for x in v]
    return v


def mask(args: dict) -> dict:
    return mask_value(args or {})


def args_hash(args: dict) -> str:
    canon = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8", "replace")).hexdigest()


async def write(store: Store, row: dict) -> int:
    """Append one audit row; returns its id (the event id is 'ev_<id>')."""
    return await store.insert_audit(row)


# ---------------- hash chain verification and checkpoints (F20, Tier 2) ----------------
def checkpoint_path_for(db_path: str | os.PathLike) -> str:
    return str(db_path) + ".checkpoints"


async def verify_chain(store: Store, checkpoint_path: str | os.PathLike | None = None) -> dict:
    """Walk the chain from the first row. Detects edited rows, removed rows (including the newest ones, via the
    checkpoint file) and rows without a hash. Returns {"ok", "rows", "head", "error", "first_bad_id", ...}."""
    result: dict = {"ok": True, "rows": 0, "head": None, "error": None, "first_bad_id": None, "checkpoints_checked": 0}

    def fail(row_id: int | None, message: str) -> dict:
        result.update(ok=False, error=message, first_bad_id=row_id)
        return result

    expected_prev, last_id = chain.GENESIS, 0
    while True:
        batch = await store.audit_after(last_id, 2000)
        if not batch:
            break
        for row in batch:
            result["rows"] += 1
            if row["row_hash"] is None:
                return fail(row["id"], f"row {row['id']} has no hash")
            if row["prev_hash"] != expected_prev:
                return fail(row["id"], f"row {row['id']}: the previous hash does not match; a row before it was "
                                       "removed or edited")
            if chain.compute_hash(row, row["prev_hash"]) != row["row_hash"]:
                return fail(row["id"], f"row {row['id']} was modified after it was written")
            expected_prev, last_id = row["row_hash"], row["id"]
            result["head"] = row["row_hash"]
    if checkpoint_path and os.path.exists(checkpoint_path):
        for line in await asyncio.to_thread(_read_lines, checkpoint_path):
            try:
                cp = json.loads(line)
                cp_id, cp_hash = int(cp["id"]), str(cp["row_hash"])
            except (ValueError, KeyError, TypeError):
                return fail(None, "the checkpoint file is corrupt")
            row = await store.audit_row(cp_id)
            if row is None:
                return fail(cp_id, f"row {cp_id} named by a checkpoint is missing (rows were removed)")
            if row["row_hash"] != cp_hash:
                return fail(cp_id, f"row {cp_id} no longer matches its checkpoint")
            result["checkpoints_checked"] += 1
    return result


def _read_lines(path: str | os.PathLike) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def _append_line(path: str | os.PathLike, line: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


async def write_checkpoint(store: Store, path: str | os.PathLike, reason: str = "periodic") -> dict | None:
    """Append the current head hash to a separate append-only file and log it. Returns the record, or None if the
    log is still empty."""
    head = await store.audit_head()
    if head is None:
        return None
    record = {"ts": iso(utcnow()), "id": head["id"], "row_hash": head["row_hash"], "rows": head["rows"],
              "reason": reason}
    await asyncio.to_thread(_append_line, path, json.dumps(record))
    logging.getLogger("firewall.audit").info("audit checkpoint %s", record)
    return record
