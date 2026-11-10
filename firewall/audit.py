"""Audit log (F20). Append-only. Never stores raw arguments or full tokens.

Interface change vs Section 5.1: functions take the Store as first argument (no global state).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from firewall.store import Store


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
