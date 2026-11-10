"""Task grants (F06, F34).

Interface change vs Section 5.1: functions are async and take the Store as first argument.
Phase 2 ships the minimum (create, resolve, budget, revoke); Phase 3 adds creation limits,
registry validation and the allow_critical flag.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from firewall.models import Grant
from firewall.store import Store, iso, utcnow

TOKEN_PREFIX = "fwg_"
_JSON_FIELDS = ("allowed_tools", "allowed_destinations", "allowed_paths", "approval_required_for")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _to_grant(row: dict) -> Grant:
    status = row["status"]
    now = iso(utcnow())
    if status == "active":
        if row["expires_at"] <= now:
            status = "expired"
        elif row["used_calls"] >= row["max_calls"]:
            status = "exhausted"
    return Grant(
        id=row["id"], task=row["task"] or "",
        allowed_tools=json.loads(row["allowed_tools"] or "[]"),
        allowed_destinations=json.loads(row["allowed_destinations"] or "[]"),
        allowed_paths=json.loads(row["allowed_paths"] or "[]"),
        max_calls=row["max_calls"], used_calls=row["used_calls"], max_sessions=row["max_sessions"],
        expires_at=row["expires_at"], approval_required_for=json.loads(row["approval_required_for"] or "[]"),
        status=status, token_prefix=row.get("token_prefix") or "", created_at=row.get("created_at") or "",
        created_by=row.get("created_by") or "operator",
    )


async def create_grant(store: Store, spec: dict, created_by: str = "operator") -> tuple[Grant, str]:
    """Create a grant. Returns (grant, one-time token). Only the SHA-256 of the token is stored."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(24)  # 192 bits
    now = utcnow()
    ttl = int(spec.get("ttl_seconds", 3600))
    row = {
        "id": "g_" + secrets.token_hex(4),
        "token_hash": hash_token(token),
        "token_prefix": token[:8],
        "task": spec.get("task", ""),
        "allowed_tools": list(spec.get("allowed_tools", [])),
        "allowed_destinations": list(spec.get("allowed_destinations", [])),
        "allowed_paths": list(spec.get("allowed_paths", [])),
        "max_calls": int(spec.get("max_calls", 30)),
        "max_sessions": int(spec.get("max_sessions", 2)),
        "created_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=ttl)),
        "created_by": created_by,
        "approval_required_for": list(spec.get("approval_required_for", [])),
    }
    await store.insert_grant(row)
    return _to_grant({**row, **{k: json.dumps(row[k]) for k in _JSON_FIELDS}, "used_calls": 0, "status": "active"}), token


async def resolve(store: Store, token: str | None) -> Grant | None:
    """Hash the token, look it up, then compare in constant time."""
    if not token:
        return None
    digest = hash_token(token)
    row = await store.grant_by_token_hash(digest)
    if row is None or not hmac.compare_digest(row["token_hash"], digest):
        return None
    return _to_grant(row)


async def get_grant(store: Store, grant_id: str) -> Grant | None:
    row = await store.grant_by_id(grant_id)
    return _to_grant(row) if row else None


async def reserve_budget(store: Store, grant_id: str) -> bool:
    return await store.reserve_budget(grant_id, iso(utcnow()))


async def revoke(store: Store, grant_id: str) -> None:
    await store.revoke_grant(grant_id)
