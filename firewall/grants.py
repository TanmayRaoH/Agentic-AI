"""Task grants (F06, F34).

Interface change vs Section 5.1: functions are async and take the Store as first argument.
Only the operator creates grants (admin API or CLI); the agent can never create or widen one.
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
MAX_TTL_SECONDS = 24 * 3600
MAX_CALLS = 200
MAX_SESSIONS = 5
_JSON_FIELDS = ("allowed_tools", "allowed_destinations", "allowed_paths", "approval_required_for")


class GrantError(ValueError):
    """The requested grant violates a creation rule (reported to the operator, never to the agent)."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _str_list(spec: dict, key: str) -> list[str]:
    v = spec.get(key, [])
    if not isinstance(v, (list, tuple)) or not all(isinstance(x, str) for x in v):
        raise GrantError(f"{key} must be a list of strings")
    return list(v)


def validate_spec(spec: dict, registry=None) -> dict:
    """Apply the F06 creation rules; returns the normalized values."""
    tools = _str_list(spec, "allowed_tools")
    if not tools:
        raise GrantError("allowed_tools must name at least one tool")
    out: dict = {
        "allowed_tools": tools,
        "allowed_destinations": _str_list(spec, "allowed_destinations"),
        "allowed_paths": _str_list(spec, "allowed_paths"),
        "approval_required_for": _str_list(spec, "approval_required_for"),
    }
    limits = (("ttl_seconds", 3600, 1, MAX_TTL_SECONDS), ("max_calls", 30, 1, MAX_CALLS),
              ("max_sessions", 2, 1, MAX_SESSIONS))
    for key, default, lo, hi in limits:
        v = spec.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise GrantError(f"{key} must be a whole number from {lo} to {hi} (got {v!r})")
        out[key] = v
    if registry is not None:
        for t in tools + out["approval_required_for"]:
            if not registry.has(t):
                raise GrantError(f"tool '{t}' is not in the tool registry (tools.yaml)")
        if not spec.get("allow_critical", False):
            critical = [t for t in tools if registry.risk(t) == "critical"]
            if critical:
                raise GrantError(f"critical-risk tools need the explicit allow_critical flag: {critical}")
    return out


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


async def create_grant(store: Store, spec: dict, created_by: str = "operator",
                       registry=None) -> tuple[Grant, str]:
    """Create a grant. Returns (grant, one-time token). Only the SHA-256 of the token is stored.
    Pass the registry to reject unknown tools and critical tools without allow_critical."""
    v = validate_spec(spec, registry)
    token = TOKEN_PREFIX + secrets.token_urlsafe(24)  # 192 bits
    now = utcnow()
    row = {
        "id": "g_" + secrets.token_hex(4),
        "token_hash": hash_token(token),
        "token_prefix": token[:8],
        "task": spec.get("task", ""),
        "allowed_tools": v["allowed_tools"],
        "allowed_destinations": v["allowed_destinations"],
        "allowed_paths": v["allowed_paths"],
        "max_calls": v["max_calls"],
        "max_sessions": v["max_sessions"],
        "created_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=v["ttl_seconds"])),
        "created_by": created_by,
        "approval_required_for": v["approval_required_for"],
    }
    await store.insert_grant(row)
    stored = {**row, **{k: json.dumps(row[k]) for k in _JSON_FIELDS}, "used_calls": 0, "status": "active"}
    return _to_grant(stored), token


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


async def list_grants(store: Store) -> list[Grant]:
    return [_to_grant(r) for r in await store.list_grants()]


async def reserve_budget(store: Store, grant_id: str) -> bool:
    return await store.reserve_budget(grant_id, iso(utcnow()))


async def revoke(store: Store, grant_id: str) -> bool:
    return await store.revoke_grant(grant_id) == 1


async def resume(store: Store, grant_id: str) -> bool:
    """Operator action: clear the suspended flag and the denied streak (F08)."""
    from firewall import sessions

    if await store.grant_by_id(grant_id) is None:
        return False
    await sessions.update_state(store, grant_id, suspended=False, denied_streak=0)
    return True
