"""Grant-scoped sessions and state (F02). All state is keyed by grant, never by session.

Interface change vs Section 5.1: functions take the Store first; touch_session returns whether
the session was admitted.
"""
from __future__ import annotations

import json
from datetime import timedelta

from firewall.models import Grant, GrantState
from firewall.store import Store, iso, utcnow

ACTIVE_WINDOW = timedelta(minutes=5)


async def touch_session(store: Store, session_id: str, grant: Grant) -> bool:
    """Create or refresh a session. False when the grant already has max_sessions active sessions."""
    now = utcnow()
    return await store.admit_session(session_id, grant.id, grant.max_sessions, iso(now - ACTIVE_WINDOW), iso(now))


async def active_session_count(store: Store, grant_id: str) -> int:
    return await store.active_session_count(grant_id, iso(utcnow() - ACTIVE_WINDOW))


async def load_state(store: Store, grant_id: str) -> GrantState:
    row = await store.get_state(grant_id)
    if row is None:
        return GrantState(grant_id=grant_id)
    return GrantState(
        grant_id=grant_id, labels=set(json.loads(row["labels"] or "[]")), suspicious=bool(row["suspicious"]),
        suspended=bool(row["suspended"]), denied_streak=row["denied_streak"], call_count=row["call_count"],
    )


async def update_state(store: Store, grant_id: str, *, add_labels: set | None = None,
                       suspicious: bool | None = None, suspended: bool | None = None,
                       incr_calls: int = 0, denied_streak: int | None = None) -> None:
    """Atomic merge update (use this on the request path; labels are add-only)."""
    await store.update_state(grant_id, iso(utcnow()), add_labels, suspicious, suspended, incr_calls, denied_streak)


async def save_state(store: Store, state: GrantState) -> None:
    """Full overwrite. Not for the request path: it can erase concurrent updates (operator actions and tests only)."""
    await store.put_state(
        state.grant_id, sorted(state.labels), state.call_count, state.denied_streak,
        state.suspended, state.suspicious, iso(utcnow()),
    )


async def cleanup(store: Store) -> list[str]:
    """Delete stale per-grant state (1 h after the grant stops being active, 2 h idle)."""
    return await store.cleanup_state(utcnow())
