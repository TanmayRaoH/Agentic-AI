import asyncio
from datetime import timedelta

import pytest_asyncio

from firewall import audit, grants, sessions
from firewall.models import GrantState
from firewall.store import Store, iso, utcnow


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await Store(tmp_path / "t.db").open()
    yield s
    await s.close()


async def test_f37_reserve_budget_never_overshoots_under_concurrency(store):
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "max_calls": 30})
    results = await asyncio.gather(*[grants.reserve_budget(store, g.id) for _ in range(100)])
    assert sum(results) == 30
    assert (await grants.get_grant(store, g.id)).status == "exhausted"


async def test_f37_wal_mode(store):
    cur = await store._db.execute("PRAGMA journal_mode")
    assert (await cur.fetchone())[0] == "wal"


async def test_f34_token_is_stored_hashed_and_resolves(store):
    g, token = await grants.create_grant(store, {"allowed_tools": ["x"]})
    row = await store.grant_by_id(g.id)
    dump = str(await store.list_grants()) + str(await store._all("SELECT * FROM grants"))
    assert token not in dump
    assert len(token) >= 32
    assert (await grants.resolve(store, token)).id == g.id
    assert await grants.resolve(store, token + "x") is None
    assert await grants.resolve(store, None) is None
    assert row["token_prefix"] == token[:8]


async def test_f02_two_sessions_share_state_and_new_session_cannot_clear_it(store):
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "max_sessions": 2})
    assert await sessions.touch_session(store, "s1", g)
    assert await sessions.touch_session(store, "s2", g)
    await sessions.save_state(store, GrantState(g.id, labels={"private", "untrusted"}, suspicious=True))
    state = await sessions.load_state(store, g.id)  # what a third connection would see
    assert state.labels == {"private", "untrusted"} and state.suspicious
    assert not await sessions.touch_session(store, "s3", g)
    assert (await sessions.load_state(store, g.id)).labels == {"private", "untrusted"}
    assert await sessions.touch_session(store, "s1", g)  # known session still fine


async def test_f02_same_session_id_on_two_grants_counts_per_grant(store):
    # stateless-era clients share one derived id (address + user agent); two grants must not collide
    a, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "max_sessions": 1})
    b, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "max_sessions": 1})
    assert await sessions.touch_session(store, "stateless:abc", a)
    assert await sessions.touch_session(store, "stateless:abc", b)
    assert await sessions.active_session_count(store, a.id) == 1
    assert await sessions.active_session_count(store, b.id) == 1


async def test_f12_concurrent_state_updates_never_lose_labels(store):
    """Labels are security state: a stale read-modify-write must not erase them."""
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"]})
    await asyncio.gather(
        *[sessions.update_state(store, g.id, incr_calls=1) for _ in range(40)],
        sessions.update_state(store, g.id, add_labels={"private"}),
        sessions.update_state(store, g.id, add_labels={"untrusted"}, suspicious=True),
        *[sessions.update_state(store, g.id, incr_calls=1) for _ in range(40)],
    )
    st = await sessions.load_state(store, g.id)
    assert st.labels == {"private", "untrusted"} and st.suspicious
    assert st.call_count == 80


async def test_f02_old_session_rows_are_pruned_for_active_grants(store):
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"]})
    old = iso(utcnow() - timedelta(hours=3))
    await store._run("INSERT INTO sessions(id, grant_id, created_at, last_seen) VALUES('old', ?, ?, ?)", (g.id, old, old))
    await sessions.touch_session(store, "fresh", g)
    await sessions.cleanup(store)
    ids = {s["id"] for s in await store.list_sessions()}
    assert ids == {"fresh"}

async def test_f02_stale_sessions_stop_counting(store):
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "max_sessions": 1})
    old = iso(utcnow() - timedelta(minutes=6))
    await store._run("INSERT INTO sessions(id, grant_id, created_at, last_seen) VALUES('old', ?, ?, ?)", (g.id, old, old))
    assert await sessions.active_session_count(store, g.id) == 0
    assert await sessions.touch_session(store, "new", g)


async def test_f02_expired_grant_state_is_removed(store):
    g, _ = await grants.create_grant(store, {"allowed_tools": ["x"], "ttl_seconds": 3600})
    keep, _ = await grants.create_grant(store, {"allowed_tools": ["x"]})
    await sessions.save_state(store, GrantState(g.id, labels={"private"}))
    await sessions.save_state(store, GrantState(keep.id, labels={"private"}))
    await store._run("UPDATE grants SET expires_at=? WHERE id=?", (iso(utcnow() - timedelta(hours=2)), g.id))
    await store._run("UPDATE grant_state SET last_activity=? WHERE grant_id=?", (iso(utcnow() - timedelta(hours=1, minutes=5)), g.id))
    removed = await sessions.cleanup(store)
    assert removed == [g.id]
    assert (await sessions.load_state(store, g.id)).labels == set()
    assert (await sessions.load_state(store, keep.id)).labels == {"private"}
    # idle for 2 hours is removed even for an active grant
    await store._run("UPDATE grant_state SET last_activity=? WHERE grant_id=?", (iso(utcnow() - timedelta(hours=2, minutes=1)), keep.id))
    assert await sessions.cleanup(store) == [keep.id]


def test_f20_mask_hides_values_and_args_hash_is_stable():
    masked = audit.mask({"body": "CANARY-7f3a91", "n": 3, "nested": {"l": ["secret-value"]}})
    assert "7f3a91" not in str(masked) and "secret-value" not in str(masked)
    assert masked["n"] == 3 and masked["body"].startswith("CANA")
    assert audit.args_hash({"a": 1, "b": 2}) == audit.args_hash({"b": 2, "a": 1})
    assert audit.args_hash({"a": 1}) != audit.args_hash({"a": 2})
