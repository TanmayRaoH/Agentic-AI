"""F20 Tier 2: audit hash chain, verification and checkpoint file."""
import asyncio
import json
import sqlite3

import pytest
import pytest_asyncio

from firewall import audit, chain
from firewall.store import Store


@pytest_asyncio.fixture
async def env(tmp_path):
    db = tmp_path / "c.db"
    store = await Store(db).open()
    yield store, db, tmp_path / "c.db.checkpoints"
    await store.close()


async def fill(store, n=5):
    for i in range(n):
        await audit.write(store, {"session_id": "s", "grant_id": "g_1", "tool": f"t{i}", "args_masked": {"a": f"v{i}"},
                                  "phase": "call", "verdict": "allow", "detail": {"i": i}, "mode": "enforce"})


def raw(db, sql, params=()):
    con = sqlite3.connect(db)
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


async def test_f20_an_empty_log_verifies(env):
    store, _, cp = env
    r = await audit.verify_chain(store, cp)
    assert r["ok"] and r["rows"] == 0 and r["head"] is None


async def test_f20_a_clean_chain_verifies_and_links_each_row_to_the_previous(env):
    store, _, cp = env
    await fill(store)
    r = await audit.verify_chain(store, cp)
    assert r["ok"] and r["rows"] == 5 and r["error"] is None
    rows = await store.audit_after(0)
    assert rows[0]["prev_hash"] == chain.GENESIS
    assert all(rows[i]["prev_hash"] == rows[i - 1]["row_hash"] for i in range(1, 5))
    assert r["head"] == rows[-1]["row_hash"]


@pytest.mark.parametrize("col, value", [
    ("tool", "evil"), ("verdict", "deny"), ("reason_code", "NONE"), ("grant_id", "g_other"), ("session_id", "x"),
    ("args_masked", '{"a":"changed"}'), ("detail", "{}"), ("ts", "2000-01-01T00:00:00Z"), ("mode", "monitor"),
    ("phase", "result"), ("latency_ms", 99.0),
])
async def test_f20_editing_any_field_breaks_the_chain_at_that_row(env, col, value):
    store, db, cp = env
    await fill(store)
    raw(db, f"UPDATE audit SET {col}=? WHERE id=3", (value,))
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and r["first_bad_id"] == 3


async def test_f20_deleting_a_middle_row_is_detected(env):
    store, db, cp = env
    await fill(store)
    raw(db, "DELETE FROM audit WHERE id=3")
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and r["first_bad_id"] == 4


async def test_f20_editing_prev_hash_or_row_hash_is_detected(env):
    store, db, cp = env
    await fill(store)
    raw(db, "UPDATE audit SET prev_hash=? WHERE id=2", ("f" * 64,))
    assert not (await audit.verify_chain(store, cp))["ok"]


async def test_f20_a_row_without_a_hash_is_detected(env):
    store, db, cp = env
    await fill(store)
    raw(db, "UPDATE audit SET row_hash=NULL WHERE id=5")
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and r["first_bad_id"] == 5


async def test_f20_recomputing_the_edited_row_hash_alone_still_breaks_the_next_link(env):
    store, db, cp = env
    await fill(store)
    row = await store.audit_row(2)
    row["tool"] = "evil"
    raw(db, "UPDATE audit SET tool='evil', row_hash=? WHERE id=2", (chain.compute_hash(row, row["prev_hash"]),))
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and r["first_bad_id"] == 3


async def test_f20_removing_the_newest_rows_is_caught_through_the_checkpoint(env):
    store, db, cp = env
    await fill(store)
    assert await audit.write_checkpoint(store, cp, "test")
    assert (await audit.verify_chain(store, cp))["checkpoints_checked"] == 1
    raw(db, "DELETE FROM audit WHERE id IN (4, 5)")
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and "missing" in r["error"]
    assert (await audit.verify_chain(store, None))["ok"]  # without the checkpoint the truncation is invisible


async def test_f20_a_checkpoint_that_no_longer_matches_its_row_is_detected(env):
    store, db, cp = env
    await fill(store, 3)
    await audit.write_checkpoint(store, cp)
    cp.write_text(json.dumps({"ts": "x", "id": 2, "row_hash": "0" * 64}) + "\n")
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and r["first_bad_id"] == 2


async def test_f20_a_corrupt_checkpoint_file_fails_verification(env):
    store, _, cp = env
    await fill(store, 2)
    cp.write_text("not json\n")
    r = await audit.verify_chain(store, cp)
    assert not r["ok"] and "corrupt" in r["error"]


async def test_f20_checkpoints_are_appended_not_overwritten(env):
    store, _, cp = env
    assert await audit.write_checkpoint(store, cp) is None  # nothing to anchor yet
    assert not cp.exists()
    await fill(store, 2)
    first = await audit.write_checkpoint(store, cp, "start")
    await fill(store, 2)
    second = await audit.write_checkpoint(store, cp, "stop")
    lines = [json.loads(x) for x in cp.read_text().splitlines()]
    assert [x["id"] for x in lines] == [first["id"], second["id"]] == [2, 4]
    assert lines[1]["reason"] == "stop" and (await audit.verify_chain(store, cp))["checkpoints_checked"] == 2


async def test_f20_concurrent_writers_on_one_file_never_fork_the_chain(env):
    store, db, cp = env
    other = await Store(db).open()
    try:
        await asyncio.gather(fill(store, 25), fill(other, 25))
    finally:
        await other.close()
    r = await audit.verify_chain(store, cp)
    assert r["ok"] and r["rows"] == 50


async def test_f20_concurrent_writers_in_one_store_keep_ids_and_links_in_order(env):
    store, _, cp = env
    await asyncio.gather(*[fill(store, 1) for _ in range(40)])
    r = await audit.verify_chain(store, cp)
    assert r["ok"] and r["rows"] == 40


async def test_f20_the_chain_hash_depends_on_the_previous_hash():
    row = {k: None for k in chain.FIELDS} | {"id": 1}
    assert chain.compute_hash(row, "a" * 64) != chain.compute_hash(row, "b" * 64)
