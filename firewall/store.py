"""The only module that touches SQLite (Section 6.5, F37).

One writer connection in WAL mode, guarded by an asyncio lock. Every public method takes the
lock, so audit appends, budget updates and session admission are serialized.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite

from firewall import chain

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants(
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, token_prefix TEXT, task TEXT,
  allowed_tools TEXT, allowed_destinations TEXT, allowed_paths TEXT,
  max_calls INTEGER, used_calls INTEGER DEFAULT 0, max_sessions INTEGER,
  created_at TEXT, expires_at TEXT, created_by TEXT, approval_required_for TEXT,
  status TEXT DEFAULT 'active', revoked_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_token ON grants(token_hash);
CREATE TABLE IF NOT EXISTS grant_state(
  grant_id TEXT PRIMARY KEY, labels TEXT DEFAULT '[]', call_count INTEGER DEFAULT 0,
  denied_streak INTEGER DEFAULT 0, suspended INTEGER DEFAULT 0, suspicious INTEGER DEFAULT 0,
  rate_state TEXT DEFAULT '{}', loop_state TEXT DEFAULT '{}', last_activity TEXT);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT, grant_id TEXT, created_at TEXT, last_seen TEXT, PRIMARY KEY(id, grant_id));
CREATE INDEX IF NOT EXISTS idx_sessions_grant ON sessions(grant_id);
CREATE TABLE IF NOT EXISTS fingerprints(
  grant_id TEXT, source_tool TEXT, hash INTEGER, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_fp ON fingerprints(grant_id, hash);
CREATE TABLE IF NOT EXISTS exact_tokens(
  grant_id TEXT, source_tool TEXT, token_hash TEXT, created_at TEXT, length INTEGER, poly INTEGER);
CREATE INDEX IF NOT EXISTS idx_tokens ON exact_tokens(grant_id);
CREATE TABLE IF NOT EXISTS egress_buffer(grant_id TEXT PRIMARY KEY, text TEXT);
CREATE TABLE IF NOT EXISTS pins(
  upstream TEXT, tool TEXT, hash TEXT, state TEXT, description_snapshot TEXT,
  first_seen TEXT, changed_at TEXT, new_hash TEXT, new_snapshot TEXT, reasons TEXT,
  PRIMARY KEY(upstream, tool));
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, grant_id TEXT, session_id TEXT, tool TEXT, args_masked TEXT,
  args_encrypted BLOB, args_hash TEXT, reason_codes TEXT, approval_scope TEXT,
  created_at TEXT, expires_at TEXT, status TEXT, decided_by TEXT, decided_at TEXT,
  used INTEGER DEFAULT 0, destination TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_approvals_lookup ON approvals(grant_id, tool, args_hash);
CREATE TABLE IF NOT EXISTS runtime_info(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT, grant_id TEXT, tool TEXT,
  args_masked TEXT, args_hash TEXT, phase TEXT, verdict TEXT, reason_code TEXT, rule_id TEXT,
  detail TEXT, latency_ms REAL, upstream_ms REAL, mode TEXT, prev_hash TEXT, row_hash TEXT);
CREATE INDEX IF NOT EXISTS idx_audit_grant ON audit(grant_id);
CREATE TABLE IF NOT EXISTS eval_runs(
  id TEXT PRIMARY KEY, started_at TEXT, mode TEXT, git_commit TEXT, fastmcp_version TEXT,
  results TEXT);
"""

APPROVAL_COLUMNS = ("id, grant_id, session_id, tool, args_masked, args_hash, reason_codes, approval_scope, created_at,"
                    " expires_at, status, decided_by, decided_at, used, destination, detail")
GRANT_COLUMNS = (
    "id, token_prefix, task, allowed_tools, allowed_destinations, allowed_paths, max_calls, "
    "used_calls, max_sessions, created_at, expires_at, created_by, approval_required_for, status"
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | os.PathLike = "./fw.db"):
        self.path = str(path)
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def open(self) -> Store:
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=5000")  # the admin API is a second process on the same file
        await self._db.executescript(SCHEMA)
        await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    # ---------------- generic helpers (private) ----------------
    async def _run(self, sql: str, params: tuple = ()) -> int:
        """Execute one write statement under the lock; returns rowcount."""
        async with self._lock:
            cur = await self._db.execute(sql, params)
            await self._db.commit()
            return cur.rowcount

    async def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        async with self._lock:
            cur = await self._db.execute(sql, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ---------------- grants ----------------
    async def insert_grant(self, g: dict) -> None:
        await self._run(
            "INSERT INTO grants(id, token_hash, token_prefix, task, allowed_tools, allowed_destinations,"
            " allowed_paths, max_calls, used_calls, max_sessions, created_at, expires_at, created_by,"
            " approval_required_for, status) VALUES(?,?,?,?,?,?,?,?,0,?,?,?,?,?,'active')",
            (
                g["id"], g["token_hash"], g["token_prefix"], g["task"],
                json.dumps(g["allowed_tools"]), json.dumps(g["allowed_destinations"]),
                json.dumps(g["allowed_paths"]), g["max_calls"], g["max_sessions"],
                g["created_at"], g["expires_at"], g["created_by"],
                json.dumps(g["approval_required_for"]),
            ),
        )

    async def grant_by_token_hash(self, token_hash: str) -> dict | None:
        rows = await self._all(f"SELECT {GRANT_COLUMNS}, token_hash FROM grants WHERE token_hash=?", (token_hash,))
        return rows[0] if rows else None

    async def grant_by_id(self, grant_id: str) -> dict | None:
        rows = await self._all(f"SELECT {GRANT_COLUMNS} FROM grants WHERE id=?", (grant_id,))
        return rows[0] if rows else None

    async def list_grants(self) -> list[dict]:
        return await self._all(f"SELECT {GRANT_COLUMNS} FROM grants ORDER BY created_at DESC")

    async def revoke_grant(self, grant_id: str) -> int:
        return await self._run(
            "UPDATE grants SET status='revoked', revoked_at=? WHERE id=? AND status='active'",
            (iso(utcnow()), grant_id),
        )

    async def reserve_budget(self, grant_id: str, now_iso: str) -> bool:
        """Atomic conditional update: succeeds only while budget remains (F06, F37)."""
        n = await self._run(
            "UPDATE grants SET used_calls = used_calls + 1 WHERE id=? AND status='active'"
            " AND used_calls < max_calls AND expires_at > ?",
            (grant_id, now_iso),
        )
        return n == 1

    async def set_grant_expiry(self, grant_id: str, expires_at: str) -> None:
        """Test and harness helper (e.g. to build an already expired grant)."""
        await self._run("UPDATE grants SET expires_at=? WHERE id=?", (expires_at, grant_id))

    # ---------------- approvals (F16) ----------------
    async def insert_approval(self, a: dict) -> None:
        await self._run(
            "INSERT INTO approvals(id, grant_id, session_id, tool, args_masked, args_encrypted, args_hash,"
            " reason_codes, approval_scope, created_at, expires_at, status, used, destination, detail)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',0,?,?)",
            (a["id"], a["grant_id"], a.get("session_id"), a["tool"], json.dumps(a.get("args_masked") or {}),
             a.get("args_encrypted"), a["args_hash"], json.dumps(a.get("reason_codes") or []),
             a.get("approval_scope", "once"), a["created_at"], a["expires_at"], a.get("destination"),
             json.dumps(a.get("detail") or {})),
        )

    async def insert_approval_unique(self, a: dict, now_iso: str) -> tuple[str, bool]:
        """Create a pending approval unless an identical request (same grant, tool and canonical arguments) is already
        pending; in that case return the existing id. The check and the insert are one step under the lock, so two
        identical calls arriving together can never create two rows. Returns (id, created)."""
        async with self._lock:
            cur = await self._db.execute(
                "SELECT id FROM approvals WHERE grant_id=? AND tool=? AND args_hash=? AND status='pending' AND expires_at > ?"
                " ORDER BY created_at DESC LIMIT 1", (a["grant_id"], a["tool"], a["args_hash"], now_iso))
            row = await cur.fetchone()
            if row is not None:
                return row["id"], False
            await self._db.execute(
                "INSERT INTO approvals(id, grant_id, session_id, tool, args_masked, args_encrypted, args_hash,"
                " reason_codes, approval_scope, created_at, expires_at, status, used, destination, detail)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',0,?,?)",
                (a["id"], a["grant_id"], a.get("session_id"), a["tool"], json.dumps(a.get("args_masked") or {}),
                 a.get("args_encrypted"), a["args_hash"], json.dumps(a.get("reason_codes") or []),
                 a.get("approval_scope", "once"), a["created_at"], a["expires_at"], a.get("destination"),
                 json.dumps(a.get("detail") or {})))
            await self._db.commit()
            return a["id"], True

    async def get_approval(self, approval_id: str, with_args: bool = False) -> dict | None:
        cols = "*" if with_args else APPROVAL_COLUMNS
        rows = await self._all(f"SELECT {cols} FROM approvals WHERE id=?", (approval_id,))
        return rows[0] if rows else None

    async def list_approvals(self, status: str | None = None, limit: int = 100, with_args: bool = False) -> list[dict]:
        cols = "*" if with_args else APPROVAL_COLUMNS
        if status:
            return await self._all(f"SELECT {cols} FROM approvals WHERE status=? ORDER BY created_at LIMIT ?", (status, limit))
        return await self._all(f"SELECT {cols} FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,))

    async def find_pending_approval(self, grant_id: str, tool: str, args_hash: str, now_iso: str) -> dict | None:
        """An identical request (same grant, tool and canonical arguments) that is still waiting for a decision."""
        rows = await self._all(
            f"SELECT {APPROVAL_COLUMNS} FROM approvals WHERE grant_id=? AND tool=? AND args_hash=? AND status='pending'"
            " AND expires_at > ? ORDER BY created_at DESC LIMIT 1", (grant_id, tool, args_hash, now_iso))
        return rows[0] if rows else None

    async def find_decided_approval(self, grant_id: str, tool: str, args_hash: str, status: str,
                                    since_iso: str) -> dict | None:
        """The newest unused approved/denied row for this exact call decided since `since_iso`."""
        rows = await self._all(
            f"SELECT {APPROVAL_COLUMNS} FROM approvals WHERE grant_id=? AND tool=? AND args_hash=? AND status=?"
            " AND used=0 AND decided_at >= ? ORDER BY decided_at DESC LIMIT 1",
            (grant_id, tool, args_hash, status, since_iso))
        return rows[0] if rows else None

    async def find_destination_approval(self, grant_id: str, tool: str, destination: str) -> dict | None:
        """An approval with scope 'destination' for the same tool and destination, valid for the rest of the grant."""
        rows = await self._all(
            f"SELECT {APPROVAL_COLUMNS} FROM approvals WHERE grant_id=? AND tool=? AND destination=? AND status='approved'"
            " AND approval_scope='destination' ORDER BY decided_at DESC LIMIT 1", (grant_id, tool, destination))
        return rows[0] if rows else None

    async def consume_approval(self, approval_id: str, tool: str, args_hash: str, since_iso: str,
                               status: str = "approved") -> bool:
        """Single use: flips `used` from 0 to 1 in one statement, only for a matching, recent decision."""
        n = await self._run(
            "UPDATE approvals SET used=1 WHERE id=? AND tool=? AND args_hash=? AND status=? AND used=0"
            " AND decided_at >= ?", (approval_id, tool, args_hash, status, since_iso))
        return n == 1

    async def expire_if_pending(self, approval_id: str) -> bool:
        """The waiter gave up: pending -> expired and the stored arguments are deleted. False if it was decided."""
        n = await self._run(
            "UPDATE approvals SET status='expired', args_encrypted=NULL WHERE id=? AND status='pending'", (approval_id,))
        return n == 1

    async def sweep_expired_approvals(self, now_iso: str) -> int:
        """Pending rows past their expiry become expired and lose their stored arguments (F16)."""
        return await self._run(
            "UPDATE approvals SET status='expired', args_encrypted=NULL WHERE status='pending' AND expires_at <= ?",
            (now_iso,))

    async def decide_approval(self, approval_id: str, decision: str, scope: str, by: str, now_iso: str) -> str:
        """Atomic pending -> approved/denied. Returns 'ok', 'not_found', 'conflict' (already decided),
        'expired' or 'no_destination' (scope destination on a call without a destination).
        Pending arguments are deleted once decided (F16)."""
        async with self._lock:
            cur = await self._db.execute(
                "SELECT status, expires_at, destination FROM approvals WHERE id=?", (approval_id,))
            row = await cur.fetchone()
            if row is None:
                return "not_found"
            if row["status"] != "pending":
                return "conflict"
            if row["expires_at"] <= now_iso:
                await self._db.execute("UPDATE approvals SET status='expired', args_encrypted=NULL WHERE id=?", (approval_id,))
                await self._db.commit()
                return "expired"
            if decision == "approve" and scope == "destination" and not row["destination"]:
                return "no_destination"
            status = "approved" if decision == "approve" else "denied"
            await self._db.execute(
                "UPDATE approvals SET status=?, approval_scope=?, decided_by=?, decided_at=?, args_encrypted=NULL"
                " WHERE id=? AND status='pending'", (status, scope, by, now_iso, approval_id))
            await self._db.commit()
            return "ok"

    # ---------------- runtime info (written by the gateway, read by the admin API) ----------------
    async def set_runtime(self, key: str, value: Any, now_iso: str) -> None:
        await self._run(
            "INSERT INTO runtime_info(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET"
            " value=excluded.value, updated_at=excluded.updated_at", (key, json.dumps(value), now_iso))

    async def get_runtime(self, key: str) -> Any:
        rows = await self._all("SELECT value FROM runtime_info WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else None
    # ---------------- sessions and state ----------------
    async def admit_session(self, session_id: str, grant_id: str, max_sessions: int, since_iso: str, now_iso: str) -> bool:
        """Known session: refresh. New session: admit only if fewer than max_sessions are active.
        Sessions are counted per grant, so the same id on two grants never collides."""
        async with self._lock:
            cur = await self._db.execute("SELECT 1 FROM sessions WHERE id=? AND grant_id=?", (session_id, grant_id))
            row = await cur.fetchone()
            if row is not None:
                await self._db.execute("UPDATE sessions SET last_seen=? WHERE id=? AND grant_id=?",
                                       (now_iso, session_id, grant_id))
                await self._db.commit()
                return True
            cur = await self._db.execute(
                "SELECT COUNT(*) AS n FROM sessions WHERE grant_id=? AND last_seen >= ?", (grant_id, since_iso)
            )
            if (await cur.fetchone())["n"] >= max_sessions:
                return False
            await self._db.execute(
                "INSERT INTO sessions(id, grant_id, created_at, last_seen) VALUES(?,?,?,?)",
                (session_id, grant_id, now_iso, now_iso),
            )
            await self._db.commit()
            return True

    async def active_session_count(self, grant_id: str, since_iso: str) -> int:
        rows = await self._all(
            "SELECT COUNT(*) AS n FROM sessions WHERE grant_id=? AND last_seen >= ?", (grant_id, since_iso)
        )
        return rows[0]["n"]

    async def list_sessions(self) -> list[dict]:
        return await self._all("SELECT * FROM sessions ORDER BY last_seen DESC")

    async def get_state(self, grant_id: str) -> dict | None:
        rows = await self._all("SELECT * FROM grant_state WHERE grant_id=?", (grant_id,))
        return rows[0] if rows else None

    async def put_state(self, grant_id: str, labels: list[str], call_count: int, denied_streak: int,
                        suspended: bool, suspicious: bool, now_iso: str) -> None:
        await self._run(
            "INSERT INTO grant_state(grant_id, labels, call_count, denied_streak, suspended, suspicious, last_activity)"
            " VALUES(?,?,?,?,?,?,?) ON CONFLICT(grant_id) DO UPDATE SET labels=excluded.labels,"
            " call_count=excluded.call_count, denied_streak=excluded.denied_streak,"
            " suspended=excluded.suspended, suspicious=excluded.suspicious, last_activity=excluded.last_activity",
            (grant_id, json.dumps(sorted(labels)), call_count, denied_streak, int(suspended), int(suspicious), now_iso),
        )

    async def update_state(self, grant_id: str, now_iso: str, add_labels: set | None = None,
                           suspicious: bool | None = None, suspended: bool | None = None,
                           incr_calls: int = 0, denied_streak: int | None = None, denied_delta: int = 0,
                           denied_reset: bool = False) -> dict:
        """Atomic read-merge-write under the lock. Labels are only ever added (never cleared) and
        counters are incremented in place, so concurrent calls cannot erase each other's updates."""
        async with self._lock:
            cur = await self._db.execute("SELECT * FROM grant_state WHERE grant_id=?", (grant_id,))
            row = await cur.fetchone()
            labels = set(json.loads(row["labels"] or "[]")) if row else set()
            labels |= set(add_labels or ())
            vals = {
                "call_count": (row["call_count"] if row else 0) + incr_calls,
                "denied_streak": 0 if denied_reset else (
                    denied_streak if denied_streak is not None
                    else (row["denied_streak"] if row else 0) + denied_delta),
                "suspended": int(suspended) if suspended is not None else (row["suspended"] if row else 0),
                # suspicious only ever turns on here; clearing it is an operator action (save_state)
                "suspicious": 1 if suspicious else (row["suspicious"] if row else 0),
            }
            await self._db.execute(
                "INSERT INTO grant_state(grant_id, labels, call_count, denied_streak, suspended, suspicious, last_activity)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(grant_id) DO UPDATE SET labels=excluded.labels,"
                " call_count=excluded.call_count, denied_streak=excluded.denied_streak,"
                " suspended=excluded.suspended, suspicious=excluded.suspicious, last_activity=excluded.last_activity",
                (grant_id, json.dumps(sorted(labels)), vals["call_count"], vals["denied_streak"],
                 vals["suspended"], vals["suspicious"], now_iso),
            )
            await self._db.commit()
            return vals

    async def cleanup_state(self, now: datetime) -> list[str]:
        """F02: delete a grant's state 1 hour after it stops being active, or after 2 hours idle."""
        inactive_cut = iso(now - timedelta(hours=1))
        idle_cut = iso(now - timedelta(hours=2))
        now_iso = iso(now)
        async with self._lock:
            cur = await self._db.execute(
                "SELECT s.grant_id FROM grant_state s LEFT JOIN grants g ON g.id = s.grant_id WHERE"
                " s.last_activity < ? OR g.id IS NULL OR (s.last_activity < ? AND ("
                "   g.status != 'active' OR g.expires_at <= ? OR g.used_calls >= g.max_calls))",
                (idle_cut, inactive_cut, now_iso),
            )
            ids = [r["grant_id"] for r in await cur.fetchall()]
            for gid in ids:
                for table, col in (("grant_state", "grant_id"), ("fingerprints", "grant_id"),
                                   ("exact_tokens", "grant_id"), ("egress_buffer", "grant_id"),
                                   ("sessions", "grant_id")):
                    await self._db.execute(f"DELETE FROM {table} WHERE {col}=?", (gid,))
            # session rows of still-active grants are only useful for 5 minutes; keep an hour for the audit view
            await self._db.execute("DELETE FROM sessions WHERE last_seen < ?", (inactive_cut,))
            await self._db.commit()
        return ids

    async def mutate_rate_loop(self, grant_id: str, fn) -> Any:
        """Atomic read-modify-write of the rate and loop JSON state. fn(rate, loop) -> (rate, loop, result)."""
        async with self._lock:
            await self._db.execute(
                "INSERT OR IGNORE INTO grant_state(grant_id, last_activity) VALUES(?, ?)", (grant_id, iso(utcnow())))
            cur = await self._db.execute("SELECT rate_state, loop_state FROM grant_state WHERE grant_id=?", (grant_id,))
            row = await cur.fetchone()
            rate, loop, result = fn(json.loads(row["rate_state"] or "{}"), json.loads(row["loop_state"] or "{}"))
            await self._db.execute("UPDATE grant_state SET rate_state=?, loop_state=? WHERE grant_id=?",
                                   (json.dumps(rate), json.dumps(loop), grant_id))
            await self._db.commit()
            return result

    # ---------------- tool pins (F04) ----------------
    async def observe_pin(self, upstream: str, tool: str, new_hash: str, snapshot: str, reasons: list[str],
                          now_iso: str) -> dict:
        """Atomically compare a live tool definition with its pin. Returns the resulting state and what happened:
        transition is 'first_sight', 'poisoned', 'changed' or None (nothing new)."""
        async with self._lock:
            cur = await self._db.execute("SELECT * FROM pins WHERE upstream=? AND tool=?", (upstream, tool))
            row = await cur.fetchone()
            out = {"upstream": upstream, "tool": tool, "old_hash": None, "new_hash": new_hash, "reasons": reasons}
            if row is None:
                state = "quarantined" if reasons else "pinned"
                await self._db.execute(
                    "INSERT INTO pins(upstream, tool, hash, state, description_snapshot, first_seen, reasons)"
                    " VALUES(?,?,?,?,?,?,?)", (upstream, tool, new_hash, state, snapshot, now_iso, json.dumps(reasons)))
                await self._db.commit()
                return {**out, "state": state, "transition": "poisoned" if reasons else "first_sight"}
            out["old_hash"] = row["hash"]
            if row["hash"] == new_hash:
                # unchanged since the pin; a tool already blocked stays blocked until an operator approves it
                return {**out, "state": row["state"], "transition": None}
            if row["state"] == "changed" and row["new_hash"] == new_hash:
                return {**out, "state": "changed", "transition": None}  # still waiting for the operator
            state = "quarantined" if row["state"] == "quarantined" else "changed"
            await self._db.execute(
                "UPDATE pins SET state=?, new_hash=?, new_snapshot=?, reasons=?, changed_at=? WHERE upstream=? AND tool=?",
                (state, new_hash, snapshot, json.dumps(reasons), now_iso, upstream, tool))
            await self._db.commit()
            return {**out, "state": state, "transition": "changed"}

    async def get_pin(self, tool: str) -> dict | None:
        rows = await self._all("SELECT * FROM pins WHERE tool=?", (tool,))
        return rows[0] if rows else None

    async def list_pins(self) -> list[dict]:
        rows = await self._all(
            "SELECT upstream, tool, hash, state, description_snapshot, new_hash, new_snapshot, reasons, first_seen,"
            " changed_at FROM pins ORDER BY upstream, tool")
        return rows

    async def approve_pin(self, upstream: str, tool: str, now_iso: str) -> bool:
        """Operator action: adopt the observed definition as the new pin and unblock the tool."""
        async with self._lock:
            cur = await self._db.execute("SELECT * FROM pins WHERE upstream=? AND tool=?", (upstream, tool))
            row = await cur.fetchone()
            if row is None:
                return False
            await self._db.execute(
                "UPDATE pins SET hash=COALESCE(new_hash, hash), description_snapshot=COALESCE(new_snapshot,"
                " description_snapshot), new_hash=NULL, new_snapshot=NULL, state='approved_change', changed_at=?,"
                " reasons='[]' WHERE upstream=? AND tool=?", (now_iso, upstream, tool))
            await self._db.commit()
            return True
    # ---------------- data-flow store (F12) ----------------
    async def add_fingerprints(self, grant_id: str, tool: str, hashes: list[int], now_iso: str, cap: int) -> None:
        """Insert fingerprints; keep only the most recent `cap` per grant."""
        if not hashes:
            return
        async with self._lock:
            await self._db.executemany(
                "INSERT INTO fingerprints(grant_id, source_tool, hash, created_at) VALUES(?,?,?,?)",
                [(grant_id, tool, h, now_iso) for h in hashes])
            cur = await self._db.execute("SELECT COUNT(*) AS n FROM fingerprints WHERE grant_id=?", (grant_id,))
            extra = (await cur.fetchone())["n"] - cap
            if extra > 0:
                await self._db.execute(
                    "DELETE FROM fingerprints WHERE rowid IN (SELECT rowid FROM fingerprints WHERE grant_id=?"
                    " ORDER BY rowid LIMIT ?)", (grant_id, extra))
            await self._db.commit()

    async def fingerprint_count(self, grant_id: str) -> int:
        return (await self._all("SELECT COUNT(*) AS n FROM fingerprints WHERE grant_id=?", (grant_id,)))[0]["n"]

    async def match_fingerprints(self, grant_id: str, hashes: list[int]) -> dict[int, set[str]]:
        """Which of these hashes does the grant know, and from which source tools."""
        found: dict[int, set[str]] = {}
        for i in range(0, len(hashes), 500):
            chunk = hashes[i : i + 500]
            marks = ",".join("?" * len(chunk))
            for r in await self._all(
                    f"SELECT hash, source_tool FROM fingerprints WHERE grant_id=? AND hash IN ({marks})",
                    (grant_id, *chunk)):
                found.setdefault(r["hash"], set()).add(r["source_tool"])
        return found

    async def add_exact_tokens(self, grant_id: str, tool: str, tokens: list[tuple[str, int, int]], now_iso: str) -> None:
        """tokens: (blake2b hex of the flow-normal token, length, rolling hash). Duplicates are skipped."""
        async with self._lock:
            for token_hash, length, poly in tokens:
                cur = await self._db.execute(
                    "SELECT 1 FROM exact_tokens WHERE grant_id=? AND token_hash=? AND source_tool=?",
                    (grant_id, token_hash, tool))
                if await cur.fetchone() is None:
                    await self._db.execute(
                        "INSERT INTO exact_tokens(grant_id, source_tool, token_hash, created_at, length, poly)"
                        " VALUES(?,?,?,?,?,?)", (grant_id, tool, token_hash, now_iso, length, poly))
            await self._db.commit()

    async def list_exact_tokens(self, grant_id: str) -> list[dict]:
        return await self._all(
            "SELECT source_tool, token_hash, length, poly FROM exact_tokens WHERE grant_id=?", (grant_id,))

    async def get_egress_entries(self, grant_id: str) -> list[tuple[str, str]]:
        """Recent flow-normal sink-bound text as (field key, text) entries, oldest first."""
        rows = await self._all("SELECT text FROM egress_buffer WHERE grant_id=?", (grant_id,))
        return [(k, t) for k, t in json.loads(rows[0]["text"])] if rows else []

    async def append_egress_entries(self, grant_id: str, entries: list[tuple[str, str]], cap: int = 4096) -> None:
        """Atomically append entries and keep only the most recent `cap` characters in total."""
        async with self._lock:
            cur = await self._db.execute("SELECT text FROM egress_buffer WHERE grant_id=?", (grant_id,))
            row = await cur.fetchone()
            merged = [(k, t) for k, t in json.loads(row["text"])] if row else []
            merged.extend(entries)
            total, keep = 0, []
            for k, t in reversed(merged):
                if total + len(t) > cap:
                    t = t[-(cap - total):] if cap - total > 0 else ""
                if t:
                    keep.append((k, t))
                    total += len(t)
                if total >= cap:
                    break
            keep.reverse()
            await self._db.execute(
                "INSERT INTO egress_buffer(grant_id, text) VALUES(?,?) ON CONFLICT(grant_id) DO UPDATE SET text=excluded.text",
                (grant_id, json.dumps(keep)))
            await self._db.commit()
    # ---------------- audit (append only) ----------------
    async def insert_audit(self, row: dict[str, Any]) -> int:
        """Append one row and chain it to the previous one. BEGIN IMMEDIATE takes SQLite's write lock before the
        previous hash is read, so the gateway and the admin API (two processes) can never fork the chain."""
        values = {
            "ts": row.get("ts") or iso(utcnow()), "session_id": row.get("session_id"), "grant_id": row.get("grant_id"),
            "tool": row.get("tool"),
            "args_masked": json.dumps(row.get("args_masked")) if row.get("args_masked") is not None else None,
            "args_hash": row.get("args_hash"), "phase": row.get("phase"), "verdict": row.get("verdict"),
            "reason_code": row.get("reason_code"), "rule_id": row.get("rule_id"),
            "detail": json.dumps(row.get("detail") or {}), "latency_ms": row.get("latency_ms"),
            "upstream_ms": row.get("upstream_ms"), "mode": row.get("mode"),
        }
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._db.execute("SELECT row_hash FROM audit ORDER BY id DESC LIMIT 1")
                last = await cur.fetchone()
                prev = last["row_hash"] if last and last["row_hash"] else chain.GENESIS
                cur = await self._db.execute(
                    "INSERT INTO audit(ts, session_id, grant_id, tool, args_masked, args_hash, phase, verdict,"
                    " reason_code, rule_id, detail, latency_ms, upstream_ms, mode, prev_hash)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (*values.values(), prev))
                row_id = cur.lastrowid
                digest = chain.compute_hash({"id": row_id, **values}, prev)
                await self._db.execute("UPDATE audit SET row_hash=? WHERE id=?", (digest, row_id))
                await self._db.commit()
            except BaseException:
                await self._db.rollback()
                raise
            return row_id

    async def audit_after(self, last_id: int, limit: int = 2000) -> list[dict]:
        return await self._all("SELECT * FROM audit WHERE id > ? ORDER BY id LIMIT ?", (last_id, limit))

    async def audit_head(self) -> dict | None:
        rows = await self._all("SELECT id, row_hash FROM audit ORDER BY id DESC LIMIT 1")
        if not rows:
            return None
        count = (await self._all("SELECT COUNT(*) AS n FROM audit"))[0]["n"]
        return {**rows[0], "rows": count}

    async def audit_row(self, row_id: int) -> dict | None:
        rows = await self._all("SELECT * FROM audit WHERE id=?", (row_id,))
        return rows[0] if rows else None
    async def query_audit(self, grant_id: str | None = None, verdict: str | None = None,
                          phase: str | None = None, limit: int = 100) -> list[dict]:
        where, params = [], []
        for col, val in (("grant_id", grant_id), ("verdict", verdict), ("phase", phase)):
            if val:
                where.append(f"{col}=?")
                params.append(val)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        return await self._all(sql, (*params, limit))


