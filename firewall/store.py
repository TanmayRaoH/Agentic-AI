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
  grant_id TEXT, source_tool TEXT, token_hash TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS egress_buffer(grant_id TEXT PRIMARY KEY, text TEXT);
CREATE TABLE IF NOT EXISTS pins(
  upstream TEXT, tool TEXT, hash TEXT, state TEXT, description_snapshot TEXT,
  first_seen TEXT, changed_at TEXT, PRIMARY KEY(upstream, tool));
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, grant_id TEXT, session_id TEXT, tool TEXT, args_masked TEXT,
  args_encrypted BLOB, args_hash TEXT, reason_codes TEXT, approval_scope TEXT,
  created_at TEXT, expires_at TEXT, status TEXT, decided_by TEXT, decided_at TEXT,
  used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT, grant_id TEXT, tool TEXT,
  args_masked TEXT, args_hash TEXT, phase TEXT, verdict TEXT, reason_code TEXT, rule_id TEXT,
  detail TEXT, latency_ms REAL, upstream_ms REAL, mode TEXT, prev_hash TEXT, row_hash TEXT);
CREATE INDEX IF NOT EXISTS idx_audit_grant ON audit(grant_id);
CREATE TABLE IF NOT EXISTS eval_runs(
  id TEXT PRIMARY KEY, started_at TEXT, mode TEXT, git_commit TEXT, fastmcp_version TEXT,
  results TEXT);
"""

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
                           incr_calls: int = 0, denied_streak: int | None = None) -> None:
        """Atomic read-merge-write under the lock. Labels are only ever added (never cleared) and
        counters are incremented in place, so concurrent calls cannot erase each other's updates."""
        async with self._lock:
            cur = await self._db.execute("SELECT * FROM grant_state WHERE grant_id=?", (grant_id,))
            row = await cur.fetchone()
            labels = set(json.loads(row["labels"] or "[]")) if row else set()
            labels |= set(add_labels or ())
            vals = {
                "call_count": (row["call_count"] if row else 0) + incr_calls,
                "denied_streak": denied_streak if denied_streak is not None else (row["denied_streak"] if row else 0),
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

    # ---------------- audit (append only) ----------------
    async def insert_audit(self, row: dict[str, Any]) -> int:
        async with self._lock:
            cur = await self._db.execute(
                "INSERT INTO audit(ts, session_id, grant_id, tool, args_masked, args_hash, phase, verdict,"
                " reason_code, rule_id, detail, latency_ms, upstream_ms, mode) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row.get("ts") or iso(utcnow()), row.get("session_id"), row.get("grant_id"), row.get("tool"),
                    json.dumps(row.get("args_masked")) if row.get("args_masked") is not None else None,
                    row.get("args_hash"), row.get("phase"), row.get("verdict"), row.get("reason_code"),
                    row.get("rule_id"), json.dumps(row.get("detail") or {}), row.get("latency_ms"),
                    row.get("upstream_ms"), row.get("mode"),
                ),
            )
            await self._db.commit()
            return cur.lastrowid

    async def query_audit(self, grant_id: str | None = None, verdict: str | None = None,
                          phase: str | None = None, limit: int = 100) -> list[dict]:
        where, params = [], []
        for col, val in (("grant_id", grant_id), ("verdict", verdict), ("phase", phase)):
            if val:
                where.append(f"{col}=?")
                params.append(val)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        return await self._all(sql, (*params, limit))

