"""Seed a grant straight into the database (T11). Phase 3 replaces this with the admin API and CLI.

Usage: uv run python -m firewall.seed_grant --tools notes_read mail_send_email [--max-calls 30]
Prints the one-time token. Set FW_DB_PATH to the gateway's database.
"""
from __future__ import annotations

import argparse
import asyncio
import os

from firewall import grants
from firewall.store import Store


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default="seeded grant")
    ap.add_argument("--tools", nargs="+", required=True)
    ap.add_argument("--destinations", nargs="*", default=[])
    ap.add_argument("--paths", nargs="*", default=["./sandbox"])
    ap.add_argument("--max-calls", type=int, default=30)
    ap.add_argument("--max-sessions", type=int, default=2)
    ap.add_argument("--ttl-seconds", type=int, default=3600)
    a = ap.parse_args()
    store = await Store(os.environ.get("FW_DB_PATH", "./fw.db")).open()
    grant, token = await grants.create_grant(store, {
        "task": a.task, "allowed_tools": a.tools, "allowed_destinations": a.destinations,
        "allowed_paths": a.paths, "max_calls": a.max_calls, "max_sessions": a.max_sessions,
        "ttl_seconds": a.ttl_seconds,
    }, created_by="seed-script")
    await store.close()
    print(f"grant id : {grant.id}\nexpires  : {grant.expires_at}\ntoken    : {token}\n(shown once; only its SHA-256 is stored)")


if __name__ == "__main__":
    asyncio.run(main())
