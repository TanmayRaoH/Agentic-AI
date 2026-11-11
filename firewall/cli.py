"""Operator CLI `fw` (F19): a thin wrapper over the admin API.

Subcommands: grant create | list | revoke, approvals list, approve, deny, pins list | approve, audit verify | tail.
Env: FW_ADMIN_TOKEN (required), FW_ADMIN_URL (default http://127.0.0.1:8801).
Run as: uv run fw ...   (or: uv run python -m firewall.cli ...)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx


def _client() -> httpx.Client:
    token = os.environ.get("FW_ADMIN_TOKEN")
    if not token:
        print("error: set FW_ADMIN_TOKEN", file=sys.stderr)
        raise SystemExit(2)
    base = os.environ.get("FW_ADMIN_URL", "http://127.0.0.1:8801")
    return httpx.Client(base_url=base, headers={"X-Admin-Token": token}, timeout=30)


def _call(method: str, path: str, **kw) -> dict | list:
    try:
        with _client() as c:
            r = c.request(method, path, **kw)
    except httpx.HTTPError as exc:
        print(f"error: cannot reach the admin API ({exc})", file=sys.stderr)
        raise SystemExit(1) from exc
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail", r.json())
        except ValueError:
            msg = r.text
        print(f"error {r.status_code}: {msg}", file=sys.stderr)
        raise SystemExit(1)
    return r.json()


def _print_grants(rows: list[dict]) -> None:
    print(f"{'id':<12} {'status':<10} {'used/max':<9} {'prefix':<9} expires_at            task / tools")
    for g in rows:
        print(f"{g['id']:<12} {g['status']:<10} {str(g['used_calls']) + '/' + str(g['max_calls']):<9} "
              f"{g['token_prefix']:<9} {g['expires_at']:<20} {g['task']} [{', '.join(g['allowed_tools'])}]")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fw", description="Agent Firewall operator CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    grant = sub.add_parser("grant").add_subparsers(dest="sub", required=True)
    c = grant.add_parser("create", help="create a grant (the token is printed once)")
    c.add_argument("--task", default="")
    c.add_argument("--tools", nargs="+", required=True)
    c.add_argument("--destinations", nargs="*", default=[])
    c.add_argument("--paths", nargs="*", default=[])
    c.add_argument("--max-calls", type=int, default=30)
    c.add_argument("--max-sessions", type=int, default=2)
    c.add_argument("--ttl-seconds", type=int, default=3600)
    c.add_argument("--approval-required-for", nargs="*", default=[])
    c.add_argument("--allow-critical", action="store_true")
    grant.add_parser("list")
    r = grant.add_parser("revoke")
    r.add_argument("id")

    ap = sub.add_parser("approvals").add_subparsers(dest="sub", required=True)
    lst = ap.add_parser("list")
    lst.add_argument("--status", default="pending")
    au = sub.add_parser("audit").add_subparsers(dest="sub", required=True)
    au.add_parser("verify", help="check the audit hash chain and the checkpoint file")
    tail = au.add_parser("tail", help="show the newest audit rows")
    tail.add_argument("--limit", type=int, default=20)

    pins = sub.add_parser("pins").add_subparsers(dest="sub", required=True)
    pins.add_parser("list")
    pa = pins.add_parser("approve", help="adopt the observed definition of a changed or quarantined tool")
    pa.add_argument("upstream")
    pa.add_argument("tool")

    for name in ("approve", "deny"):
        d = sub.add_parser(name)
        d.add_argument("id")
        if name == "approve":
            d.add_argument("--scope", choices=["once", "destination"], default="once")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "grant" and a.sub == "create":
        body = {"task": a.task, "allowed_tools": a.tools, "allowed_destinations": a.destinations,
                "allowed_paths": a.paths, "max_calls": a.max_calls, "max_sessions": a.max_sessions,
                "ttl_seconds": a.ttl_seconds, "approval_required_for": a.approval_required_for,
                "allow_critical": a.allow_critical}
        g = _call("POST", "/grants", json=body)
        print(f"grant id : {g['id']}\nexpires  : {g['expires_at']}\ntoken    : {g['token']}\n"
              "(shown once; send it as the X-Task-Grant header)")
    elif a.cmd == "grant" and a.sub == "list":
        _print_grants(_call("GET", "/grants"))
    elif a.cmd == "grant" and a.sub == "revoke":
        print(json.dumps(_call("DELETE", f"/grants/{a.id}")))
    elif a.cmd == "approvals" and a.sub == "list":
        rows = _call("GET", "/approvals", params={"status": a.status})
        if not rows:
            print("no approvals")
        for r in rows:
            print(f"{r['id']}  {r['status']:<9} grant={r['grant_id']} tool={r['tool']} reasons={r['reason_codes']}")
            p = r.get("preview")
            if p:  # what the operator is being asked to approve: destination, private matches and the content
                print(f"    destination: {p.get('destination') or '-'}   private matches: {p.get('private_matches', 0)}")
                print("    content: " + (p["preview"] if p.get("preview_available") else "(preview unavailable)"))
    elif a.cmd == "audit" and a.sub == "verify":
        result = _call("GET", "/audit/verify")
        if result["ok"]:
            print(f"audit chain OK: {result['rows']} rows, {result['checkpoints_checked']} checkpoints checked")
        else:
            print(f"AUDIT CHAIN BROKEN: {result['error']}", file=sys.stderr)
            return 1
    elif a.cmd == "audit" and a.sub == "tail":
        for r in reversed(_call("GET", "/audit", params={"limit": a.limit})):
            print(f"#{r['id']} {r['ts']} {r['phase']:<7} {r['verdict']:<18} {r['tool'] or '-'} {r['reason_code'] or ''}")
    elif a.cmd == "pins" and a.sub == "list":
        rows = _call("GET", "/pins")
        print(f"{'tool':<18} {'state':<16} first_seen            reasons")
        for p in rows:
            print(f"{p['tool']:<18} {p['state']:<16} {p['first_seen']:<20} {'; '.join(p['reasons'])}")
    elif a.cmd == "pins" and a.sub == "approve":
        print(json.dumps(_call("POST", f"/pins/{a.upstream}/{a.tool}/approve")))
    elif a.cmd == "approve":
        print(json.dumps(_call("POST", f"/approvals/{a.id}/decision", json={"decision": "approve", "scope": a.scope})))
    elif a.cmd == "deny":
        print(json.dumps(_call("POST", f"/approvals/{a.id}/decision", json={"decision": "deny"})))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
