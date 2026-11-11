"""Latency benchmark (F31).

200 allowed, benign calls through each path after a warm-up: straight to the upstream servers (direct), through the
gateway in monitor mode and through the gateway in enforce mode, with the injection scanner on and off.
Two numbers per path: end-to-end time seen by the client, and firewall overhead taken from the audit table
(latency_ms of the call row plus latency_ms of the result row; upstream time is excluded in both).

Usage: uv run python -m eval.bench [--calls 200] [--warmup 20] [--out eval/results/final-latency.json]

The workload alternates two grants so that no call needs an approval and the loop detector stays quiet:
  web    100 fetches of an allowed page (the result is scanned because web_fetch is untrusted)
  files  100 reads of notes and files and directory listings (private tools, nothing to scan)
"Scanner off" replaces the scanner function with a stub for that run only; no setting does this in production.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import time
from datetime import UTC, datetime
from pathlib import Path

from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport
from rich.console import Console

from eval.backends import LOGS, ROOT, RUNTIME, WORLD, stdio_transport
from eval.runner import reset_environment
from firewall import grants, scan_output
from firewall.config import Defaults, PolicyConfig, load_policy, load_tools, load_upstreams
from firewall.server import build_gateway

console = Console()
APPROVAL_KEY = "bench-approval-key-0123456789"


def workload(kind: str, n: int) -> list[tuple[str, dict]]:
    """(gateway tool name, arguments) for n calls."""
    if kind == "web":
        return [("web_fetch", {"url": f"https://docs.example.com/guide?i={i}"}) for i in range(n)]
    cycle = [("notes_read", lambda i: {"note_id": 2 + i % 2}),
             ("fs_read_file", lambda i: {"path": "./sandbox/readme.txt"}),
             ("fs_list_files", lambda i: {"path": "./sandbox/docs"})]
    return [(cycle[i % 3][0], cycle[i % 3][1](i)) for i in range(n)]


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, max(0, math.ceil(q / 100 * len(s)) - 1))], 3)


def stats(values: list[float]) -> dict:
    return {"n": len(values), "p50": percentile(values, 50), "p95": percentile(values, 95),
            "p99": percentile(values, 99)}


def bench_policy() -> PolicyConfig:
    pol = load_policy(ROOT / "policy.yaml")
    d = {**pol.defaults.model_dump(), "rate_limit_per_min": 100000, "rate_burst": 100000, "loop_threshold": 100000}
    return PolicyConfig(defaults=Defaults(**d), rules=pol.rules, allow_flows=pol.allow_flows,
                        secrets_allowed_tools=pol.secrets_allowed_tools)


async def timed(client: Client, name: str, args: dict) -> float:
    t = time.perf_counter()
    res = await client.call_tool(name, args, raise_on_error=False)
    ms = (time.perf_counter() - t) * 1000
    if res.is_error:
        raise RuntimeError(f"benchmark call {name} {args} was refused: {res.content[0].text}")
    return ms


async def run_direct(n_web: int, n_files: int, warmup: int) -> dict:
    """The same calls straight to the demo upstream servers."""
    ups = {u.name: u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.name in ("web", "notes", "fs")}
    raw = {"web_fetch": ("web", "fetch"), "notes_read": ("notes", "read"), "fs_read_file": ("fs", "read_file"),
           "fs_list_files": ("fs", "list_files")}
    clients = {name: Client(stdio_transport(u)) for name, u in ups.items()}
    times: list[float] = []
    try:
        for c in clients.values():
            await c.__aenter__()
        calls = workload("web", n_web + warmup // 2) + workload("files", n_files + warmup // 2)
        web, files = calls[: n_web + warmup // 2], calls[n_web + warmup // 2:]
        for part in (web, files):
            for i, (tool, args) in enumerate(part):
                server, name = raw[tool]
                t = time.perf_counter()
                await clients[server].call_tool(name, args)
                if i >= warmup // 2:
                    times.append((time.perf_counter() - t) * 1000)
    finally:
        for c in clients.values():
            await c.__aexit__(None, None, None)
    return {"end_to_end_ms": stats(times)}


async def run_gateway(mode: str, scanner: bool, n_web: int, n_files: int, warmup: int, tag: str) -> dict:
    half = warmup // 2
    RUNTIME.mkdir(parents=True, exist_ok=True)
    db = RUNTIME / f"bench-{tag}.db"
    for suffix in ("", "-wal", "-shm"):
        Path(f"{db}{suffix}").unlink(missing_ok=True)
    original = scan_output.injection_score_many
    if not scanner:
        scan_output.injection_score_many = lambda texts: (0.0, [])  # type: ignore[assignment]
    gw = await build_gateway(
        db_path=str(db), upstreams=[u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.enabled],
        mode=mode, tools=load_tools(ROOT / "tools.yaml"), path_base=WORLD, policy=bench_policy(),
        approval_key=APPROVAL_KEY, env_extra={"FW_WORLD": str(WORLD), "FW_LOG_DIR": str(LOGS)})
    await gw.start()
    e2e: list[float] = []
    overhead: list[float] = []
    try:
        for kind, tools, n in (("web", ["web_fetch"], n_web),
                               ("files", ["notes_read", "fs_read_file", "fs_list_files"], n_files)):
            g, token = await grants.create_grant(
                gw.store, {"task": f"bench-{kind}", "allowed_tools": tools, "allowed_destinations": ["docs.example.com"],
                           "allowed_paths": ["./sandbox"], "max_calls": 200, "max_sessions": 2},
                registry=gw.engine.registry)
            async with Client(StreamableHttpTransport(gw.url, headers={"X-Task-Grant": token}), mode="legacy") as c:
                for i, (tool, args) in enumerate(workload(kind, n + half)):
                    ms = await timed(c, tool, args)
                    if i >= half:
                        e2e.append(ms)
            rows = sorted(await gw.store.query_audit(grant_id=g.id, limit=100000), key=lambda r: r["id"])
            calls = [r for r in rows if r["phase"] == "call"][half:]
            results = [r for r in rows if r["phase"] == "result"][half:]
            if len(calls) != len(results):
                raise RuntimeError(f"audit rows do not pair up: {len(calls)} call rows, {len(results)} result rows")
            overhead += [a["latency_ms"] + b["latency_ms"] for a, b in zip(calls, results, strict=True)]
    finally:
        scan_output.injection_score_many = original  # type: ignore[assignment]
        await gw.stop()
    return {"end_to_end_ms": stats(e2e), "firewall_overhead_ms": stats(overhead)}


async def main_async(calls: int, warmup: int, out: Path) -> dict:
    n_web = n_files = calls // 2
    reset_environment()
    result: dict = {"generated": datetime.now(UTC).isoformat(timespec="seconds"), "calls_per_path": calls,
                    "warmup_calls": warmup, "paths": {}}
    console.print("direct to upstream servers ...")
    result["paths"]["direct"] = await run_direct(n_web, n_files, warmup)
    for mode in ("monitor", "enforce"):
        for scanner in (True, False):
            label = f"{mode}/scanner-{'on' if scanner else 'off'}"
            console.print(f"{label} ...")
            reset_environment()
            result["paths"][label] = await run_gateway(mode, scanner, n_web, n_files, warmup, label.replace("/", "-"))
    base = result["paths"]["direct"]["end_to_end_ms"]["p50"]
    for label, p in result["paths"].items():
        if label != "direct":
            p["added_end_to_end_p50_ms"] = round(p["end_to_end_ms"]["p50"] - base, 3)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for label, p in result["paths"].items():
        o = p.get("firewall_overhead_ms") or {}
        e = p["end_to_end_ms"]
        console.print(f"{label:28} e2e p50 {e['p50']:>8} p95 {e['p95']:>8} p99 {e['p99']:>8}   "
                      f"firewall p50 {o.get('p50', '-')} p95 {o.get('p95', '-')} p99 {o.get('p99', '-')}", highlight=False)
    console.print(f"wrote {out}")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results" / "final-latency.json")
    args = ap.parse_args()
    asyncio.run(main_async(args.calls, args.warmup, args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
