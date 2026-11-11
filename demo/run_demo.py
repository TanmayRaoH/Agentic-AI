"""One command for the live demo.

    uv run python demo/run_demo.py

It starts the admin API and the gateway on a throwaway database, creates a grant, opens the dashboard in your
browser, waits for you to connect, then runs the scripted "hijacked agent" (demo/agent_demo.py). At step 5 the
agent's email is held: click "Approve once" in the dashboard (you have 2 minutes). When the story is over the
servers keep running for questions until you press Enter, then everything is stopped and cleaned up.

Options:
    --auto-approve     approve the held email by itself after 3 seconds (rehearsal or fallback)
    --no-browser       do not open the browser
    --no-pause         do not wait for Enter (used by the tests)
    --gateway-port / --admin-port   if 8800 / 8801 are taken
Set FW_ADMIN_TOKEN to use your own admin token (default: tanmay-admin-2026-demo).
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = os.environ.get("FW_ADMIN_TOKEN", "tanmay-admin-2026-demo")
APPROVAL_KEY = os.environ.get("FW_APPROVAL_KEY", "tanmay-approval-key-2026")


AUTO_APPROVER = """
import subprocess, sys, time
for _ in range(240):
    r = subprocess.run([sys.executable, "-m", "firewall.cli", "approvals", "list"], capture_output=True, text=True)
    ids = [x.split()[0] for x in r.stdout.splitlines() if x.strip().startswith("ap_")]
    if ids:
        time.sleep(3)
        print("[auto-approve] approving", ids[0], flush=True)
        subprocess.run([sys.executable, "-m", "firewall.cli", "approve", ids[0]])
        break
    time.sleep(0.5)
"""


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_for_port(port: int, name: str, proc: subprocess.Popen, log: Path, seconds: int = 60) -> None:
    for _ in range(seconds * 4):
        if proc.poll() is not None:
            raise SystemExit(f"{name} exited early. Its log:\n{log.read_text(errors='replace')[-1500:]}")
        if not port_free(port):
            return
        time.sleep(0.25)
    raise SystemExit(f"{name} did not open port {port} within {seconds} s. Its log:\n"
                     f"{log.read_text(errors='replace')[-1500:]}")


def stop(proc: subprocess.Popen | None) -> None:
    """Stop a process and everything it started (the gateway starts the demo upstream servers)."""
    if proc is None or proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False)
    else:
        proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway-port", type=int, default=8800)
    ap.add_argument("--admin-port", type=int, default=8801)
    ap.add_argument("--auto-approve", action="store_true")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-pause", action="store_true")
    args = ap.parse_args()

    for port, what in ((args.gateway_port, "gateway"), (args.admin_port, "admin API")):
        if not port_free(port):
            print(f"Port {port} ({what}) is already in use. Close the old gateway/admin windows, or use "
                  f"--gateway-port / --admin-port.", file=sys.stderr)
            return 2

    tmp = Path(tempfile.mkdtemp(prefix="fw-demo-"))
    world, logs = tmp / "world", tmp / "logs"
    shutil.copytree(ROOT / "eval" / "fixtures" / "world", world)
    logs.mkdir()
    env = {**os.environ, "FW_ADMIN_TOKEN": ADMIN_TOKEN, "FW_APPROVAL_KEY": APPROVAL_KEY,
           "FW_DB_PATH": str(tmp / "demo.db"), "FW_GATEWAY_PORT": str(args.gateway_port),
           "FW_ADMIN_PORT": str(args.admin_port), "FW_ADMIN_URL": f"http://127.0.0.1:{args.admin_port}",
           "FW_APPROVAL_TIMEOUT_S": "120", "FW_WORLD": str(world), "FW_LOG_DIR": str(logs),
           "FW_PATH_BASE": str(world), "PYTHONUNBUFFERED": "1"}
    py = sys.executable
    admin = gateway = None
    status = 0
    try:
        print("Starting the admin API and the gateway ...", flush=True)
        admin_log, gw_log = tmp / "admin.log", tmp / "gateway.log"
        admin = subprocess.Popen([py, "-m", "firewall.admin_api"], env=env, cwd=ROOT,
                                 stdout=open(admin_log, "w"), stderr=subprocess.STDOUT)  # noqa: SIM115 - must outlive Popen
        gateway = subprocess.Popen([py, "-m", "firewall.server"], env=env, cwd=ROOT,
                                   stdout=open(gw_log, "w"), stderr=subprocess.STDOUT)  # noqa: SIM115 - must outlive Popen
        wait_for_port(args.admin_port, "admin API", admin, admin_log)
        wait_for_port(args.gateway_port, "gateway", gateway, gw_log)

        out = subprocess.run(
            [py, "-m", "firewall.cli", "grant", "create", "--task", "demo", "--tools", "notes_read", "web_fetch",
             "mail_send_email", "--destinations", "docs.example.com"],
            env=env, cwd=ROOT, capture_output=True, text=True, check=False)
        token_lines = [x.split()[-1] for x in out.stdout.splitlines() if x.startswith("token")]
        if not token_lines:
            raise SystemExit(f"could not create the grant:\n{out.stdout}{out.stderr}")
        token = token_lines[0]

        url = f"http://127.0.0.1:{args.admin_port}/dashboard"
        print(f"\nDashboard : {url}\nAdmin token (type it into the page): {ADMIN_TOKEN}\n"
              f"Gateway   : http://127.0.0.1:{args.gateway_port}/mcp\nGrant     : created, token is passed to the agent\n")
        if not args.no_browser:
            webbrowser.open(url)
        if not args.no_pause:
            input("Connect the dashboard, then press Enter to start the agent ... ")

        approver = None
        if args.auto_approve:
            approver = subprocess.Popen([py, "-c", AUTO_APPROVER], env=env, cwd=ROOT)
        status = subprocess.run([py, str(ROOT / "demo" / "agent_demo.py"), "--token", token, "--url",
                                 f"http://127.0.0.1:{args.gateway_port}/mcp"], env=env, cwd=ROOT,
                                check=False).returncode
        if approver is not None:
            approver.wait(30)

        print("\n--- audit log check ---", flush=True)
        subprocess.run([py, "-m", "firewall.cli", "audit", "verify"], env=env, cwd=ROOT, check=False)
        if not args.no_pause:
            input("\nThe servers are still running for questions. Press Enter to stop them ... ")
    except (KeyboardInterrupt, EOFError):
        print("\nStopping ...")
    finally:
        stop(gateway)
        stop(admin)
        shutil.rmtree(tmp, ignore_errors=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
