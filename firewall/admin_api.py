"""Admin API (F17): grants, approvals, policy dry-run and audit view. Separate port, 127.0.0.1 only.

Run with: FW_ADMIN_TOKEN=<16+ chars> uv run python -m firewall.admin_api
The agent can reach only the gateway port; this app is never mounted on it.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import sys
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from firewall import approvals, audit, grants, policy, sessions
from firewall.config import PolicyConfig, config_version, load_policy, load_tools
from firewall.models import GrantState
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
DASHBOARD_FILES = ("index.html", "app.js", "style.css")
# No inline script or style, no external hosts, no framing, no form posts: the page can only talk to its own origin.
DASHBOARD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
                 "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
MIN_TOKEN_LEN = 16
FAIL_LIMIT = 5
FAIL_WINDOW_S = 60.0
LOCKOUT_S = 60.0


class AdminConfigError(Exception):
    """The admin API refuses to start (token missing or too short)."""


class LoginLimiter:
    """F34: five failed attempts within a minute lock the API for 60 seconds (ADMIN_LOCKOUT)."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._fails: deque[float] = deque()
        self._locked_until = 0.0

    def locked(self) -> bool:
        return self._clock() < self._locked_until

    def record_failure(self) -> None:
        now = self._clock()
        self._fails.append(now)
        while self._fails and now - self._fails[0] > FAIL_WINDOW_S:
            self._fails.popleft()
        if len(self._fails) >= FAIL_LIMIT:
            self._locked_until = now + LOCKOUT_S
            self._fails.clear()

    def record_success(self) -> None:
        self._fails.clear()


class GrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: str = ""
    allowed_tools: list[str]
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    max_calls: int = 30
    max_sessions: int = 2
    ttl_seconds: int = 3600
    approval_required_for: list[str] = Field(default_factory=list)
    allow_critical: bool = False


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "deny"]
    scope: Literal["once", "destination"] = "once"


class PolicyTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    args: dict = Field(default_factory=dict)
    labels_seen: list[Literal["private", "untrusted"]] = Field(default_factory=list)


def check_admin_token(token: str | None) -> str:
    if not token or len(token) < MIN_TOKEN_LEN:
        raise AdminConfigError(f"FW_ADMIN_TOKEN must be set and at least {MIN_TOKEN_LEN} characters long")
    return token


def create_admin_app(store: Store, registry: Registry, policy_cfg: PolicyConfig, admin_token: str | None,
                     mode: str = "enforce", version: str = "", operator: str = "operator",
                     limiter: LoginLimiter | None = None, approval_crypto: approvals.ApprovalCrypto | None = None,
                     checkpoint_path: str | None = None) -> FastAPI:
    token = check_admin_token(admin_token)
    limiter = limiter or LoginLimiter()
    app = FastAPI(title="Agent Firewall admin", docs_url=None, redoc_url=None, openapi_url=None)
    assets = {name: (DASHBOARD_DIR / name).read_text(encoding="utf-8") for name in DASHBOARD_FILES}

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        """No CORS headers are ever added. Dashboard pages get a strict Content-Security-Policy (no inline script,
        no external hosts); everything else may not be framed or sniffed."""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            DASHBOARD_CSP if request.url.path.startswith("/dashboard") else "default-src 'none'; frame-ancestors 'none'")
        return response

    async def admin_audit(action: str, grant_id: str | None = None, **detail) -> None:
        await audit.write(store, {"phase": "admin", "verdict": "allow", "tool": action, "grant_id": grant_id,
                                  "detail": {"operator": operator, **detail}, "mode": mode})

    async def require_admin(request: Request) -> None:
        if limiter.locked():
            raise HTTPException(429, {"error": "ADMIN_LOCKOUT"})
        supplied = request.headers.get("x-admin-token", "")
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            limiter.record_failure()
            if limiter.locked():
                await audit.write(store, {"phase": "system", "verdict": "deny", "reason_code": "ADMIN_LOCKOUT",
                                          "detail": {"message": "too many failed admin attempts"}, "mode": mode})
            raise HTTPException(401, {"error": "unauthorized"})
        limiter.record_success()

    auth = [Depends(require_admin)]

    def grant_view(g) -> dict:
        return asdict(g)  # never contains the token or its hash, only the masked prefix

    async def effective_mode() -> str:
        """The mode the gateway actually runs in (it records it in the shared database at startup)."""
        return await store.get_runtime("mode") or mode

    @app.get("/health", dependencies=auth)
    async def health():
        m = await effective_mode()
        return {"status": "ok", "mode": m, "monitor_banner": m == "monitor", "config_version": version,
                "approvals_enabled": bool(await store.get_runtime("approvals_enabled")),
                "approval_mode": await store.get_runtime("approval_mode"),
                "selftest": await store.get_runtime("selftest")}

    @app.post("/grants", dependencies=auth, status_code=201)
    async def create_grant(body: GrantRequest):
        try:
            g, tok = await grants.create_grant(store, body.model_dump(), created_by=operator, registry=registry)
        except grants.GrantError as exc:
            raise HTTPException(422, {"error": str(exc)}) from None
        await admin_audit("POST /grants", g.id, task=g.task, tools=g.allowed_tools, max_calls=g.max_calls)
        return {**grant_view(g), "token": tok, "note": "the token is shown once; only its hash is stored"}

    @app.get("/grants", dependencies=auth)
    async def list_grants():
        out = []
        for g in (await grants.list_grants(store))[:200]:
            st = await sessions.load_state(store, g.id)
            out.append({**grant_view(g), "suspended": st.suspended, "suspicious": st.suspicious,
                        "labels": sorted(st.labels)})
        return out

    @app.get("/grants/{grant_id}", dependencies=auth)
    async def get_grant(grant_id: str):
        g = await grants.get_grant(store, grant_id)
        if g is None:
            raise HTTPException(404, {"error": "grant not found"})
        state = await _state(grant_id)
        return {**grant_view(g), "state": state}

    async def _state(grant_id: str) -> dict:
        s = await sessions.load_state(store, grant_id)
        return {"labels": sorted(s.labels), "suspicious": s.suspicious, "suspended": s.suspended,
                "denied_streak": s.denied_streak, "call_count": s.call_count}

    @app.delete("/grants/{grant_id}", dependencies=auth)
    async def revoke_grant(grant_id: str):
        if await grants.get_grant(store, grant_id) is None:
            raise HTTPException(404, {"error": "grant not found"})
        await grants.revoke(store, grant_id)  # idempotent: revoking a revoked grant is fine
        await admin_audit("DELETE /grants", grant_id)
        return {"id": grant_id, "status": "revoked"}

    @app.post("/grants/{grant_id}/resume", dependencies=auth)
    async def resume_grant(grant_id: str):
        if not await grants.resume(store, grant_id):
            raise HTTPException(404, {"error": "grant not found"})
        await admin_audit("POST /grants/resume", grant_id)
        return {"id": grant_id, "suspended": False}

    @app.get("/approvals", dependencies=auth)
    async def list_approvals(status: str | None = None, limit: int = 100):
        await store.sweep_expired_approvals(iso(utcnow()))  # expired rows lose their stored arguments here too
        rows = await store.list_approvals(status, min(max(limit, 1), 1000), with_args=True)
        out = []
        for r in rows:
            view = {k: v for k, v in r.items() if k != "args_encrypted"}
            view["reason_codes"] = json.loads(r["reason_codes"] or "[]")
            view["detail"] = json.loads(r.get("detail") or "{}")
            if r["status"] == "pending":
                view["preview"] = approvals.preview(approval_crypto, r)
            out.append(view)
        return out

    @app.post("/approvals/{approval_id}/decision", dependencies=auth)
    async def decide(approval_id: str, body: DecisionRequest):
        outcome = await store.decide_approval(approval_id, body.decision, body.scope, operator, iso(utcnow()))
        if outcome == "not_found":
            raise HTTPException(404, {"error": "approval not found"})
        if outcome == "no_destination":
            raise HTTPException(422, {"error": "scope 'destination' needs a call with exactly one destination"})
        if outcome in ("conflict", "expired"):
            raise HTTPException(409, {"error": "approval already decided" if outcome == "conflict" else "approval expired"})
        await admin_audit("POST /approvals/decision", None, approval_id=approval_id, decision=body.decision,
                          scope=body.scope)
        return {"id": approval_id, "status": "approved" if body.decision == "approve" else "denied"}

    @app.get("/sessions", dependencies=auth)
    async def list_sessions():
        return (await store.list_sessions())[:200]

    @app.get("/audit/verify", dependencies=auth)
    async def verify_audit():
        return await audit.verify_chain(store, checkpoint_path)

    # The dashboard files are static and contain no data, so they need no token (a browser cannot send a custom
    # header when it loads a page). Every data route above still requires X-Admin-Token.
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return HTMLResponse(assets["index.html"])

    @app.get("/dashboard/app.js")
    async def dashboard_js():
        return Response(assets["app.js"], media_type="text/javascript")

    @app.get("/dashboard/style.css")
    async def dashboard_css():
        return Response(assets["style.css"], media_type="text/css")
    @app.get("/pins", dependencies=auth)
    async def list_pins():
        pins = await store.list_pins()
        for p in pins:
            p["reasons"] = json.loads(p["reasons"] or "[]")
        return pins

    @app.post("/pins/{upstream}/{tool}/approve", dependencies=auth)
    async def approve_pin(upstream: str, tool: str):
        if not await store.approve_pin(upstream, tool, iso(utcnow())):
            raise HTTPException(404, {"error": "pin not found"})
        await admin_audit("POST /pins/approve", None, upstream=upstream, tool=tool)
        return {"upstream": upstream, "tool": tool, "state": "approved_change"}

    @app.post("/policy/test", dependencies=auth)
    async def policy_test(body: PolicyTestRequest):
        meta = registry.meta(body.tool)
        if meta is None:
            raise HTTPException(404, {"error": f"unknown tool {body.tool!r}"})
        state = GrantState(grant_id="dry-run", labels=set(body.labels_seen))
        v = policy.evaluate(policy_cfg.rules, meta, state, body.args)
        if v is None:
            return {"verdict": "allow", "reason_codes": [], "rule_id": None,
                    "note": "no policy rule matched (grant scope and inspection steps are not part of this test)"}
        return {"verdict": v.action, "reason_codes": v.reason_codes, "rule_id": v.rule_id}

    @app.get("/audit", dependencies=auth)
    async def query_audit(grant: str | None = None, verdict: str | None = None, limit: int = 100):
        return await store.query_audit(grant, verdict, None, min(max(limit, 1), 1000))

    return app


async def amain() -> None:
    port = int(os.environ.get("FW_ADMIN_PORT", "8801"))
    try:
        policy_cfg = load_policy(ROOT / "policy.yaml")
        registry = Registry(load_tools(ROOT / "tools.yaml"))
        db = os.environ.get("FW_DB_PATH", "./fw.db")
        store = await Store(db).open()
        mode = os.environ.get("FW_MODE") or policy_cfg.defaults.mode
        key = os.environ.get("FW_APPROVAL_KEY")
        crypto = approvals.ApprovalCrypto(key) if key else None  # without it the preview of pending calls is unavailable
        app = create_admin_app(store, registry, policy_cfg, os.environ.get("FW_ADMIN_TOKEN"), mode,
                               config_version(ROOT / "policy.yaml", ROOT / "tools.yaml", ROOT / "upstreams.yaml"),
                               approval_crypto=crypto,
                               checkpoint_path=os.environ.get("FW_AUDIT_CHECKPOINT") or audit.checkpoint_path_for(db))
    except Exception as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    print(f"admin API on http://127.0.0.1:{port}", flush=True)
    await server.serve()
    await store.close()


if __name__ == "__main__":
    asyncio.run(amain())
