"""Starts the firewall gateway in-process for evaluation runs and issues scenario grants."""
from __future__ import annotations

import asyncio

import httpx

from eval.backends import LOGS, ROOT, RUNTIME, WORLD, GatewayBackend, upstream_specs
from eval.scenario import Scenario
from firewall import approvals, grants
from firewall.admin_api import create_admin_app
from firewall.config import ToolEntry, load_policy, load_tools
from firewall.server import Gateway, build_gateway

APPROVAL_KEY = "eval-approval-key-0123456789"
ADMIN_TOKEN = "eval-admin-token-0123456789"
EVAL_APPROVAL_TIMEOUT_S = 4  # nobody approves attack scenarios, so a held call gives up quickly instead of after 60 s


class AutoApprover:
    """Plays the operator for benign scenarios marked auto_approve: it polls the pending approvals and approves
    each one through the admin API (in-process), exactly as a person using the CLI or dashboard would."""

    def __init__(self, gw: Gateway):
        app = create_admin_app(gw.store, gw.engine.registry, gw.engine.policy, ADMIN_TOKEN, gw.engine.mode,
                               approval_crypto=approvals.ApprovalCrypto(APPROVAL_KEY), operator="eval-operator")
        self._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://admin",
                                         headers={"X-Admin-Token": ADMIN_TOKEN})
        self._task: asyncio.Task | None = None
        self.approved: list[str] = []

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while True:
            for row in (await self._client.get("/approvals", params={"status": "pending"})).json():
                r = await self._client.post(f"/approvals/{row['id']}/decision", json={"decision": "approve", "scope": "once"})
                if r.status_code == 200:
                    self.approved.append(row["id"])
            await asyncio.sleep(0.1)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self._client.aclose()


class GatewayManager:
    """One gateway per mode. Scenarios with a malicious-upstream variant get a fresh gateway for
    every run, because the rug-pull listing counter must start from the gateway's first listing."""

    def __init__(self, mode: str):
        self.mode = mode
        self._gw: Gateway | None = None
        self._variant: str | None = None

    async def _fresh(self, scn: Scenario) -> Gateway:
        await self.stop()
        RUNTIME.mkdir(parents=True, exist_ok=True)
        db = RUNTIME / f"fw-{self.mode}.db"
        for suffix in ("", "-wal", "-shm"):
            (RUNTIME / f"{db.name}{suffix}").unlink(missing_ok=True)
        self._variant = scn.variant
        tools = load_tools(ROOT / "tools.yaml")
        if scn.variant == "shadow":  # the operator did not notice the look-alike tool: listed but never reviewed
            tools.tools["fs_read_flle"] = ToolEntry(labels=[], risk="low", reviewed=False)
        policy = load_policy(ROOT / "policy.yaml")
        policy.defaults.approval_timeout_s = EVAL_APPROVAL_TIMEOUT_S
        self._gw = await build_gateway(
            db_path=str(db), upstreams=upstream_specs(scn), mode=self.mode, tools=tools, path_base=WORLD,
            policy=policy, approval_key=APPROVAL_KEY, checkpoint_path=str(RUNTIME / f"fw-{self.mode}.checkpoints"),
            env_extra={"FW_WORLD": str(WORLD), "FW_LOG_DIR": str(LOGS)},
        )
        await self._gw.start()
        return self._gw

    async def backend_for(self, scn: Scenario) -> tuple[GatewayBackend, Gateway, str]:
        """Call after reset_environment(). Returns (backend, gateway, grant id)."""
        reuse = self._gw is not None and self._variant is None and scn.variant is None
        gw = self._gw if reuse else await self._fresh(scn)
        spec = {"task": scn.id, **scn.grant}
        expired = spec.pop("expired", False)  # harness-only: build a grant that is already past its expiry
        grant, token = await grants.create_grant(gw.store, spec, created_by="eval-runner", registry=gw.engine.registry)
        if expired:
            await gw.store.set_grant_expiry(grant.id, "2000-01-01T00:00:00+00:00")
        approver = AutoApprover(gw) if scn.auto_approve and self.mode == "enforce" else None
        return GatewayBackend(scn, gw.url, token, gw.store, grant.id, approver), gw, grant.id

    async def stop(self) -> None:
        if self._gw is not None:
            await self._gw.stop()
            self._gw = None
