"""Starts the firewall gateway in-process for evaluation runs and issues scenario grants."""
from __future__ import annotations

from eval.backends import LOGS, ROOT, RUNTIME, WORLD, GatewayBackend, upstream_specs
from eval.scenario import Scenario
from firewall import grants
from firewall.config import ToolEntry, load_tools
from firewall.server import Gateway, build_gateway


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
        self._gw = await build_gateway(
            db_path=str(db), upstreams=upstream_specs(scn), mode=self.mode, tools=tools, path_base=WORLD,
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
        return GatewayBackend(scn, gw.url, token, gw.store, grant.id), gw, grant.id

    async def stop(self) -> None:
        if self._gw is not None:
            await self._gw.stop()
            self._gw = None
