"""Phase 6 end to end: a risky call is held, shown to the operator, resumed or refused, and the audit chain stays valid."""
import asyncio
import json
import shutil

import httpx
import pytest_asyncio

from firewall import approvals, audit, grants
from firewall.admin_api import create_admin_app
from firewall.config import load_tools, load_upstreams
from firewall.server import build_gateway
from tests.integration.conftest import FIXTURE_WORLD, ROOT, client_for, relaxed_policy

KEY = "integration-approval-key-0123"
TOKEN = "integration-admin-token-0123"
H = {"X-Admin-Token": TOKEN}
TOOLS = ["notes_read", "web_fetch", "mail_send_email"]
MAIL = {"to": "team@docs.example.com", "subject": "status", "body": "A short status update for the team."}


@pytest_asyncio.fixture
async def env(tmp_path):
    started = []

    async def make(approval_mode="block", timeout_s=2):
        world, logs = tmp_path / "world", tmp_path / "logs"
        if not world.exists():
            shutil.copytree(FIXTURE_WORLD, world)
        logs.mkdir(exist_ok=True)
        specs = [u for u in load_upstreams(ROOT / "upstreams.yaml").upstreams if u.name in ("web", "mail", "notes")]
        cp = tmp_path / "fw.checkpoints"
        gw = await build_gateway(
            db_path=str(tmp_path / "fw.db"), upstreams=specs, mode="enforce", tools=load_tools(ROOT / "tools.yaml"),
            path_base=world, policy=relaxed_policy(approval_mode=approval_mode, approval_timeout_s=timeout_s),
            approval_key=KEY, checkpoint_path=str(cp), env_extra={"FW_WORLD": str(world), "FW_LOG_DIR": str(logs)})
        await gw.start()
        started.append(gw)
        app = create_admin_app(gw.store, gw.engine.registry, gw.engine.policy, TOKEN, gw.engine.mode,
                               approval_crypto=approvals.ApprovalCrypto(KEY), checkpoint_path=str(cp))
        admin = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://admin", headers=H)
        started.append(admin)
        _, tok = await grants.create_grant(
            gw.store, {"task": "t", "allowed_tools": TOOLS, "allowed_destinations": ["docs.example.com"],
                       "max_calls": 20}, registry=gw.engine.registry)
        return gw, admin, tok, logs, cp

    yield make
    for x in reversed(started):
        await (x.aclose() if isinstance(x, httpx.AsyncClient) else x.stop())


def code_of(r):
    text = r.content[0].text
    return text.split("code=")[1].split()[0] if r.is_error and "code=" in text else None


async def taint(c):
    await c.call_tool("notes_read", {"note_id": 1}, raise_on_error=False)
    await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)


async def first_pending(admin):
    for _ in range(150):
        rows = (await admin.get("/approvals", params={"status": "pending"})).json()
        if rows:
            return rows[0]
        await asyncio.sleep(0.04)
    raise AssertionError("no approval appeared")


def sent(logs):
    p = logs / "mail_log.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


async def test_f16_a_held_call_shows_its_content_then_resumes_after_approval(env):
    gw, admin, tok, logs, cp = await env(timeout_s=20)
    async with client_for(gw, tok) as c:
        await taint(c)
        call = asyncio.create_task(c.call_tool("mail_send_email", MAIL, raise_on_error=False))
        row = await first_pending(admin)
        assert not call.done() and sent(logs) == []  # held, nothing was sent
        assert row["tool"] == "mail_send_email" and "TRIFECTA_APPROVAL" in row["reason_codes"]
        assert MAIL["body"] in row["preview"]["preview"] and row["preview"]["destination"] == "docs.example.com"
        r = await admin.post(f"/approvals/{row['id']}/decision", json={"decision": "approve", "scope": "once"})
        assert r.status_code == 200
        res = await asyncio.wait_for(call, 20)
        assert not res.is_error
        assert [m["body"] for m in sent(logs)] == [MAIL["body"]]
        # the approval was single use: the same call needs a new decision
        again = asyncio.create_task(c.call_tool("mail_send_email", MAIL, raise_on_error=False))
        row2 = await first_pending(admin)
        assert row2["id"] != row["id"]
        await admin.post(f"/approvals/{row2['id']}/decision", json={"decision": "deny", "scope": "once"})
        assert code_of(await asyncio.wait_for(again, 20)) == "APPROVAL_DENIED"
    assert len(sent(logs)) == 1
    stored = (await admin.get("/approvals", params={"status": "approved"})).json()
    assert stored and "preview" not in stored[0]  # decided rows no longer carry the arguments


async def test_f16_a_call_nobody_decides_times_out_and_forwards_nothing(env):
    gw, admin, tok, logs, _ = await env(timeout_s=1)
    async with client_for(gw, tok) as c:  # the client's own timeout is far longer than the policy timeout
        await taint(c)
        res = await asyncio.wait_for(c.call_tool("mail_send_email", MAIL, raise_on_error=False), 30)
        assert code_of(res) == "APPROVAL_TIMEOUT"
    assert sent(logs) == []
    assert (await admin.get("/approvals", params={"status": "pending"})).json() == []


async def test_f16_deferred_mode_returns_the_id_and_the_retry_goes_through(env):
    gw, admin, tok, logs, _ = await env(approval_mode="defer")
    async with client_for(gw, tok) as c:
        await taint(c)
        first = await c.call_tool("mail_send_email", MAIL, raise_on_error=False)
        assert code_of(first) == "APPROVAL_PENDING"
        row = await first_pending(admin)
        assert row["id"] in first.content[0].text
        dup = await c.call_tool("mail_send_email", MAIL, raise_on_error=False)
        assert code_of(dup) == "APPROVAL_PENDING"
        assert len((await admin.get("/approvals", params={"status": "pending"})).json()) == 1  # no second row
        await admin.post(f"/approvals/{row['id']}/decision", json={"decision": "approve", "scope": "once"})
        assert not (await c.call_tool("mail_send_email", MAIL, raise_on_error=False)).is_error
    assert len(sent(logs)) == 1


async def test_f16_an_exfiltration_attempt_is_a_hard_deny_and_creates_no_approval(env):
    gw, admin, tok, logs, _ = await env()
    async with client_for(gw, tok) as c:
        note = (await c.call_tool("notes_read", {"note_id": 1}, raise_on_error=False)).content[0].text
        await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        res = await c.call_tool("mail_send_email", {**MAIL, "body": note}, raise_on_error=False)
        assert code_of(res) in ("EXFIL_FLOW", "SECRET_IN_ARGS")
    assert (await admin.get("/approvals")).json() == [] and sent(logs) == []


async def test_f20_the_chain_verifies_after_a_run_and_the_checkpoint_file_is_written(env):
    gw, admin, tok, logs, cp = await env(timeout_s=1)
    async with client_for(gw, tok) as c:
        await taint(c)
        await c.call_tool("mail_send_email", MAIL, raise_on_error=False)  # ends in APPROVAL_TIMEOUT
    r = (await admin.get("/audit/verify")).json()
    assert r["ok"] and r["rows"] >= 5 and r["checkpoints_checked"] >= 1
    assert cp.exists() and json.loads(cp.read_text().splitlines()[0])["reason"] == "start"
    # tampering with one stored row is detected through the same endpoint
    await gw.store._run("UPDATE audit SET tool='tampered' WHERE id=2")
    assert (await admin.get("/audit/verify")).json()["ok"] is False
    assert (await audit.verify_chain(gw.store, str(cp)))['first_bad_id'] == 2
