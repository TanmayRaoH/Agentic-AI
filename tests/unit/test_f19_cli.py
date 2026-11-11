"""CLI smoke tests (F19) against a real admin API served over HTTP."""
import asyncio
import re
import socket
from pathlib import Path

import pytest
import pytest_asyncio
import uvicorn

from firewall import cli, grants
from firewall.admin_api import create_admin_app
from firewall.config import load_policy, load_tools
from firewall.registry import Registry
from firewall.store import Store, iso, utcnow

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "cli-admin-token-0123456"


@pytest_asyncio.fixture
async def admin(tmp_path, monkeypatch):
    store = await Store(tmp_path / "c.db").open()
    app = create_admin_app(store, Registry(load_tools(ROOT / "tools.yaml")), load_policy(ROOT / "policy.yaml"), TOKEN)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    monkeypatch.setenv("FW_ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("FW_ADMIN_URL", f"http://127.0.0.1:{port}")
    yield store, port
    server.should_exit = True
    await task
    await store.close()


async def run_cli(*argv):
    # the CLI is synchronous (httpx.Client), so run it off the loop that serves the API
    return await asyncio.to_thread(cli.main, list(argv))


async def test_f19_grant_create_list_revoke(admin, capsys):
    store, _ = admin
    assert await run_cli("grant", "create", "--task", "demo", "--tools", "notes_read", "fs_read_file",
                         "--max-calls", "7") == 0
    out = capsys.readouterr().out
    token = re.search(r"token\s+: (\S+)", out).group(1)
    gid = re.search(r"grant id : (\S+)", out).group(1)
    assert token.startswith("fwg_")
    assert (await grants.resolve(store, token)).max_calls == 7

    await run_cli("grant", "list")
    listing = capsys.readouterr().out
    assert gid in listing and "notes_read" in listing and "active" in listing
    assert token not in listing  # only the masked prefix is ever listed

    await run_cli("grant", "revoke", gid)
    assert '"revoked"' in capsys.readouterr().out
    assert (await grants.resolve(store, token)).status == "revoked"


async def test_f19_grant_create_errors_are_readable(admin, capsys):
    with pytest.raises(SystemExit) as e:
        await run_cli("grant", "create", "--tools", "no_such_tool")
    assert e.value.code == 1
    assert "no_such_tool" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        await run_cli("grant", "create", "--tools", "fs_delete_file")
    assert "allow_critical" in capsys.readouterr().err
    assert await run_cli("grant", "create", "--tools", "fs_delete_file", "--allow-critical") == 0


async def test_f19_approvals_list_approve_deny(admin, capsys):
    store, _ = admin
    for aid in ("ap_a", "ap_b"):
        await store.insert_approval({"id": aid, "grant_id": "g_1", "tool": "mail_send_email", "args_hash": "h",
                                     "reason_codes": ["TRIFECTA_APPROVAL"], "destination": "docs.example.com", "created_at": iso(utcnow()),
                                     "expires_at": "2099-01-01T00:00:00+00:00"})
    await run_cli("approvals", "list")
    out = capsys.readouterr().out
    assert "ap_a" in out and "ap_b" in out and "TRIFECTA_APPROVAL" in out
    await run_cli("approve", "ap_a", "--scope", "destination")
    assert '"approved"' in capsys.readouterr().out
    await run_cli("deny", "ap_b")
    assert '"denied"' in capsys.readouterr().out
    await run_cli("approvals", "list")
    assert "no approvals" in capsys.readouterr().out
    with pytest.raises(SystemExit):  # second decision -> 409
        await run_cli("approve", "ap_a")
    assert "409" in capsys.readouterr().err


async def test_f19_wrong_token_and_missing_token_and_unreachable(admin, capsys, monkeypatch):
    monkeypatch.setenv("FW_ADMIN_TOKEN", "wrong-token-wrong-token")
    with pytest.raises(SystemExit) as e:
        await run_cli("grant", "list")
    assert e.value.code == 1 and "401" in capsys.readouterr().err
    monkeypatch.delenv("FW_ADMIN_TOKEN")
    with pytest.raises(SystemExit) as e:
        await run_cli("grant", "list")
    assert e.value.code == 2 and "FW_ADMIN_TOKEN" in capsys.readouterr().err
    monkeypatch.setenv("FW_ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("FW_ADMIN_URL", "http://127.0.0.1:1")
    with pytest.raises(SystemExit) as e:
        await run_cli("grant", "list")
    assert e.value.code == 1 and "cannot reach" in capsys.readouterr().err


async def test_f19_pins_list_and_approve(admin, capsys):
    store, _ = admin
    await store.observe_pin("web", "web_fetch", "h1", "Fetch.", [], "2026-01-01T00:00:00+00:00")
    await store.observe_pin("web", "web_fetch", "h2", "Fetch. changed", ["instruction pattern: hide_from_user"],
                            "2026-01-02T00:00:00+00:00")
    await run_cli("pins", "list")
    out = capsys.readouterr().out
    assert "web_fetch" in out and "changed" in out and "hide_from_user" in out
    await run_cli("pins", "approve", "web", "web_fetch")
    assert "approved_change" in capsys.readouterr().out
    await run_cli("pins", "list")
    assert "approved_change" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        await run_cli("pins", "approve", "web", "missing_tool")
    assert "404" in capsys.readouterr().err
