import asyncio
import json

from firewall import grants
from tests.integration.conftest import client_for, crashy_upstream

ALL_DEMO_TOOLS = ["fs_read_file", "web_fetch", "mail_send_email", "notes_read"]


async def _grant(gw, tools=None, **spec):
    g, token = await grants.create_grant(gw.store, {
        "task": "t", "allowed_tools": tools or ALL_DEMO_TOOLS, "allowed_paths": ["./sandbox"],
        "allowed_destinations": ["docs.example.com"], **spec})
    return g, token


async def test_f01_lists_namespaced_tools_and_calls_each(make_gateway):
    gw, logs = await make_gateway(["fs", "web", "mail", "notes"])
    assert {"fs_read_file", "web_fetch", "mail_send_email", "notes_read"} <= set(gw.tool_names)
    _, token = await _grant(gw)
    async with client_for(gw, token) as c:
        names = {t.name for t in await c.list_tools()}
        assert {"fs_read_file", "web_fetch", "mail_send_email", "notes_read"} <= names
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert "Team lunch" in r.content[0].text
        r = await c.call_tool("fs_read_file", {"path": "./sandbox/readme.txt"}, raise_on_error=False)
        assert "Sandbox readme" in r.content[0].text
        # mail before web: once private data and untrusted web content have both been seen, a send needs approval
        r = await c.call_tool("mail_send_email", {"to": "a@docs.example.com", "subject": "s", "body": "b"},
                              raise_on_error=False)
        assert "queued" in r.content[0].text
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert "Getting Started" in r.content[0].text
    executed = [json.loads(line)["tool"] for line in (logs / "upstream_calls.jsonl").read_text().splitlines()]
    assert executed == ["notes_read", "fs_read_file", "mail_send_email", "web_fetch"]


async def test_f01_dead_upstream_gives_upstream_error(make_gateway):
    gw, _ = await make_gateway(["notes"], extra=(crashy_upstream(),))
    _, token = await _grant(gw, ["crash_boom", "notes_read"])
    async with client_for(gw, token) as c:
        r = await c.call_tool("crash_boom", {}, raise_on_error=False)
        assert r.is_error and "code=UPSTREAM_ERROR" in r.content[0].text
        # other upstreams keep working
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert "Team lunch" in r.content[0].text
    rows = await gw.store.query_audit(phase="result", limit=50)
    assert any(r["reason_code"] == "UPSTREAM_ERROR" and r["verdict"] == "deny" for r in rows)


async def test_f01_slow_upstream_gives_upstream_timeout(make_gateway):
    gw, _ = await make_gateway([], extra=(crashy_upstream(timeout_s=1.0),))
    _, token = await _grant(gw, ["crash_slow"])
    async with client_for(gw, token) as c:
        r = await asyncio.wait_for(c.call_tool("crash_slow", {}, raise_on_error=False), 20)
        assert r.is_error and "code=UPSTREAM_TIMEOUT" in r.content[0].text


async def test_f01_resources_and_prompts_disabled(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, token = await _grant(gw)
    async with client_for(gw, token) as c:
        assert await c.list_resources() == []
        assert await c.list_prompts() == []
