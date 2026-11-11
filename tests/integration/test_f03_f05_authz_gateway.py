"""Authorization end to end through a real gateway (F03, F05, F06, F07, pipeline order)."""
import httpx
import pytest

from firewall import grants
from firewall.config import load_tools
from firewall.server import ConfigurationRefused
from tests.integration.conftest import ROOT, client_for

ALL = ["fs", "web", "mail", "notes"]


async def _g(gw, tools, **kw):
    return await grants.create_grant(gw.store, {"task": "t", "allowed_tools": tools, **kw}, registry=gw.engine.registry)


async def test_f03_no_grant_sees_no_tools_and_every_call_is_denied(make_gateway):
    gw, logs = await make_gateway(ALL)
    async with client_for(gw, None) as c:
        assert await c.list_tools() == []
        for tool in ("notes_read", "fs_delete_file", "totally_unknown"):
            r = await c.call_tool(tool, {}, raise_on_error=False)
            assert r.is_error and "code=NO_GRANT" in r.content[0].text, (tool, r.content[0].text)
    async with client_for(gw, "fwg_made_up_token") as c:
        assert await c.list_tools() == []
        r = await c.call_tool("notes_read", {"note_id": 1}, raise_on_error=False)
        assert "code=NO_GRANT" in r.content[0].text
    assert not (logs / "upstream_calls.jsonl").exists()  # nothing reached an upstream


async def test_f03_each_grant_sees_only_its_own_tools(make_gateway):
    gw, _ = await make_gateway(ALL)
    _, a = await _g(gw, ["notes_read", "fs_read_file"])
    _, b = await _g(gw, ["mail_send_email"])
    async with client_for(gw, a) as c:
        assert {t.name for t in await c.list_tools()} == {"notes_read", "fs_read_file"}
    async with client_for(gw, b) as c:
        assert {t.name for t in await c.list_tools()} == {"mail_send_email"}


async def test_f18_unknown_and_ungranted_tools_through_the_wire(make_gateway):
    gw, logs = await make_gateway(ALL)
    _, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        r = await c.call_tool("totally_unknown", {}, raise_on_error=False)
        assert "code=UNKNOWN_TOOL" in r.content[0].text
        r = await c.call_tool("mail_send_email", {"to": "a@b.example", "subject": "s", "body": "b"}, raise_on_error=False)
        assert "code=TOOL_NOT_GRANTED" in r.content[0].text
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert not r.is_error
    executed = (logs / "upstream_calls.jsonl").read_text().splitlines()
    assert len(executed) == 1 and "notes_read" in executed[0]
    # the agent-visible text carries only the code and the event id
    row = (await gw.store.query_audit(phase="call", verdict="deny", limit=1))[0]
    assert r is not None and row["reason_code"] == "TOOL_NOT_GRANTED"


async def test_f18_denial_text_is_generic_no_oracle(make_gateway):
    gw, _ = await make_gateway(ALL)
    _, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        r = await c.call_tool("mail_send_email", {"to": "a@b.example", "subject": "s", "body": "b"}, raise_on_error=False)
    row = (await gw.store.query_audit(phase="call", verdict="deny", limit=1))[0]
    assert r.content[0].text == f"Blocked by firewall. code=TOOL_NOT_GRANTED event=ev_{row['id']}"
    assert "mail_send_email" in row["detail"]  # the operator view has the detail, the agent does not


async def test_f06_revocation_takes_effect_on_the_next_call_over_http(make_gateway):
    gw, _ = await make_gateway(["notes"])
    g, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        assert not (await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)).is_error
        await grants.revoke(gw.store, g.id)
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert "code=GRANT_REVOKED" in r.content[0].text
        assert await c.list_tools() == []


async def test_f06_expired_and_exhausted_grants_over_http(make_gateway):
    gw, _ = await make_gateway(["notes"])
    g, tok = await _g(gw, ["notes_read"])
    await gw.store.set_grant_expiry(g.id, "2000-01-01T00:00:00+00:00")
    async with client_for(gw, tok) as c:
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert "code=GRANT_EXPIRED" in r.content[0].text
    _, tok2 = await _g(gw, ["notes_read"], max_calls=2)
    async with client_for(gw, tok2) as c:
        codes = []
        for _ in range(3):
            r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
            codes.append("ok" if not r.is_error else r.content[0].text.split("code=")[1].split()[0])
    assert codes == ["ok", "ok", "GRANT_EXHAUSTED"]


async def test_f07_policy_approval_requirement_holds_the_call_back(make_gateway):
    gw, logs = await make_gateway(["fs"])
    _, tok = await _g(gw, ["fs_delete_file"], allow_critical=True, allowed_paths=["./sandbox"])
    async with client_for(gw, tok) as c:
        r = await c.call_tool("fs_delete_file", {"path": "./sandbox/out/.keep"}, raise_on_error=False)
    assert r.is_error and "code=POLICY_APPROVAL" in r.content[0].text
    assert (logs.parent / "world" / "sandbox" / "out" / ".keep").exists()
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "require_approval" and row["rule_id"] == "rule_0"


async def test_f07_monitor_mode_shows_everything_and_forwards_but_records_would_deny(make_gateway):
    gw, logs = await make_gateway(ALL, mode="monitor")
    _, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        assert len(await c.list_tools()) == len(gw.tool_names)
        r = await c.call_tool("mail_send_email", {"to": "a@docs.example.com", "subject": "s", "body": "b"},
                              raise_on_error=False)
        assert not r.is_error
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "would_deny" and row["reason_code"] == "TOOL_NOT_GRANTED"
    assert (logs / "mail_log.jsonl").exists()


async def test_f05_gateway_refuses_to_start_when_an_upstream_tool_is_not_listed(make_gateway):
    tools = load_tools(ROOT / "tools.yaml")
    del tools.tools["notes_read"]
    with pytest.raises(ConfigurationRefused) as e:
        await make_gateway(["notes"], tools_cfg=tools)
    assert "notes_read" in str(e.value) and "tools.yaml" in str(e.value)


async def test_f05_unreviewed_tool_gets_restrictive_labels_and_a_startup_warning(make_gateway):
    tools = load_tools(ROOT / "tools.yaml")
    tools.tools["notes_read"].reviewed = False
    gw, _ = await make_gateway(["notes"], tools_cfg=tools)
    assert any("notes_read" in w and "not reviewed" in w for w in gw.warnings)
    assert gw.engine.registry.meta("notes_read").labels == ["private", "untrusted", "sink"]
    rows = [r for r in await gw.store.query_audit(phase="system", limit=10) if "startup warnings" in r["detail"]]
    assert rows and "notes_read" in rows[0]["detail"]


async def test_f17_the_gateway_port_exposes_no_admin_route(make_gateway):
    gw, _ = await make_gateway(["notes"])
    base = gw.url.rsplit("/mcp", 1)[0]
    async with httpx.AsyncClient(base_url=base) as h:
        for method, path in [("GET", "/grants"), ("POST", "/grants"), ("GET", "/approvals"), ("GET", "/health"),
                             ("POST", "/policy/test"), ("GET", "/audit"), ("GET", "/dashboard")]:
            r = await h.request(method, path, headers={"X-Admin-Token": "anything-anything-anything"})
            assert r.status_code in (404, 405), (method, path, r.status_code)


async def test_f03_filtered_out_tools_are_also_unreachable_by_direct_call(make_gateway):
    gw, logs = await make_gateway(ALL)
    _, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        names = {t.name for t in await c.list_tools()}
        assert "fs_read_file" not in names
        r = await c.call_tool("fs_read_file", {"path": "./sandbox/readme.txt"}, raise_on_error=False)
        assert "code=TOOL_NOT_GRANTED" in r.content[0].text
    assert not (logs / "upstream_calls.jsonl").exists()
