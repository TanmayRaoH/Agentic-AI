import json

from firewall import grants
from tests.integration.conftest import client_for

SECRET_ARG = "CANARY-7f3a91-super-secret-body"


async def test_f20_every_call_writes_exactly_one_call_row(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _g, token = await grants.create_grant(gw.store, {"task": "a", "allowed_tools": ["notes_read"], "max_calls": 2})
    async with client_for(gw, token) as c:
        for i in range(3):  # third call exceeds max_calls
            await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    async with client_for(gw, None) as c:  # no grant at all
        await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    calls = await gw.store.query_audit(phase="call", limit=100)
    assert len(calls) == 4
    assert sorted(r["verdict"] for r in calls) == ["allow", "allow", "deny", "deny"]
    assert {r["reason_code"] for r in calls if r["verdict"] == "deny"} == {"GRANT_EXHAUSTED", "NO_GRANT"}
    assert len(await gw.store.query_audit(phase="result", limit=100)) == 2  # only forwarded calls get a result row


async def test_f20_audit_never_stores_raw_args_or_full_token(make_gateway):
    gw, _ = await make_gateway(["mail"])
    _, token = await grants.create_grant(gw.store, {"task": "a", "allowed_tools": ["mail_send_email"]})
    async with client_for(gw, token) as c:
        await c.call_tool("mail_send_email", {"to": "a@docs.example.com", "subject": "s", "body": SECRET_ARG},
                          raise_on_error=False)
    dump = json.dumps(await gw.store.query_audit(limit=100))
    assert SECRET_ARG not in dump
    assert token not in dump
    assert "7f3a91-super" not in dump


async def test_f20_agent_sees_only_code_and_event_id(make_gateway):
    gw, _ = await make_gateway(["notes"])
    async with client_for(gw, None) as c:
        r = await c.call_tool("notes_read", {"note_id": 1}, raise_on_error=False)
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert r.is_error
    assert r.content[0].text == f"Blocked by firewall. code=NO_GRANT event=ev_{row['id']}"


async def test_f02_third_active_session_is_denied(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, token = await grants.create_grant(gw.store, {"task": "s", "allowed_tools": ["notes_read"], "max_sessions": 2})
    outcomes = []
    clients = [client_for(gw, token) for _ in range(3)]
    for c in clients:
        await c.__aenter__()
    try:
        for c in clients:
            r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
            outcomes.append(r.content[0].text)
        # the two admitted sessions can keep going
        r = await clients[0].call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
        assert not r.is_error
    finally:
        for c in clients:
            await c.__aexit__(None, None, None)
    assert "Team lunch" in outcomes[0] and "Team lunch" in outcomes[1]
    assert "code=TOO_MANY_SESSIONS" in outcomes[2]


async def test_f02_default_session_fallback_warns_once_per_process(make_gateway):
    gw, _ = await make_gateway(["notes"])
    await gw.engine.warn_default_session()
    await gw.engine.warn_default_session()
    rows = [r for r in await gw.store.query_audit(phase="system", limit=10) if "default-session" in r["detail"]]
    assert len(rows) == 1


async def test_f01_monitor_mode_records_would_deny_and_forwards(make_gateway):
    gw, logs = await make_gateway(["notes"], mode="monitor")
    async with client_for(gw, None) as c:  # no grant: would be NO_GRANT
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    assert not r.is_error and "Team lunch" in r.content[0].text
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "would_deny" and row["reason_code"] == "NO_GRANT"
    assert (logs / "upstream_calls.jsonl").exists()


async def test_f02_stateless_era_client_is_one_session_not_one_per_request(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, token = await grants.create_grant(gw.store, {"task": "s", "allowed_tools": ["notes_read"], "max_sessions": 1})
    async with client_for(gw, token, legacy=False) as c:
        for _ in range(4):
            r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
            assert not r.is_error
    sids = {r["session_id"] for r in await gw.store.query_audit(phase="call", limit=10)}
    assert len(sids) == 1 and next(iter(sids)).startswith("stateless:")
    warns = [r for r in await gw.store.query_audit(phase="system", limit=10) if "no MCP session" in r["detail"]]
    assert len(warns) == 1


async def test_f02_legacy_client_has_stable_session_id(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, token = await grants.create_grant(gw.store, {"task": "s", "allowed_tools": ["notes_read"]})
    async with client_for(gw, token) as c:
        for _ in range(3):
            await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    sids = {r["session_id"] for r in await gw.store.query_audit(phase="call", limit=10)}
    assert len(sids) == 1 and not next(iter(sids)).startswith("stateless:")


async def test_f02_task_grant_query_parameter_fallback(make_gateway):
    from fastmcp.client import Client
    from fastmcp.client.transports import StreamableHttpTransport

    gw, _ = await make_gateway(["notes"])
    _, token = await grants.create_grant(gw.store, {"task": "q", "allowed_tools": ["notes_read"]})
    async with Client(StreamableHttpTransport(f"{gw.url}?task_grant={token}"), mode="legacy") as c:
        r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    assert not r.is_error and "Team lunch" in r.content[0].text
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "allow" and row["grant_id"]


async def test_f02_two_grants_from_same_stateless_client_do_not_collide(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, t1 = await grants.create_grant(gw.store, {"task": "a", "allowed_tools": ["notes_read"], "max_sessions": 1})
    _, t2 = await grants.create_grant(gw.store, {"task": "b", "allowed_tools": ["notes_read"], "max_sessions": 1})
    for tok in (t1, t2):
        async with client_for(gw, tok, legacy=False) as c:
            r = await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
            assert not r.is_error, r.content[0].text