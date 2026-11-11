"""F39: server-initiated sampling and elicitation requests are refused and audited, never relayed."""
from fastmcp.client import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.client.transports import StreamableHttpTransport

from firewall import grants
from tests.integration.conftest import crashy_upstream


async def test_f39_sampling_and_elicitation_from_an_upstream_never_reach_the_agent(make_gateway):
    gw, _ = await make_gateway([], extra=(crashy_upstream(),))
    _, token = await grants.create_grant(
        gw.store, {"task": "t", "allowed_tools": ["crash_ask_sampling", "crash_ask_user"]}, registry=gw.engine.registry)

    seen = {"sampling": 0, "elicitation": 0}

    async def sampling_handler(messages, params, context):
        seen["sampling"] += 1
        return "the agent was asked to run a model on attacker text"

    async def elicitation_handler(message, response_type, params, context):
        seen["elicitation"] += 1
        return ElicitResult(action="accept", content="hunter2")

    client = Client(StreamableHttpTransport(gw.url, headers={"X-Task-Grant": token}), mode="legacy",
                    sampling_handler=sampling_handler, elicitation_handler=elicitation_handler)
    async with client as c:
        r1 = await c.call_tool("crash_ask_sampling", {}, raise_on_error=False)
        r2 = await c.call_tool("crash_ask_user", {}, raise_on_error=False)
    assert seen == {"sampling": 0, "elicitation": 0}, "the proxy relayed a server-initiated request"
    assert "refused" in r1.content[0].text or r1.is_error
    assert "refused" in r2.content[0].text or "decline" in r2.content[0].text.lower() or r2.is_error
    rows = [r for r in await gw.store.query_audit(phase="system", limit=20) if r["reason_code"] == "UPSTREAM_REQUEST_BLOCKED"]
    assert len(rows) >= 2 and all(r["verdict"] == "deny" for r in rows)


async def test_f39_control_without_the_block_the_proxy_does_relay_the_request(make_gateway, monkeypatch):
    """Proves the test above can fail: with the default proxy handlers the agent really is asked."""
    from firewall import server

    monkeypatch.setattr(server, "_blocking_client", lambda transport, upstream, engine: transport)
    gw, _ = await make_gateway([], extra=(crashy_upstream(),))
    _, token = await grants.create_grant(
        gw.store, {"task": "t", "allowed_tools": ["crash_ask_sampling"]}, registry=gw.engine.registry)
    seen = {"sampling": 0}

    async def sampling_handler(messages, params, context):
        seen["sampling"] += 1
        return "relayed"

    client = Client(StreamableHttpTransport(gw.url, headers={"X-Task-Grant": token}), mode="legacy",
                    sampling_handler=sampling_handler)
    async with client as c:
        await c.call_tool("crash_ask_sampling", {}, raise_on_error=False)
    assert seen["sampling"] == 1