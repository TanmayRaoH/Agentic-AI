"""F20 and F31: audit rows carry the firewall's own time, for the call and for the result."""
from firewall import grants
from tests.integration.conftest import client_for


async def test_f31_call_and_result_rows_both_record_firewall_latency(make_gateway):
    gw, _ = await make_gateway(["notes"])
    _, tok = await grants.create_grant(
        gw.store, {"task": "t", "allowed_tools": ["notes_read"]}, registry=gw.engine.registry)
    async with client_for(gw, tok) as c:
        await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)
    rows = [r for r in await gw.store.query_audit(limit=100) if r["tool"] == "notes_read"]
    call = next(r for r in rows if r["phase"] == "call")
    result = next(r for r in rows if r["phase"] == "result")
    assert call["latency_ms"] is not None and call["latency_ms"] >= 0
    assert result["latency_ms"] is not None and result["latency_ms"] >= 0
    assert result["upstream_ms"] is not None and result["upstream_ms"] > 0  # upstream time is kept apart
