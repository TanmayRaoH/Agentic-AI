import asyncio

from firewall import grants
from tests.integration.conftest import client_for


async def test_f37_50_concurrent_calls_forward_exactly_30(make_gateway):
    gw, logs = await make_gateway(["mail"])
    _, token = await grants.create_grant(gw.store, {"task": "burst", "allowed_tools": ["mail_send_email"],
                                                         "allowed_destinations": ["docs.example.com"], "max_calls": 30})
    async with client_for(gw, token) as c:
        results = await asyncio.gather(*[
            c.call_tool("mail_send_email", {"to": "a@docs.example.com", "subject": f"n{i}", "body": "x"},
                        raise_on_error=False)
            for i in range(50)
        ])
    ok = [r for r in results if not r.is_error]
    denied = [r for r in results if r.is_error]
    assert len(ok) == 30
    assert len(denied) == 20
    assert all("code=GRANT_EXHAUSTED" in r.content[0].text for r in denied)
    forwarded = (logs / "upstream_calls.jsonl").read_text().splitlines()
    assert len(forwarded) == 30
    assert len((logs / "mail_log.jsonl").read_text().splitlines()) == 30
