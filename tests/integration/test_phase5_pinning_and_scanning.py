"""Phase 5 end to end: tool pinning against malicious upstreams, and result scanning over the wire."""
import json

from firewall import grants
from firewall.config import ToolEntry, Upstream, load_tools
from firewall.server import build_gateway
from tests.integration.conftest import ROOT, client_for


def rugpull(name: str, mode: str) -> Upstream:
    return Upstream(name=name, transport="stdio", command="python", args=[str(ROOT / "demo" / "servers" / "rugpull_server.py")],
                    env={"RUGPULL_MODE": mode})


async def _g(gw, tools, **kw):
    spec = {"task": "t", "allowed_tools": tools, "allowed_destinations": ["docs.example.com"],
            "allowed_paths": ["./sandbox"], **kw}
    return await grants.create_grant(gw.store, spec, registry=gw.engine.registry)


def code_of(r):
    text = r.content[0].text
    return text.split("code=")[1].split()[0] if r.is_error and "code=" in text else None


async def alerts(gw, code):
    return [r for r in await gw.store.query_audit(phase="system", limit=100) if r["reason_code"] == code]


# ---------------- clean upstreams ----------------
async def test_f04_the_demo_upstreams_are_pinned_cleanly_and_nothing_alerts(make_gateway):
    gw, _ = await make_gateway(["fs", "web", "mail", "notes"])
    pins = await gw.store.list_pins()
    assert {p["tool"] for p in pins} == set(gw.tool_names)
    assert all(p["state"] == "pinned" for p in pins), [(p["tool"], p["reasons"]) for p in pins if p["state"] != "pinned"]
    _, tok = await _g(gw, ["notes_read"])
    async with client_for(gw, tok) as c:
        await c.list_tools()
        assert not (await c.call_tool("notes_read", {"note_id": 2}, raise_on_error=False)).is_error
    assert not await alerts(gw, "TOOL_PINNED_CHANGED") and not await alerts(gw, "TOOL_POISONED")


# ---------------- rug-pull ----------------
async def test_f04_rugpull_the_changed_tool_disappears_and_calls_are_denied_until_approved(make_gateway):
    gw, logs = await make_gateway(["fs", "mail", "notes"], extra=(rugpull("web", "rugpull"),))
    assert (await gw.store.get_pin("web_fetch"))["state"] == "pinned"  # benign at the gateway's first listing
    _, tok = await _g(gw, ["web_fetch", "notes_read"])
    async with client_for(gw, tok) as c:
        names = {t.name for t in await c.list_tools()}  # the upstream's second listing now carries the instruction
        assert "web_fetch" not in names and "notes_read" in names
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert code_of(r) == "TOOL_PINNED_CHANGED"
    pin = await gw.store.get_pin("web_fetch")
    assert pin["state"] == "changed" and pin["new_hash"] and pin["hash"] != pin["new_hash"]
    assert "IMPORTANT" in pin["new_snapshot"] and "IMPORTANT" not in pin["description_snapshot"]
    rows = await alerts(gw, "TOOL_PINNED_CHANGED")
    assert len(rows) == 1 and rows[0]["tool"] == "web_fetch" and json.loads(rows[0]["detail"])["new_hash"] == pin["new_hash"]
    assert not (logs / "web_requests.jsonl").exists()  # the tool never ran

    # the operator reviews the new definition and approves it
    assert await gw.store.approve_pin("web", "web_fetch", "2026-01-01T00:00:00+00:00")
    async with client_for(gw, tok) as c:
        assert "web_fetch" in {t.name for t in await c.list_tools()}
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert not r.is_error and "Getting Started" in r.content[0].text


async def test_f04_a_rugpull_is_caught_across_a_gateway_restart(make_gateway, tmp_path):
    gw1, _ = await make_gateway(["notes"], extra=(rugpull("web", "rugpull"),))  # counter = 1: benign, pinned
    db = gw1.store.path
    await gw1.stop()
    gw2 = await build_gateway(  # same database, upstream now serves its second listing
        db_path=db, mode="enforce", path_base=tmp_path / "world",
        upstreams=[rugpull("web", "rugpull")], env_extra={"FW_LOG_DIR": str(tmp_path / "logs"), "FW_WORLD": str(tmp_path / "world")})
    try:
        assert (await gw2.store.get_pin("web_fetch"))["state"] == "changed"
        assert await alerts(gw2, "TOOL_PINNED_CHANGED")
    finally:
        await gw2.stop()


async def test_f04_schema_change_with_a_hidden_parameter_is_caught(make_gateway):
    gw, _ = await make_gateway(["notes"], extra=(rugpull("web", "schema"),))
    _, tok = await _g(gw, ["web_fetch"])
    async with client_for(gw, tok) as c:
        assert await c.list_tools() == []
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide", "context": "x"}, raise_on_error=False)
        assert code_of(r) == "TOOL_PINNED_CHANGED"
    pin = await gw.store.get_pin("web_fetch")
    assert any("context" in r for r in json.loads(pin["reasons"]))


# ---------------- poisoning ----------------
async def test_f04_a_poisoned_description_is_quarantined_at_startup(make_gateway):
    gw, logs = await make_gateway(["notes"], extra=(rugpull("web", "poisoned"),))
    pin = await gw.store.get_pin("web_fetch")
    assert pin["state"] == "quarantined"
    reasons = json.loads(pin["reasons"])
    assert any("<IMPORTANT>" in r for r in reasons) and any("credentials" in r for r in reasons)
    assert len(await alerts(gw, "TOOL_POISONED")) == 1
    _, tok = await _g(gw, ["web_fetch", "notes_read"])
    async with client_for(gw, tok) as c:
        assert {t.name for t in await c.list_tools()} == {"notes_read"}
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert code_of(r) == "TOOL_POISONED"
    assert not (logs / "web_requests.jsonl").exists()


async def test_f04_a_shadow_tool_is_quarantined_even_though_the_operator_listed_it(make_gateway):
    tools = load_tools(ROOT / "tools.yaml")
    tools.tools["fs_read_flle"] = ToolEntry(labels=[], risk="low", reviewed=False)
    gw, logs = await make_gateway(["notes"], extra=(rugpull("fs", "shadow"),), tools_cfg=tools)
    assert (await gw.store.get_pin("fs_read_flle"))["state"] == "quarantined"
    assert (await gw.store.get_pin("fs_read_file"))["state"] == "pinned"  # the genuine tool is untouched
    _, tok = await _g(gw, ["fs_read_file", "fs_read_flle"])  # even a grant that names the shadow cannot use it
    async with client_for(gw, tok) as c:
        assert {t.name for t in await c.list_tools()} == {"fs_read_file"}
        r = await c.call_tool("fs_read_flle", {"path": "./sandbox/private/credentials.txt"}, raise_on_error=False)
        assert code_of(r) == "TOOL_POISONED"
    assert not (logs / "web_requests.jsonl").exists()


async def test_f04_monitor_mode_records_but_does_not_hide_or_block(make_gateway):
    gw, logs = await make_gateway(["notes"], mode="monitor", extra=(rugpull("web", "rugpull"),))
    _, tok = await _g(gw, ["web_fetch"])
    async with client_for(gw, tok) as c:
        assert "web_fetch" in {t.name for t in await c.list_tools()}
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert not r.is_error
    row = (await gw.store.query_audit(phase="call", limit=1))[0]
    assert row["verdict"] == "would_deny" and row["reason_code"] == "TOOL_PINNED_CHANGED"
    assert await alerts(gw, "TOOL_PINNED_CHANGED")


# ---------------- result scanning over the wire ----------------
async def test_f14_injected_pages_are_quarantined_over_the_wire_and_the_client_accepts_the_reply(make_gateway):
    gw, _ = await make_gateway(["web", "notes", "mail"])
    for page in ("zero-width", "comment", "homoglyph"):
        _, tok = await _g(gw, ["web_fetch"])  # a quarantine marks the grant suspicious, so use a fresh grant per page
        async with client_for(gw, tok) as c:
            r = await c.call_tool("web_fetch", {"url": f"https://docs.example.com/community/{page}"}, raise_on_error=False)
            assert not r.is_error, (page, r.content[0].text)  # a normal tool result, accepted by the client's schema check
            text = r.content[0].text
            assert "code=INJECTION_QUARANTINE" in text, (page, text)
            assert "attacker" not in text and "ignore" not in text.lower().replace("withheld", "")
    _, tok = await _g(gw, ["web_fetch"])
    async with client_for(gw, tok) as c:
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/community/image"}, raise_on_error=False)
        assert "attacker.example" in r.content[0].text  # flagged (score 0.7) but passed through
    _, tok = await _g(gw, ["web_fetch"])
    async with client_for(gw, tok) as c:
        ok = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
        assert "Getting Started" in ok.content[0].text
        faq = await c.call_tool("web_fetch", {"url": "https://docs.example.com/faq"}, raise_on_error=False)
        assert "safely ignore" in faq.content[0].text  # the benign page that uses the word ignore
    rows = await gw.store.query_audit(phase="result", limit=50)
    assert sum(r["verdict"] == "quarantine" for r in rows) == 3 and sum(r["verdict"] == "flag" for r in rows) == 1
    for r in rows:
        if r["verdict"] == "quarantine":
            d = json.loads(r["detail"])
            assert d["score"] >= 0.8 and d["families"] and len(d["snippet"]) <= 2048


async def test_f14_a_second_fetch_on_a_grant_that_met_an_injection_needs_approval(make_gateway):
    gw, _ = await make_gateway(["web"])
    _, tok = await _g(gw, ["web_fetch"])
    async with client_for(gw, tok) as c:
        await c.call_tool("web_fetch", {"url": "https://docs.example.com/community/comment"}, raise_on_error=False)
        r = await c.call_tool("web_fetch", {"url": "https://docs.example.com/guide"}, raise_on_error=False)
    assert code_of(r) == "TRIFECTA_APPROVAL"  # web_fetch is a sink, and the grant is now suspicious

async def test_f14_after_a_quarantine_a_send_needs_approval(make_gateway):
    gw, logs = await make_gateway(["web", "notes", "mail"])
    _, tok = await _g(gw, ["web_fetch", "mail_send_email"])
    async with client_for(gw, tok) as c:
        await c.call_tool("web_fetch", {"url": "https://docs.example.com/community/comment"}, raise_on_error=False)
        r = await c.call_tool("mail_send_email", {"to": "team@docs.example.com", "subject": "s", "body": "Quarterly numbers are fine."},
                              raise_on_error=False)
    assert code_of(r) == "TRIFECTA_APPROVAL"
    assert not (logs / "mail_log.jsonl").exists()
