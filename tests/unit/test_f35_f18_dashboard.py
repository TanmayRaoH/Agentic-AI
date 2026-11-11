"""F35 dashboard and admin hardening, F18 dashboard actions."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from firewall import grants
from firewall.admin_api import DASHBOARD_CSP, create_admin_app
from firewall.config import load_policy, load_tools
from firewall.registry import Registry
from firewall.store import Store

ROOT = Path(__file__).resolve().parents[2]
DASH = ROOT / "firewall" / "dashboard"
TOKEN = "admin-token-0123456789"
H = {"X-Admin-Token": TOKEN}
NODE = shutil.which("node")


@pytest_asyncio.fixture
async def api(tmp_path):
    store = await Store(tmp_path / "d.db").open()
    app = create_admin_app(store, Registry(load_tools(ROOT / "tools.yaml")), load_policy(ROOT / "policy.yaml"), TOKEN)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://admin") as c:
        yield c, store
    await store.close()


def strip_js_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"(?m)(^|[^:\"'\\])//.*$", r"\1", src)


# ---------------- static checks ----------------
FORBIDDEN = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage",
             "sessionStorage", "document.cookie", "setTimeout(\"", "setInterval(\""]


@pytest.mark.parametrize("needle", FORBIDDEN)
def test_f35_the_dashboard_script_never_uses_dangerous_apis(needle):
    assert needle not in strip_js_comments((DASH / "app.js").read_text(encoding="utf-8"))


def test_f35_no_inner_html_anywhere_in_the_dashboard_files():
    for f in DASH.iterdir():
        code = strip_js_comments(f.read_text(encoding="utf-8")) if f.suffix == ".js" else f.read_text(encoding="utf-8")
        assert "innerhtml" not in code.lower(), f.name


def test_f35_the_page_has_no_inline_script_style_or_event_handlers():
    html = (DASH / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html, re.IGNORECASE)
    assert not re.search(r"<style", html, re.IGNORECASE) and not re.search(r"\sstyle\s*=", html, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE) and "javascript:" not in html.lower()
    assert not re.search(r"(src|href)=[\"']https?://", html, re.IGNORECASE)  # no external hosts


# ---------------- served page ----------------
async def test_f35_the_page_is_served_without_a_token_with_a_strict_csp(api):
    c, _ = api
    for path, kind in (("/dashboard", "text/html"), ("/dashboard/app.js", "javascript"), ("/dashboard/style.css", "text/css")):
        r = await c.get(path)
        assert r.status_code == 200 and kind in r.headers["content-type"], path
        assert r.headers["content-security-policy"] == DASHBOARD_CSP
        assert r.headers["x-content-type-options"] == "nosniff"
    csp = DASHBOARD_CSP
    assert "default-src 'self'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    assert "http" not in csp and "frame-ancestors 'none'" in csp


async def test_f35_data_routes_still_need_the_token_and_api_responses_get_a_locked_down_csp(api):
    c, _ = api
    assert (await c.get("/audit")).status_code == 401
    assert (await c.get("/approvals")).status_code == 401
    r = await c.get("/health", headers=H)
    assert r.headers["content-security-policy"].startswith("default-src 'none'")


async def test_f35_no_cors_headers_are_ever_sent(api):
    c, _ = api
    for r in (await c.get("/health", headers={**H, "Origin": "http://evil.example"}),
              await c.get("/dashboard", headers={"Origin": "http://evil.example"}),
              await c.options("/grants", headers={"Origin": "http://evil.example",
                                                  "Access-Control-Request-Method": "POST"})):
        assert not [h for h in r.headers if h.lower().startswith("access-control-")]
    pre = await c.options("/grants", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
    assert pre.status_code in (401, 405)  # a cross-site preflight gets nothing useful


async def test_f35_the_dashboard_can_be_embedded_by_nobody(api):
    c, _ = api
    assert "frame-ancestors 'none'" in (await c.get("/dashboard")).headers["content-security-policy"]


# ---------------- behavior in a fake DOM (needs Node) ----------------
@pytest.fixture(scope="module")
def report():
    if not NODE:
        pytest.skip("node is not installed")
    out = subprocess.run([NODE, str(Path(__file__).with_name("dashboard_harness.js"))], check=False, capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_f35_attacker_controlled_text_is_displayed_as_plain_text(report):
    assert report["xss_payload_text_found"] is True  # the script tag and the onerror payload are visible as text
    assert report["dangerous_tags"] == []  # and no script, img, iframe, svg or link element was created
    assert report["inner_html_uses"] == 0


def test_f35_the_token_is_only_sent_in_the_header_and_never_stored(report):
    assert report["token_input_cleared"] is True
    assert report["token_headers"] == ["the-admin-token-123"]
    assert report["token_in_urls_or_bodies"] is False
    assert report["storage_uses"] == 0
    assert report["intervals"] == 1  # polling is started once


def test_f18_the_page_polls_every_panel_source(report):
    got = set(report["initial_get_paths"])
    assert {"/health", "/grants", "/pins"} <= {p.split("?")[0] for p in got}
    assert any(p.startswith("/approvals") for p in got) and any(p.startswith("/audit") for p in got)
    assert report["connected_status"].startswith("connected")


def test_f18_every_button_issues_the_right_request(report):
    assert all(report["found"].values()), report["found"]
    a = {(x["method"], x["url"]): x["body"] for x in report["actions"]}
    decision = ("POST", "/approvals/ap_1/decision")
    assert decision in a
    bodies = [x["body"] for x in report["actions"] if x["url"] == "/approvals/ap_1/decision"]
    assert {"decision": "approve", "scope": "once"} in bodies
    assert {"decision": "approve", "scope": "destination"} in bodies
    assert {"decision": "deny", "scope": "once"} in bodies
    assert ("DELETE", "/grants/g_act") in a
    assert ("POST", "/grants/g_sus/resume") in a
    assert ("POST", "/pins/web/web_fetch/approve") in a


def test_f35_the_monitor_banner_shows_only_in_monitor_mode(report):
    assert report["banner_when_enforce"] == "" and "hidden" in report["banner_class_enforce"]
    assert report["banner_when_monitor"].startswith("MONITOR MODE") and "hidden" not in report["banner_class_monitor"]


# ---------------- API-level test for each button action (F18) ----------------
async def test_f18_the_grant_buttons_work_against_the_real_api(api):
    c, store = api
    reg = Registry(load_tools(ROOT / "tools.yaml"))
    g, _ = await grants.create_grant(store, {"task": "t", "allowed_tools": ["notes_read"]}, registry=reg)
    rows = (await c.get("/grants", headers=H)).json()
    assert rows[0]["id"] == g.id and {"suspended", "suspicious", "labels"} <= rows[0].keys()
    assert (await c.delete(f"/grants/{g.id}", headers=H)).status_code == 200
    assert (await c.get(f"/grants/{g.id}", headers=H)).json()["status"] == "revoked"
