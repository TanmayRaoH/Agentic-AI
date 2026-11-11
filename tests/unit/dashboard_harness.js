// Runs firewall/dashboard/app.js against a tiny fake DOM and prints a JSON report (used by test_f35_f18_dashboard.py).
"use strict";
const fs = require("fs");
const path = require("path");

const XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"];
const flags = { innerHTML: 0, storage: 0 };

class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.listeners = {}; this.className = ""; this._text = ""; this.value = "";
    this.type = undefined;
  }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set innerHTML(v) { flags.innerHTML++; }
  get innerHTML() { flags.innerHTML++; return ""; }
  set outerHTML(v) { flags.innerHTML++; }
  get firstChild() { return this.children[0] || null; }
  get childNodes() { return this.children; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  addEventListener(name, fn) { (this.listeners[name] = this.listeners[name] || []).push(fn); }
  click() { (this.listeners.click || []).forEach((f) => f()); }
  walk(fn) { fn(this); this.children.forEach((c) => c.walk(fn)); }
}

const ids = {};
["banner", "status", "token", "connect", "filter", "counters", "approvals", "grants", "pins", "audit"].forEach((i) => {
  ids[i] = new Node(i === "connect" ? "button" : "div");
});
const document = {
  createElement: (t) => new Node(t),
  createTextNode: (t) => { const n = new Node("#text"); n._text = String(t); return n; },
  getElementById: (i) => ids[i],
};
Object.defineProperty(document, "cookie", { get() { flags.storage++; return ""; }, set() { flags.storage++; } });

const calls = [];
let monitor = false;
const DATA = {
  "/health": () => ({ status: "ok", mode: monitor ? "monitor" : "enforce", monitor_banner: monitor }),
  "/approvals": () => [{ id: "ap_1", status: "pending", tool: XSS[0], grant_id: "g_1", reason_codes: ["TRIFECTA_APPROVAL"],
    preview: { destination: "docs.example.com", private_matches: 2, preview_available: true, preview: XSS[1] } },
    { id: "ap_0", status: "approved" }],
  "/grants": () => [{ id: "g_act", status: "active", suspended: false, suspicious: false, task: XSS[0], allowed_tools: [XSS[1]],
    used_calls: 1, max_calls: 5, token_prefix: "abcd", labels: [] },
    { id: "g_sus", status: "active", suspended: true, suspicious: true, task: "t", allowed_tools: [], used_calls: 0,
      max_calls: 5, token_prefix: "efgh", labels: ["private"] }],
  "/pins": () => [{ upstream: "web", tool: "web_fetch", state: "changed", reasons: [XSS[0]], new_snapshot: XSS[1] }],
  "/audit": () => [{ id: 1, ts: "t", phase: "call", verdict: "deny", tool: XSS[0], reason_code: "EXFIL_FLOW", grant_id: "g_1",
    mode: "enforce", args_masked: XSS[1], detail: XSS[0] }],
};
function fakeFetch(url, init) {
  const method = (init && init.method) || "GET";
  calls.push({ url, method, headers: init && init.headers, body: init && init.body });
  const base = url.split("?")[0];
  const data = method === "GET" && DATA[base] ? DATA[base]() : { ok: true };
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data) });
}

let intervals = 0;
const sandbox = {
  document, fetch: fakeFetch, console, Date, JSON, Promise, Object, String, Array, Error, encodeURIComponent,
  setInterval: () => { intervals++; return 1; }, clearInterval: () => {},
};
Object.defineProperty(sandbox, "localStorage", { get() { flags.storage++; return {}; } });
Object.defineProperty(sandbox, "sessionStorage", { get() { flags.storage++; return {}; } });
sandbox.globalThis = sandbox;
const vm = require("vm");
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "..", "firewall", "dashboard", "app.js"), "utf8"), sandbox);

const tick = () => new Promise((r) => setTimeout(r, 30));
const buttons = (root) => { const out = []; root.walk((n) => { if (n.tag === "button") out.push(n); }); return out; };
const byLabel = (root, label) => buttons(root).find((b) => b.textContent === label);
const tags = (root) => { const s = new Set(); root.walk((n) => s.add(n.tag)); return [...s]; };

(async () => {
  const report = { xss_payload_text_found: false, dangerous_tags: [] };
  ids.token.value = "the-admin-token-123";
  ids.connect.click();
  report.token_input_cleared = ids.token.value === "";
  await tick();
  report.connected_status = ids.status.textContent;
  report.banner_when_enforce = ids.banner.textContent;
  report.banner_class_enforce = ids.banner.className;
  const all = Object.values(ids);
  const text = all.map((n) => n.textContent).join("\n");
  report.xss_payload_text_found = XSS.every((p) => text.includes(p));
  report.dangerous_tags = all.flatMap(tags).filter((t) => ["script", "img", "iframe", "svg", "a"].includes(t));
  report.initial_get_paths = calls.map((c) => c.url);
  report.token_headers = [...new Set(calls.map((c) => c.headers && c.headers["X-Admin-Token"]))];
  report.token_in_urls_or_bodies = calls.some((c) => c.url.includes("the-admin-token") || (c.body || "").includes("the-admin-token"));
  report.intervals = intervals;

  const mark = calls.length;
  const click = async (root, label) => { const b = byLabel(root, label); if (!b) { return false; } b.click(); await tick(); return true; };
  report.found = {
    approve_once: await click(ids.approvals, "Approve once"),
    approve_destination: await click(ids.approvals, "Approve for this destination"),
    deny: await click(ids.approvals, "Deny"),
    revoke: await click(ids.grants, "Revoke"),
    resume: await click(ids.grants, "Resume"),
    approve_pin: await click(ids.pins, "Approve change"),
  };
  report.actions = calls.slice(mark).filter((c) => c.method !== "GET").map((c) => ({
    method: c.method, url: c.url, body: c.body ? JSON.parse(c.body) : null }));

  monitor = true;
  ids.filter.listeners.change.forEach((f) => f());
  await tick();
  report.banner_when_monitor = ids.banner.textContent;
  report.banner_class_monitor = ids.banner.className;

  report.inner_html_uses = flags.innerHTML;
  report.storage_uses = flags.storage;
  console.log(JSON.stringify(report));
})().catch((e) => { console.error(e); process.exit(1); });
