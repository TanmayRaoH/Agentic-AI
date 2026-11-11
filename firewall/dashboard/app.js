// Agent Firewall dashboard (F18). Plain JavaScript, no build step, no inline code.
//
// Everything shown here is attacker-controlled (tool names, arguments, results, descriptions), so the page never
// builds HTML from data: every value is written with textContent, and attributes are only ever set from constants.
// The admin token lives in a variable in this closure. It is never written to localStorage, sessionStorage or a
// cookie, and it is sent only in the X-Admin-Token header of requests to this same origin.
(function () {
  "use strict";

  var POLL_MS = 2000;
  var state = { token: null, timer: null, busy: false };

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function byId(id) { return document.getElementById(id); }

  function cssToken(value) {
    // only letters and underscores may reach a class name
    return String(value === null || value === undefined ? "" : value).replace(/[^a-z_]/gi, "").toLowerCase();
  }

  function api(method, path, body) {
    var init = { method: method, headers: { "X-Admin-Token": state.token } };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(path, init).then(function (response) {
      return response.json().catch(function () { return null; }).then(function (data) {
        if (!response.ok) {
          var message = (data && data.detail && data.detail.error) || (data && data.detail) || ("HTTP " + response.status);
          var error = new Error(typeof message === "string" ? message : JSON.stringify(message));
          error.status = response.status;
          throw error;
        }
        return data;
      });
    });
  }

  function setStatus(text) { byId("status").textContent = text; }

  function emptyNote(container, text) { container.appendChild(el("div", "empty", text)); }

  function button(label, className, onClick) {
    var b = el("button", className, label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function act(promise) {
    return promise.then(refresh).catch(function (error) { setStatus("Action failed: " + error.message); });
  }

  // ---------------- renderers (pure: data in, DOM out) ----------------
  function renderCounters(container, audit, approvals) {
    clear(container);
    var calls = audit.filter(function (r) { return r.phase === "call"; });
    var count = function (verdicts) { return calls.filter(function (r) { return verdicts.indexOf(r.verdict) >= 0; }).length; };
    var quarantined = audit.filter(function (r) { return r.verdict === "quarantine"; }).length;
    var approved = approvals.filter(function (a) { return a.status === "approved"; }).length;
    [["Allowed", count(["allow"])], ["Denied", count(["deny", "would_deny"])],
     ["Held for approval", count(["require_approval", "would_require_approval"])],
     ["Quarantined", quarantined], ["Approved", approved]].forEach(function (pair) {
      var box = el("div", "counter");
      box.appendChild(el("b", null, pair[1]));
      box.appendChild(document.createTextNode(pair[0]));
      container.appendChild(box);
    });
  }

  function renderAudit(container, rows, filter) {
    clear(container);
    var shown = rows.filter(function (r) { return !filter || r.verdict === filter; });
    if (!shown.length) { emptyNote(container, "No audit rows yet."); return; }
    shown.forEach(function (r) {
      var row = el("div", "row");
      var head = el("div");
      head.appendChild(el("span", "verdict v-" + cssToken(r.verdict), r.verdict));
      head.appendChild(el("span", null, " " + (r.tool || "") + (r.reason_code ? "  " + r.reason_code : "")));
      row.appendChild(head);
      row.appendChild(el("div", "meta", "#" + r.id + "  " + r.ts + "  " + r.phase + "  grant " + (r.grant_id || "-") +
                                        "  mode " + (r.mode || "-")));
      if (r.args_masked) { row.appendChild(el("div", "meta", "args " + r.args_masked)); }
      if (r.detail && r.detail !== "{}") { row.appendChild(el("div", "meta", "detail " + r.detail)); }
      container.appendChild(row);
    });
  }

  function decide(approvalId, decision, scope) {
    return act(api("POST", "/approvals/" + encodeURIComponent(approvalId) + "/decision",
                   { decision: decision, scope: scope || "once" }));
  }

  function renderApprovals(container, approvals) {
    clear(container);
    var pending = approvals.filter(function (a) { return a.status === "pending"; });
    if (!pending.length) { emptyNote(container, "Nothing is waiting for a decision."); return; }
    pending.forEach(function (a) {
      var p = a.preview || {};
      var row = el("div", "row");
      row.appendChild(el("div", null, a.tool + (p.destination ? "  ->  " + p.destination : "")));
      row.appendChild(el("div", "meta", "reasons: " + (a.reason_codes || []).join(", ") +
                                        "   private matches: " + (p.private_matches === undefined ? 0 : p.private_matches) +
                                        "   grant " + a.grant_id + "   id " + a.id));
      row.appendChild(el("div", "preview", p.preview_available ? p.preview : "(preview unavailable: the admin API has no approval key)"));
      var actions = el("div", "actions");
      actions.appendChild(button("Approve once", "approve", function () { decide(a.id, "approve", "once"); }));
      if (p.destination) {
        actions.appendChild(button("Approve for this destination", "approve", function () { decide(a.id, "approve", "destination"); }));
      }
      actions.appendChild(button("Deny", "deny", function () { decide(a.id, "deny", "once"); }));
      row.appendChild(actions);
      container.appendChild(row);
    });
  }

  function renderGrants(container, grants) {
    clear(container);
    if (!grants.length) { emptyNote(container, "No grants."); return; }
    grants.forEach(function (g) {
      var row = el("div", "row");
      row.appendChild(el("div", null, g.id + "  " + g.status + (g.suspended ? "  SUSPENDED" : "") +
                                      (g.suspicious ? "  suspicious" : "")));
      row.appendChild(el("div", "meta", (g.task || "") + "   tools: " + (g.allowed_tools || []).join(", ") +
                                        "   calls " + g.used_calls + "/" + g.max_calls + "   token " + g.token_prefix +
                                        "   labels: " + ((g.labels || []).join(", ") || "none")));
      var actions = el("div", "actions");
      if (g.status === "active") {
        actions.appendChild(button("Revoke", "revoke", function () {
          act(api("DELETE", "/grants/" + encodeURIComponent(g.id)));
        }));
      }
      if (g.suspended) {
        actions.appendChild(button("Resume", "approve", function () {
          act(api("POST", "/grants/" + encodeURIComponent(g.id) + "/resume"));
        }));
      }
      if (actions.childNodes.length) { row.appendChild(actions); }
      container.appendChild(row);
    });
  }

  function renderPins(container, pins) {
    clear(container);
    if (!pins.length) { emptyNote(container, "No tools pinned yet."); return; }
    pins.forEach(function (p) {
      var row = el("div", "row");
      row.appendChild(el("div", null, p.tool + "  " + p.state));
      if (p.reasons && p.reasons.length) { row.appendChild(el("div", "meta", "reasons: " + p.reasons.join("; "))); }
      if (p.state === "changed" || p.state === "quarantined") {
        row.appendChild(el("div", "meta", "now: " + (p.new_snapshot || p.description_snapshot || "")));
        var actions = el("div", "actions");
        actions.appendChild(button("Approve change", "approve", function () {
          act(api("POST", "/pins/" + encodeURIComponent(p.upstream) + "/" + encodeURIComponent(p.tool) + "/approve"));
        }));
        row.appendChild(actions);
      }
      container.appendChild(row);
    });
  }

  // ---------------- polling ----------------
  function refresh() {
    if (!state.token || state.busy) { return Promise.resolve(); }
    state.busy = true;
    return Promise.all([
      api("GET", "/health"), api("GET", "/approvals?limit=200"), api("GET", "/grants"), api("GET", "/pins"),
      api("GET", "/audit?limit=100"),
    ]).then(function (r) {
      var health = r[0], approvals = r[1], grants = r[2], pins = r[3], audit = r[4];
      var banner = byId("banner");
      banner.textContent = health.monitor_banner ? "MONITOR MODE: calls are logged but NOT blocked" : "";
      banner.className = health.monitor_banner ? "banner" : "banner hidden";
      renderCounters(byId("counters"), audit, approvals);
      renderApprovals(byId("approvals"), approvals);
      renderGrants(byId("grants"), grants);
      renderPins(byId("pins"), pins);
      renderAudit(byId("audit"), audit, byId("filter").value);
      setStatus("connected, mode " + health.mode + ", updated " + new Date().toLocaleTimeString());
    }).catch(function (error) {
      setStatus(error.status === 401 ? "Wrong admin token." : error.status === 429 ? "Locked out for a minute (too many wrong tokens)." : "Error: " + error.message);
      if (error.status === 401 || error.status === 429) { stop(); }
    }).then(function () { state.busy = false; });
  }

  function stop() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    state.token = null;
  }

  function connect() {
    var input = byId("token");
    stop();
    state.token = input.value;
    input.value = ""; // the token is kept in memory only
    if (!state.token) { setStatus("Enter the admin token."); return; }
    refresh();
    state.timer = setInterval(refresh, POLL_MS);
  }

  byId("connect").addEventListener("click", connect);
  byId("filter").addEventListener("change", function () { refresh(); });

  if (typeof globalThis !== "undefined") {
    // read-only access to the renderers for the test harness; no state and no token are exposed
    globalThis.__fwDashboard = Object.freeze({
      renderAudit: renderAudit, renderApprovals: renderApprovals, renderGrants: renderGrants, renderPins: renderPins,
      renderCounters: renderCounters,
    });
  }
})();
