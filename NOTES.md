# NOTES

Project root is the repository root (the guide's `agent-firewall/` folder is this repo).
The guide is mirrored at `.kiro/steering/agent-firewall-guide.md`; `Reference.md` is the original.

## Environment
- Python 3.14.0 (pyproject requires >=3.12; uv chose the installed 3.14), uv 0.8.14, Windows/PowerShell.
- fastmcp **4.1.6**, pydantic 2.14, pytest 9.2, pytest-asyncio 1.4.

## Section 11 findings (fastmcp 4.1.6)
| Item | Finding |
|---|---|
| Middleware hooks | `on_call_tool(context, call_next) -> ToolResult` and `on_list_tools(context, call_next) -> Sequence[Tool]` exist. Also `on_request`, `on_message`, `on_initialize`, `on_discover`, resource/prompt hooks. |
| Header access | `fastmcp.server.dependencies.get_http_headers(include_all=False, include=None)` exists. **Default strips `authorization`, `cookie`, `mcp-session-id`** etc.; `x-task-grant` is not stripped. Query-param fallback not needed unless tests show otherwise. |
| Proxy API | Differs from guide. No `fastmcp.server.proxy` module. Proxy classes live in `fastmcp.server.providers.proxy` (`FastMCPProxy`, `ProxyClient`, `StatefulProxyClient`, `ProxyProvider`). `fastmcp.server.create_proxy(target, *, mode=None, **settings)` is the factory. `FastMCP.mount(server, namespace=None, tool_names=None)` replaces prefix-style mounting (`namespace` not `prefix`). |
| Package top level | `import fastmcp` exposes only lazy attrs (`settings`, `utilities`); import `FastMCP` from `fastmcp.server.server` (verify exact path at Phase 2). |
| Sessions (verified Phase 2) | **Differs from the guide.** fastmcp 4 clients negotiate the 2026-07-28 protocol era by default; there every request is its own connection and `ctx.session_id` is a new uuid per request. Only handshake-era clients (`Client(mode="legacy")`, the official SDKs today) send a stable `mcp-session-id` header. The gateway reads that header (`get_http_headers(include={"mcp-session-id"})`, it is stripped by default) and otherwise identifies a client as `stateless:<hash(client address + user agent)>` with one WARN audit row. `max_sessions` is therefore only meaningful for handshake-era clients; grant state never depends on it. |
| Mounting (verified Phase 2) | `FastMCP.mount(create_proxy(transport), namespace=name)` gives `fs_read_file` style names. Middleware on the parent sees calls to mounted proxies. `mcp.list_tools(run_middleware=False)` lists without our middleware (used for startup discovery). |
| Headers (verified Phase 2) | `x-task-grant` arrives intact through `get_http_headers()`; query-param fallback `task_grant` is implemented but untested over HTTP. |
| Upstream failures (verified Phase 2) | A dead upstream surfaces as `ToolError("Error calling tool ...")` whose cause chain holds `MCPError: Connection closed`; middleware walks the chain to tell this (UPSTREAM_ERROR) from an ordinary tool error (passed through). |
| HTTP serving | `mcp.http_app()` served by our own `uvicorn.Server` so tests can start and stop it cleanly. `StdioTransport(keep_alive=True)` keeps one subprocess per upstream. |
| Server-initiated requests (F39) | `default_proxy_sampling_handler`, `default_proxy_elicitation_handler`, `default_proxy_roots_handler` exist in the proxy provider: the proxy **can relay sampling/elicitation to the client**. F39 must override these handlers. Verify at Phase 5. |
| Tool-name prefixing | To verify at Phase 2 by printing real `list_tools` names, then align tools.yaml. |

## Module design (public functions -> features)
| Module | Public functions | Features |
|---|---|---|
| models.py | Verdict, Match, Grant, GrantState, ToolMeta | all |
| config.py | load_tools, load_policy, load_upstreams, ConfigError | F23, F05 |
| store.py | all SQL; single writer + lock | F37, F02, F06, F20 |
| audit.py | write, mask | F20 |
| sessions.py | touch_session, active_session_count, load_state, save_state | F02 |
| grants.py | create_grant, resolve, reserve_budget, revoke | F06, F34 |
| policy.py | evaluate | F07 |
| ratelimit.py | check_rate | F08 |
| limits.py | check_arg_limits | F33 |
| inspect_args.py | find_secrets, find_pii | F09 |
| paths.py | check_paths | F10 |
| destinations.py | check_destination | F11 |
| flow.py | flow_normal, fingerprints, candidates, register_private, check_egress | F12, F13 |
| scan_output.py | injection_score | F14 |
| content.py | extract_text | F40 |
| redact.py | redact | F15 |
| pinning.py | tool_hash, check_pin | F04 |
| approvals.py | request, wait, consume | F16 |
| engine.py | Engine.check_call/check_result/filter_tools/deny/agent_message/audit_call | pipeline, F01, F03 |
| middleware.py | FirewallMiddleware | F01, F02, F20 |
| server.py | gateway entry | F01 |
| admin_api.py | FastAPI app | F17, F35, F18 |
| cli.py | `fw` | F19 |
| metrics.py / alerts.py / replay.py | | F22 / F22 / F21 |
| llm.py + agents/ | | F24-F27 |

## Phase 1 design decisions
- Demo servers expose unprefixed tool names (`read_file`, `fetch`, `send_email`, `read`); the upstream name is the prefix, so the agent sees `fs_read_file`, `web_fetch`, `mail_send_email`, `notes_read` (matches tools.yaml). The unprotected backend adds the prefix itself, the gateway will do it via `mount(namespace=...)`.
- Added tools beyond the guide's six, all listed in tools.yaml: `fs_list_files`, `fs_run_command` (simulated, never executes), `notes_write`. Needed for the benign "list files" scenario, D03 (shell metacharacters) and E02 (stage via notes).
- The fs server is jailed to a fake world dir (`eval/runtime/world`, copied from `eval/fixtures/world` before every run). Absolute paths map into it and `..` cannot climb out, so unprotected attacks never touch the real disk. `/etc/passwd` is a fake file.
- Ground truth: `eval/runtime/logs/upstream_calls.jsonl` (every executed call), `mail_log.jsonl` and `web_requests.jsonl` (sinks), plus world files compared with the fixture.
- Rug-pull server (`demo/servers/rugpull_server.py`, env `RUGPULL_MODE`): modes poisoned, rugpull, schema, shadow. The listing counter lives in `rugpull_state.json` in the log dir, so it counts across processes. "Description changes after first listing" means: the first `tools/list` is benign, the second and later are not. When the gateway lists at startup, that startup listing counts as the first.
- Extra scenario fields beyond the guide's example: `variant` (swaps the web or fs upstream for the rug-pull server), `list: true` step (agent reloads its tool list), template ops rev, url, rot13, upper, spaced, dashed, half1, half2, slice, repeat, `${step.N.text}`.
- A04 and E03 both split the canary itself (halves / three slices), not the note text, so the split is deterministic.
- Windows detail: fs_write_file writes with `newline=""` so `\n` is not turned into `\r\n` (this broke BN06 until fixed).

## Phase 2 design decisions and interface changes
- Section 5.1 contract changes (recorded as required): `grants`, `sessions`, `audit` functions are async and take the `Store` as first argument (no global state). `sessions.touch_session` returns a bool (admitted or not). `Verdict` gained a `grant_id` field and a `code` property. `Engine.check_result` and `Engine.audit_call` gained optional latency and upstream_ms parameters. `Engine.deny` gained an optional `grant_id`.
- Pipeline implemented so far: step 1 (grant, status, sessions), step 2 (suspended), step 12 (atomic budget), step 13 (forward with per-upstream timeout), audit of call and result. Steps 3 to 11 and result scanning are marked in `engine.py`.
- `grants.py` ships the minimum (create, resolve, reserve, revoke) early because the concurrency test needs the budget. Creation limits, registry validation and `allow_critical` (T14) still belong to Phase 3.
- Monitor mode: every deny is audited as `would_deny` and forwarded, except FIREWALL_ERROR, which always blocks (fail closed). Programmatic `mode=` bypasses the FW_ALLOW_MONITOR check (used by the eval harness); the env path (`python -m firewall.server`) enforces it.
- Audit masking (`audit.mask`) currently masks every string (first 4 chars + length + hash). Phase 4 refines it to mask only detected secrets and keep harmless short values readable.
- Audit rows: one `call` row per tools/call decision, one `result` row per forwarded call (also for UPSTREAM_ERROR, UPSTREAM_TIMEOUT), `system` rows for WARNs. Event id is `ev_<audit row id>`.
- Resources and prompts: listing returns empty, read/get raise with code RESOURCES_DISABLED unless `allow_resources` (full scanning of allowed resources comes with F14).
- Eval harness: `eval/gateway_harness.py` starts the gateway in-process, reusing it across scenarios except those with a malicious-upstream `variant` (fresh gateway per run so the rug-pull listing counter starts at the gateway's startup listing). The eval client uses `mode="legacy"` so session semantics apply.
- Phase 2 review fixes: (1) request-path state changes go through `sessions.update_state`, an atomic merge under the store lock (labels add-only, counters incremented in place); `save_state` is a full overwrite for operator/test use only, because a read-modify-write could erase a concurrent label (a taint reset). (2) `sessions` primary key is now `(id, grant_id)`: stateless-era clients share one derived id, and two grants on one host must not collide. The earlier test `test_f02_session_bound_to_one_grant` encoded the opposite (wrong) rule and was replaced by `test_f02_same_session_id_on_two_grants_counts_per_grant`. (3) Session rows older than 1 hour are pruned. (4) The `task_grant` query-parameter fallback now has a test. Schema changed with no migration: delete any old `fw.db`.
- Known gaps left for later phases (by design): tools/list is not yet filtered to the grant (F03, Phase 3), so an enforce-mode client without a grant can still see the catalog until then; server-initiated sampling/elicitation is still relayed by the proxy (F39, Phase 5); no hash chain yet (F20 Tier 2, Phase 6). Prefer the `X-Task-Grant` header over the query parameter: URLs end up in access logs.
- Seed script: `uv run python -m firewall.seed_grant --tools notes_read ...` (T11).

## Phase log
- Phase 0: layout, uv project, deps, strict config models (F23), Makefile skeleton, Section 11 findings. Tests: `uv run pytest` passes.
- Phase 1: demo servers (fs, notes, web, mail, rug-pull), scenario format + scripted attacker, ground truth, unprotected runner. 21 dev attack scenarios (A to E) and 8 benign scenarios. Baseline (3 reps each): attacks 20/20 succeed (D04 is gateway_only and excluded), benign 8/8. Saved in `eval/results/before_table.md`. Not committed (awaiting user approval).
- Phase 2: store (SQLite WAL, single writer), audit, grants (minimum), sessions, engine (steps 1, 2, 12), middleware, gateway server, seed script, eval harness for monitor and enforce. 33 tests pass. Monitor run (3 reps): attacks 20/20 succeed and benign 8/8, identical to the unprotected baseline; audit call rows equal calls made in all 87 runs. Not committed (awaiting user approval).
