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
| Sessions | `Context.session_id` exists; HTTP transport required. Verify at Phase 2. |
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

## Phase log
- Phase 0: layout, uv project, deps, strict config models (F23), Makefile skeleton, Section 11 findings. Tests: `uv run pytest` passes.
