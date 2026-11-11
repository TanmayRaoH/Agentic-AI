# Threat model

Agent Firewall sits between an AI agent and its MCP tool servers. Every `tools/call` passes through it.

## Assets

- Private data reachable through tools: files, notes, credentials.
- Side-effecting tools: send, write, delete, execute.
- The operator's trust in approvals: an approval must mean what the operator saw.

## Adversaries

| ID | Who | What they can do |
|---|---|---|
| A1 | Author of untrusted content the agent reads (web pages, emails, documents, tool output) | Plant instructions that a model may follow |
| A2 | A malicious or compromised upstream MCP server | Poison tool descriptions, change them after approval (rug-pull), return hostile results |
| A3 | A hijacked agent | The model follows attacker instructions and issues arbitrary tool calls with its own credentials |

## Trust assumptions

- The gateway host and the admin API are not compromised.
- The operator is honest.
- `tools.yaml` was reviewed by a human (a tool without `reviewed: true` is treated as private, untrusted and a sink).
- The agent can reach only the gateway port. The admin API is on a different port bound to 127.0.0.1 and needs an admin token.

## Trust boundaries

1. Agent to gateway: the agent is untrusted. It presents a grant token; everything else it sends is checked.
2. Gateway to upstream servers: upstream tool definitions and results are untrusted. Definitions are pinned; results are scanned.
3. Operator to admin API: the operator is trusted; the admin token is compared in constant time with a lockout after repeated failures.
4. Admin dashboard: everything it displays is attacker-controlled and is rendered as text only.

## What the firewall does about each adversary

| Threat | Control (feature) |
|---|---|
| A3 calls tools it was never given | Task-scoped, expiring grants; unknown tools and tools outside the grant are denied (F06, F03) |
| A3 sends private data out | Taint labels and value fingerprints keyed by grant, matched after base64, hex, URL, reverse and ROT13 decoding, spacing and chunking (F12); destination allowlist (F11); secret and PII inspection (F09) |
| A3 uses a new session to shed taint | State belongs to the grant, not the session (F02) |
| A1 plants an instruction in a page | Output scanner with quarantine; a flagged grant makes every sink call need approval (F14, F13) |
| Private and untrusted data meet, then a send | Trifecta rule asks the operator (F13), even when no fingerprint matches |
| A2 poisons or changes a tool | Tool pinning by hash, poisoning scan, name-shadow check (F04) |
| A2 asks the client to sample or elicit | Server-initiated requests are refused and audited (F39) |
| Path, command and SSRF tricks | Path jail with symlink and traversal checks, command allowlist, IP-literal and private-range denial (F10, F11) |
| Runaway or flooding agent | Size limits, token bucket, loop breaker, circuit breaker (F33, F08) |
| Operator approves one thing, another is sent | Approvals are single use and bound to the tool and the canonical argument hash (F16) |
| Log tampering | Hash-chained audit log with an external checkpoint file (F20) |
| Attacker text attacks the operator | Dashboard renders with `textContent`, strict CSP, no CORS (F35) |

The firewall fails closed: an error in any check denies the call.

## Out of scope

These are also listed in the README limitations.

- Attacks that never cross a tool call, such as jailbreaking the model directly, or leaking data in the agent's own final reply or in rendered markdown images.
- Covert channels such as timing.
- A compromised host or admin API.
- Denial of service beyond the basic limits.
- Leaks that are paraphrased or summarized so that no fingerprint matches. These are mitigated only by the trifecta approval rule, and only after the grant has seen both private and untrusted data.
- Tools mislabeled in `tools.yaml`.

## Known evasions measured in the evaluation

See `eval/report.md` for the current list. At the time of writing they include a secret written out in words, a secret with lookalike (Cyrillic) letters, a reference-style markdown image, and a non-English override sentence.

## Consequence for evaluation

Each scenario is either prevention (a harmful effect is observable at a sink, in a file, or in an upstream execution log) or detection (content was flagged or quarantined). Leakage through the agent's own reply has no observable sink, so it can only be a detection scenario.
