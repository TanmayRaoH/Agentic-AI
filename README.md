# Agent Firewall

A security gateway between an AI agent and its MCP tool servers. Every `tools/call` passes through it. It decides allow, deny or require-approval, scans tool results, and logs everything to a hash-chained audit log. A built-in attack suite measures the result: unprotected versus protected.

**Honest positioning.** Session-level "lethal trifecta" tracking already exists in open-source tools (Open Edison, Sluice). This project does not claim novelty there. What it adds is the combination below plus a measured, honestly reported evaluation.

- **Task-scoped, expiring grants.** The operator (never the agent) issues a grant per task: allowed tools, destinations and paths, call budget, time limit, session limit. With no grant, nothing is visible and every call is denied.
- **Deterministic data-flow enforcement keyed by task.** Taint labels (private, untrusted, sink) and value fingerprints live with the grant, so a new session cannot reset them. Fingerprints survive base64, hex, URL encoding, reversal, ROT13, inserted spacing and chunking. No LLM is in the enforcement path.
- **Tool pinning.** Each tool's name, description and schema is hashed at first sight. A change (rug-pull) or a hidden instruction (poisoning) blocks the tool.
- **Measured evaluation.** Scripted attacker, ground truth taken from what actually executed, dev and held-out attack sets, a before/after table, latency numbers and a limitations list.

Architecture: [docs/architecture.md](docs/architecture.md). Threat model: [docs/threat-model.md](docs/threat-model.md). Full results: [eval/report.md](eval/report.md).

## Results

Measured on one machine with the scripted attacker, 3 repetitions per scenario, majority outcome. See [eval/report.md](eval/report.md) for per-category tables, the attacks that still succeed, and the latency table.

| Measure | Unprotected | Monitor (logs only) | Enforce |
|---|---|---|---|
| **Attack success, held-out set** (10 prevention scenarios) | 100% | 100% | **20%** (2 of 10) |
| Attack success, dev set (20 scenarios, tuned against) | 100% | 100% | 0% |
| Detection rate, held-out set (7 scenarios) | 0% | 71% | 71% |
| Detection rate, dev set (4 scenarios) | 0% | 25% | 100% |
| Gateway-only controls held (4) | 0 of 4 | 0 of 4 | 4 of 4 |
| Benign task success (13 scenarios) | 13 of 13 | 13 of 13 | 12 of 13 |
| False-positive call rate | n/a | n/a | 2 of 33 calls |
| Latency added at the median, end to end | n/a | about 13 ms | about 13 ms |

Read these carefully:

- The dev set was used while building, so its 0% is optimistic. The **held-out set** (17 scenarios, 6 adapted from published attacks) is the honest number. It was run before any tuning and again at the end; no detector was changed in response to a held-out result.
- Two held-out attacks still get through: a secret sent with Cyrillic lookalike letters, and a secret spelled out in words. Two held-out detection scenarios are missed: a reference-style markdown image and a French override sentence.
- One benign task fails: twelve quick read-only calls hit the default rate limit (burst of 10). Raising `rate_burst` in `policy.yaml` fixes it; the default is kept as specified.
- The held-out scenarios were written by the same person who wrote the detectors, so they are not fully independent.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). Node.js is optional (one dashboard test uses it).

```powershell
uv sync

# 1. admin API (separate port, 127.0.0.1 only)
$env:FW_ADMIN_TOKEN = "choose-a-long-admin-token"
$env:FW_APPROVAL_KEY = "choose-a-long-approval-key"
uv run python -m firewall.admin_api        # port 8801

# 2. gateway (in another terminal, same two variables)
uv run python -m firewall.server           # port 8800

# 3. create a grant and use the token as the X-Task-Grant header
uv run fw grant create --task "summarize notes" --tools notes_read --max-calls 10
uv run fw approvals list
uv run fw approve <id>
uv run fw audit verify
```

### Live demo

One command starts everything on a throwaway database, opens the dashboard, and runs a scripted "hijacked agent" that makes allowed calls, two blocked exfiltration attempts and one call held for approval (click Approve once in the dashboard):

```powershell
uv run python demo/run_demo.py
```

If the gateway and admin API are already running and you have a grant, run only the agent:

```powershell
uv run python demo/agent_demo.py --token <the fwg_ token printed by grant create>
```

While it waits at step 5, approve the held email in the dashboard or with `uv run fw approve <id>` (default timeout 60 s).

The operator dashboard is at `http://127.0.0.1:8801/dashboard` (enter the admin token on the page; it stays in memory only).

### Evaluation

```powershell
uv run python -m eval.run_all          # everything: baseline, all modes, both sets, latency, report (about 25 minutes)
uv run python -m eval.run_all --quick  # shortened run used by CI
uv run python -m eval.runner --modes enforce --sets dev heldout --only HO09   # one scenario
uv run pytest                          # unit, integration and the attack regression suite
```

With `make`, the same targets are `make eval`, `make eval-quick`, `make test`. The evaluation shares `eval/runtime` with the regression tests, so do not run both at once.

## Configuration

| File / variable | Purpose |
|---|---|
| `policy.yaml` | mode, trifecta mode, approval mode and timeout, thresholds, rate limits, rules |
| `tools.yaml` | every upstream tool with labels, risk, `reviewed`, argument kinds. A missing tool refuses startup. |
| `upstreams.yaml` | upstream MCP servers |
| `FW_ADMIN_TOKEN` | required, at least 16 characters |
| `FW_APPROVAL_KEY` | required to run the gateway (encrypts pending approvals), at least 16 characters |
| `FW_DB_PATH`, `FW_GATEWAY_PORT`, `FW_ADMIN_PORT` | defaults `./fw.db`, 8800, 8801 |
| `FW_MODE=monitor` + `FW_ALLOW_MONITOR=1` | monitor mode logs would-be denials and forwards everything; it needs both settings and shows a red banner |
| `FW_APPROVAL_TIMEOUT_S` | overrides the policy timeout (default 60) |

Changing the database schema between versions needs a fresh `fw.db`; there is no migration.

## Limitations

These are also in the evaluation report and the threat model.

- The attacker is scripted and not adaptive. The numbers describe known attack shapes, not a determined adversary.
- Detection of hostile content is heuristic and English-centric.
- Flow tracking matches text. Paraphrase, summaries, spelled-out values, lookalike characters and character-by-character leaks beyond the 4 KB egress buffer evade fingerprints. The trifecta rule only helps once the grant has seen both private and untrusted data.
- Out of scope: attacks that never cross a tool call (jailbreaking the model, leaks in the agent's own reply, rendered markdown images), covert channels such as timing, a compromised host, denial of service beyond basic limits, and tools mislabeled in `tools.yaml`.
- The audit hash chain is tamper-evident, not tamper-proof: someone who can rewrite the database and the checkpoint file can recompute it. The checkpoint file is written at start, hourly and at graceful stop.
- SQLite with one gateway process. Running several gateway instances needs a different store (the SQL lives only in `firewall/store.py`, so MySQL or Postgres is a contained change).
- Scenario counts are below the original targets: 28 dev attacks (category H not built) and 13 benign tasks.
- AgentDojo was not run.

## Not done

Tier 3 features that were not built: session timeline and replay (F21), metrics and alerts (F22), retention and purge (F36), `POST /reload`, `POST /grants/plan`, and the four LLM agents (demo agent, grant planner, attack generator, incident explainer). A 2-minute demo recording is still to be made.

## Future work

AgentDojo integration; an LLM judge as a non-enforcing advisor; OPA-style policy; a multi-instance store.

## Credits

Ideas borrowed from Open Edison (Edison Watch), Sluice, LlamaFirewall (Meta), Lasso MCP gateway and rug-pull scanners. Built on FastMCP. Held-out scenarios adapted from AgentDojo (Debenedetti et al.), EchoLeak (arXiv 2509.10540), ChatInject (arXiv 2509.22830), Greshake et al. (arXiv 2302.12173), Embrace The Red (Unicode tag smuggling) and Invariant Labs (MCP tool poisoning).
