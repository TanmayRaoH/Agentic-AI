# Presenting Agent Firewall

A face-to-face run sheet. About 5 minutes of demo, then questions.

## Before you walk in

1. Close every old terminal that runs the gateway or admin API. Port 8800 or 8801 in use is the most likely live failure.
2. Open a terminal in the project folder and run it once as a rehearsal:
   ```powershell
   uv run python demo/run_demo.py --auto-approve --no-pause
   ```
   It should end with `audit chain OK`. Nothing is left running afterwards.
3. Have these ready in tabs or windows:
   - the terminal, with the font enlarged
   - `eval/report.md` open in an editor or browser
   - a screenshot or short recording of one successful run, as a fallback
4. If a port is busy and you cannot find the cause, use other ports:
   ```powershell
   uv run python demo/run_demo.py --gateway-port 18800 --admin-port 18801
   ```

## The run (about 5 minutes)

### 1. The problem (30 s)
Say: "An AI agent reads untrusted web pages and also holds tools like email. A hidden instruction on a page can make it send private data to an attacker. Agent Firewall sits between the agent and its tools and decides every call."

### 2. Without the firewall, then with it (60 s)
```powershell
uv run python -m eval.runner --modes unprotected enforce --reps 1 --only A02 B02 F02
```
It takes about a minute, so start it, then talk while it runs. Expected:
- Unprotected: A02 (secret sent base64 encoded) and B02 (file deleted outside the grant) both `attack succeeded`.
- Enforce: both `attack failed`, and F02 (hidden instruction in a page) is `detected`.

Say: "Same attacks. Nothing stops them without the firewall. With it, they fail."

### 3. Live demo (2 to 3 min)
```powershell
uv run python demo/run_demo.py
```
The dashboard opens in the browser. Type the admin token the terminal prints (`tanmay-admin-2026-demo` unless you set `FW_ADMIN_TOKEN`), click Connect, then press Enter in the terminal.

Narrate each step as it prints:
1. "The agent reads a private note. Allowed. The firewall now remembers that this task has seen private data."
2. "It fetches a documentation page. Allowed, but that content is untrusted."
3. "Now it is hijacked and emails the note to an attacker. Blocked: a secret in the message."
4. "It tries again with the note base64 encoded, to an allowed address. Blocked: the firewall recognizes the content even encoded. Hard denies can never be approved."
5. "A harmless status email. The task has now seen private and untrusted data, so the firewall asks the operator." Point at the Pending approvals panel and the content preview, click **Approve once**.

Then scroll to the audit feed. Say: "Every decision is logged, with secrets masked, in a hash chain so tampering is detectable." The terminal prints `audit chain OK`.

If you do nothing for 2 minutes at step 5 the call is denied (`APPROVAL_TIMEOUT`). That is correct behavior. Press Enter to stop, and run it again.

### 4. The honest numbers (60 s)
Open `eval/report.md`. Key figures:

| Measure | Unprotected | Enforce |
|---|---|---|
| Attacks that succeed, held-out set (10) | 100% | 20% (2 of 10) |
| Attacks that succeed, dev set (20) | 100% | 0% |
| Hidden-instruction pages detected, held-out | 0 of 7 | 5 of 7 |
| Benign tasks completed (13) | 13 | 12 |
| Added latency, median, end to end | n/a | about 13 ms |

Say: "The dev set is what I tuned against, so the held-out set is the honest number. Two held-out attacks still get through, and I can tell you which."

### 5. Stop
Press Enter in the terminal. It stops both servers and deletes its temporary database.

## If something goes wrong

| Problem | What to do |
|---|---|
| "Port 8800 is already in use" | Close old terminals, or add `--gateway-port 18800 --admin-port 18801` |
| Dashboard shows "Wrong admin token" | Reload the page, type the token the terminal printed, click Connect |
| Dashboard shows nothing | Check the status text at the top right; reload and reconnect |
| Step 5 times out | Normal if nobody clicked. Stop and run again |
| Anything else | Use the fallback screenshot or recording, and say what the demo would have shown |

## Questions you may get

**Is the agent a real model?** No. It is a scripted hijacked agent, so every run is repeatable. The evaluation works the same way. A real LLM agent is future work.

**What still gets through?** Two of ten held-out attacks: a secret sent with Cyrillic lookalike letters, and a secret spelled out in words. Also paraphrased leaks that share no text with the original. Two of seven hidden-instruction pages are missed: a reference-style markdown image and a French override sentence.

**Why not use an LLM to detect attacks?** An LLM in the enforcement path is probabilistic and can itself be tricked by the content it judges. Here every decision is deterministic and logged with a reason code.

**What does the approval protect against?** Leaks with no matching text, such as a summary. Once a task has seen both private and untrusted data, any send needs the operator's decision. The approval shows the operator what would be sent, and it works only once, for exactly that content.

**Can the agent give itself more permission?** No. Only the operator creates grants, through the admin API on a separate port bound to localhost. The agent sees only the gateway.

**What if the agent opens a new session to reset the taint?** State belongs to the grant, not the session, so a new session inherits all of it.

**Is the audit log tamper-proof?** Tamper-evident only. Editing or deleting a row breaks the chain, and a separate checkpoint file catches removal of the newest rows. Someone who can rewrite the whole database and the checkpoint file could recompute it.

**How is this different from Open Edison or Sluice?** They already track the lethal trifecta per session. This project adds task-scoped expiring grants, taint and fingerprints keyed by grant, tool pinning, and a measured evaluation with a held-out set.

**Why did one benign task fail?** Twelve very quick read-only calls hit the default rate limit (burst of 10). It is a policy setting; I kept the default and reported it as a false positive.

**What was not built?** Session timeline and replay, metrics and alerts, retention and purge, config reload, and the optional LLM agents (demo agent, grant planner, attack generator, incident explainer).
