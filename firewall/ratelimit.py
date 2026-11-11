"""Rate limit and loop breaker (F08). All counters belong to the grant, never to a session."""
from __future__ import annotations

import time

from firewall import audit
from firewall.config import Defaults
from firewall.models import Verdict
from firewall.store import Store


def decide(rate: dict, loop: dict, now: float, key: str, cfg: Defaults) -> tuple[dict, dict, str | None]:
    """Pure function: token bucket first, then the identical-call loop check. Returns new states and a code."""
    per_sec = cfg.rate_limit_per_min / 60.0
    tokens = float(rate.get("tokens", cfg.rate_burst))
    last = float(rate.get("ts", now))
    tokens = min(float(cfg.rate_burst), tokens + max(0.0, now - last) * per_sec)
    code: str | None = None
    if tokens >= 1.0:
        tokens -= 1.0
    else:
        code = "RATE_LIMIT"
    recent = [e for e in loop.get("calls", []) if now - e[0] <= cfg.loop_window_s]
    same = sum(1 for _, k in recent if k == key)
    if code is None and same + 1 >= cfg.loop_threshold:
        code = "LOOP_DETECTED"
    recent.append([now, key])  # denied attempts count too, so hammering a blocked call stays blocked
    return {"tokens": tokens, "ts": now}, {"calls": recent[-200:]}, code


async def check_rate(store: Store, grant_id: str, tool: str, args: dict, cfg: Defaults,
                     now: float | None = None) -> Verdict | None:
    key = f"{tool}:{audit.args_hash(args)}"
    code = await store.mutate_rate_loop(grant_id, lambda r, lp: decide(r, lp, now if now is not None else time.time(), key, cfg))
    return Verdict("deny", [code]) if code else None
