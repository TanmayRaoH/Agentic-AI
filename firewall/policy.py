"""Policy engine (F07). Rules are evaluated in order; the first matching rule wins.

A rule can only tighten what a grant allows. It never allows anything and it cannot undo a hard
deny (the engine only reaches this step after steps 1 to 9 passed).
"""
from __future__ import annotations

import re
from datetime import datetime
from fnmatch import fnmatchcase

from firewall.config import Rule
from firewall.models import GrantState, ToolMeta, Verdict

MAX_REGEX_INPUT = 32 * 1024  # same bound as the single-string argument limit


def _in_window(window: str, now: datetime) -> bool:
    """window is 'H-H' in local hours, start inclusive, end exclusive; 22-6 wraps midnight."""
    start_s, end_s = window.split("-", 1)
    start, end = int(start_s), int(end_s)
    h = now.hour
    return start <= h < end if start < end else (h >= start or h < end)


def _matches(rule: Rule, meta: ToolMeta, state: GrantState, args: dict, now: datetime) -> bool:
    m = rule.match
    if m.tool is not None and not fnmatchcase(meta.name, m.tool):
        return False
    if m.risk and meta.risk not in m.risk:
        return False
    if m.labels and not (set(m.labels) & set(meta.labels)):
        return False
    if m.labels_seen and not set(m.labels_seen) <= set(state.labels):
        return False
    for arg_name, pattern in m.arg_regex.items():
        value = args.get(arg_name)
        if value is None or re.search(pattern, str(value)[:MAX_REGEX_INPUT]) is None:
            return False
    return not (m.time_window is not None and not _in_window(m.time_window, now))


def evaluate(rules: list[Rule], meta: ToolMeta, state: GrantState, args: dict,
             now: datetime | None = None) -> Verdict | None:
    """Returns None when no rule matches."""
    now = now or datetime.now()  # local time, as the time_window condition is local hours
    for i, rule in enumerate(rules):
        if _matches(rule, meta, state, args, now):
            rid = rule.id or f"rule_{i}"
            if rule.action == "deny":
                return Verdict("deny", ["POLICY_DENY"], rule_id=rid)
            return Verdict("require_approval", ["POLICY_APPROVAL"], rule_id=rid)
    return None
