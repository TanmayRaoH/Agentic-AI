"""Scripted attacker (F28): runs scenario steps against a Backend, like a hijacked agent would.

Template variables inside step args and conditions:
  ${canary}  ${prev.text}  ${step.N.text}
  ${b64:X} ${hex:X} ${rev:X} ${url:X} ${rot13:X} ${upper:X} ${spaced:X} ${dashed:X}
  ${half1:X} ${half2:X} ${slice:A:B:X} ${repeat:N:X}
"""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Protocol

from eval.scenario import Scenario

CANARY = "CANARY-7f3a91"


@dataclass
class Ctx:
    prev_text: str = ""
    step_texts: dict[int, str] = field(default_factory=dict)


def _match(s: str, k: int) -> int:
    depth = 1
    while k < len(s):
        if s.startswith("${", k):
            depth += 1
            k += 2
            continue
        if s[k] == "}":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    raise ValueError(f"unterminated template in: {s!r}")


def resolve(s: str, ctx: Ctx) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        if s.startswith("${", i):
            j = _match(s, i + 2)
            out.append(_eval(s[i + 2 : j], ctx))
            i = j + 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _eval(expr: str, ctx: Ctx) -> str:
    if expr == "canary":
        return CANARY
    if expr == "prev.text":
        return ctx.prev_text
    m = re.fullmatch(r"step\.(\d+)\.text", expr)
    if m:
        return ctx.step_texts.get(int(m.group(1)), "")
    op, _, arg = expr.partition(":")
    if op == "slice":
        a, b, rest = arg.split(":", 2)
        return resolve(rest, ctx)[int(a) : int(b)]
    if op == "repeat":
        n, rest = arg.split(":", 1)
        return resolve(rest, ctx) * int(n)
    val = resolve(arg, ctx)
    if op == "b64":
        return base64.b64encode(val.encode()).decode()
    if op == "hex":
        return val.encode().hex()
    if op == "rev":
        return val[::-1]
    if op == "url":
        return urllib.parse.quote(val, safe="")
    if op == "rot13":
        return codecs.encode(val, "rot13")
    if op == "upper":
        return val.upper()
    if op == "spaced":
        return " ".join(val)
    if op == "dashed":
        return "-".join(val[i : i + 4] for i in range(0, len(val), 4))
    if op == "half1":
        return val[: len(val) // 2]
    if op == "half2":
        return val[len(val) // 2 :]
    raise ValueError(f"unknown template op: {op!r}")


def resolve_any(v: Any, ctx: Ctx) -> Any:
    if isinstance(v, str):
        return resolve(v, ctx)
    if isinstance(v, dict):
        return {k: resolve_any(x, ctx) for k, x in v.items()}
    if isinstance(v, list):
        return [resolve_any(x, ctx) for x in v]
    return v


@dataclass
class CallOutcome:
    text: str
    is_error: bool = False
    code: str | None = None  # firewall reason code parsed from the message, if any


class Backend(Protocol):
    async def visible_tools(self) -> set[str]: ...
    async def call(self, name: str, args: dict) -> CallOutcome: ...
    async def detections(self) -> set[str]: ...


@dataclass
class StepRecord:
    index: int
    kind: str  # call, list, skipped
    tool: str | None = None
    args: dict | None = None
    outcome: CallOutcome | None = None


async def run_steps(scn: Scenario, backend: Backend) -> tuple[list[StepRecord], Ctx]:
    ctx = Ctx()
    visible = await backend.visible_tools()
    records: list[StepRecord] = []
    for idx, step in enumerate(scn.steps):
        if step.list:
            visible = await backend.visible_tools()
            records.append(StepRecord(idx, "list"))
            continue
        if step.if_visible and step.if_visible not in visible:
            records.append(StepRecord(idx, "skipped", step.call))
            continue
        args = resolve_any(step.args, ctx)
        out = await backend.call(step.call, args)
        records.append(StepRecord(idx, "call", step.call, args, out))
        ctx.prev_text = out.text
        ctx.step_texts[idx] = out.text
    return records, ctx
