"""Tool pinning and the tool-poisoning scan (F04).

On first sight of a tool the gateway stores a SHA-256 over its name, description and input schema. A later
listing with a different hash puts the tool in state `changed` (rug-pull); both on first sight and on every
change the description and schema are scanned for hidden instructions, and a flagged tool is `quarantined`.
Calls to a changed or quarantined tool are denied, and the tool disappears from tools/list, until an
operator approves it. The approved hash then becomes the pin (state `approved_change`).
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field

from firewall import scan_output
from firewall.store import Store, iso, utcnow

STATE_PINNED = "pinned"
STATE_CHANGED = "changed"
STATE_QUARANTINED = "quarantined"
STATE_APPROVED = "approved_change"
BLOCKING_STATES = (STATE_CHANGED, STATE_QUARANTINED)

RESERVED_NAMES = ("read_file", "send_email", "execute", "shell")
HIDDEN_CHANNEL_PARAMS = frozenset({"notes", "note", "context", "extra", "metadata", "meta", "reason", "thoughts",
                                   "scratchpad", "memo", "comment", "comments", "internal", "hidden", "debug_info"})
MAX_TEXT = 20_000
SNAPSHOT_CHARS = 2000

_ANGLE_TAG = re.compile(r"<\s*/?\s*(?:important|system|instructions?|hidden|secret|admin|override)\s*>", re.IGNORECASE)
_READ_SENSITIVE = re.compile(
    r"\b(?:read|open|cat|access|load|retrieve|fetch|include|attach|pass|send|copy)\b[^\n]{0,50}?"
    r"(?:~/|/etc/|\.ssh|id_rsa|\.env\b|\.aws|credentials?|passwords?|secrets?|api[ _-]?keys?|private key|/private/|private/)", re.IGNORECASE)
_CALL_OTHER = re.compile(r"\b(?:call|invoke|use|run|execute|first|before|then|also)\b[^.\n]{0,40}?\b[a-z]{2,12}_[a-z_]{2,30}\b", re.IGNORECASE)
_LONG_WHITESPACE = re.compile(r"\s{20,}")


def canonical(tool) -> str:
    return json.dumps(
        {"name": tool.name, "description": getattr(tool, "description", None) or "",
         "input_schema": getattr(tool, "parameters", None) or {}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def tool_hash(tool) -> str:
    return hashlib.sha256(canonical(tool).encode("utf-8")).hexdigest()


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _schema_text(schema: dict, depth: int = 0) -> list[str]:
    """Descriptions, titles, defaults and enum values of a schema, plus the names of its properties."""
    out: list[str] = []
    if not isinstance(schema, dict) or depth > 12:
        return out
    for key in ("description", "title"):
        if isinstance(schema.get(key), str):
            out.append(schema[key])
    if isinstance(schema.get("default"), str):
        out.append(schema["default"])
    for e in schema.get("enum") or []:
        if isinstance(e, str):
            out.append(e)
    for name, sub in (schema.get("properties") or {}).items():
        out.append(str(name))
        out += _schema_text(sub, depth + 1)
    for key in ("items", "additionalProperties"):
        if isinstance(schema.get(key), dict):
            out += _schema_text(schema[key], depth + 1)
    return out


def scan_tool(tool, other_names: set[str], reviewed: dict[str, bool] | None = None) -> list[str]:
    """Returns the reasons a tool looks poisoned (empty list means clean)."""
    reasons: list[str] = []
    name = tool.name
    description = (getattr(tool, "description", None) or "")[:MAX_TEXT]
    schema = getattr(tool, "parameters", None) or {}
    schema_strings = _schema_text(schema)
    text = "\n".join([description, *schema_strings])[: MAX_TEXT * 2]
    folded, hidden = scan_output.fold(text)

    if _ANGLE_TAG.search(folded):
        reasons.append("hidden-instruction tag such as <IMPORTANT>")
    _score, families = scan_output.injection_score(text)
    for fam in ("hide_from_user", "override_phrase", "fake_role_header", "exfil_verb_target", "addressed_to_agent"):
        if fam in families:
            reasons.append(f"instruction pattern: {fam}")
    if _READ_SENSITIVE.search(folded):
        reasons.append("tells the model to read or pass files, keys or credentials")
    mentioned = [n for n in other_names if n != name and re.search(rf"\b{re.escape(n)}\b", folded)]
    if mentioned and _CALL_OTHER.search(folded):
        reasons.append(f"tells the model to call another tool ({mentioned[0]})")
    if hidden or _LONG_WHITESPACE.search(text):
        reasons.append("invisible characters or unusually long whitespace")
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    desc_lower = description.lower()
    for pname, sub in props.items():
        if pname.lower() in HIDDEN_CHANNEL_PARAMS:
            explained = bool(isinstance(sub, dict) and (sub.get("description") or "").strip()) or pname.lower() in desc_lower
            if not explained:
                reasons.append(f"parameter '{pname}' looks like a hidden channel and is not explained")

    # name shadowing
    bare = name.split("_", 1)[1] if "_" in name else name
    for reserved in RESERVED_NAMES:
        if bare != reserved and edit_distance(bare, reserved) <= 2:
            reasons.append(f"name shadows the reserved name '{reserved}'")
            break
    reviewed = reviewed or {}
    for other in other_names:
        if other != name and edit_distance(name, other) <= 2 and not reviewed.get(name, False):
            reasons.append(f"name is within edit distance 2 of the registered tool '{other}'")
            break
    return list(dict.fromkeys(reasons))


@dataclass
class PinEvent:
    """What changed when a tool was observed. `state` is the state after the observation."""
    upstream: str
    tool: str
    state: str
    transition: str | None  # None when nothing changed: "first_sight", "changed", "poisoned", "restored"
    old_hash: str | None = None
    new_hash: str | None = None
    reasons: list[str] = field(default_factory=list)


def snapshot(tool) -> str:
    props = ", ".join((getattr(tool, "parameters", None) or {}).get("properties", {}) or [])
    text = f"{getattr(tool, 'description', None) or ''}\n[parameters: {props}]"
    return scan_output.mask_secrets(unicodedata.normalize("NFKC", text))[:SNAPSHOT_CHARS]


async def observe(store: Store, tool, other_names: set[str], reviewed: dict[str, bool] | None = None) -> PinEvent:
    """Record a live tool definition and return what, if anything, changed. Atomic in the store."""
    upstream = tool.name.split("_", 1)[0]
    h = tool_hash(tool)
    reasons = scan_tool(tool, other_names, reviewed)
    r = await store.observe_pin(upstream, tool.name, h, snapshot(tool), reasons, iso(utcnow()))
    return PinEvent(r["upstream"], r["tool"], r["state"], r["transition"], r["old_hash"], r["new_hash"], r["reasons"])


async def check_pin(store: Store, upstream: str, tool) -> str:
    """Current state of a tool: pinned, changed, quarantined or approved_change (unknown tools are pinned on sight)."""
    row = await store.get_pin(tool.name)
    return row["state"] if row else STATE_PINNED
