"""Core data types (Section 5.1)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Action = Literal["allow", "deny", "require_approval"]


@dataclass
class Verdict:
    action: Action
    reason_codes: list[str] = field(default_factory=list)  # first item is the primary reason
    rule_id: str | None = None
    detail: dict = field(default_factory=dict)  # masked, operator-only
    event_id: str = ""
    grant_id: str | None = None  # added: lets audit rows carry the grant without a second lookup

    @property
    def code(self) -> str | None:
        return self.reason_codes[0] if self.reason_codes else None


@dataclass
class Match:
    kind: str  # secret type, pii type, pattern family
    masked: str  # first 4 characters plus short hash
    path: str  # location inside the arguments


@dataclass
class Grant:
    id: str
    task: str
    allowed_tools: list[str]
    allowed_destinations: list[str]
    allowed_paths: list[str]
    max_calls: int
    used_calls: int
    max_sessions: int
    expires_at: str
    approval_required_for: list[str]
    status: str  # active, expired, exhausted, revoked
    token_prefix: str = ""
    created_at: str = ""
    created_by: str = "operator"


@dataclass
class GrantState:
    grant_id: str
    labels: set[str] = field(default_factory=set)  # subset of private, untrusted
    suspicious: bool = False
    suspended: bool = False
    denied_streak: int = 0
    call_count: int = 0


@dataclass
class ToolMeta:
    name: str
    labels: list[str]
    risk: str
    reviewed: bool
    arg_kinds: dict[str, str]
    path_roots: list[str]
    dest_arg: str | None
    commands: list[str] = field(default_factory=list)
    allow_shell: bool = False
