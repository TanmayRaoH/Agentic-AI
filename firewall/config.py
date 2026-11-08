"""Strict pydantic models for tools.yaml, policy.yaml and upstreams.yaml (F23)."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

Label = Literal["private", "untrusted", "sink"]
Risk = Literal["low", "medium", "high", "critical"]
ArgKind = Literal["path", "url", "email", "command", "text"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConfigError(Exception):
    """Raised with file, key and a fix hint; the process must refuse to start."""


# ---- tools.yaml ----
class ToolEntry(_Strict):
    labels: list[Label] = Field(default_factory=list)
    risk: Risk = "low"
    reviewed: bool = False
    arg_kinds: dict[str, ArgKind] = Field(default_factory=dict)
    path_roots: list[str] = Field(default_factory=list)
    dest_arg: str | None = None
    idempotent: bool = False
    allow_shell: bool = False
    commands: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> ToolEntry:
        if "sink" in self.labels and not self.dest_arg:
            raise ValueError("sink tools need dest_arg (add dest_arg: <argument name>)")
        if "path" in self.arg_kinds.values() and not self.path_roots:
            raise ValueError("tools with a path argument need path_roots")
        return self


class ToolsConfig(_Strict):
    tools: dict[str, ToolEntry]


# ---- policy.yaml ----
class Defaults(_Strict):
    mode: Literal["enforce", "monitor"] = "enforce"
    unknown_tool: Literal["deny"] = "deny"
    on_error: Literal["deny"] = "deny"
    trifecta_mode: Literal["approve", "block", "off"] = "approve"
    approval_mode: Literal["block", "defer"] = "block"
    approval_timeout_s: int = 60
    injection_block_threshold: float = 0.8
    injection_flag_threshold: float = 0.4
    scan_all: bool = False
    block_binary_from_untrusted: bool = True
    redact_private_secrets: bool = False
    allow_resources: bool = False
    audit_retention_days: int = 30


class RuleMatch(_Strict):
    tool: str | None = None
    risk: list[Risk] = Field(default_factory=list)
    labels: list[Label] = Field(default_factory=list)
    labels_seen: list[Literal["private", "untrusted"]] = Field(default_factory=list)
    arg_regex: dict[str, str] = Field(default_factory=dict)
    time_window: str | None = None


class Rule(_Strict):
    match: RuleMatch
    action: Literal["deny", "require_approval"]
    id: str | None = None


class AllowFlow(_Strict):
    from_: str = Field(alias="from")
    to: str
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class PolicyConfig(_Strict):
    defaults: Defaults = Field(default_factory=Defaults)
    rules: list[Rule] = Field(default_factory=list)
    allow_flows: list[AllowFlow] = Field(default_factory=list)
    secrets_allowed_tools: list[str] = Field(default_factory=list)


# ---- upstreams.yaml ----
class Upstream(_Strict):
    name: str
    transport: Literal["stdio", "http"]
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    timeout_s: float = 30.0

    @model_validator(mode="after")
    def _check(self) -> Upstream:
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio upstreams need command")
        if self.transport == "http" and not self.url:
            raise ValueError("http upstreams need url")
        return self


class UpstreamsConfig(_Strict):
    upstreams: list[Upstream]


def _load(path: Path, model):
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return model.model_validate(data)
    except FileNotFoundError:
        raise ConfigError(f"{path}: file not found; create it (see Reference.md Section 6)")
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}")
    except ValidationError as exc:
        lines = [f"{path}: {'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        raise ConfigError("\n".join(lines))


def load_tools(path: Path = Path("tools.yaml")) -> ToolsConfig:
    return _load(path, ToolsConfig)


def load_policy(path: Path = Path("policy.yaml")) -> PolicyConfig:
    return _load(path, PolicyConfig)


def load_upstreams(path: Path = Path("upstreams.yaml")) -> UpstreamsConfig:
    return _load(path, UpstreamsConfig)
