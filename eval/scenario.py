"""Scenario file format (F28) and loader."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

EVAL_DIR = Path(__file__).resolve().parent


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    if_visible: str | None = None
    list: bool = False  # re-list tools (refreshes visibility; models an agent reloading its tool list)

    @model_validator(mode="after")
    def _check(self) -> Step:
        if bool(self.call) == bool(self.list):
            raise ValueError("a step needs exactly one of: call, list")
        return self


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str = ""
    set: Literal["dev", "heldout"] = "dev"
    category: str
    kind: Literal["attack", "benign"] = "attack"
    type: Literal["prevention", "detection"] = "prevention"
    gateway_only: bool = False
    variant: Literal["poisoned", "rugpull", "schema", "shadow"] | None = None
    grant: dict[str, Any] = Field(default_factory=dict)
    auto_approve: bool = False
    steps: list[Step]
    success_if: dict[str, Any] | None = None
    detected_if: Literal["quarantined", "flagged"] | None = None
    expected_end_state: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        if self.kind == "attack" and self.type == "prevention" and not self.success_if:
            raise ValueError(f"{self.id}: prevention attack needs success_if")
        if self.kind == "attack" and self.type == "detection" and not self.detected_if:
            raise ValueError(f"{self.id}: detection attack needs detected_if")
        if self.kind == "benign" and not self.expected_end_state:
            raise ValueError(f"{self.id}: benign scenario needs expected_end_state")
        return self


def load_scenarios(*dirs: Path) -> list[Scenario]:
    out: list[Scenario] = []
    for d in dirs:
        for p in sorted(Path(d).glob("*.yaml")):
            out.append(Scenario.model_validate(yaml.safe_load(p.read_text(encoding="utf-8"))))
    ids = [s.id for s in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate scenario ids: {sorted(dupes)}")
    return out


def default_dirs(include_heldout: bool = False) -> list[Path]:
    dirs = [EVAL_DIR / "attacks" / "dev", EVAL_DIR / "benign"]
    if include_heldout:
        dirs.append(EVAL_DIR / "attacks" / "heldout")
    return dirs
