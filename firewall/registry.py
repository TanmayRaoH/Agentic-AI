"""Tool registry and startup validation (F05).

A tool without `reviewed: true` is treated as private + untrusted + sink, so a tool nobody has
looked at gets the most restrictive handling. Setting `reviewed: true` is a human act.
"""
from __future__ import annotations

from collections.abc import Iterable

from firewall.config import ToolEntry, ToolsConfig
from firewall.models import ToolMeta

RESTRICTIVE_LABELS = ["private", "untrusted", "sink"]


class Registry:
    def __init__(self, cfg: ToolsConfig):
        self._tools: dict[str, ToolEntry] = dict(cfg.tools)

    def names(self) -> set[str]:
        return set(self._tools)

    def has(self, name: str) -> bool:
        return name in self._tools

    def entry(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def meta(self, name: str) -> ToolMeta | None:
        e = self._tools.get(name)
        if e is None:
            return None
        labels = list(e.labels) if e.reviewed else list(RESTRICTIVE_LABELS)
        return ToolMeta(
            name=name, labels=labels, risk=e.risk, reviewed=e.reviewed, arg_kinds=dict(e.arg_kinds),
            path_roots=list(e.path_roots), dest_arg=e.dest_arg, commands=list(e.commands),
            allow_shell=e.allow_shell,
        )

    def reviewed_map(self) -> dict[str, bool]:
        return {n: e.reviewed for n, e in self._tools.items()}

    def unreviewed(self) -> list[str]:
        return sorted(n for n, e in self._tools.items() if not e.reviewed)

    def risk(self, name: str) -> str | None:
        e = self._tools.get(name)
        return e.risk if e else None

    def validate_discovery(self, discovered: Iterable[str]) -> tuple[list[str], list[str]]:
        """Returns (missing, warnings). `missing` are discovered tools absent from tools.yaml: the
        gateway must refuse to start. Warnings cover listed-but-not-discovered and unreviewed tools."""
        found = set(discovered)
        missing = sorted(found - self.names())
        warnings = [f"tool '{n}' is listed in tools.yaml but no upstream provides it" for n in sorted(self.names() - found)]
        for n in self.unreviewed():
            warnings.append(
                f"tool '{n}' is not reviewed: treated as private+untrusted+sink until a human sets reviewed: true")
        return missing, warnings
