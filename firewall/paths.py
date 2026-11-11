"""Path and command safety (F10).

A path argument is accepted only if, after real resolution, it lies inside BOTH one of the tool's
path_roots (tools.yaml) AND one of the grant's allowed_paths. Relative paths and roots are
resolved against `base` (the directory the upstream tool treats as its working directory).
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from urllib.parse import unquote

from firewall.models import Grant, ToolMeta, Verdict

SHELL_META = set(";|&`<>\n\r")


def _violation(code: str, arg: str, reason: str) -> Verdict:
    return Verdict("deny", [code], detail={"arg": arg, "reason": reason})


def _inside(child: str, parent: str) -> bool:
    c, p = os.path.normcase(child), os.path.normcase(parent)
    try:
        return os.path.commonpath([c, p]) == p
    except ValueError:  # different drives
        return False


def _has_dotdot(path: str) -> bool:
    return any(seg == ".." for seg in re.split(r"[\\/]+", path))


def _check_one_path(arg: str, raw: object, meta: ToolMeta, grant: Grant, base: Path) -> Verdict | None:
    if not isinstance(raw, str):
        return _violation("PATH_VIOLATION", arg, "not a string")
    if "\0" in raw:
        return _violation("PATH_VIOLATION", arg, "null byte")
    # Nothing is expanded here, but the upstream might: refuse inputs that rely on expansion.
    if raw.startswith("~") or "$" in raw:
        return _violation("PATH_VIOLATION", arg, "tilde or variable expansion")
    if _has_dotdot(raw):
        return _violation("PATH_VIOLATION", arg, "dot-dot segment")
    decoded = raw
    for _ in range(2):  # percent-encoded traversal such as %2e%2e%2f
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
        if "\0" in decoded or _has_dotdot(decoded):
            return _violation("PATH_VIOLATION", arg, "encoded traversal")
    joined = base / raw
    real = os.path.realpath(joined)
    roots = [os.path.realpath(base / r) for r in meta.path_roots]
    grants_ = [os.path.realpath(base / g) for g in grant.allowed_paths]
    matching_roots = [r for r in roots if _inside(real, r)]
    if not matching_roots:
        return _violation("PATH_VIOLATION", arg, "outside the tool's allowed roots")
    if not any(_inside(real, g) for g in grants_):
        return _violation("PATH_VIOLATION", arg, "outside the grant's allowed paths")
    # a symlink anywhere on the way must not point outside the root the path ended up in
    root = matching_roots[0]
    lexical = Path(os.path.normpath(joined))
    for anc in [lexical, *lexical.parents]:
        if (os.path.islink(anc) or os.path.isjunction(anc)) and not _inside(os.path.realpath(anc), root):
            return _violation("PATH_VIOLATION", arg, "symlink pointing outside")
    return None


def _check_command(arg: str, raw: object, meta: ToolMeta) -> Verdict | None:
    if not isinstance(raw, str):
        return _violation("COMMAND_VIOLATION", arg, "not a string")
    if not meta.allow_shell and (any(c in SHELL_META for c in raw) or "$" in raw):
        return _violation("COMMAND_VIOLATION", arg, "shell metacharacter")
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError:
        return _violation("COMMAND_VIOLATION", arg, "unbalanced quoting")
    if not tokens:
        return _violation("COMMAND_VIOLATION", arg, "empty command")
    if tokens[0] not in meta.commands:
        return _violation("COMMAND_VIOLATION", arg, "command not in the allowlist")
    return None


def check_paths(meta: ToolMeta, args: dict, grant: Grant, base: Path | None = None) -> Verdict | None:
    """Checks every argument whose arg_kind is path or command. None means all passed."""
    base = Path(base) if base is not None else Path.cwd()
    for arg, kind in meta.arg_kinds.items():
        if kind not in ("path", "command") or arg not in args or args[arg] is None:
            continue
        v = (_check_one_path(arg, args[arg], meta, grant, base) if kind == "path"
             else _check_command(arg, args[arg], meta))
        if v is not None:
            return v
    return None
