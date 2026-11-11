"""Destination allowlist (F11).

Applies to sink tools via their dest_arg. The destination is the email domain, the URL host, or a
bare hostname. Allowed entries match exactly; a subdomain matches only an entry starting with '*.'
(and '*.example.com' does not match example.com itself).
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from firewall.models import Grant, ToolMeta, Verdict

_EMAIL_SPLIT = re.compile(r"[,;]")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*", re.IGNORECASE)


class DestinationError(ValueError):
    pass


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    return name.split(" ", 1)[0] if name else "UNKNOWN"


def normalize_host(host: str) -> str:
    """lowercase, strip trailing dot, reject mixed scripts, IDNA-encode."""
    host = unicodedata.normalize("NFKC", host).strip().lower().rstrip(".")
    if not host:
        raise DestinationError("empty host")
    letters = [c for c in host if c.isalpha()]
    scripts = {_script(c) for c in letters}
    if len(scripts) > 1 and any(not c.isascii() for c in letters):
        raise DestinationError("mixed-script lookalike host")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DestinationError(f"invalid host: {exc}") from None


def _entry(e: str) -> str:
    wildcard = e.startswith("*.")
    base = normalize_host(e[2:] if wildcard else e)
    return ("*." if wildcard else "") + base


def _is_special_host(host: str) -> bool:
    """IP literals in any notation, localhost, private, loopback and link-local ranges."""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True  # every IP literal is special: wildcard entries never match it, only an exact entry does
    except ValueError:
        pass
    # decimal, hex or octal tricks such as 2130706433, 0x7f.1, 0177.0.0.1
    return bool(_NUMERIC_HOST.fullmatch(h))


def _hosts_from_value(kind: str, value: str) -> list[str]:
    """Extract destination hosts. Raises DestinationError for anything ambiguous."""
    if kind == "email":
        hosts = []
        parts = [p.strip() for p in _EMAIL_SPLIT.split(value) if p.strip()]
        if not parts:
            raise DestinationError("no recipient")
        for p in parts:
            addr = p
            if "<" in p or ">" in p:
                m = re.fullmatch(r"[^<>]*<([^<>]+)>\s*", p)
                if not m:
                    raise DestinationError("malformed recipient")
                addr = m.group(1).strip()
            if addr.count("@") != 1 or re.search(r"\s", addr):
                raise DestinationError("malformed recipient")
            hosts.append(normalize_host(addr.rpartition("@")[2]))
        return hosts
    if kind == "url":
        parts = urlsplit(value.strip())
        if parts.scheme.lower() not in ("http", "https"):
            raise DestinationError("scheme not allowed")
        if not parts.netloc or "@" in parts.netloc or "\\" in parts.netloc:
            raise DestinationError("userinfo or malformed authority")
        host = parts.hostname
        if not host:
            raise DestinationError("no host")
        try:
            parts.port  # noqa: B018 - raises on a non-numeric port
        except ValueError:
            raise DestinationError("invalid port") from None
        return [normalize_host(host)]
    # bare hostname (kind text or unspecified)
    host = value.strip().split("/", 1)[0].split(":", 1)[0] if "]" not in value else value.strip()
    return [normalize_host(host)]


def _matches(host: str, entries: list[str]) -> bool:
    special = _is_special_host(host)
    for e in entries:
        if e.startswith("*."):
            if not special and host.endswith(e[1:]) and host != e[2:]:
                return True
        elif host == e:
            return True  # exact match; this is also how an operator explicitly lists an IP or localhost
    return False


def destinations_of(meta: ToolMeta, args: dict) -> list[str]:
    """Normalized destination hosts of a sink call. Raises DestinationError when it cannot be determined."""
    if not meta.dest_arg:
        raise DestinationError("sink tool has no dest_arg")
    value = args.get(meta.dest_arg)
    if not isinstance(value, str) or not value.strip():
        raise DestinationError("destination argument missing")
    return _hosts_from_value(meta.arg_kinds.get(meta.dest_arg, "text"), value)


def check_destination(meta: ToolMeta, args: dict, grant: Grant) -> Verdict | None:
    """DEST_NOT_ALLOWED unless every destination is explicitly allowed. Non-sink tools are not checked."""
    if "sink" not in meta.labels:
        return None
    try:
        hosts = destinations_of(meta, args)
        entries = [_entry(e) for e in grant.allowed_destinations]
    except DestinationError as exc:
        return Verdict("deny", ["DEST_NOT_ALLOWED"], detail={"reason": str(exc)})
    for h in hosts:
        if not _matches(h, entries):
            return Verdict("deny", ["DEST_NOT_ALLOWED"], detail={"reason": "not in allowed_destinations", "host": h})
    return None
