"""Secret and PII detection (F09).

Every pattern is linear-time safe: bounded quantifiers behind a literal prefix, or a simple
tokenizer followed by small checks. Nothing here backtracks on hostile input, which the 1 MB
timing tests verify. Emails use '@' anchored scanning because a regex that starts at every
character of a long local part would be quadratic.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

from firewall.content import iter_strings
from firewall.models import Match

# Performance note: no pattern starts with \b or a lookbehind. Those disable CPython's literal-prefix
# fast search and made 1 MB scans slow. Boundaries are checked in Python after a match instead.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z0-9]{2,10} ){0,3}PRIVATE KEY(?: BLOCK)?-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,255}")),
    ("slack_token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,200}")),
    ("canary", re.compile(r"CANARY-[A-Za-z0-9]{4,64}")),
]
_HINTS = {
    "aws_access_key_id": lambda t: "AKIA" in t,
    "private_key_block": lambda t: "PRIVATE KEY" in t,
    "github_token": lambda t: any(p in t for p in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    "slack_token": lambda t: "xox" in t,
    "canary": lambda t: "CANARY-" in t,
}
_BEARER = re.compile(r"earer[ \t]{1,8}[A-Za-z0-9._~+/-]{16,512}=*")  # preceded by B or b, checked in code
# Key-like names are found with plain substring searches (a case-insensitive alternation tried at every position
# of a long input is slow), then a short tail pattern is matched right behind each hit.
_ASSIGN_KEYWORDS = ("apikey", "api_key", "api-key", "secret", "token", "passwd", "password", "accesskey", "access_key",
                    "access-key", "privatekey", "private_key", "private-key")
_ASSIGN_TAIL = re.compile(r"[A-Za-z0-9_-]{0,20}[ \t]{0,8}[:=][ \t]{0,8}[\"']?([A-Za-z0-9/+_=-]{32,64})")
MAX_ASSIGN_HITS = 20_000
_HAS_ALPHA = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"[0-9]")
_JWT_TOKEN = re.compile(r"eyJ[A-Za-z0-9_.-]+")  # tokenize first, validate each token below
_JWT_FULL = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")

# PII numbers are found by first cutting out number-like runs (digits with spaces, dashes, dots, brackets),
# then classifying only runs of a plausible length. Long digit soup is never a phone, card or id.
_NUMRUN = re.compile(r"\+?\d[\d ()\-.]{8,}\d")
MAX_NUMRUN = 64
_PHONE = re.compile(r"(?<!\d)\+?\d[\d ()\-.]{8,18}\d(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_ID12 = re.compile(r"(?<!\d)(?<!\d[ -])(?:\d{12}|\d{4}[ -]\d{4}[ -]\d{4})(?![ -]?\d)")
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9._%+-]+")
_EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_EMAIL_CHARS_L = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")
_EMAIL_CHARS_R = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")
MAX_EMAILS_PER_STRING = 1000

def short_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:6]


def mask_match(raw: str) -> str:
    """First 4 characters plus a short hash, never the whole value."""
    return f"{raw[:4]}...#{short_hash(raw)}"


def normalize(text: str) -> str:
    return text if text.isascii() else unicodedata.normalize("NFKC", text)  # ASCII is unchanged by NFKC


def scan_secrets(text: str) -> list[tuple[str, str]]:
    """Return (kind, raw_value) for every secret found in text (after NFKC). Raw values stay in memory only."""
    t = normalize(text)
    found: list[tuple[str, str]] = []
    # a plain substring test is far cheaper than a regex scan, and most text contains none of these
    for kind, pat in SECRET_PATTERNS:
        if _HINTS[kind](t):
            found.extend((kind, m.group(0)) for m in pat.finditer(t))
    if "earer" in t:
        for m in _BEARER.finditer(t):
            if m.start() > 0 and t[m.start() - 1] in "Bb":
                found.append(("bearer_token", t[m.start() - 1 : m.end()]))
    low = t.lower()
    if len(low) != len(t):  # a few characters change length when lower-cased; keep indexes aligned
        low = t
    for kw in _ASSIGN_KEYWORDS:
        i, hits = low.find(kw), 0
        while i >= 0 and hits < MAX_ASSIGN_HITS:
            m = _ASSIGN_TAIL.match(t, i + len(kw))
            if m:
                value = m.group(1)
                if _HAS_ALPHA.search(value) and _HAS_DIGIT.search(value):  # "mixed characters" only
                    found.append(("api_key_assignment", value))
            i, hits = low.find(kw, i + 1), hits + 1
    if "eyJ" in t:
        for tok in _JWT_TOKEN.finditer(t):
            if _JWT_FULL.fullmatch(tok.group(0)):
                found.append(("jwt", tok.group(0)))
    return found

def find_secrets(args: dict) -> list[Match]:
    out: list[Match] = []
    for path, s in iter_strings(args):
        out.extend(Match(kind, mask_match(raw), path) for kind, raw in scan_secrets(s))
    return out


# ---------------- PII ----------------
def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _emails(t: str) -> list[str]:
    out: list[str] = []
    start, count = 0, 0
    while count < MAX_EMAILS_PER_STRING:
        i = t.find("@", start)
        if i < 0:
            break
        count += 1
        start = i + 1
        lo = i
        while lo > 0 and i - lo < 64 and t[lo - 1] in _EMAIL_CHARS_L:
            lo -= 1
        hi = i + 1
        while hi < len(t) and hi - i < 256 and t[hi] in _EMAIL_CHARS_R:
            hi += 1
        local, domain = t[lo:i], t[i + 1 : hi].rstrip(".-")
        if local and _EMAIL_LOCAL.fullmatch(local) and _EMAIL_DOMAIN.fullmatch(domain):
            out.append(f"{local}@{domain}")
    return out


def scan_pii(text: str) -> list[tuple[str, str]]:
    t = normalize(text)
    found: list[tuple[str, str]] = [("email", e) for e in _emails(t)] if "@" in t else []
    for run_match in _NUMRUN.finditer(t):
        run = run_match.group(0)
        if len(run) > MAX_NUMRUN:
            continue
        for m in _CARD.finditer(run):
            digits = re.sub(r"\D", "", m.group(0))
            if len(digits) == 16 and luhn_ok(digits):
                found.append(("card_number", m.group(0)))
        found.extend(("national_id", m.group(0)) for m in _ID12.finditer(run))
        for m in _PHONE.finditer(run):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            has_separator = raw.startswith("+") or any(c in raw for c in " ()-.")
            if 10 <= len(digits) <= 15 and has_separator and not (len(digits) == 12 and raw.replace(" ", "").isdigit()):
                found.append(("phone", raw))
    return found

def find_pii(args: dict) -> list[Match]:
    out: list[Match] = []
    for path, s in iter_strings(args):
        out.extend(Match(kind, mask_match(raw), path) for kind, raw in scan_pii(s))
    return out
