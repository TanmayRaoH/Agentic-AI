"""Data-flow (taint) engine (F12, F13).

Private data that a tool returned is remembered per grant as hashed 12-character shingles
(winnowed) and as hashed exact tokens. Every sink call is compared against them after the
arguments are normalized and decoded (base64, hex, percent-encoding, reversal, ROT13, up to
two layers), so encodings, inserted spaces and dashes, case changes and chunking do not hide a leak.
No raw private text is stored. No model is involved.
"""
from __future__ import annotations

import base64
import codecs
import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from urllib.parse import unquote

from firewall import inspect_args
from firewall.config import AllowFlow
from firewall.content import iter_strings
from firewall.models import Verdict
from firewall.store import Store, iso, utcnow

SHINGLE = 12
WINDOW = 4
FP_THRESHOLD = 3  # winnowed fingerprints that must overlap
MIN_TOKEN = 8  # shorter exact tokens are ignored
SHORT_TEXT = 24  # below this a private result is stored as one exact token, not as shingles
FP_CAP = 50_000
EGRESS_BUFFER = 4096
MAX_DECODED_TOTAL = 1024 * 1024
MAX_CANDIDATES = 64
POLY_MOD = (1 << 61) - 1
POLY_BASE = 1_000_003

_ZERO_WIDTH = dict.fromkeys(
    [0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF]
    + list(range(0xE0000, 0xE0080)))
_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX_BLOB = re.compile(r"[0-9A-Fa-f]{8,}")
ALIGN_LIMIT = 64 * 1024  # try several base64 alignments only for inputs up to this size


# ---------------- normalization and fingerprints ----------------
def flow_normal(text: str) -> str:
    """NFKC, lowercase, drop zero-width characters, keep only letters and digits."""
    t = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).lower()
    return "".join(ch for ch in t if ch.isalnum())


def _h64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")


def to_signed(h: int) -> int:
    return h - (1 << 64) if h >= (1 << 63) else h


def fingerprints(text: str) -> set[int]:
    """Winnowed 12-character shingle hashes of the flow-normal form (unsigned 64-bit)."""
    return _winnow(flow_normal(text))


def _winnow(n: str) -> set[int]:
    if len(n) < SHINGLE:
        return set()
    hashes = [_h64(n[i : i + SHINGLE]) for i in range(len(n) - SHINGLE + 1)]
    if len(hashes) < WINDOW:
        return {min(hashes)}
    return {min(hashes[i : i + WINDOW]) for i in range(len(hashes) - WINDOW + 1)}


def poly_hash(s: str) -> int:
    h = 0
    for ch in s:
        h = (h * POLY_BASE + ord(ch)) % POLY_MOD
    return h


def token_record(norm: str) -> tuple[str, int, int]:
    return (hashlib.blake2b(norm.encode("utf-8"), digest_size=16).hexdigest(), len(norm), poly_hash(norm))


def find_exact(text: str, tokens: list[dict]) -> set[str]:
    """Rolling-hash substring search for stored exact tokens. Returns the source tools that matched.
    A rolling hash hit is verified with the real hash, so collisions cannot cause false matches."""
    by_len: dict[int, dict[int, list[dict]]] = {}
    for t in tokens:
        by_len.setdefault(t["length"], {}).setdefault(t["poly"], []).append(t)
    hits: set[str] = set()
    for length, table in by_len.items():
        if len(text) < length:
            continue
        top = pow(POLY_BASE, length - 1, POLY_MOD)
        h = 0
        for i, ch in enumerate(text):
            if i >= length:
                h = (h - ord(text[i - length]) * top) % POLY_MOD
            h = (h * POLY_BASE + ord(ch)) % POLY_MOD
            if i >= length - 1 and h in table:
                window = text[i - length + 1 : i + 1]
                digest = hashlib.blake2b(window.encode("utf-8"), digest_size=16).hexdigest()
                hits.update(t["source_tool"] for t in table[h] if t["token_hash"] == digest)
    return hits


# ---------------- decoding ----------------
def _printable_utf8(raw: bytes) -> str | None:
    """Accept a decoding only if it is valid UTF-8 text without control characters; random bytes almost never are."""
    if not raw or len(raw) > MAX_DECODED_TOTAL:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in s) else s


def _b64(blob: str, offset: int = 0) -> str | None:
    """Decode one base64 blob starting `offset` characters in (a glued-on prefix shifts the alignment)."""
    s = blob[offset:].replace("-", "+").replace("_", "/").rstrip("=")
    if len(s) % 4 == 1:
        s = s[:-1]
    s += "=" * (-len(s) % 4)
    try:
        return _printable_utf8(base64.b64decode(s, validate=False))
    except ValueError:
        return None


def _hex(blob: str, offset: int = 0) -> str | None:
    s = blob[offset:]
    s = s[: len(s) // 2 * 2]
    try:
        return _printable_utf8(bytes.fromhex(s))
    except ValueError:
        return None


def _decoders(text: str) -> list[tuple[str, str]]:
    """All blobs of one kind are decoded and joined into ONE candidate, so padding a message with junk blobs
    cannot push the real one out of the candidate list."""
    out: list[tuple[str, str]] = []
    if "%" in text:
        u = unquote(text)
        if u != text:
            out.append(("url", u))
    b64_blobs = _B64_BLOB.findall(text)
    if b64_blobs:
        for off in (0, 1, 2, 3) if len(text) <= ALIGN_LIMIT else (0,):
            parts = [d for b in b64_blobs if (d := _b64(b, off))]
            if parts:
                out.append(("b64", "\n".join(parts)))
    hex_blobs = _HEX_BLOB.findall(text)
    if hex_blobs:
        for off in (0, 1) if len(text) <= ALIGN_LIMIT else (0,):
            parts = [d for b in hex_blobs if (d := _hex(b, off))]
            if parts:
                out.append(("hex", "\n".join(parts)))
    if len(text) >= MIN_TOKEN:
        out.append(("rev", text[::-1]))
        out.append(("rot13", codecs.encode(text, "rot13")))
    return out

def candidate_items(text: str) -> list[tuple[str, tuple[str, ...]]]:
    """The raw text plus its decodings, at most two layers deep. Each item carries the decoder path."""
    items: list[tuple[str, tuple[str, ...]]] = [(text, ())]
    seen = {text}
    frontier = items
    total = len(text)
    for _ in range(2):
        nxt: list[tuple[str, tuple[str, ...]]] = []
        for t, path in frontier:
            for kind, d in _decoders(t):
                if d in seen:
                    continue
                total += len(d)
                if total > MAX_DECODED_TOTAL or len(items) + len(nxt) >= MAX_CANDIDATES:
                    break
                seen.add(d)
                nxt.append((d, (*path, kind)))
        items += nxt
        frontier = nxt
    return items


def candidates(text: str) -> list[str]:
    return [t for t, _ in candidate_items(text)]


# ---------------- private data registration ----------------
async def register_private(store: Store, grant_id: str, tool: str, text: str) -> None:
    """Remember a private tool result: fingerprints for long text, exact tokens for short text and for
    every secret-like substring found by the F09 detectors."""
    norm = flow_normal(text)
    now = iso(utcnow())
    tokens: list[tuple[str, int, int]] = []
    if SHORT_TEXT > len(norm) >= MIN_TOKEN:
        tokens.append(token_record(norm))
    elif len(norm) >= SHORT_TEXT:
        await store.add_fingerprints(grant_id, tool, [to_signed(h) for h in _winnow(norm)], now, FP_CAP)
    for _kind, raw in inspect_args.scan_secrets(text):
        n = flow_normal(raw)
        if len(n) >= MIN_TOKEN:
            tokens.append(token_record(n))
    if tokens:
        await store.add_exact_tokens(grant_id, tool, tokens, now)


# ---------------- egress check ----------------
@dataclass
class EgressResult:
    verdict: Verdict | None = None
    declassified: list[str] = field(default_factory=list)
    # (field key, flow-normal text) entries to remember once the call is allowed
    buffer_entries: list[tuple[str, str]] = field(default_factory=list)
    fp_overlap: int = 0  # distinct private fingerprints found in this call (shown to the operator, F16)


def _covered(sources: set[str], tool: str, allow_flows: list[AllowFlow]) -> bool:
    return all(any(fnmatchcase(s, f.from_) and fnmatchcase(tool, f.to) for f in allow_flows) for s in sources)


PAIR_ENTRIES = 32  # how many recent buffer entries are tried as neighbours of a new piece


async def evaluate_egress(store: Store, grant_id: str, tool: str, args: dict,
                          allow_flows: list[AllowFlow] | None = None) -> EgressResult:
    """Compare everything a sink call sends with the private data of the grant.

    The egress buffer is kept per argument field (and per encoding), so a secret sent in pieces through
    the same field is rejoined even when other arguments change between calls. Pieces are also tried
    next to the most recent entries of other fields."""
    leaves = list(iter_strings(args))
    if not leaves:
        return EgressResult()
    sources_text = [(p, s) for p, s in leaves]
    if len(leaves) > 1:
        sources_text.append(("*joined", "\n".join(s for _, s in leaves)))  # a secret split across arguments
    items: list[tuple[str, str, tuple[str, ...]]] = []  # (key, flow-normal text, decoder path)
    seen_norm: set[tuple[str, str]] = set()
    for key, s in sources_text:
        for text, path in candidate_items(s):
            n = flow_normal(text)
            full_key = key + (":" + "/".join(path) if path else "")
            if n and (full_key, n) not in seen_norm:
                seen_norm.add((full_key, n))
                items.append((full_key, n, path))
    result = EgressResult(buffer_entries=[
        (k, n) for k, n, path in items if "rev" not in path and "rot13" not in path and not k.startswith("*joined")])

    tokens = await store.list_exact_tokens(grant_id)
    have_fp = await store.fingerprint_count(grant_id) > 0
    if not tokens and not have_fp:
        return result
    entries = await store.get_egress_entries(grant_id)
    max_token = min(512, max((t["length"] for t in tokens), default=0))
    recent = entries[-PAIR_ENTRIES:]
    token_sources: set[str] = set()
    fp_hits: dict[int, set[str]] = {}

    async def scan(text: str, fingerprint: bool) -> None:
        nonlocal token_sources
        if tokens and len(text) >= MIN_TOKEN:
            token_sources |= find_exact(text, tokens)
        if have_fp and fingerprint and len(text) >= SHINGLE:
            fps = [to_signed(h) for h in _winnow(text)]
            if fps:
                for h, srcs in (await store.match_fingerprints(grant_id, fps)).items():
                    fp_hits.setdefault(h, set()).update(srcs)

    for key, n, _path in items:
        await scan(n, True)
        same = "".join(t for k, t in entries if k == key)
        if same:
            await scan(same + n, True)
        if tokens and max_token:  # pieces next to other fields' recent entries (tokens only, kept cheap)
            head, tail_len = n[: max_token - 1], max_token - 1
            for k2, e2 in recent:
                if k2 != key:
                    await scan(e2[-tail_len:] + head, False)
                    await scan(n[-tail_len:] + e2[:tail_len], False)
    fp_sources = set().union(*fp_hits.values()) if len(fp_hits) >= FP_THRESHOLD else set()
    result.fp_overlap = len(fp_hits)
    sources = token_sources | fp_sources
    if not sources:
        return result
    flows = allow_flows or []
    if flows and _covered(sources, tool, flows):
        result.declassified = sorted(sources)
        return result
    result.verdict = Verdict("deny", ["EXFIL_FLOW"], detail={
        "sources": sorted(sources), "exact_token_match": bool(token_sources), "fingerprint_overlap": len(fp_hits)})
    return result


async def check_egress(store: Store, grant_id: str, tool: str, args: dict,
                       allow_flows: list[AllowFlow] | None = None) -> Verdict | None:
    return (await evaluate_egress(store, grant_id, tool, args, allow_flows)).verdict


async def record_egress(store: Store, grant_id: str, entries: list[tuple[str, str]]) -> None:
    if entries:
        await store.append_egress_entries(grant_id, entries, EGRESS_BUFFER)