"""Output injection scanner (F14).

Scans text that came back from an untrusted tool for instructions aimed at the agent. The score is a
noisy-or of fixed weights per matched pattern family, so one strong signal (an override phrase) or
several weaker ones push a result over the quarantine threshold. There is no model in this path.

Preprocessing: NFKC, strip zero-width and Unicode tag characters (their presence is itself a family;
tag characters are also decoded, because they can spell hidden ASCII), fold Cyrillic and Greek
lookalikes to Latin, pull out text hidden in HTML comments and hidden elements, and decode base64 blobs
one level.

Performance: every family is found by first locating a cheap literal anchor (a verb, a bracket, a tag)
and then matching a short, bounded window behind it. No pattern is applied at every position of a long
input, so hostile text (a million repeated anchors, unclosed comments, endless brackets) costs time
proportional to its length. The scanned text is capped.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from bisect import bisect_left

from firewall import inspect_args

MAX_SCAN_CHARS = 256 * 1024  # equals the result cap (F33): the gateway never hands the scanner more than this per text
SNIPPET_BYTES = 2048
MAX_HIDDEN_ELEMENTS = 50
MAX_HIDDEN_CHARS = 64 * 1024

FAMILY_WEIGHTS = {
    "override_phrase": 0.9,
    "fake_role_header": 0.7,
    "addressed_to_agent": 0.6,
    "exfil_verb_target": 0.7,
    "tool_call_request": 0.5,
    "markdown_exfil": 0.7,
    "hide_from_user": 0.8,
    "hidden_chars": 0.4,
}

# Lookalikes that survive NFKC (Cyrillic and Greek letters that look like Latin ones).
_CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "γ": "y", "η": "n", "μ": "u", "ω": "w",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x",
    "У": "y", "І": "i", "Ј": "j", "Ѕ": "s", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k",
    "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

_STRIP = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x200E, 0x200F, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E]
    + list(range(0xE0000, 0xE0080)))
_TAG_CHARS = re.compile("[\U000e0020-\U000e007e]+")
_TAG_CHARS_ANY = re.compile("[\U000e0000-\U000e007f]+")
_ASCII_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

_OPEN_TAG = re.compile(r"<([A-Za-z][A-Za-z0-9]{0,10})(\s[^<>]{0,300})?>")
_HIDDEN_ATTR = ("hidden", "display:none", "display: none", "visibility:hidden", "visibility: hidden",
                "font-size:0", "font-size: 0", "opacity:0", "opacity: 0", 'aria-hidden="true"', "aria-hidden='true'")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_EMAIL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._%+-")
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
# Words that on their own make "send ..." suspicious (no destination needed), and data words that count once a
# destination is also present.
STRICT_WORDS = ("secret", "password", "credential", "api key", "api_key", "apikey", "api-key", "token",
                "private key", "ssh key")
_NOT_A_VERB_AFTER_EMAIL = frozenset({"address", "addresses", "account", "accounts", "client", "server", "list", "body",
                                     "subject", "message", "template", "notification", "notifications", "service",
                                     "provider", "id", "ids", "settings", "inbox", "alias", "domain"})
_NEGATION_WORDS = ("never", " not ", "n't", "cannot", "no one", "nobody", "avoid")
_NEXT_WORD = re.compile(r"\s+([a-z]+)")

# ---- anchors (cheap) and tails (bounded windows) ----
_OVERRIDE_ANCHOR = re.compile(r"\b(?:ignore|disregard|forget|override|bypass|discard)\b")
_OVERRIDE_TAIL = re.compile(
    r"[^.\n]{0,20}?\b(?:previous|prior|above|earlier|preceding|all|any|your|the|these|those|everything)\b"
    r"[^.\n]{0,20}?\b(?:instructions?|prompts?|rules?|guidelines?|directives?|context|messages?|commands?|above)\b")
_OVERRIDE_SYSTEM = re.compile(
    r"\bsystem prompt\b[^.\n]{0,20}\b(?:ignore|disregard|override|reveal)\b|\bnew instructions?\s*:"
    r"|\bfrom now on\b[^.\n]{0,30}\byou (?:will|must|are|shall)\b|\bhenceforth\b[^.\n]{0,30}\byou (?:will|must|are|shall)\b")
_OVERRIDE_SYSPROMPT_TAIL = re.compile(r"[^.\n]{0,20}\bsystem prompt\b")
_ROLE_TOKEN = re.compile(r"<\|?\s*(?:im_start|im_end|system|assistant|endoftext)\s*\|?>|\[\s*(?:system|inst|/inst)\s*\]|<<\s*sys\s*>>")
_ROLE_LINE = re.compile(r"(?:^|\n)[ \t>#*]{0,6}(?:system|assistant|developer)[ \t]*(?:message|prompt)?[ \t]*:([^\n]{0,200})")
_ROLE_LINE_INSTRUCTION = re.compile(r"\b(?:you|your|must|should|always|never|ignore|obey|approve|respond|answer|execute|grant|comply|follow)\b")
_ROLE_HEADING = re.compile(r"(?:^|\n)#{1,4}[ \t]*(?:system|instructions?)\b")
_AGENT_WORDS = r"(?:ai|a\.i\.|assistant|agent|llm|language model|model|chatbot|claude|chatgpt|gpt|copilot)"
_ADDRESSED_A = re.compile(
    r"\b(?:notes?|messages?|instructions?|attention|important|hey|dear|hello|hi)\b[ ,:]{0,3}(?:to|for)?\s*(?:the\s+)?"
    + _AGENT_WORDS + r"\b")
_ADDRESSED_IMPERATIVE = re.compile(
    r"\b(?:ai|llm|assistant|agent|model|chatbot)\b[ ]{0,1}[,:][ ]{0,2}(?:please\s+)?"
    r"(?:send|forward|email|e-mail|upload|post|read|open|call|run|execute|do|ignore|reply|respond|summari[sz]e|add|include|"
    r"visit|click|fetch|download|delete|write|copy|share|output|print|reveal|tell|use|first|now|immediately|must|should|before)\b")
_ADDRESSED_B = re.compile(
    r"\b(?:ai|llm|assistant|agent|model|chatbot)\b[ ,:]{1,3}(?:please\s+)?(?:you\s+(?:must|should|need|will|have to)|must|should|now|immediately|first|before)\b"
    r"|\bif you are (?:an?\s+)?(?:ai|llm|language model|assistant|chatbot|agent)\b"
    r"|\bwhen (?:you|the (?:ai|assistant|agent|model)) (?:read|reads|see|sees|process|processes|summari[sz]e|summari[sz]es)\b[^.\n]{0,40}\b(?:this|the following)\b"
    r"|\bas an? (?:ai|llm|language model|assistant|agent)\b[^.\n]{0,30}\byou (?:must|should|will|need)\b")
_EXFIL_VERBS = ("send", "forward", "email", "e-mail", "upload", "post", "transmit", "exfiltrate", "leak", "ship",
                "submit", "copy", "relay", "share")
_AGENT_ANY = re.compile(r"\b(?:ai|a\.i\.|llm|assistant|agent|model|chatbot|claude|chatgpt|gpt|copilot)\b")
_EXFIL_ANCHOR = re.compile(r"\b(?:send|forward|e-?mail|upload|post|transmit|exfiltrate|leak|ship|submit|copy|relay|share)\b")
_SECRET_ANCHOR = re.compile(r"\b(?:secrets?|passwords?|credentials?|api[ _-]?keys?|tokens?|private keys?|ssh keys?|notes?|contents?|files?|data|documents?)\b")
_CONNECTOR = re.compile(r"[^.\n]{0,60}?\b(?:to|at|via|into)\b[^.\n]{0,20}$")
_TOOL_ANCHOR = re.compile(r"\b(?:call|invoke|use|run|execute|trigger)\b")
_TOOL_TAIL = re.compile(r"\s+(?:the\s+)?(?:`|\"|')?[a-z]{2,12}_[a-z_]{2,30}\b")
_QUERY_VALUE = re.compile(r"[?&][\w.-]{1,40}=[^&)\s\"'>]{12,}")
_HIDE = re.compile(
    r"\b(?:do not|don'?t|never|without|avoid|refrain from)\b[^.\n]{0,25}\b(?:tell|inform|notify|alert|mention|show|reveal|disclose|let)\b[^.\n]{0,30}\b(?:user|human|operator|owner|them)\b"
    r"|\b(?:keep|hide|conceal)\b[^.\n]{0,30}\b(?:secret|hidden|private|from the (?:user|human))\b[^.\n]{0,20}\b(?:from|to)\b[^.\n]{0,15}\b(?:user|human|operator)\b"
    r"|\bwithout (?:the )?(?:user|human)\b[^.\n]{0,20}\b(?:knowing|noticing|seeing|realizing|being aware)\b"
    r"|\b(?:user|human) (?:must|should|will) not (?:see|know|notice)\b"
    r"|\b(?:silently|secretly|quietly|covertly)\b[^.\n]{0,25}\b(?:send|forward|email|upload|post|run|execute|call|read|copy)\b")
_HIDE_ANCHOR = re.compile(r"\b(?:do not|don'?t|never|without|avoid|refrain|keep|hide|conceal|user|human|silently|secretly|quietly|covertly)\b")
_US_ME = re.compile(r"\s+(?:us|me)\b")


def fold(text: str) -> tuple[str, int]:
    """NFKC, strip invisible characters, fold lookalikes. Returns (folded text, weighted invisible count)."""
    t = text if text.isascii() else unicodedata.normalize("NFKC", text)
    strong = t.count("\u200b") + t.count("\u2060") + t.count("\ufeff") - (1 if t.startswith("\ufeff") else 0)
    strong += sum(len(run) for run in _TAG_CHARS_ANY.findall(t))
    weak_near_ascii = 0
    for joiner in ("\u200c", "\u200d"):
        total = t.count(joiner)
        if total > 2000:  # nobody writes that many joiners in a page; do not loop over them
            weak_near_ascii += total
            continue
        i = t.find(joiner)
        while i >= 0:
            # joiners are normal in emoji and in Indic and Arabic scripts; only count them inside ASCII words
            if (i > 0 and t[i - 1] in _ASCII_ALNUM) or (i + 1 < len(t) and t[i + 1] in _ASCII_ALNUM):
                weak_near_ascii += 1
            i = t.find(joiner, i + 1)
    hidden = strong + (weak_near_ascii if weak_near_ascii >= 3 else 0)
    return t.translate(_STRIP).translate(_CONFUSABLE_TABLE), hidden

def extract_hidden(text: str) -> list[str]:
    """Text a human reader would not see: HTML comments and hidden elements. Linear: uses find, never a
    pattern applied at every position."""
    out: list[str] = []
    total = 0
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0 or total >= MAX_HIDDEN_CHARS:
            break
        end = text.find("-->", start + 4)
        body_end = end if end >= 0 else len(text)  # an unclosed comment hides the rest of the page
        body = text[start + 4 : min(body_end, start + 4 + 4000)]
        out.append(body)
        total += len(body)
        if end < 0:
            break
        pos = end + 3
    lower = text.lower()
    count = 0
    for m in _OPEN_TAG.finditer(text):
        attrs = (m.group(2) or "").lower()
        if attrs and any(h in attrs for h in _HIDDEN_ATTR):
            close = lower.find("</" + m.group(1).lower(), m.end())
            stop = close if close >= 0 else len(text)
            out.append(text[m.end() : min(stop, m.end() + 4000)])
            count += 1
            if count >= MAX_HIDDEN_ELEMENTS:
                break
    return out


def _decoded_blobs(text: str) -> list[str]:
    out = []
    for m in _B64_BLOB.finditer(text):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=False)
            s = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if s and all(ord(c) >= 32 or c in "\t\n\r" for c in s):
            out.append(s)
        if len(out) >= 8:
            break
    return out


def _has_email(t: str, start: int, end: int) -> bool:
    """Is there an address in t[start:end]? Scans outward from each '@' with bounded steps."""
    at = t.find("@", start, end)
    tries = 0
    while at >= 0 and tries < 4:
        lo = at
        while lo > 0 and at - lo < 64 and t[lo - 1] in _EMAIL_CHARS:
            lo -= 1
        hi = at + 1
        while hi < len(t) and hi - at < 100 and t[hi] in _DOMAIN_CHARS:
            hi += 1
        domain = t[at + 1 : hi]
        if lo < at and "." in domain.strip(".") and domain[0] not in ".-":
            return True
        tries += 1
        at = t.find("@", at + 1, end)
    return False


def _negated(t: str, pos: int) -> bool:
    """Is the verb at pos negated earlier in the same sentence ("never send", "do not post")?"""
    prev = t[max(0, pos - 30) : pos].rsplit(".", 1)[-1].rsplit("\n", 1)[-1]
    return any(w in " " + prev for w in _NEGATION_WORDS)


def _sentence_end(t: str, start: int, limit: int) -> int:
    """End of the window: the limit, or the end of the sentence if that comes first."""
    end = min(len(t), start + limit)
    for sep in (". ", ".\n", "\n"):
        i = t.find(sep, start, end)
        if 0 <= i < end:
            end = i
    return end


def _positions(t: str, needle: str) -> list[int]:
    out, i = [], t.find(needle)
    while i >= 0 and len(out) < 50_000:
        out.append(i)
        i = t.find(needle, i + 1)
    return out


def _near(sorted_positions: list[int], start: int, end: int) -> bool:
    i = bisect_left(sorted_positions, start)
    return i < len(sorted_positions) and sorted_positions[i] < end


def _exfil(words: str) -> bool:
    # Cheap global checks first: with no destination and no secret word anywhere, nothing can match.
    dest = sorted(_positions(words, "@") + _positions(words, "http"))
    strict: list[int] = []
    for w in STRICT_WORDS:
        strict += _positions(words, w)
    strict.sort()
    if not dest and not strict:
        return False
    if any(v in words for v in _EXFIL_VERBS):
        for m in _EXFIL_ANCHOR.finditer(words):
            end = _sentence_end(words, m.end(), 100)
            if end <= m.end() or not (_near(dest, m.end(), end) or _near(strict, m.end(), min(end, m.end() + 80))):
                continue
            if _US_ME.match(words, m.end()):  # "email us at support@..." is contact information, not exfiltration
                continue
            nxt = _NEXT_WORD.match(words, m.end())
            if nxt and nxt.group(1) in _NOT_A_VERB_AFTER_EMAIL and words[m.start() : m.start() + 3] in ("ema", "e-m"):
                continue  # "email address", "email accounts": a noun, not the verb
            if _negated(words, m.start()):
                continue
            if _has_email(words, m.end(), end) or words.find("http", m.end(), end) >= 0:
                return True
            win = words[m.end() : min(end, m.end() + 80)]
            if any(w in win for w in STRICT_WORDS):
                return True
    if dest:
        for m in _SECRET_ANCHOR.finditer(words):
            end = _sentence_end(words, m.end(), 90)
            if end <= m.end() or not _near(dest, m.end(), end):
                continue
            url = words.find("http", m.end(), end)
            at = words.find("@", m.end(), end)
            target = url if url >= 0 else at
            if target < 0 or _negated(words, m.start()):
                continue
            if _CONNECTOR.match(words, m.end(), target) and (url >= 0 or _has_email(words, m.end(), end)):
                return True
    return False

_OVERRIDE_WORDS = ("ignore", "disregard", "forget", "override", "bypass", "discard", "new instruction", "from now on",
                   "henceforth", "system prompt")


def _override(words: str) -> bool:
    if not any(w in words for w in _OVERRIDE_WORDS):
        return False
    n = len(words)
    for m in _OVERRIDE_ANCHOR.finditer(words):
        end = min(n, m.end() + 90)
        if _OVERRIDE_TAIL.match(words, m.end(), end) or _OVERRIDE_SYSPROMPT_TAIL.match(words, m.end(), end):
            return True
    return _OVERRIDE_SYSTEM.search(words) is not None

def _fake_role(raw_lower: str) -> bool:
    if not any(w in raw_lower for w in ("system", "assistant", "developer", "<|", "[inst", "[/inst", "<<")):
        return False
    if _ROLE_TOKEN.search(raw_lower) or _ROLE_HEADING.search(raw_lower):
        return True
    return any(_ROLE_LINE_INSTRUCTION.search(m.group(1)) for m in _ROLE_LINE.finditer(raw_lower))


def _addressed(words: str) -> bool:
    if _AGENT_ANY.search(words) is None and "language model" not in words:
        return False
    return bool(_ADDRESSED_A.search(words) or _ADDRESSED_IMPERATIVE.search(words) or _ADDRESSED_B.search(words))


def _tool_call(words: str) -> bool:
    if "_" not in words:  # tool names contain an underscore
        return False
    return any(_TOOL_TAIL.match(words, m.end(), min(len(words), m.end() + 60)) for m in _TOOL_ANCHOR.finditer(words))


def _markdown_exfil(raw_lower: str) -> bool:
    """A markdown image or link, or an <img>, whose URL carries query data."""
    n = len(raw_lower)
    pos = 0
    for _ in range(2000):
        i = raw_lower.find("](http", pos)
        if i < 0:
            break
        pos = i + 6
        close = raw_lower.find(")", i, min(n, i + 700))
        if close < 0:
            continue
        if raw_lower.rfind("[", max(0, i - 200), i) >= 0 and _QUERY_VALUE.search(raw_lower, i, close):
            return True
    pos = 0
    for _ in range(2000):
        i = raw_lower.find("<img", pos)
        if i < 0:
            break
        pos = i + 4
        end = min(n, i + 500)
        if raw_lower.find("http", i, end) >= 0 and _QUERY_VALUE.search(raw_lower, i, end):
            return True
    return False


def _hide_from_user(words: str) -> bool:
    if not any(w in words for w in ("user", "human", "operator", "owner", "them", "secret", "hidden", "hide", "conceal", "silently", "quietly", "covertly")):
        return False
    n = len(words)
    for m in _HIDE_ANCHOR.finditer(words):
        if _HIDE.match(words, m.start(), min(n, m.start() + 140)):
            return True
    return False


def _match_families(raw_lower: str, words: str) -> set[str]:
    fam: set[str] = set()
    if _override(words):
        fam.add("override_phrase")
    if _fake_role(raw_lower):
        fam.add("fake_role_header")
    if _addressed(words):
        fam.add("addressed_to_agent")
    if _exfil(words):
        fam.add("exfil_verb_target")
    if _tool_call(words):
        fam.add("tool_call_request")
    if _markdown_exfil(raw_lower):
        fam.add("markdown_exfil")
    if _hide_from_user(words):
        fam.add("hide_from_user")
    return fam


def injection_score(text: str) -> tuple[float, list[str]]:
    """Noisy-or score in [0, 1] and the sorted list of matched families."""
    return _score(_families(text[:MAX_SCAN_CHARS]))


def injection_score_many(texts: list[str]) -> tuple[float, list[str]]:
    """Score several texts (the blocks of one result) together: families found in any of them count, so an
    instruction split across blocks still combines. Each text is scanned separately and capped."""
    fam: set[str] = set()
    for t in texts:
        fam |= _families(t[:MAX_SCAN_CHARS])
    return _score(fam)


def _score(fam: set[str]) -> tuple[float, list[str]]:
    keep = 1.0
    for f in fam:
        keep *= 1.0 - FAMILY_WEIGHTS[f]
    return round(1.0 - keep, 4), sorted(fam)


def _families(text: str) -> set[str]:
    folded, hidden = fold(text)
    pieces = [folded]
    # Unicode tag characters (U+E0020..U+E007E) spell ASCII invisibly: decode them so the hidden text is scanned
    tag_text = "".join(chr(ord(c) - 0xE0000) for run in _TAG_CHARS.findall(text) for c in run)
    if tag_text:
        pieces.append(fold(tag_text)[0])
    pieces += [fold(h)[0] for h in extract_hidden(text)]
    pieces += [fold(blob)[0] for blob in _decoded_blobs(text)]
    raw_lower = "\n".join(pieces).lower()
    words = raw_lower.replace("<", " ").replace(">", " ")  # markup becomes spaces; attribute words stay readable
    fam = _match_families(raw_lower, words)
    if hidden:
        fam.add("hidden_chars")
    return fam


def mask_secrets(text: str) -> str:
    """Replace detected secrets with a short placeholder (used for the audit snippet)."""
    out = text
    for kind, raw in inspect_args.scan_secrets(text):
        out = out.replace(raw, f"[{kind}#{inspect_args.short_hash(raw)}]")
    return out


def snippet(text: str) -> str:
    """At most 2 KB of the scanned text, secrets masked, for the operator's review."""
    return mask_secrets(text)[:SNIPPET_BYTES]
