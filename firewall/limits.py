"""Size and complexity limits (F33)."""
from __future__ import annotations

from typing import Any

from firewall.models import Verdict

MAX_ARGS_BYTES = 64 * 1024  # approximate JSON size of all arguments
MAX_STRING_CHARS = 32 * 1024  # any single string value
MAX_DEPTH = 8  # nesting depth of dicts and lists (the top-level arguments object is depth 1)
MAX_LIST_ITEMS = 500
MAX_RESULT_BYTES = 256 * 1024
TRUNCATION_MARKER = "\n[Firewall] Result truncated at 256 KB. code=RESULT_TRUNCATED"


def _too_large(what: str, **detail) -> Verdict:
    return Verdict("deny", ["ARG_TOO_LARGE"], detail={"limit": what, **detail})


def check_arg_limits(args: dict) -> Verdict | None:
    """Iterative walk with early exit, so even hostile input is rejected in time proportional to the limit."""
    size = 0
    stack: list[tuple[Any, int]] = [(args, 1)]
    while stack:
        v, depth = stack.pop()
        if isinstance(v, str):
            if len(v) > MAX_STRING_CHARS:
                return _too_large("string_chars", chars=len(v))
            size += len(v.encode("utf-8", "surrogatepass")) + 2
        elif isinstance(v, dict):
            if depth > MAX_DEPTH:
                return _too_large("depth", depth=depth)
            for k, x in v.items():
                size += len(str(k)) + 4
                stack.append((x, depth + 1))
        elif isinstance(v, (list, tuple)):
            if depth > MAX_DEPTH:
                return _too_large("depth", depth=depth)
            if len(v) > MAX_LIST_ITEMS:
                return _too_large("list_items", items=len(v))
            size += 2
            stack.extend((x, depth + 1) for x in v)
        else:
            size += 8  # numbers, booleans, null
        if size > MAX_ARGS_BYTES:
            return _too_large("json_bytes", bytes_at_least=size)
    return None


def _text_bytes(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def _structured_bytes(obj: Any) -> int:
    from firewall.content import iter_strings

    return sum(_text_bytes(s) for _, s in iter_strings(obj))


def _trim_structured(obj: Any, budget: list[int], depth: int = 0) -> Any:
    """Copy of obj whose string leaves together fit in budget[0] bytes; the first cut string gets the marker."""
    if isinstance(obj, str):
        raw = obj.encode("utf-8", "surrogatepass")
        if len(raw) <= budget[0]:
            budget[0] -= len(raw)
            return obj
        cut = raw[: max(budget[0], 0)].decode("utf-8", "ignore")
        budget[0] = 0
        return cut + TRUNCATION_MARKER
    if depth > 64:
        return "[truncated]"
    if isinstance(obj, dict):
        return {k: _trim_structured(v, budget, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_trim_structured(v, budget, depth + 1) for v in obj]
    return obj


def cap_result(result: Any, max_bytes: int = MAX_RESULT_BYTES) -> tuple[Any, bool]:
    """Truncate text in a ToolResult to max_bytes (text blocks and structured copy are each capped) and append
    a marker. The shape of structured content is kept, because clients validate it against the tool's schema.
    Returns (result, truncated)."""
    content = getattr(result, "content", None)
    if content is None:
        return result, False
    total = sum(_text_bytes(b.text) for b in content if isinstance(getattr(b, "text", None), str))
    structured = getattr(result, "structured_content", None)
    structured_total = _structured_bytes(structured) if structured is not None else 0
    if total <= max_bytes and structured_total <= max_bytes:
        return result, False
    kept, budget = [], max_bytes
    for block in content:
        text = getattr(block, "text", None)
        if not isinstance(text, str):
            kept.append(block)  # binary and resource blocks are handled by F40
            continue
        raw = text.encode("utf-8", "surrogatepass")
        if budget <= 0:
            continue
        if len(raw) <= budget:
            kept.append(block)
            budget -= len(raw)
        else:
            cut = raw[:budget].decode("utf-8", "ignore")
            kept.append(block.model_copy(update={"text": cut + TRUNCATION_MARKER}))
            budget = 0
    update: dict[str, Any] = {"content": kept}
    if structured is not None:
        update["structured_content"] = _trim_structured(structured, [max_bytes])
    return result.model_copy(update=update), True