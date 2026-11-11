"""Walking strings in arguments and results (F09, F12, F40 basics).

Arguments are JSON-like (dict, list, str, numbers). Results are fastmcp ToolResult objects whose
text lives in `content` (TextContent, embedded text resources) and `structured_content`.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def iter_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (path, string) for every string value anywhere inside obj (iterative, no recursion limit)."""
    stack: list[tuple[str, Any]] = [(path, obj)]
    while stack:
        p, v = stack.pop()
        if isinstance(v, str):
            yield p, v
        elif isinstance(v, dict):
            for k, x in reversed(list(v.items())):
                stack.append((f"{p}.{k}" if p else str(k), x))
        elif isinstance(v, (list, tuple)):
            for i, x in reversed(list(enumerate(v))):
                stack.append((f"{p}[{i}]", x))


def extract_text(result: Any) -> list[str]:
    """Every string a result carries: text blocks, embedded text resources, structured content leaves."""
    if isinstance(result, str):
        return [result]
    if isinstance(result, (dict, list, tuple)):
        return [s for _, s in iter_strings(result)]
    out: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            out.append(text)
            continue
        resource = getattr(block, "resource", None)  # embedded resource
        rtext = getattr(resource, "text", None)
        if isinstance(rtext, str):
            out.append(rtext)
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        out.extend(s for _, s in iter_strings(structured))
    return out


def has_binary(result: Any) -> bool:
    """Does the result carry image, audio or embedded binary resource blocks? (F40)"""
    for block in getattr(result, "content", None) or []:
        if getattr(block, "type", None) in ("image", "audio"):
            return True
        resource = getattr(block, "resource", None)
        if resource is not None and getattr(resource, "blob", None):
            return True
    return False


def map_strings(obj: Any, fn, depth: int = 0) -> Any:
    """Copy of obj with fn applied to every string leaf (used by redaction)."""
    if isinstance(obj, str):
        return fn(obj)
    if depth > 64:
        return obj
    if isinstance(obj, dict):
        return {k: map_strings(v, fn, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [map_strings(v, fn, depth + 1) for v in obj]
    return obj


def map_result_strings(result: Any, fn) -> Any:
    """A copy of a ToolResult with fn applied to text blocks, embedded text resources and structured content."""
    new_content = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            new_content.append(block.model_copy(update={"text": fn(text)}))
            continue
        resource = getattr(block, "resource", None)
        rtext = getattr(resource, "text", None)
        if isinstance(rtext, str):
            new_content.append(block.model_copy(update={"resource": resource.model_copy(update={"text": fn(rtext)})}))
            continue
        new_content.append(block)
    update: dict[str, Any] = {"content": new_content}
    if getattr(result, "structured_content", None) is not None:
        update["structured_content"] = map_strings(result.structured_content, fn)
    return result.model_copy(update=update)
