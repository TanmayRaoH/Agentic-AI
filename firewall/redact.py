"""Output redaction (F15).

When policy `redact_private_secrets` is true, secrets found in results from private tools are replaced
by a placeholder that keeps a stable short hash, so the agent can still refer to "the key" without
holding it. Fingerprints are taken from the original text BEFORE redaction, so sending the unredacted
value out is still caught.
"""
from __future__ import annotations

from firewall import inspect_args


def redact(text: str) -> str:
    out = text
    for kind, raw in sorted(inspect_args.scan_secrets(text), key=lambda kv: -len(kv[1])):
        out = out.replace(raw, f"[REDACTED:{kind}#{inspect_args.short_hash(raw)}]")
    return out
