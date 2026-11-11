"""Approval queue (F16).

A call that only needs an approval (TRIFECTA_APPROVAL, PII_IN_ARGS, POLICY_APPROVAL, GRANT_APPROVAL) creates a
row here. The full arguments are kept ENCRYPTED, only while the row is pending, so the operator can see what
would be sent; they are deleted the moment the row is decided or expires. An approved row authorizes exactly one
call whose tool and canonical argument hash match, within 120 seconds of the decision. Scope `destination`
authorizes the same tool and destination for the rest of the grant, but only for approval-type reasons: every
hard-deny check still runs on every call.

Interface change vs Section 5.1: functions take the Store (and crypto) explicitly.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken

from firewall import audit, scan_output
from firewall.store import Store, iso, utcnow

MAX_AGE_S = 120  # an approval can be used for 120 seconds after it was given
DENIAL_AGE_S = 900  # how long a denial waits to be delivered to a retrying agent (deferred mode)
PREVIEW_CHARS = 500
MIN_KEY_CHARS = 16
POLL_S = 0.2


class ApprovalKeyError(ValueError):
    """FW_APPROVAL_KEY is missing or too short."""


class ApprovalCrypto:
    """Fernet encryption of pending-approval arguments with a key derived from FW_APPROVAL_KEY."""

    def __init__(self, secret: str | None):
        if not secret or len(secret) < MIN_KEY_CHARS:
            raise ApprovalKeyError(f"FW_APPROVAL_KEY must be set and at least {MIN_KEY_CHARS} characters long")
        derived = hashlib.sha256(b"agent-firewall pending approvals v1|" + secret.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, args: dict) -> bytes:
        return self._fernet.encrypt(json.dumps(args, ensure_ascii=False, default=str).encode("utf-8"))

    def decrypt(self, blob: bytes) -> dict | None:
        try:
            return json.loads(self._fernet.decrypt(bytes(blob)).decode("utf-8"))
        except (InvalidToken, ValueError, TypeError):
            return None  # wrong key or damaged data: the preview is unavailable, nothing else breaks


async def request(store: Store, crypto: ApprovalCrypto, grant_id: str, session_id: str, tool: str, args: dict,
                  reasons: list[str], scope: str = "once", *, ttl_s: float, destination: str | None = None,
                  detail: dict | None = None) -> str:
    """Create a pending approval and return its id. `reasons` are the approval-type reason codes. If an identical
    request is already pending, its id is returned and no second row is created."""
    now = utcnow()
    approval_id = "ap_" + secrets.token_hex(5)
    approval_id, _created = await store.insert_approval_unique({
        "id": approval_id, "grant_id": grant_id, "session_id": session_id, "tool": tool,
        "args_masked": audit.mask(args), "args_encrypted": crypto.encrypt(args), "args_hash": audit.args_hash(args),
        "reason_codes": list(reasons), "approval_scope": scope, "created_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=ttl_s)), "destination": destination, "detail": detail or {},
    }, iso(now))
    return approval_id


async def wait(store: Store, approval_id: str, timeout_s: float, poll_s: float = POLL_S) -> str:
    """Hold until the operator decides. Returns 'approved', 'denied' or 'expired'. On timeout (or if the caller is
    cancelled, e.g. the agent disconnected) the row is expired and its stored arguments are deleted."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    try:
        while True:
            row = await store.get_approval(approval_id)
            if row is None:
                return "expired"
            if row["status"] in ("approved", "denied", "expired"):
                return row["status"]
            if loop.time() >= deadline:
                if await store.expire_if_pending(approval_id):
                    return "expired"
                continue  # it was decided at the last moment: loop once more and report that decision
            await asyncio.sleep(min(poll_s, max(deadline - loop.time(), 0.01)))
    except asyncio.CancelledError:
        try:
            await asyncio.shield(store.expire_if_pending(approval_id))
        except Exception as exc:  # noqa: BLE001 - store already closed during shutdown: nothing left to clean
            logging.getLogger("firewall.approvals").debug("cleanup of %s skipped: %r", approval_id, exc)
        raise


async def consume(store: Store, approval_id: str, tool: str, args_hash: str, status: str = "approved") -> bool:
    """Use an approval (or deliver a denial) exactly once, and only for the same tool and canonical arguments."""
    age = MAX_AGE_S if status == "approved" else DENIAL_AGE_S
    return await store.consume_approval(approval_id, tool, args_hash, iso(utcnow() - timedelta(seconds=age)), status)


def preview(crypto: ApprovalCrypto | None, row: dict) -> dict:
    """What the operator sees: tool, destination, a 500-character content preview with secrets masked, the
    reasons and the number of private fingerprint matches. Needs the pending arguments, which exist only while
    the row is pending."""
    reasons = json.loads(row.get("reason_codes") or "[]")
    detail = json.loads(row.get("detail") or "{}")
    out = {
        "tool": row["tool"], "destination": row.get("destination"), "reasons": reasons,
        "private_matches": detail.get("private_matches", 0), "preview": None, "preview_available": False,
    }
    blob = row.get("args_encrypted")
    if crypto is None or not blob:
        return out
    args = crypto.decrypt(blob)
    if args is None:
        return out
    text = json.dumps(args, ensure_ascii=False, default=str)
    out["preview"] = scan_output.mask_secrets(text)[:PREVIEW_CHARS]
    out["preview_available"] = True
    return out
