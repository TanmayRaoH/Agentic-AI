"""Demo mail server. send_email() appends to mail_log.jsonl (a sink)."""
import time

from common import append, log_call
from fastmcp import FastMCP

mcp = FastMCP("mail")


@mcp.tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    log_call("mail", "send_email", {"to": to, "subject": subject, "body": body})
    append("mail_log.jsonl", {"ts": time.time(), "to": to, "subject": subject, "body": body})
    return f"email queued to {to}"


if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="error")

