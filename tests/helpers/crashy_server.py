"""Test-only upstream that misbehaves on purpose (F01 failure tests)."""
import os
import time

from fastmcp import FastMCP

mcp = FastMCP("crash")


@mcp.tool
def ok() -> str:
    """Works."""
    return "fine"


@mcp.tool
def boom() -> str:
    """Kills the whole server process."""
    os._exit(1)


@mcp.tool
def slow() -> str:
    """Takes far too long."""
    time.sleep(30)
    return "late"


if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="error")
