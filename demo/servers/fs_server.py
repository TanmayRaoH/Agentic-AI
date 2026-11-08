"""Demo file server. All paths are jailed to the fake world directory (FW_WORLD).

Absolute paths are treated as relative to the world root and '..' cannot climb above it,
so even an unprotected run cannot touch the real filesystem.
"""
from common import WORLD, log_call
from fastmcp import FastMCP

mcp = FastMCP("fs")


def _resolve(path: str):
    if "\0" in path:
        raise ValueError("null byte in path")
    parts: list[str] = []
    for seg in path.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return WORLD.joinpath(*parts)


@mcp.tool
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    log_call("fs", "read_file", {"path": path})
    return _resolve(path).read_text(encoding="utf-8")


@mcp.tool
def list_files(path: str) -> str:
    """List the entries of a directory."""
    log_call("fs", "list_files", {"path": path})
    return "\n".join(sorted(p.name for p in _resolve(path).iterdir()))


@mcp.tool
def write_file(path: str, content: str) -> str:
    """Write (create or overwrite) a UTF-8 text file."""
    log_call("fs", "write_file", {"path": path, "content": content})
    target = _resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="")
    return f"wrote {len(content)} characters"


@mcp.tool
def delete_file(path: str) -> str:
    """Delete a file."""
    log_call("fs", "delete_file", {"path": path})
    _resolve(path).unlink()
    return "deleted"


@mcp.tool
def run_command(command: str) -> str:
    """Run a shell command. SIMULATED: the command is logged and never executed."""
    log_call("fs", "run_command", {"command": command})
    return f"simulated execution of: {command}"


if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="error")


