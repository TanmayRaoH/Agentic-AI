"""Demo web server. fetch() serves canned pages and records every request (it is a sink)."""
from common import fetch_page, log_call, record_web_request
from fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool
def fetch(url: str) -> str:
    """Fetch a web page and return its text."""
    log_call("web", "fetch", {"url": url})
    record_web_request(url)
    return fetch_page(url)


if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="error")

