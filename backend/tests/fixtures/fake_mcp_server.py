"""Tiny stdio MCP server for tests: records every tool call to a file."""
import json
import os
import sys

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("fake-tools")
LOG = os.environ["FAKE_MCP_LOG"]


def _record(tool, args):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"tool": tool, "args": args}) + "\n")


@mcp.tool()
def create_issue(title: str, body: str, labels: list[str] | None = None) -> str:
    _record("create_issue", {"title": title, "body": body, "labels": labels})
    return "issue #1 created"


@mcp.tool()
def post_message(text: str) -> str:
    _record("post_message", {"text": text})
    return "sent"


@mcp.tool()
def always_fails(text: str) -> str:
    raise RuntimeError("boom")


if __name__ == "__main__":
    mcp.run("stdio")
