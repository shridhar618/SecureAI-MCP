"""MCP client: connects to one stdio MCP server and calls one tool.

Runs inside the worker subprocess (see worker.py), not in the Flask
process -- the web app uses eventlet/Socket.IO, and keeping asyncio and
child-process management out of it avoids interfering with that.
"""

import asyncio
import os

MAX_RESULT_CHARS = 500


def _result_text(result):
    parts = []
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if text:
            parts.append(text)
    return " ".join(parts)[:MAX_RESULT_CHARS]


async def call_tool(server, tool, arguments, timeout):
    """server: {"command": str, "args": list, "env": dict} (env already expanded).

    Returns {"ok": bool, "detail": str}. Never raises for tool/server
    failures -- the caller records the outcome and moves on.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=server["command"],
        args=server.get("args", []),
        env={**os.environ, **server.get("env", {})},
    )

    async def _run():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(tool, arguments)

    try:
        result = await asyncio.wait_for(_run(), timeout=timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "detail": f"timed out after {timeout}s"}
    except Exception as exc:  # noqa: BLE001 - report any transport/protocol failure
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:MAX_RESULT_CHARS]}

    text = _result_text(result)
    # mcp 2.x exposes is_error; 1.x exposed isError.
    if getattr(result, "is_error", False) or getattr(result, "isError", False):
        return {"ok": False, "detail": text or "tool reported an error"}
    return {"ok": True, "detail": text or "ok"}
