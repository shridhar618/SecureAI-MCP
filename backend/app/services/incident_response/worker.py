"""Subprocess entry point: executes MCP tool calls and prints the results.

Usage (internal):  python -m app.services.incident_response.worker
Reads one JSON object on stdin:
    {"timeout": 30, "calls": [{"name", "server": {...}, "tool", "arguments": {...}}]}
Writes a JSON list on stdout, one {"name", "ok", "detail"} per call.

Calls are independent: a failure in one never prevents the others.
"""

import asyncio
import json
import sys

from app.services.incident_response.client import call_tool
from app.services.incident_response.config import expand_env


async def run_calls(payload):
    timeout = payload.get("timeout", 30)
    results = []
    for call in payload.get("calls", []):
        server = dict(call["server"])
        server["env"] = expand_env(server.get("env", {}))
        outcome = await call_tool(server, call["tool"], call.get("arguments", {}), timeout)
        results.append({"name": call["name"], **outcome})
    return results


def main():
    payload = json.load(sys.stdin)
    results = asyncio.run(run_calls(payload))
    sys.stdout.write(json.dumps(results))


if __name__ == "__main__":
    main()
