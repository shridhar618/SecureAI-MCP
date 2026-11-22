"""MCP activity analytics endpoint."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app import db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.audit import record_audit_event


def _call(username, tool, status="allowed", reason=None, target=None, age=timedelta(0)):
    user = User.query.filter_by(username=username).first()
    meta = {"tool": tool, "status": status, "args_summary": {"limit": 5}}
    if reason:
        meta["reason_code"] = reason
    if target:
        meta["target"] = target
    row = record_audit_event("mcp_tool_call", user=user, description=f"MCP tool call: {tool} ({status})",
                             resource=tool, status=status, metadata=meta)
    if age:
        row.timestamp = datetime.now(UTC) - age
        db.session.commit()
    return row


@pytest.fixture()
def seeded(app):
    with app.app_context():
        _call("admin", "get_risk_events")
        _call("admin", "get_risk_events")
        _call("admin", "get_audit_log")
        _call("intern_bob", "get_audit_log", "denied", "permission")
        _call("intern_bob", "get_risk_events", "denied", "permission")
        _call("intern_bob", "get_risk_events", "denied", "rate_limited")
        _call("hr_jane", "open_governance_case", "allowed", target="GOV-009")
        _call("admin", "get_risk_events", age=timedelta(days=3))
        _call("admin", "get_risk_events", age=timedelta(days=20))   # outside the 7d default
        # noise that must not be counted
        record_audit_event("login", user=User.query.filter_by(username="admin").first(), description="login")


def test_requires_admin(client, auth_headers):
    assert client.get("/api/mcp/activity").status_code == 401
    for creds in [("intern_bob", "intern123"), ("hr_jane", "hr123")]:
        assert client.get("/api/mcp/activity", headers=auth_headers(*creds)).status_code == 403


def test_aggregates_default_window(client, auth_headers, seeded):
    d = client.get("/api/mcp/activity", headers=auth_headers("admin", "admin123")).get_json()
    assert d["window"] == "7d"
    assert d["total_calls"] == 8 and d["allowed"] == 5 and d["denied"] == 3
    assert d["denial_rate"] == round(3 / 8, 4) and d["truncated"] is False
    tools = {t["tool"]: t for t in d["by_tool"]}
    assert tools["get_risk_events"]["calls"] == 5 and tools["get_risk_events"]["denied"] == 2
    assert tools["get_audit_log"]["denied"] == 1
    callers = {c["username"]: c for c in d["by_caller"]}
    assert callers["intern_bob"]["denied"] == 3 and callers["intern_bob"]["allowed"] == 0
    assert callers["admin"]["calls"] == 4
    assert {r["reason"]: r["count"] for r in d["denial_reasons"]} == {"permission": 2, "rate_limited": 1}
    assert sum(x["allowed"] + x["denied"] for x in d["per_day"]) == 8
    assert d["by_tool"][0]["calls"] >= d["by_tool"][-1]["calls"]          # sorted by volume


def test_window_selection(client, auth_headers, seeded):
    h = auth_headers("admin", "admin123")
    assert client.get("/api/mcp/activity?window=24h", headers=h).get_json()["total_calls"] == 7
    assert client.get("/api/mcp/activity?window=30d", headers=h).get_json()["total_calls"] == 9
    assert client.get("/api/mcp/activity?window=forever", headers=h).status_code == 400
    assert client.get("/api/mcp/activity?window='; DROP TABLE users;--", headers=h).status_code == 400


def test_recent_list_is_minimal_and_ordered(client, auth_headers, seeded):
    d = client.get("/api/mcp/activity", headers=auth_headers("admin", "admin123")).get_json()
    assert d["recent"][0]["tool"] != "login"
    assert set(d["recent"][0]) == {"id", "timestamp", "username", "tool", "status", "reason_code", "target"}
    ids = [r["id"] for r in d["recent"]]
    assert ids == sorted(ids, reverse=True)
    case_call = next(r for r in d["recent"] if r["tool"] == "open_governance_case")
    assert case_call["target"] == "GOV-009"
    blob = json.dumps(d)
    for leak in ("args_summary", "email", "password", "chain_hash"):
        assert leak not in blob


def test_empty_window(client, auth_headers):
    d = client.get("/api/mcp/activity", headers=auth_headers("admin", "admin123")).get_json()
    assert d["total_calls"] == 0 and d["denial_rate"] == 0.0 and d["by_tool"] == [] and d["recent"] == []
    assert len(d["per_day"]) >= 7


def test_real_mcp_calls_show_up(app, client, auth_headers):
    """End to end: calls made through the real MCP server appear in the analytics."""
    import asyncio
    from mcp.client import Client
    from app.mcp_server.server import build_server
    from app.models.mcp_token import McpToken

    with app.app_context():
        token = McpToken.mint(User.query.filter_by(username="intern_amy").first(), days=1)[1]

    async def run():
        async with Client(build_server(app, token_provider=lambda: token)) as c:
            await c.call_tool("get_risk_events", {})
            await c.call_tool("get_audit_log", {})   # denied for an intern
    asyncio.run(run())

    d = client.get("/api/mcp/activity", headers=auth_headers("admin", "admin123")).get_json()
    assert (d["allowed"], d["denied"]) == (1, 1)
    assert d["denial_reasons"] == [{"reason": "permission", "count": 1}]
