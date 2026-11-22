"""Admin API for MCP tokens."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app import db
from app.mcp_server.auth import AuthError, authenticate
from app.models.audit_log import AuditLog
from app.models.mcp_token import McpToken
from app.models.user import User


@pytest.fixture()
def admin_h(auth_headers):
    return auth_headers("admin", "admin123")


def _create(client, headers, **body):
    body.setdefault("username", "intern_bob")
    return client.post("/api/mcp/tokens", json=body, headers=headers)


def test_requires_authentication_and_admin(client, auth_headers):
    assert client.get("/api/mcp/tokens").status_code == 401
    for creds in [("intern_bob", "intern123"), ("hr_jane", "hr123")]:
        h = auth_headers(*creds)
        assert client.get("/api/mcp/tokens", headers=h).status_code == 403
        assert _create(client, h).status_code == 403
        assert client.post("/api/mcp/tokens/1/revoke", headers=h).status_code == 403


def test_create_returns_raw_token_once_and_it_authenticates(app, client, admin_h):
    res = _create(client, admin_h, label="claude-code", days=7)
    assert res.status_code == 201
    tok = res.get_json()["token"]
    assert tok["token"].startswith("sai_mcp_") and tok["username"] == "intern_bob" and tok["status"] == "active"

    with app.app_context():
        caller = authenticate(tok["token"])   # the minted token really works for the MCP server
        assert caller.username == "intern_bob"
        row = db.session.get(McpToken, tok["id"])
        assert row.token_hash != tok["token"] and tok["token"] not in json.dumps(row.label or "")

    listing = client.get("/api/mcp/tokens", headers=admin_h)
    assert listing.status_code == 200
    assert "token" not in json.dumps(listing.get_json()).replace('"tokens"', "")  # raw value never listed
    assert tok["token"] not in listing.get_data(as_text=True)
    assert "token_hash" not in listing.get_data(as_text=True)


@pytest.mark.parametrize("body", [
    {"username": ""}, {"username": None}, {"username": "nobody_here"}, {"days": 0}, {"days": 366},
    {"days": "30"}, {"days": True}, {"label": "x" * 81}, {"label": 5},
])
def test_create_validates_input(client, admin_h, body):
    assert _create(client, admin_h, **body).status_code in (400, 404)


def test_cannot_create_for_suspended_user(app, client, admin_h):
    with app.app_context():
        User.query.filter_by(username="intern_bob").first().is_active = False
        db.session.commit()
    assert _create(client, admin_h).status_code == 404


def test_active_token_cap_per_user(client, admin_h):
    for _ in range(10):
        assert _create(client, admin_h).status_code == 201
    assert _create(client, admin_h).status_code == 409


def test_revoke_blocks_mcp_use_and_is_idempotent(app, client, admin_h):
    tok = _create(client, admin_h).get_json()["token"]
    res = client.post(f"/api/mcp/tokens/{tok['id']}/revoke", headers=admin_h)
    assert res.status_code == 200 and res.get_json()["token"]["status"] == "revoked"
    with app.app_context():
        with pytest.raises(AuthError):
            authenticate(tok["token"])
    assert client.post(f"/api/mcp/tokens/{tok['id']}/revoke", headers=admin_h).status_code == 200
    assert client.post("/api/mcp/tokens/99999/revoke", headers=admin_h).status_code == 404
    with app.app_context():   # second revoke must not write a second audit row
        assert AuditLog.query.filter_by(event_type="mcp_token_revoked").count() == 1


def test_expired_status_reported(app, client, admin_h):
    tok = _create(client, admin_h).get_json()["token"]
    with app.app_context():
        db.session.get(McpToken, tok["id"]).expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.session.commit()
    rows = client.get("/api/mcp/tokens", headers=admin_h).get_json()["tokens"]
    assert [r["status"] for r in rows if r["id"] == tok["id"]] == ["expired"]


def test_create_and_revoke_are_audited_without_secrets(app, client, admin_h):
    tok = _create(client, admin_h).get_json()["token"]
    client.post(f"/api/mcp/tokens/{tok['id']}/revoke", headers=admin_h)
    with app.app_context():
        rows = AuditLog.query.filter(AuditLog.event_type.in_(["mcp_token_created", "mcp_token_revoked"])).all()
        assert sorted(r.event_type for r in rows) == ["mcp_token_created", "mcp_token_revoked"]
        assert all(r.username == "admin" for r in rows)
        assert all(tok["token"] not in (r.event_metadata or "") + r.query for r in rows)
