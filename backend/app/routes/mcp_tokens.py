"""Admin API for MCP tokens (see docs/MCP_SERVER.md).

The raw token is returned exactly once, at creation; only its SHA-256 hash
is stored, so it cannot be shown again. Every create/revoke is audited.
"""

from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request
from flask_jwt_extended import jwt_required

from app import db
from app.models.mcp_token import McpToken
from app.models.user import User
from app.services.audit import record_audit_event
from app.utils.authz import require_permission

mcp_tokens_bp = Blueprint("mcp_tokens", __name__)

MAX_DAYS = 365
MAX_ACTIVE_PER_USER = 10


def _naive_utc(value):
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _status(row, now):
    if row.revoked_at is not None:
        return "revoked"
    if _naive_utc(row.expires_at) <= now:
        return "expired"
    return "active"


def _iso(value):
    return value.isoformat() if value else None


def _serialize(row, now):
    return {
        "id": row.id,
        "username": row.user.username if row.user else None,
        "role": row.user.role if row.user else None,
        "label": row.label,
        "status": _status(row, now),
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "last_used_at": _iso(row.last_used_at),
        "revoked_at": _iso(row.revoked_at),
    }


@mcp_tokens_bp.route("/mcp/tokens", methods=["GET"])
@jwt_required()
@require_permission("system_configuration_admin")
def list_tokens():
    now = datetime.now(UTC).replace(tzinfo=None)
    rows = McpToken.query.order_by(McpToken.id.desc()).limit(500).all()
    return jsonify({"tokens": [_serialize(r, now) for r in rows]}), 200


@mcp_tokens_bp.route("/mcp/tokens", methods=["POST"])
@jwt_required()
@require_permission("system_configuration_admin")
def create_token():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    label = data.get("label") or ""
    days = data.get("days", 30)

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "username is required"}), 400
    if not isinstance(label, str) or len(label) > 80:
        return jsonify({"error": "label must be text of at most 80 characters"}), 400
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        return jsonify({"error": f"days must be a whole number between 1 and {MAX_DAYS}"}), 400

    user = User.query.filter_by(username=username.strip()).first()
    if user is None or user.is_active is False:
        return jsonify({"error": "No active user with that username"}), 404

    now = datetime.now(UTC).replace(tzinfo=None)
    active = sum(1 for t in McpToken.query.filter_by(user_id=user.id).all() if _status(t, now) == "active")
    if active >= MAX_ACTIVE_PER_USER:
        return jsonify({"error": f"That user already has {MAX_ACTIVE_PER_USER} active tokens; revoke one first"}), 409

    row, raw = McpToken.mint(user, days=days, label=label.strip())
    record_audit_event(
        "mcp_token_created",
        user=g.current_user,
        description=f"MCP token #{row.id} created for {user.username}",
        resource=f"mcp_token:{row.id}",
        metadata={"target": user.username, "days": days},
    )
    payload = _serialize(row, now)
    payload["token"] = raw  # shown once; never stored or returned again
    return jsonify({"token": payload}), 201


@mcp_tokens_bp.route("/mcp/tokens/<int:token_id>/revoke", methods=["POST"])
@jwt_required()
@require_permission("system_configuration_admin")
def revoke_token(token_id):
    row = db.session.get(McpToken, token_id)
    if row is None:
        return jsonify({"error": "Token not found"}), 404
    now = datetime.now(UTC).replace(tzinfo=None)
    if row.revoked_at is None:
        row.revoked_at = now
        db.session.commit()
        record_audit_event(
            "mcp_token_revoked",
            user=g.current_user,
            description=f"MCP token #{row.id} revoked (owner {row.user.username})",
            resource=f"mcp_token:{row.id}",
            metadata={"target": row.user.username},
        )
    return jsonify({"token": _serialize(row, now)}), 200
