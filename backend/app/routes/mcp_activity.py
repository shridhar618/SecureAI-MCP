"""Admin analytics over MCP tool calls, built from the audit trail.

Every MCP call already writes an `mcp_tool_call` AuditLog row (see
app/mcp_server/server.py), so this reads that; nothing new is recorded.
Only tool names, usernames, statuses and reason codes are returned.
"""

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from app.models.audit_log import AuditLog
from app.utils.authz import require_permission

mcp_activity_bp = Blueprint("mcp_activity", __name__)

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
MAX_ROWS = 5000
RECENT = 50


def _meta(row):
    try:
        data = json.loads(row.event_metadata) if row.event_metadata else {}
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


@mcp_activity_bp.route("/mcp/activity", methods=["GET"])
@jwt_required()
@require_permission("ai_governance_admin")
def mcp_activity():
    window = request.args.get("window", "7d")
    if window not in WINDOWS:
        return jsonify({"error": f"window must be one of: {', '.join(WINDOWS)}"}), 400

    now = datetime.now(UTC).replace(tzinfo=None)
    since = now - WINDOWS[window]
    q = (
        AuditLog.query
        .filter(AuditLog.event_type == "mcp_tool_call", AuditLog.timestamp >= since)
        .order_by(AuditLog.id.desc())
    )
    total_in_window = q.count()
    rows = q.limit(MAX_ROWS).all()

    by_tool = defaultdict(lambda: Counter())
    by_caller = defaultdict(lambda: Counter())
    reasons = Counter()
    per_day = defaultdict(lambda: Counter())
    allowed = denied = 0
    last_seen = {}

    for r in rows:
        ok = r.status == "allowed"
        key = "allowed" if ok else "denied"
        allowed += ok
        denied += not ok
        tool = r.resource or "unknown"
        by_tool[tool][key] += 1
        by_caller[r.username][key] += 1
        last_seen.setdefault(r.username, r.timestamp)
        per_day[(r.timestamp.date().isoformat())][key] += 1
        if not ok:
            reasons[_meta(r).get("reason_code") or "unspecified"] += 1

    def rows_for(counter_map, label):
        out = [
            {label: name, "calls": c["allowed"] + c["denied"], "allowed": c["allowed"], "denied": c["denied"]}
            for name, c in counter_map.items()
        ]
        return sorted(out, key=lambda x: -x["calls"])

    callers = rows_for(by_caller, "username")
    for c in callers:
        c["last_seen"] = _iso(last_seen.get(c["username"]))

    days = []
    day = since.date()
    while day <= now.date():
        c = per_day.get(day.isoformat(), Counter())
        days.append({"date": day.isoformat(), "allowed": c["allowed"], "denied": c["denied"]})
        day += timedelta(days=1)

    recent = []
    for r in rows[:RECENT]:
        meta = _meta(r)
        recent.append({
            "id": r.id,
            "timestamp": _iso(r.timestamp),
            "username": r.username,
            "tool": r.resource,
            "status": r.status,
            "reason_code": meta.get("reason_code"),
            "target": meta.get("target"),
        })

    return jsonify({
        "window": window,
        "since": _iso(since),
        "total_calls": total_in_window,
        "analysed": len(rows),
        "truncated": total_in_window > len(rows),
        "allowed": allowed,
        "denied": denied,
        "denial_rate": round(denied / len(rows), 4) if rows else 0.0,
        "by_tool": rows_for(by_tool, "tool"),
        "by_caller": callers,
        "denial_reasons": [{"reason": k, "count": v} for k, v in reasons.most_common()],
        "per_day": days,
        "recent": recent,
    }), 200
