"""Admin API for the incident-alert (MCP client) settings.

Reads and edits the `mode` of backend/mcp_servers.json and shows whether the
secrets it references are set. Secret VALUES are never read into a response:
only whether each ${VAR} is set. Servers, tools and routing stay in the file
(reviewed in git/ops), not editable from the browser.
"""

import json
import os
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

from flask import Blueprint, g, jsonify, request
from flask_jwt_extended import jwt_required

from app.models.audit_log import AuditLog
from app.services.audit import record_audit_event
from app.services.incident_response.config import (
    INCIDENT_KINDS, MODES, ConfigError, config_path, load_config,
)
from app.services.incident_response.payload import build_incident, render
from app.utils.authz import require_permission

incident_settings_bp = Blueprint("incident_settings", __name__)

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
RECENT = 15


def _referenced_vars(raw):
    found = []
    for var in _VAR.findall(json.dumps(raw.get("servers", {})) + json.dumps(raw.get("actions", []))):
        if var not in found:
            found.append(var)
    return found


def _read_raw(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _mode_source(raw):
    if (os.getenv("INCIDENT_MCP_MODE") or "").strip():
        return "env"
    return "file" if raw is not None and raw.get("mode") else "default"


def _state():
    path = config_path()
    exists = path.is_file()
    raw = _read_raw(path) if exists else None
    state = {
        "modes": list(MODES),
        "config_file": {"name": path.name, "exists": exists, "valid": False, "error": None},
        "mode": "off", "mode_source": _mode_source(raw),
        "servers": [], "actions": [], "required_env": [],
    }
    if not exists:
        state["config_file"]["error"] = (
            f"{path.name} not found. Copy mcp_servers.example.json to {path.name} to enable alerts."
        )
        return state, None
    try:
        cfg = load_config(path)
    except ConfigError as exc:
        state["config_file"]["error"] = str(exc)
        return state, None
    state["config_file"]["valid"] = True
    state["mode"] = cfg.mode
    state["servers"] = [{"name": s.name, "command": s.command} for s in cfg.servers.values()]
    state["actions"] = [{"name": a.name, "server": a.server, "tool": a.tool, "on": list(a.on)} for a in cfg.actions]
    state["required_env"] = [{"name": v, "set": bool(os.environ.get(v))} for v in _referenced_vars(raw or {})]
    return state, cfg


def _recent():
    rows = (AuditLog.query.filter_by(event_type="mcp_incident_action")
            .order_by(AuditLog.id.desc()).limit(RECENT).all())
    out = []
    for r in rows:
        try:
            meta = json.loads(r.event_metadata) if r.event_metadata else {}
        except ValueError:
            meta = {}
        out.append({
            "id": r.id, "timestamp": r.timestamp.isoformat() + "Z" if r.timestamp else None,
            "action": meta.get("action"), "kind": meta.get("incident_kind"), "mode": meta.get("mode"),
            "subject": meta.get("subject"), "status": r.status, "target": r.resource,
        })
    return out


@incident_settings_bp.route("/incident-alerts", methods=["GET"])
@jwt_required()
@require_permission("system_configuration_admin")
def get_settings():
    state, _ = _state()
    state["recent"] = _recent()
    return jsonify(state), 200


@incident_settings_bp.route("/incident-alerts/mode", methods=["PUT"])
@jwt_required()
@require_permission("system_configuration_admin")
def set_mode():
    data = request.get_json(silent=True) or {}
    new_mode = data.get("mode")
    if new_mode not in MODES:
        return jsonify({"error": f"mode must be one of: {', '.join(MODES)}"}), 400

    state, cfg = _state()
    if cfg is None:
        return jsonify({"error": state["config_file"]["error"] or "Incident config is not valid."}), 409
    if (os.getenv("INCIDENT_MCP_MODE") or "").strip():
        return jsonify({"error": "The INCIDENT_MCP_MODE environment variable overrides the file. "
                                 "Change or unset it on the server instead."}), 409

    if new_mode == "live":
        missing = [v["name"] for v in state["required_env"] if not v["set"]]
        if missing:
            return jsonify({"error": "Cannot go live: these environment variables are not set.",
                            "missing_env": missing}), 409
        if not cfg.actions:
            return jsonify({"error": "Cannot go live: no actions are configured."}), 409
        if data.get("confirm") is not True:
            return jsonify({"error": "Going live sends real messages. Send confirm=true to proceed."}), 400

    old_mode = cfg.mode
    if new_mode != old_mode:
        path = config_path()
        raw = _read_raw(path) or {}
        raw["mode"] = new_mode
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mcp_servers.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(raw, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        record_audit_event(
            "incident_config_change", user=g.current_user,
            description=f"Incident alert mode changed: {old_mode} -> {new_mode}",
            resource="incident_alerts.mode", metadata={"from": old_mode, "to": new_mode},
        )
    state, _ = _state()
    state["recent"] = _recent()
    return jsonify(state), 200


@incident_settings_bp.route("/incident-alerts/preview", methods=["POST"])
@jwt_required()
@require_permission("system_configuration_admin")
def preview():
    """What each action WOULD send for a sample incident. Never contacts any
    external service and records nothing."""
    kind = (request.get_json(silent=True) or {}).get("kind")
    if kind not in INCIDENT_KINDS:
        return jsonify({"error": f"kind must be one of: {', '.join(INCIDENT_KINDS)}"}), 400
    state, cfg = _state()
    if cfg is None:
        return jsonify({"error": state["config_file"]["error"] or "Incident config is not valid."}), 409

    user = SimpleNamespace(username="sample_user", role="intern")
    event = SimpleNamespace(
        factors=json.dumps(["salary/compensation data", "threat: Sensitive data extraction"]),
        risk_level="high", risk_score=0.82, cumulative_score=1.74, audit_log_id=None, id=None,
    )
    case = SimpleNamespace(case_code=lambda: "GOV-000") if kind == "governance_case_opened" else None
    incident = build_incident(kind, user, event, case=case, reason="Sample incident for preview.")
    calls = [
        {"action": a.name, "server": a.server, "tool": a.tool, "arguments": render(a.arguments, incident)}
        for a in cfg.actions_for(kind)
    ]
    return jsonify({"kind": kind, "mode": cfg.mode, "sent": False, "sample": True, "calls": calls}), 200
