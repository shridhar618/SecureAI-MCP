"""Decides what to do for an incident, audits it, and runs the MCP calls."""

import json
import logging
import subprocess
import sys
import threading

from flask import current_app

from app import db
from app.services.audit import record_audit_event
from app.services.incident_response.config import ConfigError, load_config
from app.services.incident_response.payload import build_incident, render

log = logging.getLogger(__name__)

_BACKEND_DIR = None


def _backend_dir():
    global _BACKEND_DIR
    if _BACKEND_DIR is None:
        from pathlib import Path
        _BACKEND_DIR = str(Path(__file__).resolve().parents[3])
    return _BACKEND_DIR


def _audit(user, action, status, detail, kind, risk_level="high", mode=None):
    record_audit_event(
        "mcp_incident_action",
        user=user,  # audit_logs.user_id is NOT NULL; row is the subject's, action is automated
        description=f"[automated] MCP {action.name}: {detail}"[:500],
        resource=f"mcp:{action.server}.{action.tool}",
        status=status,
        risk_level=risk_level,
        metadata={"incident_kind": kind, "subject": user.username, "mode": mode, "action": action.name},
    )


def _execute(app, config, calls, user_id, kind, actions):
    """Runs in a background thread: spawn the worker, audit each outcome."""
    request = json.dumps({"timeout": config.timeout_seconds, "calls": calls})
    outcomes = {}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "app.services.incident_response.worker"],
            input=request,
            capture_output=True,
            text=True,
            cwd=_backend_dir(),
            timeout=config.timeout_seconds * max(len(calls), 1) + 15,
        )
        if proc.returncode == 0:
            outcomes = {r["name"]: r for r in json.loads(proc.stdout or "[]")}
        else:
            err = (proc.stderr or "worker failed").strip().splitlines()[-1:] or ["worker failed"]
            outcomes = {a.name: {"ok": False, "detail": err[0]} for a in actions}
    except Exception as exc:  # noqa: BLE001
        outcomes = {a.name: {"ok": False, "detail": f"{type(exc).__name__}: {exc}"} for a in actions}

    with app.app_context():
        from app.models.user import User
        user = db.session.get(User, user_id)
        for action in actions:
            result = outcomes.get(action.name, {"ok": False, "detail": "no result returned"})
            try:
                _audit(
                    user, action,
                    "allowed" if result["ok"] else "failed",
                    result["detail"], kind,
                    risk_level="low" if result["ok"] else "medium",
                    mode="live",
                )
            except Exception:  # noqa: BLE001
                log.exception("Could not audit MCP action %s", action.name)


def dispatch_incident(kind, user, risk_event, case=None, reason=None):
    """Entry point called by the risk engine after its commit succeeds.

    Returns the background thread when live actions were started (tests
    join it), otherwise None. Never raises: incident automation must not
    break the request that produced the risk event.
    """
    try:
        config = load_config()
        if config.mode == "off":
            return None
        actions = config.actions_for(kind)
        if not actions:
            return None

        incident = build_incident(kind, user, risk_event, case=case, reason=reason)

        if config.mode == "dry_run":
            for action in actions:
                preview = json.dumps(render(action.arguments, incident), sort_keys=True)
                _audit(user, action, "dry_run", f"would call with {preview}", kind,
                       risk_level="low", mode="dry_run")
            return None

        calls = [
            {
                "name": action.name,
                "server": {
                    "command": config.servers[action.server].command,
                    "args": config.servers[action.server].args,
                    "env": config.servers[action.server].env,
                },
                "tool": action.tool,
                "arguments": render(action.arguments, incident),
            }
            for action in actions
        ]
        for action in actions:
            _audit(user, action, "queued", "dispatching to MCP server", kind,
                   risk_level="low", mode="live")

        app = current_app._get_current_object()
        thread = threading.Thread(
            target=_execute,
            args=(app, config, calls, user.id, kind, actions),
            daemon=True,
            name="mcp-incident-dispatch",
        )
        thread.start()
        return thread
    except ConfigError as exc:
        log.error("Incident MCP config problem: %s", exc)
    except Exception:  # noqa: BLE001
        log.exception("Incident MCP dispatch failed")
    return None
