import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import db
from app.models.audit_log import AuditLog
from app.models.governance_case import GovernanceCase
from app.models.user import User
from app.services.incident_response import dispatch_incident
from app.services.incident_response.config import ConfigError, load_config
from app.services.incident_response.payload import render
from app.services.risk_tracking import record_risk_event

FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")


def _write_config(tmp_path, monkeypatch, mode, call_log):
    cfg = {
        "mode": mode,
        "timeout_seconds": 20,
        "servers": {
            "fake": {"command": sys.executable, "args": [FAKE_SERVER],
                     "env": {"FAKE_MCP_LOG": str(call_log)}},
        },
        "actions": [
            {"name": "issue", "server": "fake", "tool": "create_issue",
             "on": ["governance_case_opened"],
             "arguments": {"title": "{title}", "body": "{body}", "labels": ["security-incident"]}},
            {"name": "notify", "server": "fake", "tool": "post_message",
             "arguments": {"text": "{summary}"}},
            {"name": "broken", "server": "fake", "tool": "always_fails",
             "on": ["governance_case_opened"], "arguments": {"text": "x"}},
        ],
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(cfg))
    monkeypatch.setenv("INCIDENT_MCP_CONFIG", str(path))
    monkeypatch.delenv("INCIDENT_MCP_MODE", raising=False)


def _result(level="high", score=0.9):
    return SimpleNamespace(
        risk_level=level, risk_score=score, reason="attempted data export",
        triggered_rules=[{"rule": "bulk_export", "weight": 0.9, "detail": "SECRET PROMPT TEXT"}],
        validator_notes=[],
    )


def _audit(app_ctx_user=None):
    return AuditLog.query.filter_by(event_type="mcp_incident_action").order_by(AuditLog.id).all()


@pytest.fixture()
def amy(app):
    with app.app_context():
        user = User.query.filter_by(username="intern_amy").first()
        log = AuditLog(user_id=user.id, username=user.username, role=user.role, query="q",
                       status="allowed", event_type="ai_request")
        db.session.add(log)
        db.session.commit()
        yield user, log


def test_off_by_default_does_nothing(app, amy, monkeypatch, tmp_path):
    monkeypatch.setenv("INCIDENT_MCP_CONFIG", str(tmp_path / "missing.json"))
    user, log = amy
    record_risk_event(user, log, _result())
    assert _audit() == []


def test_dry_run_audits_without_calling_out(app, amy, monkeypatch, tmp_path):
    calls = tmp_path / "calls.jsonl"
    _write_config(tmp_path, monkeypatch, "dry_run", calls)
    user, log = amy
    record_risk_event(user, log, _result())  # high risk, crosses default threshold
    rows = _audit()
    assert rows and all(r.status == "dry_run" for r in rows)
    assert not calls.exists()
    assert not any("SECRET PROMPT TEXT" in (r.query or "") for r in rows)


def test_live_calls_mcp_server_and_audits(app, amy, monkeypatch, tmp_path):
    calls = tmp_path / "calls.jsonl"
    _write_config(tmp_path, monkeypatch, "live", calls)
    user, log = amy
    with app.app_context():
        event = record_risk_event(user, log, _result(score=99.0))
        case = GovernanceCase.query.filter_by(user_id=user.id).first()
        assert case is not None
        thread = dispatch_incident("governance_case_opened", user, event, case=case)
        assert thread is not None
        thread.join(timeout=90)
        assert not thread.is_alive()

        recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        tools = {r["tool"] for r in recorded}
        assert {"create_issue", "post_message"} <= tools
        issue = next(r for r in recorded if r["tool"] == "create_issue")
        assert case.case_code() in issue["args"]["title"]
        assert "SECRET PROMPT TEXT" not in json.dumps(recorded)

        by_status = {}
        for row in _audit():
            by_status.setdefault(row.status, []).append(row.query)
        print("AUDIT", by_status)
        assert "queued" in by_status
        assert "allowed" in by_status          # issue + notify succeeded
        assert any("broken" in q for q in by_status.get("failed", []))  # failure recorded, others unaffected


def test_config_validation(tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"mode": "live", "servers": {},
                               "actions": [{"name": "a", "server": "nope", "tool": "t"}]}))
    with pytest.raises(ConfigError):
        load_config(bad)
    bad.write_text(json.dumps({"mode": "yolo"}))
    with pytest.raises(ConfigError):
        load_config(bad)


def test_render_leaves_unknown_placeholders():
    assert render({"a": ["{x} {y}"]}, {"x": "1"}) == {"a": ["1 {y}"]}
