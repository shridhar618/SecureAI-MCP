"""Admin API for incident-alert settings."""

import json

import pytest

from app.models.audit_log import AuditLog

CONFIG = {
    "mode": "off",
    "timeout_seconds": 30,
    "servers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${TEST_GH_TOKEN}"}},
        "slack": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"],
                  "env": {"SLACK_BOT_TOKEN": "${TEST_SLACK_TOKEN}"}},
    },
    "actions": [
        {"name": "github_issue", "server": "github", "tool": "create_issue", "on": ["governance_case_opened"],
         "arguments": {"owner": "${TEST_GH_OWNER}", "title": "{title}", "body": "{body}"}},
        {"name": "slack_notify", "server": "slack", "tool": "slack_post_message",
         "on": ["high_risk_request", "governance_case_opened"], "arguments": {"text": "{summary}"}},
    ],
}
SECRET_VALUE = "s3cr3t-token-value-XYZ"


@pytest.fixture()
def cfg(app, tmp_path, monkeypatch):
    path = tmp_path / "mcp_servers.json"
    path.write_text(json.dumps(CONFIG))
    monkeypatch.setenv("INCIDENT_MCP_CONFIG", str(path))
    monkeypatch.delenv("INCIDENT_MCP_MODE", raising=False)
    for var in ("TEST_GH_TOKEN", "TEST_SLACK_TOKEN", "TEST_GH_OWNER"):
        monkeypatch.delenv(var, raising=False)
    return path


@pytest.fixture()
def admin_h(auth_headers):
    return auth_headers("admin", "admin123")


def _put(client, h, **body):
    return client.put("/api/incident-alerts/mode", json=body, headers=h)


def test_requires_admin(client, auth_headers, cfg):
    assert client.get("/api/incident-alerts").status_code == 401
    for creds in [("intern_bob", "intern123"), ("hr_jane", "hr123")]:
        h = auth_headers(*creds)
        assert client.get("/api/incident-alerts", headers=h).status_code == 403
        assert _put(client, h, mode="dry_run").status_code == 403
        assert client.post("/api/incident-alerts/preview", json={"kind": "high_risk_request"}, headers=h).status_code == 403


def test_state_without_config_file(client, admin_h, tmp_path, monkeypatch):
    monkeypatch.setenv("INCIDENT_MCP_CONFIG", str(tmp_path / "missing.json"))
    monkeypatch.delenv("INCIDENT_MCP_MODE", raising=False)
    d = client.get("/api/incident-alerts", headers=admin_h).get_json()
    assert d["mode"] == "off" and d["config_file"]["exists"] is False and "not found" in d["config_file"]["error"]
    assert _put(client, admin_h, mode="dry_run").status_code == 409


def test_state_reports_config_and_never_secret_values(client, admin_h, cfg, monkeypatch):
    monkeypatch.setenv("TEST_GH_TOKEN", SECRET_VALUE)
    res = client.get("/api/incident-alerts", headers=admin_h)
    d = res.get_json()
    assert SECRET_VALUE not in res.get_data(as_text=True)
    assert d["mode"] == "off" and d["mode_source"] == "file" and d["config_file"]["valid"] is True
    assert [a["name"] for a in d["actions"]] == ["github_issue", "slack_notify"]
    env = {e["name"]: e["set"] for e in d["required_env"]}
    assert env == {"TEST_GH_TOKEN": True, "TEST_SLACK_TOKEN": False, "TEST_GH_OWNER": False}
    assert d["modes"] == ["off", "dry_run", "live"] and d["recent"] == []


def test_invalid_config_is_reported_and_blocks_changes(client, admin_h, cfg):
    cfg.write_text("{ not json")
    d = client.get("/api/incident-alerts", headers=admin_h).get_json()
    assert d["config_file"]["valid"] is False and d["config_file"]["error"]
    assert _put(client, admin_h, mode="dry_run").status_code == 409


@pytest.mark.parametrize("body", [{}, {"mode": "LIVE"}, {"mode": "on"}, {"mode": None}, {"mode": 1}])
def test_invalid_mode_rejected(client, admin_h, cfg, body):
    assert _put(client, admin_h, **body).status_code == 400


def test_switch_to_dry_run_writes_file_preserves_rest_and_audits(app, client, admin_h, cfg):
    res = _put(client, admin_h, mode="dry_run")
    assert res.status_code == 200 and res.get_json()["mode"] == "dry_run"
    saved = json.loads(cfg.read_text())
    assert saved["mode"] == "dry_run"
    assert saved["servers"] == CONFIG["servers"] and saved["actions"] == CONFIG["actions"]
    assert not list(cfg.parent.glob(".mcp_servers.*"))           # no temp file left behind
    with app.app_context():
        rows = AuditLog.query.filter_by(event_type="incident_config_change").all()
        assert len(rows) == 1 and rows[0].username == "admin"
        assert json.loads(rows[0].event_metadata) == {"from": "off", "to": "dry_run"}
    _put(client, admin_h, mode="dry_run")                         # no-op: no second audit row
    with app.app_context():
        assert AuditLog.query.filter_by(event_type="incident_config_change").count() == 1


def test_live_blocked_until_env_set_then_needs_confirm(client, admin_h, cfg, monkeypatch):
    res = _put(client, admin_h, mode="live", confirm=True)
    assert res.status_code == 409
    assert set(res.get_json()["missing_env"]) == {"TEST_GH_TOKEN", "TEST_SLACK_TOKEN", "TEST_GH_OWNER"}
    assert json.loads(cfg.read_text())["mode"] == "off"

    for var in ("TEST_GH_TOKEN", "TEST_SLACK_TOKEN", "TEST_GH_OWNER"):
        monkeypatch.setenv(var, "x")
    assert _put(client, admin_h, mode="live").status_code == 400                 # no confirm
    assert _put(client, admin_h, mode="live", confirm="yes").status_code == 400  # must be literal true
    assert json.loads(cfg.read_text())["mode"] == "off"
    res = _put(client, admin_h, mode="live", confirm=True)
    assert res.status_code == 200 and res.get_json()["mode"] == "live"
    assert json.loads(cfg.read_text())["mode"] == "live"


def test_going_back_to_off_needs_no_confirmation(client, admin_h, cfg, monkeypatch):
    for var in ("TEST_GH_TOKEN", "TEST_SLACK_TOKEN", "TEST_GH_OWNER"):
        monkeypatch.setenv(var, "x")
    _put(client, admin_h, mode="live", confirm=True)
    assert _put(client, admin_h, mode="off").get_json()["mode"] == "off"


def test_env_override_blocks_file_edit(client, admin_h, cfg, monkeypatch):
    monkeypatch.setenv("INCIDENT_MCP_MODE", "dry_run")
    d = client.get("/api/incident-alerts", headers=admin_h).get_json()
    assert d["mode"] == "dry_run" and d["mode_source"] == "env"
    res = _put(client, admin_h, mode="off")
    assert res.status_code == 409 and "INCIDENT_MCP_MODE" in res.get_json()["error"]
    assert json.loads(cfg.read_text())["mode"] == "off"


def test_preview_shows_rendered_calls_and_sends_nothing(app, client, admin_h, cfg, monkeypatch):
    monkeypatch.setenv("TEST_SLACK_TOKEN", SECRET_VALUE)
    res = client.post("/api/incident-alerts/preview", json={"kind": "governance_case_opened"}, headers=admin_h)
    assert res.status_code == 200
    d = res.get_json()
    assert d["sent"] is False and d["sample"] is True
    assert [c["action"] for c in d["calls"]] == ["github_issue", "slack_notify"]
    gh = d["calls"][0]["arguments"]
    assert "GOV-000" in gh["title"] and "sample_user" in gh["body"]
    assert gh["owner"] == "${TEST_GH_OWNER}"                      # placeholders are not expanded
    assert SECRET_VALUE not in res.get_data(as_text=True)
    only_slack = client.post("/api/incident-alerts/preview", json={"kind": "high_risk_request"}, headers=admin_h).get_json()
    assert [c["action"] for c in only_slack["calls"]] == ["slack_notify"]
    with app.app_context():                                         # nothing recorded
        assert AuditLog.query.filter_by(event_type="mcp_incident_action").count() == 0


@pytest.mark.parametrize("body", [{}, {"kind": "nope"}, {"kind": None}, {"kind": 3}])
def test_preview_validates_kind(client, admin_h, cfg, body):
    assert client.post("/api/incident-alerts/preview", json=body, headers=admin_h).status_code == 400


def test_recent_activity_lists_incident_rows(client, admin_h, cfg, app):
    from app.models.user import User
    from app.services.audit import record_audit_event
    with app.app_context():
        record_audit_event("mcp_incident_action", user=User.query.filter_by(username="intern_bob").first(),
                           description="[automated] MCP slack_notify: would call", resource="mcp:slack.slack_post_message",
                           status="dry_run", metadata={"incident_kind": "high_risk_request", "mode": "dry_run",
                                                       "subject": "intern_bob", "action": "slack_notify"})
    d = client.get("/api/incident-alerts", headers=admin_h).get_json()
    assert d["recent"][0]["action"] == "slack_notify" and d["recent"][0]["status"] == "dry_run"
    assert set(d["recent"][0]) == {"id", "timestamp", "action", "kind", "mode", "subject", "status", "target"}
