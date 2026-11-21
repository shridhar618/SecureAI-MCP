# MCP incident response

When the risk engine raises a serious event, SecureAI acts as an MCP **client**
and calls tools on external MCP servers.

| Trigger | Default actions |
|---|---|
| `high_risk_request` (single high-risk AI request) | Slack message to the manager |
| `governance_case_opened` (cumulative risk threshold crossed) | GitHub issue, Slack message, calendar review slot |

## Enable it
1. `cp backend/mcp_servers.example.json backend/mcp_servers.json` and edit servers/actions.
2. Export the secrets it references (`GITHUB_TOKEN`, `SLACK_BOT_TOKEN`, `INCIDENT_GITHUB_OWNER`, ...).
3. Pick a mode in the file or via `INCIDENT_MCP_MODE`:
   - `off` (default) nothing happens
   - `dry_run` actions are audited as "would call ..." but nothing is sent
   - `live` MCP servers are called

Start with `dry_run`, read the `mcp_incident_action` rows in the audit log, then switch to `live`.

## Safety properties
- Payloads contain username, role, scores and rule names only; never the prompt or AI response.
- Each action is audited (`queued` -> `allowed` / `failed`), including failures.
- Runs in a background thread + subprocess; a broken server cannot fail the user's request.
- Only tools listed in `actions` can be called.

## Code
`backend/app/services/incident_response/` (hook: `services/risk_tracking.py`).
Tests: `backend/tests/test_incident_response.py` (uses a fake stdio MCP server).
