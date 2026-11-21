# SecureAI as an MCP server

Lets Claude Desktop, Claude Code and other MCP clients query SecureAI governance
data with the same RBAC, audit logging and data minimisation as the web API.
(The opposite direction, SecureAI calling out to GitHub/Slack, is in
`MCP_INCIDENT_RESPONSE.md`.)

It runs as its **own process**, never inside the eventlet web server.

## Quick start

```bash
cd backend
# 1. Mint a token for an existing active user (printed once; only its hash is stored)
venv311/bin/python -m app.mcp_server --mint-token alice_admin --days 30 --label "claude-code"
# 2. Register with Claude Code
claude mcp add secureai -e SECUREAI_MCP_TOKEN=sai_mcp_... -- \
  /abs/path/SecureAI-MCP/backend/venv311/bin/python -m app.mcp_server
```
Run from `backend/` (the module reads the same `.env`/`DATABASE_URL` as the web app), so
use `cwd` in the config below, or `cd backend &&` in a wrapper.

Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "secureai": {
      "command": "/abs/path/SecureAI-MCP/backend/venv311/bin/python",
      "args": ["-m", "app.mcp_server"],
      "cwd": "/abs/path/SecureAI-MCP/backend",
      "env": { "SECUREAI_MCP_TOKEN": "sai_mcp_..." }
    }
  }
}
```

Demo question: *"Which users crossed the risk threshold this week, what rules did
they trip, and which policy applies?"* -> `get_governance_cases(since="7d")`
returns each case with `rules_tripped` and `policy_citations`.

Revoke a token: `python -m app.mcp_server --revoke-token <id>`.

HTTP: `python -m app.mcp_server --http --port 8765`, clients send
`Authorization: Bearer <token>` to `http://127.0.0.1:8765/mcp`. Binds to loopback
by default; put TLS in front of it before exposing it anywhere else.

## Authentication

Every connection needs a SecureAI MCP token (`mcp_tokens` table: SHA-256 hash,
user, expiry, revoked_at). No token, an unknown/expired/revoked token, or a
suspended user is refused. stdio refuses to start without a valid
`SECUREAI_MCP_TOKEN`. The caller's **role is read live on every call**, so
demotion/suspension applies immediately. A token never grants more than its owner's role.

## Tool / permission matrix (`app/mcp_server/permissions.py`)

Deny by default. Permissions come from `services/permissions.py`.

| Tool | Requires | Scope |
|---|---|---|
| `search_policies(query, top_k<=10)` | `use_ai_assistant` | semantic RAG if installed, else keyword fallback |
| `check_action_against_policy(description)` | `use_ai_assistant` | evaluated as the caller's role; executes nothing, records nothing |
| `summarize_user_risk(username?)` | `use_ai_assistant` | non-admin: self only |
| `get_risk_events(user?, level?, since?, limit<=100)` | `use_ai_assistant` | non-admin: self only |
| `get_governance_cases(status?, user?, since?, limit<=100)` | `ai_governance_admin` | admin |
| `get_case(case_code)` | `ai_governance_admin` | admin; includes action timeline |
| `get_audit_log(user?, event_type?, since?, limit<=100, offset, include_chain_status)` | `ai_governance_admin` | admin; paginated; hash-chain status optional |
| `open_governance_case(username, reason, confirm)` | `ai_governance_admin` **and** Admin role | needs `confirm=true`; opens a case only, never changes access |

`since` accepts `24h`, `7d`, `2w` or an ISO-8601 date.

## Audit

Every call by an identified caller writes an `AuditLog` row: `event_type="mcp_tool_call"`,
`resource=<tool>`, `status` allowed/denied, metadata with the tool and an argument
summary (lengths and usernames/enums only, no free text). Denials are logged
(rate-limit denials at most once per minute per caller). Calls the MCP SDK rejects before
any handler runs (missing required arguments, unknown tool names) are audited too, with
`reason_code` `schema_invalid` / `unknown_tool` (unknown tools are recorded as
`unknown_tool`; attacker-supplied names and values are never stored), and count toward the
rate limit. If the audit write fails the call is refused. Calls with an unknown token have no user to attach (`audit_logs.user_id`
is NOT NULL) and go to the server log only.

## Data minimisation

One serializer module (`serializers.py`) with allow-lists. Never returned: password
hashes, login codes, emails, face data, IPs/user agents, raw prompts, AI responses,
keyword fragments from validator notes. Risk events expose rule names only.
Free text (case triggers, action notes, audit descriptions, policy excerpts) is wrapped
as `{"untrusted_text": ...}`, and each tool description says results are data, not
instructions.

## Limits

`limit` 1-100, string length caps, ORM-only queries, 60 calls/minute per caller
(`SECUREAI_MCP_RATE_LIMIT`, in-memory per process).
