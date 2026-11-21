"""
Incident-response automation over MCP (Model Context Protocol).

When the risk engine raises a serious event (a single high-risk AI request,
or a governance case being opened), SecureAI acts as an MCP *client* and
calls tools on external MCP servers -- GitHub (open an issue), Slack
(notify the manager) and a calendar (schedule a review).

Design rules, in line with the rest of the platform:

  * Off by default. Nothing leaves the system until an admin supplies a
    config file and sets a mode (see config.py).
  * dry_run mode records exactly what *would* be sent, without calling out.
  * Data minimisation: payloads carry usernames, scores and rule names --
    never the raw prompt or the AI response.
  * Every action (planned, succeeded, failed) lands in the audit trail as
    an "mcp_incident_action" event.
  * Never blocks or breaks the request that raised the risk event; all
    outbound work runs off the request path and failures are only logged.
"""

from app.services.incident_response.dispatcher import dispatch_incident

__all__ = ["dispatch_incident"]
