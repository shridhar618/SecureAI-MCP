"""The single per-tool permission matrix. Deny by default: a tool that is not
listed here cannot be called, and a caller whose role lacks the listed
permission is refused (and the refusal is audited).

Roles map to permissions through app.services.permissions, the same source
the Flask API uses, so MCP access can never exceed web access.
"""

from dataclasses import dataclass

ADMIN_PERMISSION = "ai_governance_admin"


@dataclass(frozen=True)
class ToolRule:
    permission: str          # permission the caller's role must hold
    own_data_only: bool      # non-admins may only query themselves
    admin_role_only: bool = False  # additionally requires the Admin role
    writes: bool = False


TOOL_RULES: dict[str, ToolRule] = {
    "search_policies": ToolRule("use_ai_assistant", own_data_only=False),
    "check_action_against_policy": ToolRule("use_ai_assistant", own_data_only=False),
    "summarize_user_risk": ToolRule("use_ai_assistant", own_data_only=True),
    "get_risk_events": ToolRule("use_ai_assistant", own_data_only=True),
    "get_governance_cases": ToolRule(ADMIN_PERMISSION, own_data_only=False),
    "get_case": ToolRule(ADMIN_PERMISSION, own_data_only=False),
    "get_audit_log": ToolRule(ADMIN_PERMISSION, own_data_only=False),
    "open_governance_case": ToolRule(ADMIN_PERMISSION, own_data_only=False, admin_role_only=True, writes=True),
}


class Denied(Exception):
    """Raised for any refusal; the message is safe to show the client."""

    def __init__(self, message: str, kind: str = "denied"):
        super().__init__(message)
        self.kind = kind  # "denied" | "invalid"
