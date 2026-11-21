"""Authentication for the MCP server: dedicated, hashed, expiring tokens.

The caller's role and active flag are re-read from the database on every
call, so demoting or suspending a user takes effect immediately.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from app import db
from app.models.mcp_token import McpToken, hash_token
from app.models.user import User
from app.services.permissions import permissions_for_role


class AuthError(Exception):
    def __init__(self, message: str, user: User | None = None):
        super().__init__(message)
        self.user = user  # set when the token was recognised (so we can audit)


@dataclass(frozen=True)
class Caller:
    user_id: int
    username: str
    role: str            # legacy lowercase role string
    role_name: str       # display role used for permission lookup
    permissions: tuple
    token_id: int

    @property
    def is_admin(self) -> bool:
        return "ai_governance_admin" in self.permissions


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def authenticate(raw_token: str | None) -> Caller:
    """Must be called inside an app context."""
    if not raw_token or len(raw_token) > 200:
        raise AuthError("Authentication required: no valid SecureAI MCP token.")
    row = McpToken.query.filter_by(token_hash=hash_token(raw_token)).first()
    if row is None:
        raise AuthError("Authentication required: no valid SecureAI MCP token.")
    user = db.session.get(User, row.user_id)
    if user is None:
        raise AuthError("Authentication required: no valid SecureAI MCP token.")
    now = datetime.now(UTC).replace(tzinfo=None)
    if row.revoked_at is not None:
        raise AuthError("This MCP token has been revoked.", user)
    if _naive_utc(row.expires_at) <= now:
        raise AuthError("This MCP token has expired.", user)
    if user.is_active is False:
        raise AuthError("This account has been suspended.", user)

    row.last_used_at = now
    db.session.commit()
    role_name = user.role_ref.name if user.role_ref else user.role
    return Caller(
        user_id=user.id,
        username=user.username,
        role=user.role,
        role_name=role_name,
        permissions=tuple(permissions_for_role(role_name)),
        token_id=row.id,
    )
