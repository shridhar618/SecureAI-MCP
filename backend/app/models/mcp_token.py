import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from app import db

TOKEN_PREFIX = "sai_mcp_"


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class McpToken(db.Model):
    """A scoped credential for the MCP server. Only the SHA-256 hash is
    stored, so a database leak does not reveal usable tokens. The caller's
    role is always read live from the user, never cached on the token."""

    __tablename__ = "mcp_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref=db.backref("mcp_tokens", lazy=True))

    @classmethod
    def mint(cls, user, days: int = 30, label: str | None = None):
        """Returns (row, raw_token). The raw token is shown once, never stored."""
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        row = cls(
            user_id=user.id,
            token_hash=hash_token(raw),
            label=(label or "")[:80] or None,
            expires_at=datetime.now(UTC) + timedelta(days=days),
        )
        db.session.add(row)
        db.session.commit()
        return row, raw
