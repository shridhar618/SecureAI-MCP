"""Tool implementations. Each takes the authenticated Caller first; the
server wrapper (server.py) handles auth, the permission matrix, rate
limiting and audit logging, so nothing here re-implements those.

All queries go through the ORM; all arguments are validated here.
"""

import re
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_

from app import db
from app.mcp_server import serializers as ser
from app.mcp_server.permissions import Denied
from app.models.attendance_record import AttendanceRecord
from app.models.audit_log import AuditLog
from app.models.governance_case import CASE_STATUSES, GovernanceCase
from app.models.policy_chunk import PolicyChunk
from app.models.policy_document import PolicyDocument
from app.models.risk_event import RiskEvent
from app.models.user import User
from app.models.work_escalation import WorkEscalation
from app.services import ledger
from app.services.audit import EVENT_TYPES
from app.services.governance import apply_governance
from app.services.rag_service import rag_status, retrieve_policy_evidence
from app.services.risk_config_service import load_risk_config
from app.services.risk_tracking import open_manual_case

MAX_LIMIT = 100
RISK_LEVELS = ("low", "medium", "high")
AUDIT_EVENT_TYPES = set(EVENT_TYPES) | {"ai_request", "mcp_tool_call", "permission_denied"}
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-@]{1,80}$")
_CASE_RE = re.compile(r"^GOV-(\d{1,9})$", re.IGNORECASE)
_SINCE_RE = re.compile(r"^(\d{1,4})([hdw])$")


# ── validation helpers ─────────────────────────────────────────────────────

def _bad(msg):
    raise Denied(msg, kind="invalid")


def _limit(value, default=50):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LIMIT:
        _bad(f"limit must be an integer between 1 and {MAX_LIMIT}.")
    return value


def _username(value):
    if value is None:
        return None
    if not isinstance(value, str) or not _USERNAME_RE.match(value):
        _bad("username must be 1-80 characters: letters, digits, _ . - @")
    return value


def _text(value, name, max_len, required=True):
    if value is None:
        if required:
            _bad(f"{name} is required.")
        return None
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > max_len:
        _bad(f"{name} must be a non-empty string of at most {max_len} characters.")
    return value.strip()


def _since(value):
    """'24h' / '7d' / '2w' or an ISO-8601 date(time). Returns naive UTC."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        _bad("since must be like '24h', '7d', '2w' or an ISO-8601 date.")
    m = _SINCE_RE.match(value.strip())
    now = datetime.now(UTC).replace(tzinfo=None)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return now - timedelta(**{{"h": "hours", "d": "days", "w": "weeks"}[unit]: n})
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        _bad("since must be like '24h', '7d', '2w' or an ISO-8601 date.")
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def _resolve_target(caller, username):
    """Non-admins may only ever see themselves; asking for anyone else is a
    denial (audited), not a silent filter."""
    username = _username(username)
    if caller.is_admin:
        return username
    if username not in (None, caller.username):
        raise Denied("Your role may only access your own data.")
    return caller.username


def _find_user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        _bad("No such user.")
    return user


# ── policy tools ───────────────────────────────────────────────────────────

def _like_escape(term):
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_policies(query, top_k):
    if rag_status()["ready"]:
        hits = retrieve_policy_evidence(query, top_k=top_k)
        if hits:
            return "semantic", [
                ser.policy_chunk(h["document_name"], h["category"], h["section"], h["page"], h["content"], h["score"])
                for h in hits
            ]
    terms = [t for t in re.findall(r"[A-Za-z0-9]{3,}", query.lower())][:6]
    if not terms:
        return "keyword", []
    conds = [PolicyChunk.content.ilike(f"%{_like_escape(t)}%", escape="\\") for t in terms]
    rows = (
        PolicyChunk.query.join(PolicyDocument, PolicyChunk.document_id == PolicyDocument.id)
        .filter(PolicyDocument.status == "active", or_(*conds))
        .limit(200).all()
    )
    scored = sorted(rows, key=lambda c: -sum(t in c.content.lower() for t in terms))[:top_k]
    return "keyword", [
        ser.policy_chunk(c.document.name, c.document.category, c.section, c.page, c.content, None, "keyword")
        for c in scored
    ]


def search_policies(caller, query, top_k=4):
    """Search SecureAI policy documents and return cited chunks. Uses semantic
    RAG when installed, otherwise keyword search (the 'retrieval' field says which)."""
    query = _text(query, "query", 500)
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 10:
        _bad("top_k must be an integer between 1 and 10.")
    mode, results = _search_policies(query, top_k)
    return {"retrieval": mode, "count": len(results), "results": results}


def check_action_against_policy(caller, description):
    """Dry-run a described action through SecureAI's governance engine using the
    CALLER's own role. Returns allowed / blocked / needs_review. Executes nothing."""
    description = _text(description, "description", 2000)
    result = apply_governance(
        response="", query=description, role=caller.role,
        permissions=list(caller.permissions), risk_config=load_risk_config(),
    )
    decision = {"allowed": "allowed", "blocked": "blocked"}.get(result.status, "needs_review")
    if decision == "allowed" and result.risk_level != "low":
        decision = "needs_review"
    rules = ser.rule_names(result.triggered_rules)
    _, clauses = _search_policies(description, 3)
    return {
        "decision": decision,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "rules": rules,
        "policy_citations": list(result.policy_evidence or []),
        "reason": ser.untrusted(result.reason),
        "matching_policy_clauses": clauses,
        "evaluated_as_role": caller.role_name,
        "executed": False,
    }


# ── risk tools ─────────────────────────────────────────────────────────────

def get_risk_events(caller, user=None, level=None, since=None, limit=50):
    """List risk events (rule names and scores only; never prompt text).
    Non-admins can only list their own."""
    target = _resolve_target(caller, user)
    if level is not None and level not in RISK_LEVELS:
        _bad("level must be one of: low, medium, high.")
    since_dt, limit = _since(since), _limit(limit)
    q = RiskEvent.query.join(User, RiskEvent.user_id == User.id)
    if target:
        q = q.filter(User.username == target)
    if level:
        q = q.filter(RiskEvent.risk_level == level)
    if since_dt:
        q = q.filter(RiskEvent.created_at >= since_dt)
    total = q.count()
    rows = q.order_by(RiskEvent.created_at.desc()).limit(limit).all()
    return {
        "total_matching": total,
        "returned": len(rows),
        "cumulative_risk_case_threshold": load_risk_config().get("cumulative_risk_case_threshold"),
        "events": [ser.risk_event(r) for r in rows],
    }


def summarize_user_risk(caller, username=None):
    """Summarise one user's risk: cumulative score, recent events, open case,
    attendance and escalation signals. Non-admins may only ask about themselves."""
    target = _resolve_target(caller, username) or caller.username
    user = _find_user(target)
    last = RiskEvent.query.filter_by(user_id=user.id).order_by(RiskEvent.created_at.desc()).first()
    by_level = dict(
        db.session.query(RiskEvent.risk_level, func.count(RiskEvent.id))
        .filter(RiskEvent.user_id == user.id).group_by(RiskEvent.risk_level).all()
    )
    recent = RiskEvent.query.filter_by(user_id=user.id).order_by(RiskEvent.created_at.desc()).limit(5).all()
    open_case = (
        GovernanceCase.query.filter(GovernanceCase.user_id == user.id, GovernanceCase.status != "resolved")
        .order_by(GovernanceCase.created_at.desc()).first()
    )
    week = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=7)
    att = AttendanceRecord.query.filter(AttendanceRecord.user_id == user.id, AttendanceRecord.created_at >= week).count()
    esc = WorkEscalation.query.filter_by(created_by_user_id=user.id, status="open").count()
    return {
        "username": user.username,
        "role": user.role,
        "is_active": bool(user.is_active),
        "is_suspicious": bool(user.is_suspicious),
        "sensitive_query_count": user.sensitive_query_count or 0,
        "cumulative_risk_score": last.cumulative_score if last else 0.0,
        "threshold": load_risk_config().get("cumulative_risk_case_threshold"),
        "events_by_level": {k: by_level.get(k, 0) for k in RISK_LEVELS},
        "recent_events": [ser.risk_event(e) for e in recent],
        "open_case": ser.case_summary(open_case) if open_case and caller.is_admin
        else ({"case_code": open_case.case_code(), "status": open_case.status} if open_case else None),
        "signals": {"attendance_events_last_7d": att, "open_work_escalations_raised": esc},
    }


# ── governance cases ───────────────────────────────────────────────────────

def get_governance_cases(caller, status=None, user=None, since=None, limit=50):
    """List governance cases (admin only), with the rules each one tripped and
    the policies that apply. Free-text fields are untrusted data."""
    if status is not None and status not in CASE_STATUSES:
        _bad(f"status must be one of: {', '.join(CASE_STATUSES)}.")
    username, since_dt, limit = _username(user), _since(since), _limit(limit)
    q = GovernanceCase.query.join(User, GovernanceCase.user_id == User.id)
    if status:
        q = q.filter(GovernanceCase.status == status)
    if username:
        q = q.filter(User.username == username)
    if since_dt:
        q = q.filter(GovernanceCase.created_at >= since_dt)
    total = q.count()
    rows = q.order_by(GovernanceCase.created_at.desc()).limit(limit).all()
    return {"total_matching": total, "returned": len(rows), "cases": [ser.case_summary(c) for c in rows]}


def get_case(caller, case_code):
    """Get one governance case (e.g. 'GOV-003') including its action timeline."""
    m = _CASE_RE.match(case_code.strip()) if isinstance(case_code, str) and len(case_code) <= 20 else None
    if not m:
        _bad("case_code must look like GOV-003.")
    case = db.session.get(GovernanceCase, int(m.group(1)))
    if case is None:
        _bad("No such case.")
    return ser.case_detail(case)


def open_governance_case(caller, username, reason, confirm=False):
    """WRITE (admin only, confirm=true required): open a governance review case.
    Does not change the user's access; humans do that via an admin action."""
    username = _username(username)
    reason = _text(reason, "reason", 500)
    if confirm is not True:
        raise Denied("confirm=true is required to open a case.", kind="denied")
    if username is None:
        _bad("username is required.")
    target = _find_user(username)
    opener = db.session.get(User, caller.user_id)
    case = open_manual_case(target, opener, reason)
    if case is None:
        _bad("That user already has an unresolved case.")
    return {"opened": True, "case_code": case.case_code(), "status": case.status,
            "username": target.username, "access_changed": False}


# ── audit log ──────────────────────────────────────────────────────────────

_chain_cache: dict = {"at": 0.0, "value": None}


def _chain_status():
    now = time.monotonic()
    if _chain_cache["value"] is None or now - _chain_cache["at"] > 60:
        r = ledger.verify_chain(db.session)
        fb = r.get("first_break")
        _chain_cache["value"] = {
            "ok": r["ok"], "checked": r["checked"], "unsealed": r["unsealed"],
            "issue_count": r["issue_count"], "head_hash": r["head_hash"],
            "first_break": {"seq": fb["seq"], "kind": fb["kind"]} if fb else None,
            "verified_at": r["verified_at"],
        }
        _chain_cache["at"] = now
    return _chain_cache["value"]


def get_audit_log(caller, user=None, event_type=None, since=None, limit=50, offset=0, include_chain_status=False):
    """Paginated audit log (admin only). Raw prompts and AI responses are never
    returned. Descriptions/reasons are untrusted data. Set include_chain_status
    for the hash-chain verification result (cached 60s)."""
    username, since_dt, limit = _username(user), _since(since), _limit(limit)
    if event_type is not None and event_type not in AUDIT_EVENT_TYPES:
        _bad("Unknown event_type.")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1_000_000:
        _bad("offset must be a non-negative integer.")
    q = db.session.query(AuditLog)
    if username:
        q = q.filter(AuditLog.username == username)
    if event_type == "ai_request":
        q = q.filter(or_(AuditLog.event_type.is_(None), AuditLog.event_type == "ai_request"))
    elif event_type:
        q = q.filter(AuditLog.event_type == event_type)
    if since_dt:
        q = q.filter(AuditLog.timestamp >= since_dt)
    total = q.count()
    rows = q.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
    out = {
        "total_matching": total, "offset": offset, "returned": len(rows),
        "has_more": offset + len(rows) < total,
        "entries": [ser.audit_row(r) for r in rows],
    }
    if include_chain_status is True:
        out["chain_status"] = _chain_status()
    return out
