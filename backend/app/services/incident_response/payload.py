"""Builds the privacy-minimised incident payload sent to external tools."""

import json
from datetime import UTC, datetime, timedelta

from app.services.rule_names import rule_names


class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _next_business_day_start(now):
    day = now + timedelta(days=1)
    while day.weekday() >= 5:  # skip Saturday/Sunday
        day += timedelta(days=1)
    return day.replace(hour=10, minute=0, second=0, microsecond=0)


def build_incident(kind, user, risk_event, case=None, reason=None, now=None):
    """Context dict used to fill the {placeholders} in action arguments.

    Deliberately excludes the raw prompt, the AI response and e-mail
    addresses: external services only get what a responder needs to triage.
    """
    now = now or datetime.now(UTC)
    try:
        factors = json.loads(risk_event.factors) if risk_event.factors else []
    except (TypeError, ValueError):
        factors = []
    # Names only: factors also hold validator notes that quote the user's text.
    rules = rule_names(factors, max_len=80)[:10]
    review_start = _next_business_day_start(now)
    review_end = review_start + timedelta(minutes=30)

    case_code = case.case_code() if case else ""
    who = f"{user.username} ({user.role})"
    if kind == "governance_case_opened":
        title = f"[SecureAI] Governance case {case_code} opened for {user.username}"
    else:
        title = f"[SecureAI] High-risk AI request from {user.username}"

    summary = (
        f"{title}. Risk {risk_event.risk_level} "
        f"(score {risk_event.risk_score:.2f}, cumulative {risk_event.cumulative_score:.2f})."
    )
    body_lines = [
        f"**User:** {who}",
        f"**Risk level:** {risk_event.risk_level}",
        f"**Risk score:** {risk_event.risk_score:.2f} (cumulative {risk_event.cumulative_score:.2f})",
        f"**Triggered rules:** {', '.join(rules) or 'n/a'}",
        f"**Reason:** {(reason or 'see audit log')[:300]}",
    ]
    if case_code:
        body_lines.append(f"**Governance case:** {case_code}")
    body_lines.append(f"**Audit log id:** {risk_event.audit_log_id}")
    body_lines.append("")
    body_lines.append("_Created automatically by SecureAI. The prompt text is intentionally not included._")

    return {
        "kind": kind,
        "title": title,
        "summary": summary,
        "body": "\n".join(body_lines),
        "username": user.username,
        "role": user.role,
        "risk_level": risk_event.risk_level,
        "risk_score": f"{risk_event.risk_score:.2f}",
        "cumulative_score": f"{risk_event.cumulative_score:.2f}",
        "rules": ", ".join(rules),
        "reason": (reason or "")[:300],
        "case_code": case_code,
        "audit_log_id": str(risk_event.audit_log_id or ""),
        "risk_event_id": str(risk_event.id or ""),
        "review_start": review_start.isoformat().replace("+00:00", "Z"),
        "review_end": review_end.isoformat().replace("+00:00", "Z"),
    }


def render(value, incident):
    """Fills {placeholders} in strings, recursing through lists/dicts.

    Unknown placeholders are left as-is rather than raising, so a typo in
    the config produces a visible "{typo}" instead of a lost incident.
    """
    if isinstance(value, str):
        return value.format_map(_SafeDict(incident))
    if isinstance(value, list):
        return [render(v, incident) for v in value]
    if isinstance(value, dict):
        return {k: render(v, incident) for k, v in value.items()}
    return value
