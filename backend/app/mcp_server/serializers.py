"""The one place that decides what leaves the server.

Everything is built from explicit allow-lists. Never returned: password
hashes, login codes, emails, face data, IPs/user agents, raw prompts
(AuditLog.query for chat rows), AI responses, validator-note keyword
fragments.

Free text that could be attacker-influenced is wrapped as
{"untrusted_text": ...}; clients must treat it as data, not instructions.
"""

import json
import re

from app.services.governance import _policy_evidence_for  # same engine as the API

MAX_TEXT = 500
_AUDIT_META_KEYS = ("tool", "status", "args_summary", "reason_code", "target")
_NOTE_RE = re.compile(r"^(Detected .+? signal)\b")


def untrusted(text, cap: int = MAX_TEXT):
    if text is None:
        return None
    return {"untrusted_text": str(text)[:cap]}


def iso(dt):
    return dt.isoformat() if dt else None


def _json_list(raw):
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def rule_names(items) -> list[str]:
    """Reduce stored factors/triggered_rules to rule names only.

    Validator notes embed matched keywords from the prompt/response
    ("matched: 'password'"), so they are cut down to their category, and
    the intent-analysis note (which quotes signals) is dropped.
    """
    out = []
    for item in items or []:
        if isinstance(item, dict):
            item = item.get("rule") or item.get("label")
        if not isinstance(item, str):
            continue
        if item.startswith("Intent analysis"):
            continue
        match = _NOTE_RE.match(item)
        name = match.group(1) if match else item
        name = name[:120]
        if name not in out:
            out.append(name)
    return out


def policy_citations(rules: list[str]) -> list[str]:
    # names double as layer-2 notes: the engine matches categories by substring
    return _policy_evidence_for(rules, rules)


def user_ref(user) -> dict | None:
    if user is None:
        return None
    return {"username": user.username, "role": user.role}


def risk_event(event) -> dict:
    rules = rule_names(_json_list(event.factors))
    return {
        "id": event.id,
        "username": event.user.username if event.user else None,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "cumulative_score": event.cumulative_score,
        "rules": rules,
        "policy_citations": policy_citations(rules),
        "case_code": f"GOV-{event.case_id:03d}" if event.case_id else None,
        "created_at": iso(event.created_at),
    }


def case_summary(case) -> dict:
    rules = []
    for ev in case.risk_events:
        for name in rule_names(_json_list(ev.factors)):
            if name not in rules:
                rules.append(name)
    return {
        "case_code": case.case_code(),
        "username": case.user.username if case.user else None,
        "role": case.user.role if case.user else None,
        "status": case.status,
        "trigger": untrusted(case.trigger),
        "risk_score_at_open": case.risk_score_at_open,
        "assigned_admin": case.assigned_admin.username if case.assigned_admin else None,
        "event_count": len(case.risk_events),
        "rules_tripped": rules,
        "policy_citations": policy_citations(rules),
        "created_at": iso(case.created_at),
        "updated_at": iso(case.updated_at),
        "resolved_at": iso(case.resolved_at),
    }


def case_detail(case) -> dict:
    payload = case_summary(case)
    payload["actions"] = [
        {
            "action_type": a.action_type,
            "admin": a.admin.username if a.admin else None,
            "note": untrusted(a.note),
            "created_at": iso(a.created_at),
        }
        for a in case.actions
    ]
    payload["risk_events"] = [risk_event(e) for e in case.risk_events]
    return payload


def audit_row(row) -> dict:
    is_chat = (row.event_type or "ai_request") == "ai_request"
    try:
        meta = json.loads(row.event_metadata) if row.event_metadata else {}
    except (TypeError, ValueError):
        meta = {}
    meta = {k: meta[k] for k in _AUDIT_META_KEYS if isinstance(meta, dict) and k in meta}
    payload = {
        "id": row.id,
        "chain_seq": row.chain_seq,
        "chain_hash": row.chain_hash,
        "timestamp": iso(row.timestamp),
        "username": row.username,
        "role": row.role,
        "event_type": row.event_type or "ai_request",
        "status": row.status,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "resource": row.resource,
        "rules": rule_names(_json_list(row.triggered_rules)),
        "metadata": meta,
    }
    # For chat rows `query` is the user's raw prompt: never returned.
    # For other events it is a short system-written description.
    payload["description"] = None if is_chat else untrusted(row.query, 300)
    payload["reason"] = untrusted(row.reason, 300)
    return payload


def policy_chunk(document_name, category, section, page, text, score=None, mode="semantic") -> dict:
    from app.services.rag_service import sanitize_retrieved_content

    cite = document_name or "policy"
    if section:
        cite += f" - {section}"
    if page:
        cite += f" (p.{page})"
    return {
        "citation": cite,
        "document": document_name,
        "category": category,
        "section": section,
        "page": page,
        "score": score,
        "retrieval": mode,
        "excerpt": untrusted(sanitize_retrieved_content(text or ""), 1200),
    }
