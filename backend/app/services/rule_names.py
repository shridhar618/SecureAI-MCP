"""Reduce stored risk factors to rule names only.

RiskEvent.factors / AuditLog.triggered_rules mix rule labels with validator
notes, and those notes quote the user's text: "matched: 'password'" and the
intent-analysis note ("... - Sensitive data extraction: “give me the salary ...").
Anything leaving the system (MCP server responses, incident payloads sent to
GitHub/Slack) must go through this so it never carries prompt fragments.
"""

import re

_NOTE_RE = re.compile(r"^(Detected .+? signal)\b")


def rule_names(items, max_len: int = 120) -> list[str]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            item = item.get("rule") or item.get("label") or item.get("name")
        if not isinstance(item, str):
            continue
        if item.startswith("Intent analysis"):
            continue
        match = _NOTE_RE.match(item)
        name = (match.group(1) if match else item)[:max_len]
        if name and name not in out:
            out.append(name)
    return out
