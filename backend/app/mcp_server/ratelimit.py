"""Per-caller sliding-window rate limit (in-memory, per process)."""

import os
import threading
import time
from collections import defaultdict, deque

MAX_CALLS = int(os.getenv("SECUREAI_MCP_RATE_LIMIT", "60"))
WINDOW_SECONDS = 60

_calls: dict[int, deque] = defaultdict(deque)
_last_audited: dict[int, float] = {}
_lock = threading.Lock()


def reset() -> None:
    with _lock:
        _calls.clear()
        _last_audited.clear()


def check(user_id: int) -> tuple[bool, bool]:
    """Returns (allowed, should_audit_denial). Denials are audited at most
    once per window so a runaway client cannot flood the audit table."""
    now = time.monotonic()
    with _lock:
        q = _calls[user_id]
        while q and now - q[0] >= WINDOW_SECONDS:
            q.popleft()
        if len(q) < MAX_CALLS:
            q.append(now)
            return True, False
        last = _last_audited.get(user_id)
        if last is None or now - last >= WINDOW_SECONDS:
            _last_audited[user_id] = now
            return False, True
        return False, False
