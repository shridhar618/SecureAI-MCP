"""Loads and validates the incident-response MCP configuration.

The config is a JSON file (default: backend/mcp_servers.json, override with
INCIDENT_MCP_CONFIG). See backend/mcp_servers.example.json for the shape.

Mode resolution (first match wins):
    INCIDENT_MCP_MODE env var  ->  "mode" in the file  ->  "off"

Modes:
    off      nothing happens (default; also used when no file exists)
    dry_run  actions are planned and audited, but no MCP server is contacted
    live     actions are executed against the configured MCP servers
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

MODES = ("off", "dry_run", "live")
INCIDENT_KINDS = ("high_risk_request", "governance_case_opened")

_BACKEND_DIR = Path(__file__).resolve().parents[3]
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


@dataclass
class ServerSpec:
    name: str
    command: str
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)


@dataclass
class ActionSpec:
    name: str
    server: str
    tool: str
    arguments: dict
    on: tuple = INCIDENT_KINDS


@dataclass
class IncidentMCPConfig:
    mode: str = "off"
    timeout_seconds: int = 30
    servers: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)

    def actions_for(self, kind):
        return [a for a in self.actions if kind in a.on]


def expand_env(value):
    """Replaces ${VAR} with the environment value, recursively.

    Unset variables expand to "" so a missing secret fails at the MCP
    server (visible in the audit trail) instead of leaking the literal
    "${VAR}" text to a third party.
    """
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def config_path():
    return Path(os.getenv("INCIDENT_MCP_CONFIG") or _BACKEND_DIR / "mcp_servers.json")


def load_config(path=None):
    """Returns an IncidentMCPConfig. Missing file => mode "off"."""
    path = Path(path) if path else config_path()
    env_mode = (os.getenv("INCIDENT_MCP_MODE") or "").strip().lower()

    if not path.is_file():
        if env_mode and env_mode not in MODES:
            raise ConfigError(f"INCIDENT_MCP_MODE must be one of {MODES}")
        return IncidentMCPConfig(mode="off")

    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Cannot read MCP config {path}: {exc}") from exc

    mode = env_mode or str(raw.get("mode", "off")).lower()
    if mode not in MODES:
        raise ConfigError(f"mode must be one of {MODES}, got {mode!r}")

    servers = {}
    for name, spec in (raw.get("servers") or {}).items():
        if not spec.get("command"):
            raise ConfigError(f"server {name!r} needs a 'command'")
        servers[name] = ServerSpec(
            name=name,
            command=spec["command"],
            args=list(spec.get("args", [])),
            env=dict(spec.get("env", {})),
        )

    actions = []
    for spec in raw.get("actions") or []:
        for key in ("name", "server", "tool"):
            if not spec.get(key):
                raise ConfigError(f"every action needs {key!r}: {spec}")
        if spec["server"] not in servers:
            raise ConfigError(f"action {spec['name']!r} uses unknown server {spec['server']!r}")
        on = tuple(spec.get("on") or INCIDENT_KINDS)
        bad = [k for k in on if k not in INCIDENT_KINDS]
        if bad:
            raise ConfigError(f"action {spec['name']!r} has unknown trigger(s) {bad}")
        actions.append(ActionSpec(
            name=spec["name"],
            server=spec["server"],
            tool=spec["tool"],
            arguments=dict(spec.get("arguments", {})),
            on=on,
        ))

    return IncidentMCPConfig(
        mode=mode,
        timeout_seconds=int(raw.get("timeout_seconds", 30)),
        servers=servers,
        actions=actions,
    )
