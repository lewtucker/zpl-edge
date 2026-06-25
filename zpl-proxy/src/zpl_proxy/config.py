from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class StaticIdentity:
    ip: str
    agent_id: str
    agent_role: Optional[str] = None


@dataclass
class RedactRule:
    pattern: str
    replacement: str


@dataclass
class ProxyConfig:
    listen_host: str
    listen_port: int
    data_dir: Path
    docker_socket: str
    docker_cache_ttl: int
    identity_header: str
    body_size_limit: int
    log_level: str
    identities: list[StaticIdentity] = field(default_factory=list)
    redact: list[RedactRule] = field(default_factory=list)
    # mitmproxy ignore_hosts regexes (matched against "host:port"). Matching
    # connections are passed through as a raw TCP tunnel — never TLS-intercepted,
    # logged, aggregated, or shipped. Use for noisy/sensitive egress the agent
    # routes through us anyway (e.g. Telegram bot polling) but we don't govern.
    ignore_hosts: list[str] = field(default_factory=list)
    # NOTE: enforcement (rule set + mode: flag/enforce/monitor) is delivered by the
    # hub via GET /api/watcher/bundle and held on the WatcherHub — NOT configured
    # locally. No policy_file / mode here.
    # Hub (MCP Defender) — ship egress logs to a central control plane. When both
    # are set, the watcher POSTs batches to {hub_url}/api/watcher/logs with the
    # guard token. Put the real token in proxy.local.yaml (gitignored).
    hub_url: Optional[str] = None
    hub_guard_token: Optional[str] = None


def load_config(path: Path | None = None) -> ProxyConfig:
    if path is None:
        path = Path(os.environ.get("ZPL_CONFIG", "/app/config/proxy.yaml"))

    if path.exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    # proxy.local.yaml sits next to proxy.yaml and is gitignored.
    # It merges on top — use it for machine-specific IPs, real tokens, etc.
    local_path = path.with_name("proxy.local.yaml")
    if local_path.exists():
        with open(local_path) as f:
            local = yaml.safe_load(f) or {}
        # Lists append; scalars override
        for key in ("identities", "redact", "ignore_hosts"):
            raw[key] = raw.get(key, []) + local.get(key, [])
        for key, val in local.items():
            if key not in ("identities", "redact", "ignore_hosts"):
                raw[key] = val

    identities = [
        StaticIdentity(
            ip=entry["ip"],
            agent_id=entry["agent_id"],
            agent_role=entry.get("agent_role"),
        )
        for entry in raw.get("identities", [])
    ]

    redact = [
        RedactRule(pattern=entry["pattern"], replacement=entry["replacement"])
        for entry in raw.get("redact", [])
    ]

    return ProxyConfig(
        listen_host=raw.get("listen_host", "0.0.0.0"),
        listen_port=int(raw.get("listen_port", 8080)),
        data_dir=Path(raw.get("data_dir", "data")),
        docker_socket=raw.get("docker_socket", "/var/run/docker.sock"),
        docker_cache_ttl=int(raw.get("docker_cache_ttl", 30)),
        identity_header=raw.get("identity_header", "X-ZPL-Agent-ID"),
        body_size_limit=int(raw.get("body_size_limit", 1048576)),
        log_level=raw.get("log_level", os.environ.get("LOG_LEVEL", "INFO")),
        identities=identities,
        redact=redact,
        ignore_hosts=[str(h) for h in raw.get("ignore_hosts", [])],
        hub_url=raw.get("hub_url") or os.environ.get("ZPL_HUB_URL"),
        hub_guard_token=raw.get("hub_guard_token") or os.environ.get("ZPL_HUB_GUARD_TOKEN"),
    )
