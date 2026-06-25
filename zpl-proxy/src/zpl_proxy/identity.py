from __future__ import annotations

import base64
import binascii
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
import requests_unixsocket

from zpl_proxy.config import StaticIdentity


@dataclass
class AgentIdentity:
    agent_id: str
    agent_role: Optional[str]
    source: str  # 'static' | 'docker' | 'header' | 'proxy-auth' | 'unknown'
    raw_labels: dict = field(default_factory=dict)
    subject: Optional[str] = None      # the person, for ZPL enforcement (proxy-auth only)
    roles: list = field(default_factory=list)  # subject's roles, for P1 injection


def parse_basic_proxy_auth(header_value: Optional[str]) -> Optional[tuple[str, str]]:
    """Parse `Proxy-Authorization: Basic base64(user:pass)` → (user, pass).

    Returns None for an absent or malformed header. Used to read the per-agent
    identity we encode in each agent's proxy URL (`http://<agent>:<token>@host:port`).
    """
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        raw = base64.b64decode(parts[1], validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
    if ":" not in raw:
        return None
    user, pw = raw.split(":", 1)
    return user, pw


_UNKNOWN = AgentIdentity(agent_id="unknown", agent_role=None, source="unknown")


class IdentityResolver:
    def __init__(
        self,
        docker_socket: str,
        identity_header: str,
        cache_ttl: int,
        static_identities: list[StaticIdentity] | None = None,
    ) -> None:
        self._socket = docker_socket
        self._header = identity_header
        self._ttl = cache_ttl
        self._static: dict[str, AgentIdentity] = {
            s.ip: AgentIdentity(agent_id=s.agent_id, agent_role=s.agent_role, source="static")
            for s in (static_identities or [])
        }
        # cache: peer_ip → (AgentIdentity, expire_time)
        self._cache: dict[str, tuple[AgentIdentity, float]] = {}
        self._session = requests_unixsocket.Session()

    def resolve_sync(self, peer_ip: str, headers: dict[str, str]) -> AgentIdentity:
        cached, expires = self._cache.get(peer_ip, (None, 0))
        if cached is not None and time.monotonic() < expires:
            return cached

        identity = (
            self._static.get(peer_ip)
            or self._resolve_docker(peer_ip)
            or self._resolve_header(headers)
        )

        ttl = self._ttl if identity.source != "unknown" else 5
        self._cache[peer_ip] = (identity, time.monotonic() + ttl)
        return identity

    def _resolve_docker(self, peer_ip: str) -> Optional[AgentIdentity]:
        try:
            socket_url = self._socket.replace("/", "%2F")
            resp = self._session.get(
                f"http+unix://{socket_url}/containers/json",
                timeout=2,
            )
            resp.raise_for_status()
            containers = resp.json()
        except Exception:
            return None

        for container in containers:
            networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
            for net in networks.values():
                if net.get("IPAddress") == peer_ip:
                    labels = container.get("Labels") or {}
                    agent_id = (
                        labels.get("zpl.agent_id")
                        or container.get("Names", ["unknown"])[0].lstrip("/")
                    )
                    return AgentIdentity(
                        agent_id=agent_id,
                        agent_role=labels.get("zpl.agent_role"),
                        source="docker",
                        raw_labels=labels,
                    )
        return None

    def _resolve_header(self, headers: dict[str, str]) -> AgentIdentity:
        # headers may be mixed-case from mitmproxy
        for k, v in headers.items():
            if k.lower() == self._header.lower():
                return AgentIdentity(agent_id=v, agent_role=None, source="header")
        return _UNKNOWN
