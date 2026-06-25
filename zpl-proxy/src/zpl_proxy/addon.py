from __future__ import annotations

import json
import os
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import structlog
from mitmproxy import http
from mitmproxy.tools.main import mitmdump

from zpl_proxy.config import ProxyConfig, load_config
from zpl_proxy.identity import IdentityResolver, parse_basic_proxy_auth
from zpl_proxy.mcp import detect_mcp_frame, detect_mcp_response
from zpl_engine import check as zpl_check, verb_for_method, zpl_token
from zpl_proxy.storage.jsonl import JsonlWriter

log = structlog.get_logger()


def _safe_body(content: bytes, limit: int) -> str | None:
    if not content:
        return None
    if len(content) > limit:
        return f"<body truncated: {len(content)} bytes>"
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return f"<binary: {len(content)} bytes>"


def _headers_dict(headers) -> dict:
    return dict(headers)


def _redact(value: str, rules) -> str:
    for rule in rules:
        value = value.replace(rule.pattern, rule.replacement)
    return value


class ZplLogger:
    def __init__(self) -> None:
        self._config: ProxyConfig | None = None
        self._identity: IdentityResolver | None = None
        self._jsonl: JsonlWriter | None = None
        self._agg = None  # EgressAggregate | None — bucketed dedup store (Phase 1b)
        self._hub = None  # WatcherHub | None — reverse-channel client to the hub
                          # (also holds the compiled rule set + mode for enforcement)
        # Rolling in-memory tail of recent http events WITH their decision, for the
        # hub's on-demand "tail" pull (near-live decision view). Bounded; lost on
        # restart (fine — it's a live view, not durable storage).
        self._tail: deque = deque(maxlen=500)
        self._start_times: dict[str, float] = {}
        # Per-agent identity from proxy-auth: client_conn.id → {agent, subject, roles}.
        # Captured at CONNECT (HTTPS) where Proxy-Authorization lives, reused for every
        # tunnelled request on that connection. Bounded — cleared on client disconnect.
        self._conn_agent: dict[str, dict] = {}
        # P0 local-store maintenance: throttle the periodic prune/disk-check; pause
        # capture (never egress) when the volume is low on space.
        self._last_maintain: float = 0.0
        self._capture_paused: bool = False

    def running(self) -> None:
        """Initialize at proxy STARTUP (not lazily on first request): bring up the
        WatcherHub so it registers + polls the rule-set bundle immediately, so an
        idle proxy still loads/enforces policy and the first request isn't evaluated
        before the bundle arrives. Also apply config-driven ignore_hosts (pass-through
        tunneling) — independent of how mitmdump was launched."""
        self._ensure_init()
        extra = list(self._config.ignore_hosts or [])
        if not extra:
            return
        from mitmproxy import ctx
        current = list(ctx.options.ignore_hosts or [])
        merged = current + [h for h in extra if h not in current]
        if merged != current:
            ctx.options.update(ignore_hosts=merged)
            log.info("ignore_hosts pass-through applied", hosts=extra)

    def _ensure_init(self) -> None:
        if self._config is not None:
            return
        config_path = Path(os.environ.get("ZPL_CONFIG", "/app/config/proxy.yaml"))
        self._config = load_config(config_path)
        self._config.data_dir.mkdir(parents=True, exist_ok=True)

        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(__import__("logging"), self._config.log_level, 20)
            ),
        )

        self._identity = IdentityResolver(
            docker_socket=self._config.docker_socket,
            identity_header=self._config.identity_header,
            cache_ttl=self._config.docker_cache_ttl,
            static_identities=self._config.identities,
        )
        self._jsonl = JsonlWriter(self._config.data_dir / "requests.jsonl",
                                  max_bytes=self._config.max_capture_mb * 1024 * 1024)

        # Phase 1b: the durable, hub-pullable egress store — bucketed + deduped.
        from zpl_proxy.storage.aggregate import EgressAggregate
        self._agg = EgressAggregate(self._config.data_dir / "egress_agg.db")

        if self._config.hub_url and self._config.hub_guard_token:
            import socket
            from zpl_proxy.hub import WatcherHub
            listen = f"{self._config.listen_host}:{self._config.listen_port}"
            self._hub = WatcherHub(
                self._config.hub_url, self._config.hub_guard_token, self._agg,
                listen=listen, hostname=socket.gethostname(),
                tail_source=lambda: list(self._tail),
            )
            log.info("watcher_hub_enabled", hub=self._config.hub_url)

        # Enforcement uses the hub-delivered rule set (self._hub.crs) + mode, NOT a
        # local file — the rule set is polled from the hub; the engine ships on redeploy.
        log.info("zpl_proxy_started", port=self._config.listen_port)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """HTTPS CONNECT — the only place Proxy-Authorization is seen for tunnelled
        TLS. Capture the per-agent identity here and pin it to the connection so every
        request inside the tunnel is attributed to that agent."""
        self._ensure_init()
        ident = self._resolve_proxy_auth(flow.request.headers.get("Proxy-Authorization"))
        if ident:
            self._conn_agent[flow.client_conn.id] = ident

    def client_disconnected(self, client) -> None:
        self._conn_agent.pop(getattr(client, "id", None), None)

    def request(self, flow: http.HTTPFlow) -> None:
        self._ensure_init()
        self._start_times[flow.id] = time.monotonic()
        # Plaintext HTTP carries Proxy-Authorization on the request itself; strip it
        # before forwarding (hop-by-hop) but capture the identity first.
        pa = flow.request.headers.pop("Proxy-Authorization", None)
        if pa and flow.client_conn.id not in self._conn_agent:
            ident = self._resolve_proxy_auth(pa)
            if ident:
                self._conn_agent[flow.client_conn.id] = ident
        self._enforce(flow)   # no-ops unless the hub bundle is flag/enforce with rules

    def _resolve_proxy_auth(self, header_value) -> dict | None:
        """Map a Proxy-Authorization header to a per-agent identity via the bundle's
        proxy_auth map ({token → {agent, subject, roles}}). The password is the lookup
        key (a Defender-minted token); the username is a cosmetic agent label / fallback."""
        creds = parse_basic_proxy_auth(header_value)
        if not creds or not self._hub:
            return None
        user, token = creds
        m = self._hub.proxy_auth or {}
        entry = m.get(token) or m.get(user)
        if not entry:
            return None
        return {"agent": entry.get("agent") or user,
                "subject": entry.get("subject"),
                "roles": entry.get("roles") or []}

    def _flow_identity(self, flow: http.HTTPFlow) -> dict | None:
        """The per-agent proxy-auth identity for this flow, if any (pinned at CONNECT)."""
        return self._conn_agent.get(flow.client_conn.id)

    def response(self, flow: http.HTTPFlow) -> None:
        self._ensure_init()
        elapsed_ms = int((time.monotonic() - self._start_times.pop(flow.id, time.monotonic())) * 1000)

        try:
            self._record(flow, elapsed_ms)
        except Exception as exc:
            log.error("record_failed", flow_id=flow.id, error=str(exc))

    def _enforce(self, flow: http.HTTPFlow) -> None:
        """Evaluate the request against the hub-delivered rule set, using the SAME
        engine + attribute model as the hub (verb_for_method, server=host,
        object=path). enforce → 403 on deny; flag → log the would-be-deny, don't
        block; otherwise no-op. Fails OPEN on any error (never blocks on a bug)."""
        hub = self._hub
        if not hub or hub.crs is None or hub.mode not in ("flag", "enforce"):
            return
        try:
            parsed = urlparse(flow.request.pretty_url)
            dest_host = parsed.hostname or flow.request.host
            method = flow.request.method
            path = _redact(flow.request.path, self._config.redact)

            # Identity: a per-agent proxy-auth identity (multi-agent watcher) overrides the
            # guard's single subject/agent when present; otherwise fall back to the guard.
            # P1: inject the subject's roles so role/group ZPL rules match — under BOTH
            # `roles` (RFC `roles:{…}`) and `role` (the singular `with role:operator` form).
            ident = self._flow_identity(flow)
            if ident:
                subject = ident["subject"] or "unknown"
                agent = ident["agent"] or "unknown"
                roles = ident["roles"] or (hub.subjects.get(zpl_token(subject)) if hub.subjects else None)
            else:
                subject = hub.subject or "unknown"
                agent = hub.agent or "unknown"
                roles = hub.subjects.get(zpl_token(subject)) if hub.subjects else None
            decision = zpl_check(
                hub.crs,
                user=subject,
                agent_id=agent,
                tool=path, args={"path": path},
                service=dest_host, verb=verb_for_method(method),
                subject_attrs={"roles": roles, "role": roles} if roles else None,
            )
            flow.metadata["policy_verdict"] = "allow" if decision.allowed else "deny"
            flow.metadata["policy_rule"] = decision.rule_name or ""
            # Effective, mode-adjusted decision (what the hub UI shows): allow→allowed,
            # deny→denied under enforce (blocked) or flagged under flag (passed through).
            flow.metadata["policy_decision"] = (
                "allowed" if decision.allowed
                else ("denied" if hub.mode == "enforce" else "flagged"))

            if not decision.allowed:
                if hub.mode == "enforce":
                    body = json.dumps({"error": "blocked by ZPL policy",
                                       "reason": decision.reason}).encode()
                    flow.response = http.Response.make(403, body, {"Content-Type": "application/json"})
                    log.info("request_blocked", host=dest_host, method=method, path=path,
                             reason=decision.reason)
                else:  # flag
                    log.info("request_flagged", host=dest_host, method=method, path=path,
                             reason=decision.reason)
        except Exception as exc:
            # Fail open on unexpected errors — log but don't block.
            log.error("enforce_error", error=str(exc), flow_id=flow.id)

    def _record(self, flow: http.HTTPFlow, elapsed_ms: int) -> None:
        peer_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        req_headers = _headers_dict(flow.request.headers)
        # Prefer the per-agent proxy-auth identity (multi-agent watcher); else the
        # IP/Docker/header resolver.
        pa = self._flow_identity(flow)
        if pa:
            from zpl_proxy.identity import AgentIdentity
            agent = AgentIdentity(agent_id=pa["agent"], agent_role=None, source="proxy-auth",
                                  subject=pa["subject"], roles=pa["roles"])
        else:
            agent = self._identity.resolve_sync(peer_ip, req_headers)
        # Attribution carried to the hub: a resolved agent (proxy-auth/static/docker) is
        # preserved; 'unknown' becomes '' so the Defender falls back to the guard's agent.
        agg_agent = "" if agent.source == "unknown" else agent.agent_id

        req_body = flow.request.content
        resp_body = flow.response.content if flow.response else b""

        mcp_req = detect_mcp_frame(req_body, flow.request.headers.get("content-type", ""))
        mcp_resp = detect_mcp_response(resp_body) if mcp_req else None

        parsed = urlparse(flow.request.pretty_url)
        dest_host = parsed.hostname or flow.request.host
        dest_port = parsed.port or flow.request.port
        path = _redact(flow.request.path, self._config.redact)

        request_type = "mcp" if mcp_req else "http"

        ts = datetime.now(timezone.utc).isoformat()

        record = {
            "ts": ts,
            "agent_id": agent.agent_id,
            "agent_role": agent.agent_role,
            "peer_ip": peer_ip,
            "identity_source": agent.source,
            "request_type": request_type,
            "dest_host": dest_host,
            "dest_port": dest_port,
            "method": flow.request.method,
            "path": path,
            "request_headers": json.dumps(req_headers),
            "request_body": _safe_body(req_body, self._config.body_size_limit) if self._config.capture_bodies else None,
            # MCP
            "mcp_method": mcp_req.method if mcp_req else None,
            "tool_name": mcp_req.tool_name if mcp_req else None,
            "tool_args": json.dumps(mcp_req.tool_args) if (mcp_req and mcp_req.tool_args) else None,
            # Response
            "response_code": flow.response.status_code if flow.response else None,
            "response_time_ms": elapsed_ms,
            "response_headers": json.dumps(_headers_dict(flow.response.headers)) if flow.response else None,
            "response_body": _safe_body(resp_body, self._config.body_size_limit) if self._config.capture_bodies else None,
            # MCP response
            "tool_result": json.dumps(mcp_resp.tool_result) if (mcp_resp and mcp_resp.tool_result) else None,
            # Policy enforcement
            "policy_verdict": flow.metadata.get("policy_verdict"),
            "policy_rule_id": flow.metadata.get("policy_rule_id"),
        }

        if not self._capture_paused:
            self._jsonl.write(record)   # forensic log (rotated; bodies only if capture_bodies)
        self._maybe_maintain()          # throttled: prune old aggregate buckets + disk check

        # Phase 1b durable store: fold every HTTP request into the bucketed aggregate.
        # This is what the hub pulls on demand (deduped, secret-scrubbed).
        if self._agg is not None and request_type == "http":
            try:
                self._agg.record(
                    host=dest_host,
                    method=flow.request.method,
                    path=path,   # already redaction-filtered above
                    ts=ts,
                    status=flow.response.status_code if flow.response else None,
                    # per-agent attribution; '' (unattributed) → the Defender uses the guard agent
                    agent=agg_agent,
                )
            except Exception as exc:
                log.warning("egress_agg_failed", error=str(exc))

            # Rolling tail of recent http events WITH the (mode-adjusted) decision,
            # for the hub's on-demand near-live "tail" pull. Decision is None in
            # monitor/unbound (captured but not evaluated).
            self._tail.append({
                "ts": ts, "host": dest_host, "method": flow.request.method, "path": path,
                "agent": agg_agent,
                "status": flow.response.status_code if flow.response else None,
                "decision": flow.metadata.get("policy_decision"),
                "rule": flow.metadata.get("policy_rule") or None,
            })

        # No continuous push: the hub pulls deduped slices on demand from the
        # aggregate (see hub.WatcherHub). Egress stays entirely local until fetched.

        # Per-request line is DEBUG so the default-INFO log doesn't grow per request
        # (decisions surface via request_flagged/request_blocked in _enforce).
        log.debug(
            "request_logged",
            agent=agent.agent_id,
            type=request_type,
            host=dest_host,
            method=flow.request.method,
            path=path,
            tool=mcp_req.tool_name if mcp_req else None,
            status=flow.response.status_code if flow.response else None,
        )

    def _maybe_maintain(self) -> None:
        """Throttled (~hourly) local-store upkeep: prune aggregate buckets past the
        retention window and pause forensic capture if the volume is low on space.
        Never raises into the request path; never blocks egress."""
        import shutil
        now = time.monotonic()
        if now - self._last_maintain < 3600:
            return
        self._last_maintain = now
        try:
            if self._agg is not None and self._config.retention_days > 0:
                cutoff = (datetime.now(timezone.utc)
                          - timedelta(days=self._config.retention_days)).isoformat()
                removed = self._agg.prune(cutoff)
                if removed:
                    log.info("egress_agg_pruned", removed=removed, retention_days=self._config.retention_days)
            free_mb = shutil.disk_usage(self._config.data_dir).free / (1024 * 1024)
            paused = free_mb < 200
            if paused != self._capture_paused:
                self._capture_paused = paused
                log.warning("capture_paused", paused=paused, free_mb=int(free_mb))
        except Exception as exc:  # never let upkeep break logging/egress
            log.warning("maintain_failed", error=str(exc))

    def done(self) -> None:
        if self._hub:
            self._hub.stop()
        if self._jsonl:
            self._jsonl.close()
        if self._agg:
            self._agg.close()


addons = [ZplLogger()]


def main() -> None:
    """Entry point for `zpl-proxy` CLI — runs mitmdump with this addon."""
    config = load_config()
    # ignore_hosts is applied by the addon's running() hook (so it also works when
    # mitmdump is launched directly with -s addon.py), not via CLI args here.
    mitmdump(
        args=[
            "--listen-host", config.listen_host,
            "--listen-port", str(config.listen_port),
            "--quiet",
            "-s", __file__,
        ]
    )
