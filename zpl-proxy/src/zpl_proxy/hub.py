"""hub.py — reverse-channel client to the MCP Defender hub (Phase 1b).

Logs live here on the watcher; the hub pulls slices on demand. This client makes
ONLY outbound calls (NAT-safe), on a background thread:

  1. register once at startup (POST /api/watcher/register),
  2. poll for work (GET /api/watcher/commands) on an interval,
  3. fulfill a 'fetch' by querying the local bucketed aggregate for the requested
     window and uploading the deduped slice (POST /api/watcher/logs with command_id).

No continuous push — the hub asks, the watcher answers. Best-effort: network errors
are logged and retried on the next tick; the data plane never blocks on the hub.
"""
from __future__ import annotations

import threading

import httpx
import structlog

log = structlog.get_logger()


class WatcherHub:
    def __init__(self, hub_url: str, guard_token: str, aggregate, *,
                 listen: str = "", hostname: str = "", version: str = "0.1",
                 poll_interval: float = 5.0, autostart: bool = True,
                 tail_source=None, stats_source=None, prune_source=None) -> None:
        base = hub_url.rstrip("/")
        self._register_url = base + "/api/watcher/register"
        self._commands_url = base + "/api/watcher/commands"
        self._logs_url = base + "/api/watcher/logs"
        self._bundle_url = base + "/api/watcher/bundle"
        self._tail_url = base + "/api/watcher/tail"
        self._heartbeat_url = base + "/api/watcher/heartbeat"
        self._token = guard_token
        self._agg = aggregate
        self._tail_source = tail_source   # callable → list of recent event dicts
        self._stats_source = stats_source  # callable → local-store stats dict (heartbeat)
        self._prune_source = prune_source  # callable(params) → prune local stores on command
        self._listen = listen
        self._hostname = hostname
        self._version = version
        self._poll = poll_interval
        self._registered = False
        # Authoritative ZPL identity, delivered by the hub (register + every poll).
        # Used for local-log stamping now, and ZPL enforcement in Phase 2.
        self.subject: str | None = None
        self.agent: str | None = None
        # Bound rule set for local enforcement, pulled from the hub (rule-set ONLY —
        # engine code ships on redeploy). crs = compiled rule set (None = nothing to
        # enforce); mode drives behavior (enforce blocks, flag logs, else no-op).
        self.crs = None
        self.mode: str = "monitor"
        self.subjects: dict = {}   # P1: {subject → [roles]} from the bundle (owner memberships)
        self.proxy_auth: dict = {}  # multi-agent: {token → {agent, subject, roles}} from the bundle
        self._bundle_version: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="watcher-hub", daemon=True)
        if autostart:
            self._thread.start()

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        with httpx.Client(timeout=15.0) as client:
            while not self._stop.is_set():
                try:
                    if not self._registered:
                        self._register(client)
                    if self._registered:
                        self._poll_once(client)
                        self._poll_bundle(client)
                        self._heartbeat(client)
                except Exception as exc:  # never let the loop die
                    log.warning("watcher_hub_tick_failed", error=str(exc))
                self._stop.wait(self._poll)

    def _register(self, client: httpx.Client) -> None:
        resp = client.post(self._register_url, headers=self._headers, json={
            "hostname": self._hostname, "version": self._version,
            "listen": self._listen, "capabilities": ["fetch"],
        })
        if resp.status_code == 200:
            self._registered = True
            self._set_identity(resp.json())
            log.info("watcher_registered", hub=self._register_url,
                     subject=self.subject, agent=self.agent)
        else:
            log.warning("watcher_register_rejected", status=resp.status_code)

    def _set_identity(self, payload: dict) -> None:
        sub, ag = payload.get("subject"), payload.get("agent")
        changed = (sub and sub != self.subject) or (ag and ag != self.agent)
        if sub:
            self.subject = sub
        if ag:
            self.agent = ag
        if changed:  # log on first set + whenever a portal edit propagates (no restart)
            log.info("watcher_identity_updated", subject=self.subject, agent=self.agent)

    def _heartbeat(self, client: httpx.Client) -> None:
        """Report liveness + local-store stats so the portal shows watcher health
        (disk used, events, age, capture state). Best-effort; never blocks."""
        stats = self._stats_source() if self._stats_source else {}
        resp = client.post(self._heartbeat_url, headers=self._headers, json={
            "hostname": self._hostname, "version": self._version,
            "listen": self._listen, "stats": stats,
        })
        if resp.status_code != 200:
            log.warning("watcher_heartbeat_rejected", status=resp.status_code)

    def _poll_once(self, client: httpx.Client) -> None:
        resp = client.get(self._commands_url, headers=self._headers)
        if resp.status_code != 200:
            log.warning("watcher_poll_rejected", status=resp.status_code)
            return
        payload = resp.json()
        self._set_identity(payload)   # refresh identity each poll (picks up portal edits)
        for cmd in payload.get("commands", []):
            if cmd.get("type") == "fetch":
                self._fulfill_fetch(client, cmd)
            elif cmd.get("type") == "tail":
                self._fulfill_tail(client, cmd)
            elif cmd.get("type") == "prune" and self._prune_source:
                self._prune_source(cmd.get("params") or {})   # admin-triggered local cleanup

    def _poll_bundle(self, client: httpx.Client) -> None:
        """Pull the guard's bound rule set + mode; recompile only on version change.
        Keeps last-known-good on any network/compile error (never blocks the data
        plane, never reverts to an unguarded state because of a transient failure)."""
        resp = client.get(self._bundle_url, headers=self._headers)
        if resp.status_code != 200:
            log.warning("watcher_bundle_rejected", status=resp.status_code)
            return
        b = resp.json()
        version = b.get("version")
        if version == self._bundle_version:
            return
        mode = b.get("mode") or "monitor"
        zpl = b.get("zpl") or ""
        crs = None
        if mode in ("flag", "enforce") and zpl.strip():
            try:
                from .zpl_checker import compile_rules
                crs = compile_rules(zpl)
            except Exception as exc:
                log.warning("watcher_bundle_compile_failed", error=str(exc), version=version)
                return  # keep last-known-good
        self.crs = crs
        self.mode = mode
        self.subjects = b.get("subjects") or {}   # P1: refreshed with the rule set (folded into version)
        self.proxy_auth = b.get("proxy_auth") or {}  # multi-agent: token → {agent, subject, roles}
        self._bundle_version = version
        log.info("watcher_bundle_applied", version=version, mode=mode, rules=bool(crs))

    def _fulfill_tail(self, client: httpx.Client, cmd: dict) -> None:
        """Upload the rolling per-event tail (with decisions) for the near-live view.
        Ephemeral on the hub side — not ingested into recordings."""
        if self._tail_source is None:
            return
        events = self._tail_source()
        n = int((cmd.get("params") or {}).get("limit", 100))
        resp = client.post(self._tail_url, headers=self._headers,
                           json={"events": events[-n:]})
        if resp.status_code != 200:
            log.warning("watcher_tail_upload_rejected", status=resp.status_code)

    def _fulfill_fetch(self, client: httpx.Client, cmd: dict) -> None:
        params = cmd.get("params") or {}
        if params.get("mode") == "range":
            rows = self._agg.query(since=params.get("frm"), until=params.get("to"))
        else:  # "recent" → the whole (already deduped) local store
            rows = self._agg.query()
        records = [{
            "host": r["host"], "method": r["method"], "path": r["norm_path"],
            "status": r["sample_status"], "count": r["count"],
            "query_keys": r["query_keys"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "ts": r["last_seen"],
            "agent": r.get("agent") or "",   # per-agent attribution (multi-agent watcher)
        } for r in rows]
        resp = client.post(self._logs_url, headers=self._headers,
                           json={"command_id": cmd.get("id"), "records": records})
        if resp.status_code == 200:
            log.info("watcher_fetch_fulfilled", command=cmd.get("id"), patterns=len(records),
                     recording=resp.json().get("recording_id"))
        else:
            log.warning("watcher_fetch_upload_rejected", status=resp.status_code,
                        command=cmd.get("id"))
