"""WatcherHub — reverse-channel client: register, poll, fulfill a fetch (Phase 1b)."""
from zpl_proxy.hub import WatcherHub
from zpl_proxy.storage.aggregate import EgressAggregate

HUB = "https://mcp-defender.lewtucker.net"


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeClient:
    """Scripts GET responses (by url) and records every POST."""
    def __init__(self, get_map=None):
        self.posts = []
        self.gets = []
        self._get_map = get_map or {}

    def get(self, url, headers=None):
        self.gets.append({"url": url, "headers": headers})
        return self._get_map.get(url, _Resp(200, {"commands": []}))

    def post(self, url, headers=None, json=None):
        self.posts.append({"url": url, "headers": headers, "json": json})
        if url.endswith("/register"):
            return _Resp(200, {"ok": True, "subject": "OpenClawMini", "agent": "openclaw-mini"})
        return _Resp(200, {"ok": True, "recording_id": "rec1"})


def _hub(agg):
    return WatcherHub(HUB, "tok123", agg, listen="127.0.0.1:8080",
                      hostname="mini", autostart=False)


def _agg(tmp_path):
    a = EgressAggregate(tmp_path / "agg.db")
    a.record(host="api.telegram.org", method="POST",
             path="/bot:id/getUpdates?offset=1", ts="2026-06-15T14:00:00+00:00", status=200)
    return a


def test_register_posts_with_bearer_and_captures_identity(tmp_path):
    h = _hub(_agg(tmp_path))
    fake = _FakeClient()
    h._register(fake)
    assert h._registered is True
    call = fake.posts[0]
    assert call["url"] == HUB + "/api/watcher/register"
    assert call["headers"]["Authorization"] == "Bearer tok123"
    assert "fetch" in call["json"]["capabilities"]
    assert call["json"]["listen"] == "127.0.0.1:8080"
    # the hub delivers the authoritative ZPL identity in the register response
    assert h.subject == "OpenClawMini" and h.agent == "openclaw-mini"


def test_poll_refreshes_identity(tmp_path):
    h = _hub(_agg(tmp_path))
    fake = _FakeClient({HUB + "/api/watcher/commands":
                        _Resp(200, {"subject": "Renamed", "agent": "a2", "commands": []})})
    h._poll_once(fake)
    assert h.subject == "Renamed" and h.agent == "a2"


def test_poll_fulfills_fetch_from_aggregate(tmp_path):
    h = _hub(_agg(tmp_path))
    cmd = {"id": "c1", "type": "fetch", "params": {"mode": "recent"}}
    fake = _FakeClient({HUB + "/api/watcher/commands": _Resp(200, {"commands": [cmd]})})
    h._poll_once(fake)
    # one upload to /logs, tagged with the command id, carrying the deduped slice
    up = [p for p in fake.posts if p["url"].endswith("/logs")]
    assert len(up) == 1
    body = up[0]["json"]
    assert body["command_id"] == "c1"
    assert len(body["records"]) == 1
    rec = body["records"][0]
    assert rec["host"] == "api.telegram.org" and rec["count"] == 1
    assert "AAGf" not in rec["path"]                 # token scrubbed upstream
    assert rec["query_keys"] == ["offset"]


def test_range_fetch_passes_window(tmp_path):
    a = EgressAggregate(tmp_path / "agg.db")
    a.record(host="h", method="GET", path="/a", ts="2026-06-15T13:00:00+00:00")
    a.record(host="h", method="GET", path="/a", ts="2026-06-15T15:00:00+00:00")
    h = _hub(a)
    cmd = {"id": "c2", "type": "fetch",
           "params": {"mode": "range", "frm": "2026-06-15T14:00:00+00:00",
                      "to": "2026-06-15T16:00:00+00:00"}}
    fake = _FakeClient({HUB + "/api/watcher/commands": _Resp(200, {"commands": [cmd]})})
    h._poll_once(fake)
    body = [p for p in fake.posts if p["url"].endswith("/logs")][0]["json"]
    assert len(body["records"]) == 1   # only the 15:00 bucket is in [14:00,16:00]
