"""MCP-aware enforcement in the watcher addon: per-tool on tools/call, reachability
on the handshake (SSE open / initialize), non-MCP egress unchanged, and SSE responses
streamed through instead of buffered."""
import json
from unittest.mock import MagicMock

from zpl_proxy.addon import ZplLogger
from zpl_proxy.zpl_checker import compile_rules

ZPL = (
    "Define kyle as a user with name:kyle.\n"
    "Define hermes as an endpoint with name:hermes.\n"
    "Define mcp-good as a server with name:mcp-good.\n"
    "Define create_run as a service with tool:create_run.\n"
    "Allow kyle on hermes to access create_run on mcp-good.\n"
)


class _Hub:
    def __init__(self, mode="enforce"):
        self.crs = compile_rules(ZPL)
        self.mode = mode
        self.subject = "kyle"
        self.agent = "hermes"
        self.subjects = {}
        self.proxy_auth = {}


def _logger(mode="enforce"):
    log = ZplLogger()
    log._config = MagicMock()
    log._config.body_size_limit = 1_000_000
    log._config.redact = []
    log._hub = _Hub(mode)
    return log


def _flow(host, *, method="POST", path="/mcp",
          accept="application/json, text/event-stream", body=b""):
    flow = MagicMock()
    flow.client_conn.id = "c1"
    flow.id = "f1"
    flow.metadata = {}
    flow.request.headers = {"accept": accept, "content-type": "application/json"}
    flow.request.content = body
    flow.request.pretty_url = f"https://{host}{path}"
    flow.request.host = host
    flow.request.method = method
    flow.request.path = path
    flow.response = None
    return flow


def _tools_call(name, args=None):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args or {}}}).encode()


def _frame(method):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


def test_allowed_tool_passes():
    log = _logger(); f = _flow("mcp-good", body=_tools_call("create_run"))
    log._enforce(f)
    assert f.response is None
    assert f.metadata["policy_verdict"] == "allow"


def test_denied_tool_blocked_403():
    log = _logger(); f = _flow("mcp-good", body=_tools_call("delete_run"))
    log._enforce(f)
    assert f.response is not None and f.response.status_code == 403


def test_handshake_reachable_on_authorized_host():
    log = _logger(); f = _flow("mcp-good", body=_frame("initialize"))
    log._enforce(f)
    assert f.response is None and f.metadata["policy_verdict"] == "allow"


def test_handshake_blocked_on_unauthorized_host():
    log = _logger(); f = _flow("evil-mcp", body=_frame("initialize"))
    log._enforce(f)
    assert f.response is not None and f.response.status_code == 403


def test_sse_open_get_uses_reachability():
    log = _logger()
    ok = _flow("mcp-good", method="GET", path="/sse", body=b"")
    log._enforce(ok)
    assert ok.response is None                                  # reachable host
    bad = _flow("evil-mcp", method="GET", path="/sse", body=b"")
    log._enforce(bad)
    assert bad.response is not None and bad.response.status_code == 403


def test_non_mcp_egress_uses_host_path_check():
    # No text/event-stream in Accept → ordinary host/path/verb check; no rule → deny.
    log = _logger()
    f = _flow("api.example.com", method="GET", path="/x", accept="application/json", body=b"")
    log._enforce(f)
    assert f.response is not None and f.response.status_code == 403


def test_flag_mode_marks_but_does_not_block():
    log = _logger(mode="flag"); f = _flow("mcp-good", body=_tools_call("delete_run"))
    log._enforce(f)
    assert f.response is None                                   # flag never blocks
    assert f.metadata["policy_decision"] == "flagged"


def test_responseheaders_streams_event_stream():
    log = _logger()
    f = MagicMock(); f.metadata = {}
    f.response.headers = {"content-type": "text/event-stream; charset=utf-8"}
    f.response.stream = False
    log.responseheaders(f)
    assert f.response.stream is True and f.metadata["streamed"] is True


def test_responseheaders_leaves_json_buffered():
    log = _logger()
    f = MagicMock(); f.metadata = {}
    f.response.headers = {"content-type": "application/json"}
    f.response.stream = False
    log.responseheaders(f)
    assert f.response.stream is False and "streamed" not in f.metadata


def test_record_aggregates_mcp_egress():
    # An MCP POST to a server must now land in the egress aggregate (host/method/path),
    # so it shows on the HTTP guard — not only in the raw forensic log.
    log = _logger()
    log._config.capture_bodies = False
    log._jsonl = MagicMock()
    log._agg = MagicMock()
    log._maybe_maintain = MagicMock()
    log._conn_agent = {"c1": {"agent": "Hermes", "subject": "kyle", "roles": []}}
    f = _flow("mcp-defender.lewtucker.net", method="POST", path="/messages",
              body=_tools_call("robot_health"))
    f.client_conn.peername = ("127.0.0.1", 5000)
    f.response = MagicMock(); f.response.status_code = 200
    f.response.content = b""; f.response.headers = {}
    log._record(f, 5)
    assert log._agg.record.called
    kw = log._agg.record.call_args.kwargs
    assert kw["host"] == "mcp-defender.lewtucker.net"
    assert kw["agent"] == "Hermes" and kw["subject"] == "kyle"
