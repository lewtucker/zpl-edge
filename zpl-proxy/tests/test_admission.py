"""Admission control: the watcher requires a valid proxy_auth credential in all
modes, but only once the hub has delivered a non-empty proxy_auth map (self-coordinating
with the Defender seeding the guard's own token). No hub / pre-first-bundle → fail open."""
import base64
from unittest.mock import MagicMock

from zpl_proxy.addon import ZplLogger


def _basic(user: str, token: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()


class _FakeHub:
    def __init__(self, proxy_auth=None):
        self.proxy_auth = proxy_auth or {}


def _logger(hub=None):
    """A ZplLogger with _ensure_init short-circuited (no config/disk) and a fake hub."""
    log = ZplLogger()
    log._config = MagicMock()   # non-None → _ensure_init() early-returns
    log._hub = hub
    return log


def _flow(proxy_auth=None, conn_id="c1", flow_id="f1"):
    flow = MagicMock()
    flow.client_conn.id = conn_id
    flow.id = flow_id
    flow.request.headers = {"Proxy-Authorization": proxy_auth} if proxy_auth else {}
    flow.response = None
    return flow


def test_admission_not_enforced_without_hub():
    assert _logger(hub=None)._admission_enforced() is False


def test_admission_not_enforced_with_empty_proxy_auth():
    # Pre-first-bundle window: hub is up but no credentials seeded yet → fail open.
    assert _logger(hub=_FakeHub({}))._admission_enforced() is False


def test_admission_enforced_once_credentials_seeded():
    assert _logger(hub=_FakeHub({"tok": {"agent": "g"}}))._admission_enforced() is True


def test_connect_rejects_uncredentialed_tunnel():
    log = _logger(hub=_FakeHub({"tok": {"agent": "g", "subject": "s", "roles": []}}))
    flow = _flow()  # no Proxy-Authorization
    log.http_connect(flow)
    assert flow.response is not None and flow.response.status_code == 407
    assert flow.client_conn.id not in log._conn_agent


def test_connect_admits_valid_credential_and_pins_identity():
    log = _logger(hub=_FakeHub({"tok": {"agent": "hermes", "subject": "kyle", "roles": ["r"]}}))
    flow = _flow(proxy_auth=_basic("hermes", "tok"))
    log.http_connect(flow)
    assert flow.response is None
    assert log._conn_agent[flow.client_conn.id]["agent"] == "hermes"


def test_connect_does_not_reject_when_admission_off():
    # No hub (local dev) → uncredentialed CONNECT is left alone (backward compatible).
    log = _logger(hub=None)
    flow = _flow()
    log.http_connect(flow)
    assert flow.response is None


def test_plaintext_request_rejected_before_enforcement():
    log = _logger(hub=_FakeHub({"tok": {"agent": "g", "subject": "s", "roles": []}}))
    log._enforce = MagicMock()
    flow = _flow()  # plaintext HTTP, no CONNECT, no credential
    log.request(flow)
    assert flow.response is not None and flow.response.status_code == 407
    log._enforce.assert_not_called()   # rejected before any policy evaluation


def test_plaintext_request_admits_valid_credential():
    log = _logger(hub=_FakeHub({"tok": {"agent": "hermes", "subject": "kyle", "roles": []}}))
    log._enforce = MagicMock()
    flow = _flow(proxy_auth=_basic("hermes", "tok"))
    log.request(flow)
    assert flow.response is None
    assert log._conn_agent[flow.client_conn.id]["agent"] == "hermes"
    # Proxy-Authorization is stripped (hop-by-hop) before forwarding upstream.
    assert "Proxy-Authorization" not in flow.request.headers
    log._enforce.assert_called_once()


def test_request_on_already_pinned_connection_passes():
    # CONNECT already admitted + pinned this conn; the tunnelled request needs no re-auth.
    log = _logger(hub=_FakeHub({"tok": {"agent": "hermes", "subject": "kyle", "roles": []}}))
    log._enforce = MagicMock()
    log._conn_agent["c1"] = {"agent": "hermes", "subject": "kyle", "roles": []}
    flow = _flow(conn_id="c1")  # no Proxy-Authorization on the tunnelled request
    log.request(flow)
    assert flow.response is None
    log._enforce.assert_called_once()
