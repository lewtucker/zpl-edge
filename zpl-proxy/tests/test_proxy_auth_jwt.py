"""P3 integration — the addon resolves a delegated JWT proxy credential to VERIFIED,
spoof-proof identity, and admits/rejects the tunnel on verification (not the username)."""
import base64
import datetime as dt
from unittest.mock import MagicMock

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

from zpl_proxy.addon import ZplLogger

AUD = "http://127.0.0.1:8099/mcp/g1"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    jwk = OKPAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    return priv, {"keys": [jwk]}


def _mint(priv, *, agent=None, roles=None, sub="Lew", aud=AUD):
    now = dt.datetime.now(dt.timezone.utc)
    p = {"iss": "mcp-defender", "sub": sub, "aud": aud, "guard_id": "g1",
         "iat": now, "exp": now + dt.timedelta(seconds=3600)}
    if agent:
        p["agent"] = agent
    if roles:
        p["roles"] = roles
    return jwt.encode(p, priv, algorithm="EdDSA", headers={"kid": "k1"})


class _FakeHub:
    def __init__(self, jwks, audience, proxy_auth=None):
        self.jwks, self.audience = jwks, audience
        # the guard's own token is always present, so admission is enforced
        self.proxy_auth = proxy_auth or {"guard-tok": {"agent": "guard", "subject": "Lew"}}


def _logger(hub):
    log = ZplLogger()
    log._config = MagicMock()   # non-None → _ensure_init() early-returns
    log._hub = hub
    return log


def _basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def _flow(proxy_auth):
    flow = MagicMock()
    flow.client_conn.id = "c1"
    flow.id = "f1"
    flow.request.headers = {"Proxy-Authorization": proxy_auth}
    flow.response = None
    return flow


def test_delegated_jwt_resolves_spoof_proof():
    priv, jwks = _keypair()
    log = _logger(_FakeHub(jwks, AUD))
    tok = _mint(priv, agent="hermes", roles=["operator"])
    # username is forged as "evil" — the verified agent claim must win
    ident = log._resolve_proxy_auth(_basic("evil", tok))
    assert ident == {"agent": "hermes", "subject": "Lew", "roles": ["operator"]}


def test_invalid_jwt_rejected():
    priv, jwks = _keypair()
    other, _ = _keypair()
    log = _logger(_FakeHub(jwks, AUD))
    assert log._resolve_proxy_auth(_basic("x", _mint(other, agent="z"))) is None   # wrong key
    assert log._resolve_proxy_auth(_basic("x", _mint(priv, agent="z", aud="http://evil/mcp/g1"))) is None  # wrong aud


def test_connect_admits_jwt_and_pins_verified_identity():
    priv, jwks = _keypair()
    log = _logger(_FakeHub(jwks, AUD))
    flow = _flow(_basic("evil", _mint(priv, agent="hermes", roles=["operator"])))
    log.http_connect(flow)
    assert flow.response is None                                   # admitted
    assert log._conn_agent[flow.client_conn.id]["agent"] == "hermes"   # verified, not "evil"
    assert log._conn_agent[flow.client_conn.id]["subject"] == "Lew"


def test_connect_rejects_invalid_jwt():
    priv, jwks = _keypair()
    other, _ = _keypair()
    log = _logger(_FakeHub(jwks, AUD))
    flow = _flow(_basic("x", _mint(other, agent="z")))   # signed by an unknown key
    log.http_connect(flow)
    assert flow.response is not None and flow.response.status_code == 407


def test_static_proxy_auth_still_works():
    # a non-JWT password still resolves via the static map (precedence/back-compat)
    priv, jwks = _keypair()
    hub = _FakeHub(jwks, AUD, proxy_auth={"statictok": {"agent": "openclaw", "subject": "kyle", "roles": []}})
    log = _logger(hub)
    assert log._resolve_proxy_auth(_basic("openclaw", "statictok")) == {
        "agent": "openclaw", "subject": "kyle", "roles": []}
