"""P3 — the watcher verifies a delegated per-agent JWT presented as the proxy-auth password.

Self-contained: mints EdDSA tokens with a generated Ed25519 key + its JWK (no dependency on
the Defender package), exactly the shape inbound_auth ships in the bundle's `jwks`.
"""
import datetime as dt

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

from zpl_proxy import jwt_verify

AUD = "http://watcher.local/mcp/g1"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_jwk = jwt.utils.bytes_to_number  # noqa: F841  (touch to keep import tidy)
    jwk = OKPAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    return priv, {"keys": [jwk]}


def _mint(priv, *, aud=AUD, iss="mcp-defender", agent=None, roles=None, ttl=3600, sub="Lew"):
    now = dt.datetime.now(dt.timezone.utc)
    payload = {"iss": iss, "sub": sub, "aud": aud, "guard_id": "g1",
               "iat": now, "exp": now + dt.timedelta(seconds=ttl)}
    if agent:
        payload["agent"] = agent
    if roles:
        payload["roles"] = roles
    return jwt.encode(payload, priv, algorithm="EdDSA", headers={"kid": "k1"})


def test_looks_like_jwt():
    assert jwt_verify.looks_like_jwt("a.b." + "c" * 30)
    assert not jwt_verify.looks_like_jwt("plain-token")
    assert not jwt_verify.looks_like_jwt("")


def test_valid_delegated_token():
    priv, jwks = _keypair()
    tok = _mint(priv, agent="hermes", roles=["operator"])
    c = jwt_verify.verify_delegated(tok, jwks, AUD)
    assert c and c["sub"] == "Lew" and c["agent"] == "hermes" and c["roles"] == ["operator"]


def test_spoof_proof_identity():
    # the verified agent claim wins over a forged proxy-auth username
    priv, jwks = _keypair()
    c = jwt_verify.verify_delegated(_mint(priv, agent="hermes"), jwks, AUD)
    ident = jwt_verify.identity_from_claims(c, hdr_agent="evil-agent")
    assert ident == {"subject": "Lew", "agent": "hermes", "roles": None}


def test_plain_token_falls_back_to_username_agent():
    priv, jwks = _keypair()
    c = jwt_verify.verify_delegated(_mint(priv), jwks, AUD)
    ident = jwt_verify.identity_from_claims(c, hdr_agent="hermes")
    assert ident == {"subject": "Lew", "agent": "hermes", "roles": None}


def test_rejections():
    priv, jwks = _keypair()
    other, _ = _keypair()
    tok = _mint(priv, agent="hermes")
    assert jwt_verify.verify_delegated(tok, jwks, "http://watcher.local/mcp/OTHER") is None  # wrong aud
    assert jwt_verify.verify_delegated(tok[:-3] + "xyz", jwks, AUD) is None                  # tampered
    assert jwt_verify.verify_delegated(tok, {}, AUD) is None                                 # no jwks
    assert jwt_verify.verify_delegated(_mint(other, agent="x"), jwks, AUD) is None           # wrong key
    assert jwt_verify.verify_delegated(_mint(priv, iss="evil"), jwks, AUD) is None           # wrong issuer
    assert jwt_verify.verify_delegated(_mint(priv, ttl=-10), jwks, AUD) is None              # expired
