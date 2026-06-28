"""P3 — verify a delegated per-agent JWT presented as the proxy-auth password.

Framework-free (PyJWT + the bundle's JWKS) so the watcher reads identity from the
VERIFIED token's claims, not a client-set username. Mirrors the gateway's resource-server
verification: EdDSA signature against the Defender's published key, plus exp + aud binding.
A token that fails any check returns None and the caller falls back to the static
proxy_auth credential map (precedence: verified JWT > proxy_auth map > none).
"""
from __future__ import annotations

import json

import jwt
from jwt.algorithms import OKPAlgorithm

ISSUER = "mcp-defender"   # must match the Defender's inbound_auth.ISSUER


def looks_like_jwt(token: str) -> bool:
    return bool(token) and token.count(".") == 2 and len(token) > 20


def _key_for(jwks: dict, kid: str | None):
    for k in (jwks or {}).get("keys", []):
        if kid is None or k.get("kid") == kid:
            try:
                return OKPAlgorithm.from_jwk(json.dumps(k))
            except Exception:
                return None
    return None


def verify_delegated(token: str, jwks: dict, audience: str) -> dict | None:
    """Return the VERIFIED claims if `token` is a valid Defender-minted JWT bound to this
    guard's audience, else None. Checks EdDSA signature (via the bundle's JWKS), issuer,
    expiry, and aud — the same binding the gateway enforces."""
    if not looks_like_jwt(token) or not jwks:
        return None
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        key = _key_for(jwks, kid)
        if key is None:
            return None
        return jwt.decode(
            token, key=key, algorithms=["EdDSA"], issuer=ISSUER,
            audience=(audience or None),
            options={"require": ["exp", "sub"], "verify_aud": bool(audience)},
        )
    except Exception:
        return None


def identity_from_claims(claims: dict, hdr_agent: str | None = None) -> dict:
    """Resolve {subject, agent, roles} from VERIFIED claims — same contract as the gateway.
    A delegated token (carries an `agent` claim) is authoritative + spoof-proof: sub→subject,
    agent claim→agent, roles claim→roles. A plain token (no `agent`) keeps the verified
    subject and falls back to the proxy-auth username as the agent label."""
    if claims.get("agent"):
        return {"subject": claims.get("sub"), "agent": claims["agent"],
                "roles": claims.get("roles")}
    return {"subject": claims.get("sub"),
            "agent": hdr_agent or claims.get("sub") or "agent",
            "roles": claims.get("roles")}
