# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the VC badge issuer (demo stand-in).

Covers the JWKS/health endpoints and the /vc/issue + /vc/verify contract
opencode-agent relies on for badge resolution (claims, header type, sig).
"""

import json

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

import app as issuer

client = TestClient(issuer.app)

VALID_REQUEST = {
    "id": "opencode-agent",
    "caps": ["scan", "remediate", "delegate"],
    "delegating_user": "sarah@org-a.example",
    "intent": "cross-domain-remediation",
    "act_chain": ["opencode-agent"],
}


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_jwks_shape():
    r = client.get("/jwks")
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert len(keys) == 1
    jwk = keys[0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == issuer._kid
    assert jwk["n"] and jwk["e"]


def test_issue_claims_and_header():
    r = client.post("/vc/issue", json=VALID_REQUEST)
    assert r.status_code == 200
    body = r.json()
    badge = body["badge"]

    header = pyjwt.get_unverified_header(badge)
    assert header["typ"] == issuer.VC_TYP
    assert header["kid"] == issuer._kid
    assert header["alg"] == "RS256"

    claims = body["claims"]
    assert claims["iss"] == issuer.ISSUER_URL
    assert claims["sub"] == "opencode-agent"
    assert claims["exp"] - claims["iat"] == issuer.BADGE_TTL
    assert claims["jti"]
    assert claims["caps"] == VALID_REQUEST["caps"]
    assert claims["delegating_user"] == VALID_REQUEST["delegating_user"]
    assert claims["intent"] == VALID_REQUEST["intent"]
    assert claims["act_chain"] == VALID_REQUEST["act_chain"]


def test_issue_generates_unique_jti():
    a = client.post("/vc/issue", json=VALID_REQUEST).json()["claims"]["jti"]
    b = client.post("/vc/issue", json=VALID_REQUEST).json()["claims"]["jti"]
    assert a != b


def test_issue_requires_all_fields():
    assert client.post("/vc/issue", json={"id": "only-id"}).status_code == 422
    assert client.post("/vc/issue", json={}).status_code == 422


def test_verify_accepts_own_valid_badge():
    badge = client.post("/vc/issue", json=VALID_REQUEST).json()["badge"]
    r = client.post("/vc/verify", json={"badge": badge})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["claims"]["sub"] == "opencode-agent"
    assert body["claims"]["act_chain"] == VALID_REQUEST["act_chain"]


def test_verify_rejects_tampered_badge():
    badge = client.post("/vc/issue", json=VALID_REQUEST).json()["badge"]
    header, payload, sig = badge.split(".")
    tampered = f"{header}.{payload}x.{sig}"
    r = client.post("/vc/verify", json={"badge": tampered})
    assert r.status_code == 400
    assert r.json()["valid"] is False


def test_verify_rejects_badge_from_a_different_key():
    import uuid

    from cryptography.hazmat.primitives.asymmetric import rsa

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = pyjwt.encode(
        {"iss": issuer.ISSUER_URL, "sub": "mallory"},
        other_key,
        algorithm="RS256",
        headers={"kid": str(uuid.uuid4()), "typ": issuer.VC_TYP},
    )
    r = client.post("/vc/verify", json={"badge": forged})
    assert r.status_code == 400
    assert r.json()["valid"] is False


def test_verify_signature_matches_jwks_public_key():
    """The published JWKS must be able to independently verify a badge."""
    badge = client.post("/vc/issue", json=VALID_REQUEST).json()["badge"]
    jwk = client.get("/jwks").json()["keys"][0]
    pub = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    decoded = pyjwt.decode(badge, pub, algorithms=["RS256"], issuer=issuer.ISSUER_URL)
    assert decoded["sub"] == "opencode-agent"
