# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Minimal VC badge issuer (stand-in) for the cross-domain demo.

identity-node's real REST API (ghcr.io/agntcy/identity/node) has no badge
concept — it only does CIMD id generate/resolve (see identity-node-init.py
and the README's "How CIMD actually works" section). Real badge issue/verify
(POST /v1alpha1/apps/{app_id}/badges, POST /v1alpha1/badges/verify, full W3C
VC model) is served by a separate identity-service/bff component this demo
does not deploy.

This service plays the badge-issuer role the same way idjag-issuer plays the
ID-JAG-issuer role: an ephemeral RSA key pair, a JWKS endpoint, and a
self-signed vc+jwt on demand. It is a demo helper, not a production VC
issuer or wallet.
"""

from __future__ import annotations

import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

ISSUER_URL = os.environ.get("ISSUER_URL", "http://vc-issuer:9003")
VC_TYP = "vc+jwt"
BADGE_TTL = int(os.environ.get("BADGE_TTL", "3600"))

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_kid = str(uuid.uuid4())

app = FastAPI(title="VC Badge Issuer (demo stand-in)", version="0.1.0")


def _int_to_b64url(value: int, length: int) -> str:
    import base64

    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _public_jwk() -> dict:
    nums = _key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": _kid,
        "n": _int_to_b64url(nums.n, (nums.n.bit_length() + 7) // 8),
        "e": _int_to_b64url(nums.e, (nums.e.bit_length() + 7) // 8),
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/jwks")
def jwks():
    return {"keys": [_public_jwk()]}


class IssueRequest(BaseModel):
    # The delegate this badge is issued to (e.g. "opencode-agent").
    id: str
    # Capabilities this badge grants (e.g. ["scan", "remediate", "delegate"]).
    caps: list[str]
    # The human whose delegation this badge represents.
    delegating_user: str
    # Single-string intent tag (kept as a string, not a list, to match the
    # shape opencode-agent already mocked before this was real).
    intent: str
    # Acting agent chain, mirrored into the `act_chain` claim.
    act_chain: list[str]


@app.post("/vc/issue")
def issue(body: IssueRequest):
    now = int(time.time())
    claims = {
        "iss": ISSUER_URL,
        "sub": body.id,
        "iat": now,
        "exp": now + BADGE_TTL,
        "jti": str(uuid.uuid4()),
        "caps": body.caps,
        "delegating_user": body.delegating_user,
        "intent": body.intent,
        "act_chain": body.act_chain,
    }
    badge = jwt.encode(
        claims,
        _key,
        algorithm="RS256",
        headers={"kid": _kid, "typ": VC_TYP},
    )
    return {"badge": badge, "claims": claims}


class VerifyRequest(BaseModel):
    badge: str


@app.post("/vc/verify")
def verify(body: VerifyRequest):
    try:
        claims = jwt.decode(
            body.badge,
            _key.public_key(),
            algorithms=["RS256"],
            issuer=ISSUER_URL,
        )
    except jwt.InvalidTokenError as exc:
        return JSONResponse(status_code=400, content={"valid": False, "error": str(exc)})
    return {"valid": True, "claims": claims}
