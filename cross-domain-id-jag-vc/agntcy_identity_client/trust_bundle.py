# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Two-VC Verifiable Presentation primitives backed by Vault Transit.

The Identity Node stores and verifies the Agent Badge VC.  A distinct
secondary issuer signs an Organization VC.  The agent then signs a VP that
contains both compact credentials with the key published through its CIMD
resolver metadata.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import VaultConfig
from .vault import b64url, get_issuer_jwk, vault_sign_rs256

W3C_CREDENTIALS_CONTEXT = "https://www.w3.org/2018/credentials/v1"
ORGANIZATION_CREDENTIAL_TYPE = "OrganizationCredential"
VERIFIABLE_PRESENTATION_TYPE = "VerifiablePresentation+jwt"


def _iso(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_compact(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Decode a compact JWS without treating the decoded claims as trusted."""
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(_unb64url(encoded_header))
        payload = json.loads(_unb64url(encoded_payload))
        return (
            header,
            payload,
            f"{encoded_header}.{encoded_payload}".encode(),
            _unb64url(encoded_signature),
        )
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("malformed compact JWS") from exc


def rsa_public_from_jwk(jwk: dict[str, str]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise ValueError("verification key is not RSA")
    return rsa.RSAPublicNumbers(
        int.from_bytes(_unb64url(jwk["e"]), "big"),
        int.from_bytes(_unb64url(jwk["n"]), "big"),
    ).public_key()


async def sign_compact(
    client: httpx.AsyncClient,
    cfg: VaultConfig,
    payload: dict[str, Any],
    *,
    typ: str,
) -> str:
    """Sign a compact JWS with a non-exportable Vault Transit key."""
    jwk = await get_issuer_jwk(client, cfg)
    header = {"alg": "RS256", "kid": jwk["kid"], "typ": typ}
    encoded_header = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = await vault_sign_rs256(client, cfg, signing_input)
    return f"{signing_input}.{signature}"


def _timestamp(value: int | str | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def verify_compact(
    token: str,
    jwk: dict[str, str],
    *,
    expected_typ: str | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify signature, key id, issuer/audience and temporal validity."""
    header, payload, signing_input, signature = decode_compact(token)
    if header.get("alg") != "RS256":
        raise ValueError("unexpected signing algorithm")
    if header.get("kid") != jwk.get("kid"):
        raise ValueError("signing key id does not match trusted JWK")
    if expected_typ is not None and header.get("typ") != expected_typ:
        raise ValueError("unexpected compact token type")
    rsa_public_from_jwk(jwk).verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    issuer = payload.get("iss", payload.get("issuer"))
    if expected_issuer is not None and issuer != expected_issuer:
        raise ValueError("issuer mismatch")
    if expected_audience is not None:
        audience = payload.get("aud")
        if audience != expected_audience and expected_audience not in (audience or []):
            raise ValueError("audience mismatch")

    current = int(time.time()) if now is None else now
    expires = _timestamp(payload.get("exp", payload.get("expirationDate")))
    if expires is None or expires <= current:
        raise ValueError("credential or presentation is expired")
    not_before = _timestamp(payload.get("nbf"))
    if not_before is not None and not_before > current:
        raise ValueError("credential or presentation is not active")
    return payload


async def issue_organization_vc(
    client: httpx.AsyncClient,
    cfg: VaultConfig,
    *,
    organization_uri: str,
    organization_id: str,
    legal_name: str,
    ttl_seconds: int = 3600,
) -> tuple[str, dict[str, Any]]:
    now = int(time.time())
    credential = {
        "@context": [W3C_CREDENTIALS_CONTEXT],
        "type": ["VerifiableCredential", ORGANIZATION_CREDENTIAL_TYPE],
        "issuer": cfg.issuer,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": _iso(now),
        "expirationDate": _iso(now + ttl_seconds),
        "credentialSubject": {
            "id": organization_uri,
            "organizationId": organization_id,
            "legalName": legal_name,
            "verificationMethod": "secondary-enterprise-registry",
        },
    }
    return await sign_compact(client, cfg, credential, typ="JWT"), credential


async def create_verifiable_presentation(
    client: httpx.AsyncClient,
    holder_cfg: VaultConfig,
    *,
    holder: str,
    agent_badge_vc: str,
    organization_vc: str,
    challenge: str,
    domain: str,
    ttl_seconds: int = 300,
) -> tuple[str, dict[str, Any]]:
    now = int(time.time())
    payload = {
        "iss": holder,
        "sub": holder,
        "aud": domain,
        "nonce": challenge,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "vp": {
            "@context": [W3C_CREDENTIALS_CONTEXT],
            "type": ["VerifiablePresentation"],
            "holder": holder,
            "verifiableCredential": [agent_badge_vc, organization_vc],
        },
    }
    return (
        await sign_compact(client, holder_cfg, payload, typ=VERIFIABLE_PRESENTATION_TYPE),
        payload,
    )


def credential_has_type(token: str, credential_type: str) -> bool:
    return credential_type in (decode_compact(token)[1].get("type") or [])
