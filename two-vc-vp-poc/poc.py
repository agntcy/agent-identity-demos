#!/usr/bin/env python3
# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Runnable two-VC/VP trust-bundle proof of concept.

The demo models the architecture in ``db_seq_diagram.png``:

    Organization VC issuer signs the secondary organization VC
    Identity Service   publishes CIMD/JWKS and signs the Agent Badge VC
    Security Autonomous Agent signs the VP with its CIMD key
    Verifier           applies the cross-issuer trust and binding policy

This is intentionally local and deterministic in shape, but uses real RSA
signatures and JWT-style compact serialization. It does not pretend that a
Directory record, the VP, or the Identity Node is itself the trust anchor.
The verifier's configured issuer keys and binding policy are the trust model.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


VP_JWT_TYPE = "VerifiablePresentation+jwt"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def iso_time(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_multibase(value: bytes) -> str:
    # Multibase base58btc prefix + raw SHA-256 digest.
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(hashlib.sha256(value).digest(), "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "z" + (encoded or "1")


def rsa_public_from_jwk(jwk: dict[str, str]) -> rsa.RSAPublicKey:
    """Reconstruct the resolver-selected RSA public key from a JWK."""
    if jwk.get("kty") != "RSA":
        raise ValueError("CIMD JWKS key is not RSA")
    return rsa.RSAPublicNumbers(
        int.from_bytes(unb64url(jwk["e"]), "big"),
        int.from_bytes(unb64url(jwk["n"]), "big"),
    ).public_key()


@dataclass
class SigningKey:
    private_key: rsa.RSAPrivateKey
    kid: str

    @classmethod
    def create(cls, kid: str) -> "SigningKey":
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=2048), kid)

    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    def public_jwk(self) -> dict[str, str]:
        numbers = self.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }

    def sign(self, signing_input: bytes) -> str:
        signature = self.private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return b64url(signature)


def sign_jwt(payload: dict[str, Any], key: SigningKey, typ: str) -> str:
    header = {"alg": "RS256", "kid": key.kid, "typ": typ}
    encoded_header = b64url(canonical(header))
    encoded_payload = b64url(canonical(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    return f"{encoded_header}.{encoded_payload}.{key.sign(signing_input)}"


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(unb64url(encoded_header))
        payload = json.loads(unb64url(encoded_payload))
        return header, payload, f"{encoded_header}.{encoded_payload}".encode(), unb64url(encoded_signature)
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        raise ValueError("malformed compact token") from exc


def verify_jwt(
    token: str,
    public_key: rsa.RSAPublicKey,
    *,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    header, payload, signing_input, signature = decode_jwt(token)
    if header.get("alg") != "RS256":
        raise ValueError("unexpected signing algorithm")
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    token_issuer = payload.get("iss", payload.get("issuer"))
    if expected_issuer is not None and token_issuer != expected_issuer:
        raise ValueError("issuer mismatch")
    if expected_audience is not None:
        audience = payload.get("aud")
        if audience != expected_audience and expected_audience not in (audience or []):
            raise ValueError("audience mismatch")
    current = int(time.time()) if now is None else now
    expiration = payload.get("exp", payload.get("expirationDate"))
    if isinstance(expiration, str):
        expiration = int(datetime.fromisoformat(expiration.replace("Z", "+00:00")).timestamp())
    if expiration is None or expiration < current:
        raise ValueError("token is expired")
    if payload.get("nbf", current) > current:
        raise ValueError("token is not active")
    return payload


def vc_payload(
    *,
    issuer: str,
    subject: dict[str, Any],
    vc_type: str,
    now: int,
    ttl: int = 3600,
) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", vc_type],
        "issuer": issuer,
        "issuanceDate": iso_time(now),
        "expirationDate": iso_time(now + ttl),
        "credentialSubject": subject,
    }


class SecondaryVcIssuer:
    """Mock secondary organization-VC issuer and explicit trust anchor."""

    issuer = "https://attestation.example/issuers/organization"

    def __init__(self) -> None:
        self.key = SigningKey.create("organization-attestation-2026")
        self.registry = {
            "urn:org:acme-security": {
                "organizationId": "acme-security-org-001",
                "legalName": "Acme Security Engineering",
            }
        }

    def issue_organization_vc(self, organization_uri: str, now: int) -> str:
        organization = self.registry[organization_uri]
        document = vc_payload(
            issuer=self.issuer,
            vc_type="OrganizationCredential",
            now=now,
            subject={"id": organization_uri, **organization},
        )
        return sign_jwt(document, self.key, "JWT")


class IdentityService:
    """Organization-controlled issuer plus CIMD/JWKS and VP service."""

    issuer = "https://identity.acme.example/issuers/agent-badge"
    organization_uri = "urn:org:acme-security"

    def __init__(self) -> None:
        self.issuer_key = SigningKey.create("acme-badge-2026")
        self.agent_key = SigningKey.create("security-autonomous-agent-2026")
        self.cimd_id = "https://identity.acme.example/cimd/security-autonomous-agent"
        self.cimd_document = {
            "id": self.cimd_id,
            "client_id": "security-autonomous-agent",
            "controller": self.organization_uri,
            "jwks_uri": f"{self.cimd_id}/.well-known/jwks.json",
            "verification_method": [{"id": f"{self.cimd_id}#key-1", "type": "JsonWebKey"}],
        }
        self.agent_card = {
            "name": "Security Autonomous Agent",
            "description": "Autonomous agent that coordinates security remediation workflows.",
            "url": "https://agents.acme.example/security-autonomous-agent",
            "version": "0.1.0",
            "capabilities": {"streaming": False, "pushNotifications": False},
            "skills": [{
                "id": "security-remediation",
                "name": "Security Remediation",
                "description": "Find and coordinate remediation of security weaknesses.",
                "tags": ["security", "remediation"],
            }],
        }

    def publish_cimd(self) -> dict[str, Any]:
        return {**self.cimd_document, "jwks": {"keys": [self.agent_key.public_jwk()]}}

    def issue_agent_badge(self, now: int) -> str:
        cimd_bytes = canonical(self.cimd_document)
        subject = {
            "id": self.cimd_id,
            # This is the OASF/A2A description carried by the Agent Badge.
            "badge": self.agent_card,
            "operatedBy": self.organization_uri,
            "relatedResource": [{
                "id": self.cimd_id,
                "digest": sha256_multibase(cimd_bytes),
                "digestAlgorithm": "sha-256",
            }],
        }
        document = vc_payload(
            issuer=self.issuer,
            vc_type="AgentBadge",
            now=now,
            subject=subject,
        )
        return sign_jwt(document, self.issuer_key, "JWT")

    def create_vp(self, badge_vc: str, organization_vc: str, challenge: str, domain: str, now: int) -> str:
        vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": self.cimd_id,
            "verifiableCredential": [badge_vc, organization_vc],
        }
        payload = {
            "iss": self.cimd_id,
            "sub": self.cimd_id,
            "aud": domain,
            "nonce": challenge,
            "iat": now,
            "exp": now + 300,
            "vp": vp,
        }
        return sign_jwt(payload, self.agent_key, VP_JWT_TYPE)


@dataclass
class TrustPolicy:
    trusted_org_issuer: str
    trusted_badge_issuer: str
    trusted_organization: str
    trusted_identity_service: str
    trusted_resolver: str


class Verifier:
    def __init__(self, secondary: SecondaryVcIssuer, identity: IdentityService, policy: TrustPolicy) -> None:
        self.secondary = secondary
        self.identity = identity
        self.policy = policy

    def request_trust_bundle(self, challenge: str, domain: str) -> dict[str, str]:
        return {"challenge": challenge, "domain": domain, "resolver": self.policy.trusted_resolver}

    def verify_bundle(self, vp_token: str, challenge: str, domain: str, now: int) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        vp_header, vp_claims, _, _ = decode_jwt(vp_token)
        holder = vp_claims.get("iss")
        checks.append(self._check("VP type", vp_header.get("typ") == VP_JWT_TYPE))
        checks.append(self._check("VP challenge", vp_claims.get("nonce") == challenge))
        checks.append(self._check("VP domain", vp_claims.get("aud") == domain))
        checks.append(self._check("VP holder", holder == vp_claims.get("vp", {}).get("holder")))

        cimd = self.identity.publish_cimd()
        agent_jwk = cimd["jwks"]["keys"][0]
        resolved_agent_key = rsa_public_from_jwk(agent_jwk)
        checks.append(self._check("VP kid resolves in CIMD JWKS", vp_header.get("kid") == agent_jwk.get("kid")))
        # In a production resolver, the JWK comes from the approved CIMD URI.
        verify_jwt(vp_token, resolved_agent_key, expected_audience=domain, now=now)
        checks.append(self._check("VP signature via CIMD JWKS", True))

        credentials = vp_claims.get("vp", {}).get("verifiableCredential", [])
        checks.append(self._check("VP contains two VCs", len(credentials) == 2))
        if len(credentials) != 2:
            raise ValueError("VP must contain exactly the Agent Badge VC and Organization VC")

        badge = None
        organization = None
        for token in credentials:
            _, payload, _, _ = decode_jwt(token)
            types = payload.get("type", [])
            if "AgentBadge" in types:
                badge = payload
            if "OrganizationCredential" in types:
                organization = payload
        if badge is None or organization is None:
            raise ValueError("VP does not contain both required credential types")

        # Verify each VC with the issuer key selected by its trusted issuer.
        badge_token = next(token for token in credentials if "AgentBadge" in decode_jwt(token)[1].get("type", []))
        organization_token = next(token for token in credentials if "OrganizationCredential" in decode_jwt(token)[1].get("type", []))
        verify_jwt(badge_token, self.identity.issuer_key.public_key(), expected_issuer=self.policy.trusted_badge_issuer, now=now)
        verify_jwt(organization_token, self.secondary.key.public_key(), expected_issuer=self.policy.trusted_org_issuer, now=now)
        checks.append(self._check("Agent Badge VC signature", True))
        checks.append(self._check("Organization VC signature", True))

        badge_subject = badge["credentialSubject"]
        organization_subject = organization["credentialSubject"]
        checks.append(self._check("Badge subject equals VP holder", badge_subject.get("id") == holder))
        checks.append(self._check("Organization VC subject is trusted", organization_subject.get("id") == self.policy.trusted_organization))
        checks.append(self._check("Organization VC has an organization ID", bool(organization_subject.get("organizationId"))))
        checks.append(self._check("Identity Service authorized for organization", self.policy.trusted_badge_issuer == self.identity.issuer and self.identity.organization_uri == self.policy.trusted_organization))
        checks.append(self._check("operatedBy binding", badge_subject.get("operatedBy") == organization_subject.get("id")))
        checks.append(self._check("CIMD resolver is trusted", self.policy.trusted_resolver == "agntcy://approved-local-resolver"))

        related = (badge_subject.get("relatedResource") or [{}])[0]
        digest_matches = related.get("digest") == sha256_multibase(canonical(self.identity.cimd_document))
        checks.append(self._check("CIMD bytes match relatedResource digest", digest_matches))
        checks.append(self._check("Embedded Agent Card is Security Autonomous Agent", badge_subject.get("badge", {}).get("name") == "Security Autonomous Agent"))
        checks.append(self._check("Organization VC issuer is trusted", organization.get("issuer") == self.policy.trusted_org_issuer))
        checks.append(self._check("Badge issuer is trusted", badge.get("issuer") == self.policy.trusted_badge_issuer))

        failed = [check["name"] for check in checks if not check["passed"]]
        if failed:
            raise ValueError("trust bundle rejected: " + ", ".join(failed))
        return {
            "accepted": True,
            "holder": holder,
            "organization": organization_subject["id"],
            "organization_id": organization_subject["organizationId"],
            "agent": badge_subject["badge"]["name"],
            "checks": checks,
            "trust_anchors": {
                "organization_vc_issuer": self.policy.trusted_org_issuer,
                "agent_badge_issuer": self.policy.trusted_badge_issuer,
                "resolver": self.policy.trusted_resolver,
            },
            "note": "The VP is holder-signed evidence; the verifier policy and trusted issuer keys are the trust anchors.",
        }

    @staticmethod
    def _payload(token: str) -> dict[str, Any]:
        return decode_jwt(token)[1]

    @staticmethod
    def _check(name: str, passed: bool) -> dict[str, Any]:
        return {"name": name, "passed": bool(passed)}


def run_demo() -> dict[str, Any]:
    now = int(time.time())
    challenge = "challenge-2026-001"
    domain = "https://verifier.example/security-remediation"
    secondary = SecondaryVcIssuer()
    identity = IdentityService()
    policy = TrustPolicy(
        trusted_org_issuer=secondary.issuer,
        trusted_badge_issuer=identity.issuer,
        trusted_organization=identity.organization_uri,
        trusted_identity_service=identity.issuer,
        trusted_resolver="agntcy://approved-local-resolver",
    )
    verifier = Verifier(secondary, identity, policy)

    organization_vc = secondary.issue_organization_vc(identity.organization_uri, now)
    badge_vc = identity.issue_agent_badge(now)
    request = verifier.request_trust_bundle(challenge, domain)
    vp = identity.create_vp(badge_vc, organization_vc, request["challenge"], request["domain"], now)
    result = verifier.verify_bundle(vp, challenge, domain, now)
    return {
        "flow": [
            "Operating Organization provisions Security Autonomous Agent",
            "Identity Service publishes CIMD/JWKS and signs Agent Badge VC",
            "Secondary organization-VC issuer signs Organization VC",
            "Verifier issues challenge and domain",
            "Identity Service assembles two VCs into a VP",
            "Security Autonomous Agent signs VP with its CIMD key",
            "Verifier resolves CIMD/JWKS and validates the complete trust bundle",
        ],
        "artifacts": {
            "agent": identity.agent_card,
            "cimd": identity.cimd_document,
            "organization_vc": organization_vc,
            "agent_badge_vc": badge_vc,
            "vp": vp,
        },
        "verification": result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pretty", action="store_true", help="pretty-print the result")
    args = parser.parse_args()
    result = run_demo()
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
