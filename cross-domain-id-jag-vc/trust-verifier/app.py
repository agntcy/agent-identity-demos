# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Verifier for a holder-signed VP containing two independently issued VCs."""

from __future__ import annotations

import asyncio
import os
import secrets
import time

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agntcy_identity_client import cimd as cimd_api
from agntcy_identity_client import directory as dir_api
from agntcy_identity_client import trust_bundle
from agntcy_identity_client import vc as vc_api

IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "dir-apiserver:8888")
SECONDARY_ISSUER_URL = os.environ.get(
    "SECONDARY_ISSUER_URL", "http://secondary-vc-issuer:8500"
).rstrip("/")
TRUSTED_BADGE_ISSUER = os.environ.get("TRUSTED_BADGE_ISSUER", "agntcy:org-a")
TRUSTED_ORGANIZATION_ISSUER = os.environ.get(
    "TRUSTED_ORGANIZATION_ISSUER", "agntcy:secondary-vc-issuer"
)
TRUSTED_ORGANIZATION = os.environ.get(
    "TRUSTED_ORGANIZATION", "urn:agntcy:organization:org-a"
)
TRUSTED_AGENT_CLIENT_ID = os.environ.get(
    "TRUSTED_AGENT_CLIENT_ID", "security-autonomous-agent"
)
DEFAULT_DOMAIN = os.environ.get("VERIFIER_DOMAIN", "urn:agntcy:verifier:cross-domain-demo")

app = FastAPI(title="Two-VC Trust Bundle Verifier", version="1.0.0")
_challenges: dict[str, tuple[str, int]] = {}


class VerifyRequest(BaseModel):
    presentation: str


def _check(checks: list[dict], name: str, condition: bool) -> None:
    checks.append({"name": name, "passed": bool(condition)})
    if not condition:
        raise ValueError(name)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "verifier": DEFAULT_DOMAIN}


@app.get("/api/challenge")
def issue_challenge(domain: str = DEFAULT_DOMAIN) -> dict:
    challenge = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + 300
    _challenges[challenge] = (domain, expires_at)
    return {"challenge": challenge, "domain": domain, "expires_at": expires_at}


@app.post("/api/verify")
async def verify_presentation(body: VerifyRequest) -> JSONResponse:
    checks: list[dict] = []
    try:
        vp_header, unverified_vp, _, _ = trust_bundle.decode_compact(body.presentation)
        holder = unverified_vp.get("iss", "")
        vp = unverified_vp.get("vp") or {}
        challenge = unverified_vp.get("nonce", "")
        domain = unverified_vp.get("aud", "")
        challenge_record = _challenges.get(challenge)

        _check(checks, "VP type", vp_header.get("typ") == trust_bundle.VERIFIABLE_PRESENTATION_TYPE)
        _check(checks, "challenge was issued by verifier", challenge_record is not None)
        _check(checks, "challenge is unexpired", bool(challenge_record and challenge_record[1] > time.time()))
        _check(checks, "VP audience matches challenge domain", bool(challenge_record and challenge_record[0] == domain))
        _check(checks, "VP holder matches issuer", vp.get("holder") == holder)

        async with httpx.AsyncClient(timeout=10) as client:
            resolver = await cimd_api.resolve_id(client, IDENTITY_NODE_URL, holder)
            verification_method = (resolver.get("verificationMethod") or [{}])[0]
            holder_jwk = verification_method.get("publicKeyJwk") or {}
            trust_bundle.verify_compact(
                body.presentation,
                holder_jwk,
                expected_typ=trust_bundle.VERIFIABLE_PRESENTATION_TYPE,
                expected_issuer=holder,
                expected_audience=domain,
            )
            _check(checks, "VP signature verifies with CIMD-resolved key", True)

            credentials = vp.get("verifiableCredential") or []
            _check(checks, "VP contains exactly two credentials", len(credentials) == 2)
            badge_tokens = [
                token for token in credentials
                if trust_bundle.credential_has_type(token, vc_api.BADGE_TYPE)
            ]
            organization_tokens = [
                token for token in credentials
                if trust_bundle.credential_has_type(
                    token, trust_bundle.ORGANIZATION_CREDENTIAL_TYPE
                )
            ]
            _check(checks, "VP contains one Agent Badge VC", len(badge_tokens) == 1)
            _check(checks, "VP contains one Organization VC", len(organization_tokens) == 1)

            badge_token = badge_tokens[0]
            organization_token = organization_tokens[0]
            badge_result = await vc_api.verify_badge(client, IDENTITY_NODE_URL, badge_token)
            _check(checks, "Identity Node verifies Agent Badge VC", bool(badge_result.get("status")))
            # The Identity Node's VerificationResult normalizes
            # ``credentialSubject`` to ``document.content``.  Keep that result
            # as the authoritative proof-verification decision, but use the
            # signed envelope's original W3C claims for relationship checks.
            badge = trust_bundle.verify_compact(
                badge_token,
                holder_jwk,
                expected_typ="JOSE",
                expected_issuer=TRUSTED_BADGE_ISSUER,
            )
            _check(checks, "Agent Badge signature and validity", True)
            _check(checks, "Agent Badge issuer is trusted", badge.get("issuer") == TRUSTED_BADGE_ISSUER)

            secondary_jwks = await client.get(
                f"{SECONDARY_ISSUER_URL}/.well-known/jwks.json"
            )
            secondary_jwks.raise_for_status()
            secondary_jwk = (secondary_jwks.json().get("keys") or [{}])[0]
            organization = trust_bundle.verify_compact(
                organization_token,
                secondary_jwk,
                expected_typ="JWT",
                expected_issuer=TRUSTED_ORGANIZATION_ISSUER,
            )
            _check(checks, "Organization VC signature and validity", True)

        badge_subject = badge.get("credentialSubject") or {}
        organization_subject = organization.get("credentialSubject") or {}
        _check(checks, "Agent Badge subject equals VP holder", badge_subject.get("id") == holder)
        _check(
            checks,
            "Organization VC subject is trusted enterprise",
            organization_subject.get("id") == TRUSTED_ORGANIZATION,
        )
        _check(
            checks,
            "Agent Badge operatedBy equals Organization VC subject",
            badge_subject.get("operatedBy") == organization_subject.get("id"),
        )
        _check(
            checks,
            "trust policy authorizes badge issuer for enterprise",
            TRUSTED_BADGE_ISSUER == "agntcy:org-a"
            and TRUSTED_ORGANIZATION == "urn:agntcy:organization:org-a",
        )

        records = await asyncio.get_event_loop().run_in_executor(
            None,
            dir_api.search_agents_by_name,
            DIR_APISERVER_URL,
            TRUSTED_AGENT_CLIENT_ID,
        )
        directory_record = next(
            (
                record for record in records
                if (record.get("annotations") or {}).get("identity_id") == holder
                and record == badge_subject.get("badge")
            ),
            None,
        )
        _check(checks, "Directory contains canonical OASF agent record", directory_record is not None)
        _check(checks, "Badge OASF equals Directory record", badge_subject.get("badge") == directory_record)
        _check(
            checks,
            "Badge relatedResource digest equals Directory OASF digest",
            (badge_subject.get("relatedResource") or [{}])[0].get("digest")
            == dir_api.oasf_digest(directory_record),
        )

        _challenges.pop(challenge, None)
        return JSONResponse({
            "accepted": True,
            "holder": holder,
            "organization": organization_subject,
            "agent": (directory_record or {}).get("name", ""),
            "checks": checks,
            "trust_anchors": {
                "agent_badge_issuer": TRUSTED_BADGE_ISSUER,
                "organization_vc_issuer": TRUSTED_ORGANIZATION_ISSUER,
                "cimd_resolver": IDENTITY_NODE_URL,
                "directory": DIR_APISERVER_URL,
            },
        })
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"accepted": False, "checks": checks, "error": str(exc)},
            status_code=400,
        )
