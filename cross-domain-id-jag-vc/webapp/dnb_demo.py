# Copyright 2026 AGNTCY Contributors
# SPDX-License-Identifier: Apache-2.0
"""Live AGNTCY baseline plus a deliberately simulated business-attestation provider.

No D&B endpoints or keys are used. The fixture format and annotation names are
illustrative, not an agreed D&B integration. No Directory policy is changed.
"""
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import simple_demo
from simple_demo import event

ISSUER = "https://dnb-fixture.example.invalid"
ORGANIZATION = "urn:demo:organization:org-b"
REFERENCE = ISSUER + "/credentials/org-b-v1"
ANNOTATIONS = {
    "example.org/attestation/issuer": ISSUER,
    "example.org/attestation/reference": REFERENCE,
    "example.org/attestation/profile": "simulated-business-attestation-v1",
}
SCENARIOS = {"valid", "revoked", "expired", "stale", "unavailable", "wrong_org", "tampered"}
# Ephemeral demo key: this does not represent a D&B-controlled signing key.
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
MAX_AGE = 300


def fixture(scenario, now):
    credential = {
        "iss": ISSUER, "sub": "urn:demo:organization:unrelated" if scenario == "wrong_org" else ORGANIZATION,
        "iat": now - 120, "exp": now - 1 if scenario == "expired" else now + 3600,
        "jti": REFERENCE, "type": "SimulatedBusinessAttestation",
        "claims": {"organization_name": "Example Org B", "business_verified": True},
        "simulation": True,
    }
    token = jwt.encode(credential, KEY, algorithm="RS256", headers={"kid": "ephemeral-demo-key"})
    if scenario == "tampered":
        head, payload, signature = token.split(".")
        changed = json.loads(jwt.utils.base64url_decode(payload))
        changed["claims"]["organization_name"] = "Altered organization"
        token = ".".join((head, jwt.utils.base64url_encode(json.dumps(changed).encode()).decode(), signature))
    status = {"state": "revoked" if scenario == "revoked" else "active", "checked_at": now - (MAX_AGE + 60 if scenario in {"stale", "unavailable"} else 0), "source_available": scenario != "unavailable"}
    return token, status


def evaluate(token, status, expected_org, now):
    """Execute actual checks against simulated inputs; never upgrade missing status."""
    try:
        claims = jwt.decode(token, KEY.public_key(), algorithms=["RS256"], issuer=ISSUER, options={"require": ["iss", "sub", "iat", "exp", "jti"], "verify_exp": False, "verify_iat": False})
    except jwt.InvalidTokenError:
        return {"accepted": False, "outcome": "invalid_signature", "signature_verified": False}
    base = {"accepted": False, "signature_verified": True, "credential": claims}
    if claims.get("type") != "SimulatedBusinessAttestation" or claims.get("jti") != REFERENCE or claims["iat"] > now:
        return {**base, "outcome": "invalid_credential"}
    if claims["sub"] != expected_org:
        return {**base, "outcome": "wrong_organization"}
    if claims["exp"] <= now:
        return {**base, "outcome": "expired"}
    if not status["source_available"]:
        return {**base, "outcome": "unavailable"}
    if status["state"] != "active":
        return {**base, "outcome": "revoked"}
    valid_until = min(claims["exp"], status["checked_at"] + MAX_AGE)
    if status["checked_at"] > now or now >= valid_until:
        return {**base, "outcome": "stale", "valid_until": valid_until}
    if claims.get("claims", {}).get("business_verified") is not True:
        return {**base, "outcome": "policy_rejected"}
    return {**base, "accepted": True, "outcome": "accepted", "valid_until": valid_until}


async def run(scenario="valid"):
    if scenario not in SCENARIOS:
        yield event(-1, "error", "Unknown scenario")
        return
    live = None
    async for line in simple_demo.run(annotations=ANNOTATIONS):
        item = json.loads(line)
        if item["state"] == "complete":
            live = item["evidence"]
        else:
            item["evidence"]["source"] = "Live AGNTCY services"
            yield json.dumps(item) + "\n"
            if item["state"] == "error":
                return
    if not live:
        return
    now = int(time.time())
    token, status = fixture(scenario, now)
    result = evaluate(token, status, ORGANIZATION, now)
    common = {"source": "SIMULATED D&B / marketplace fixture", "scenario": scenario}
    yield event(7, "running", "Marketplace reads the evidence reference from the live OASF record", **common)
    yield event(7, "ok", "Loaded a local signed fixture; no D&B network request was made", **common, reference=REFERENCE, annotations=ANNOTATIONS, credential=jwt.decode(token, options={"verify_signature": False}), credential_is_untrusted_preview=True)
    yield event(8, "running", "Checking fixture issuer and RSA signature using the configured demo key", **common)
    yield event(8, "ok", "Fixture signature check completed", **common, signature_verified=result["signature_verified"], approved_issuer=ISSUER, key_origin="Ephemeral local demo key; not a D&B key")
    yield event(9, "running", "Checking the credential organization against a simulated enrollment binding", **common)
    yield event(9, "ok", "Organization comparison completed; enrollment authority is simulated", **common, agent=live["publisher"], expected_organization=ORGANIZATION, credential_organization=jwt.decode(token, options={"verify_signature": False})["sub"], binding_source="Demo enrollment fixture, not a verified D&B authorization")
    yield event(10, "running", "Evaluating simulated status, revocation, expiry and maximum age", **common)
    yield event(10, "ok", "Freshness check completed under the demo marketplace policy", **common, status=status, max_age_seconds=MAX_AGE, valid_until=result.get("valid_until"), directory_freshness_hook="Proposed only; not implemented or invoked")
    yield event(11, "running", "Marketplace applies its separate business-attestation decision", **common)
    yield event(11, "ok", "Demo policy accepted evidence" if result["accepted"] else "Demo policy withheld acceptance: " + result["outcome"], **common, accepted=result["accepted"], outcome=result["outcome"], directory_policy_changed=False)
    yield event(11, "complete", "Identity verified · simulated business evidence " + result["outcome"], **common, **live, identity_verified=True, accepted=result["accepted"], outcome=result["outcome"], directory_enforcement="Not configured by this demonstration")
