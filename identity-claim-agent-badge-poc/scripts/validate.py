#!/usr/bin/env python3
"""Validate Agent Badge-backed Directory IdentityClaims.

The agent key is held by Vault Transit. AGNTCY Identity Node v0.0.26 verifies
published VCs with the credential subject's ResolverMetadata key; this script
records that current limitation rather than claiming separate issuer-key trust.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


PATCHED_DIRECTORY = os.environ.get("POC_DIRECTORY", "127.0.0.1:8910")
STOCK_DIRECTORY = os.environ.get("POC_STOCK_DIRECTORY", "127.0.0.1:8911")
IDENTITY = os.environ.get("POC_IDENTITY", "http://127.0.0.1:4030").rstrip("/")
VAULT = os.environ.get("POC_VAULT", "http://127.0.0.1:8230").rstrip("/")
VAULT_TOKEN = os.environ["POC_VAULT_TOKEN"]

AGENT_CONTROL_KEY = "security-agent-control"
AGENT_CONTROL_ISSUER = "security-agent-control"
AGENT_SUBJECT = "security-autonomous-agent"
AGENT_NAME = "security_autonomous_agent"
CLAIM_TYPE = "agntcy.dir.identity.v1.IdentityClaim"
ENVELOPE_JOSE = "CREDENTIAL_ENVELOPE_TYPE_JOSE"
DIRECTORY_COMMIT = "08c86a4b39c554a0f2eacb7391684fff6f0bd002"


def log(message: str) -> None:
    print(f"[validate] {message}", file=sys.stderr, flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def http(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def json_http(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    status, body = http(method, url, payload, headers)
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {"raw": body.decode(errors="replace")}
    return status, parsed


def vault(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    return json_http(method, f"{VAULT}/v1/{path}", payload, {"X-Vault-Token": VAULT_TOKEN})


def wait_for(name: str, probe, attempts: int = 60) -> None:
    for attempt in range(1, attempts + 1):
        try:
            if probe():
                log(f"{name} ready after {attempt} attempt(s)")
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError(f"{name} did not become ready")


def der_len(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), offset + 1 + count


def der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length, value_offset = der_len(data, offset + 1)
    return tag, data[value_offset : value_offset + length], value_offset + length


def public_pem_to_jwk(pem: str, key_name: str) -> dict[str, str]:
    encoded = "".join(line for line in pem.splitlines() if "---" not in line)
    der = base64.b64decode(encoded)
    _, outer, _ = der_tlv(der, 0)
    _, _, offset = der_tlv(outer, 0)
    _, bit_string, _ = der_tlv(outer, offset)
    _, rsa, _ = der_tlv(bit_string[1:], 0)
    _, modulus, offset = der_tlv(rsa, 0)
    _, exponent, _ = der_tlv(rsa, offset)
    if modulus[0] == 0:
        modulus = modulus[1:]
    return {
        "kty": "RSA",
        "n": b64url(modulus),
        "e": b64url(exponent),
        "alg": "RS256",
        "use": "sig",
        "kid": f"{key_name}-v1",
    }


def vault_sign(signing_input: str, key_name: str) -> str:
    status, body = vault(
        "POST",
        f"transit/sign/{key_name}",
        {
            "input": base64.b64encode(signing_input.encode()).decode(),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pkcs1v15",
        },
    )
    if status != 200:
        raise RuntimeError(f"Vault signing failed for {key_name}: HTTP {status}: {body}")
    signature = base64.b64decode(body["data"]["signature"].split(":", 2)[2])
    return b64url(signature)


def sign_jws(payload: dict[str, Any], typ: str, jwk: dict[str, str], key_name: str) -> str:
    header = {"alg": "RS256", "typ": typ, "kid": jwk["kid"]}
    signing_input = ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode()),
            b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ]
    )
    return f"{signing_input}.{vault_sign(signing_input, key_name)}"


def sign_detached(payload: bytes, jwk: dict[str, str], key_name: str) -> str:
    header = b64url(
        json.dumps(
            {"alg": "RS256", "typ": "directory-identity-claim+jws", "kid": jwk["kid"]},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{b64url(payload)}"
    return f"{header}..{vault_sign(signing_input, key_name)}"


def verify_rs256_detached(jws: str, payload: bytes, jwk: dict[str, str]) -> bool:
    try:
        protected, detached, signature = jws.split(".")
        if detached:
            return False
        signing_input = f"{protected}.{b64url(payload)}"
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(
            signing_input.encode()
        ).digest()
        sig_int = int.from_bytes(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), "big")
        modulus = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big")
        exponent = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4)), "big")
        encoded = pow(sig_int, exponent, modulus).to_bytes((modulus.bit_length() + 7) // 8, "big")
        separator = encoded.index(b"\x00", 2)
        return (
            encoded.startswith(b"\x00\x01")
            and set(encoded[2:separator]) == {0xFF}
            and encoded[separator + 1 :] == digest_info
        )
    except (ValueError, KeyError):
        return False


def proof_jwt(subject: str, issuer: str, jwk: dict[str, str], key_name: str) -> str:
    now = int(time.time())
    return sign_jws(
        {
            "iss": f"agntcy:{issuer}",
            "sub": subject,
            "aud": [subject],
            "iat": now,
            "exp": now + 3600,
            "jti": str(uuid.uuid4()),
            "sub_jwk": jwk,
        },
        "JWT",
        jwk,
        key_name,
    )


def grpcurl(address: str, method: str, payload: dict[str, Any] | None = None) -> subprocess.CompletedProcess[str]:
    command = ["grpcurl", "-plaintext"]
    if payload is not None:
        command.extend(["-d", json.dumps(payload, separators=(",", ":"))])
    command.extend([address, method])
    return subprocess.run(command, text=True, capture_output=True, check=False)


def grpc_json(address: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    result = grpcurl(address, method, payload)
    if result.returncode != 0:
        raise RuntimeError(f"{method} failed against {address}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def grpc_stream(address: str, method: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = grpcurl(address, method, payload)
    if result.returncode != 0:
        raise RuntimeError(f"{method} failed against {address}: {result.stderr.strip()}")
    decoder = json.JSONDecoder()
    output = result.stdout
    position = 0
    values: list[dict[str, Any]] = []
    while position < len(output):
        while position < len(output) and output[position].isspace():
            position += 1
        if position >= len(output):
            break
        value, position = decoder.raw_decode(output, position)
        values.append(value)
    return values


def setup_issuer(key_name: str, issuer: str) -> dict[str, str]:
    status, body = vault("POST", f"transit/keys/{key_name}", {"type": "rsa-2048"})
    if status not in (200, 204):
        raise RuntimeError(f"Could not create Vault key {key_name}: HTTP {status}: {body}")

    status, body = vault("GET", f"transit/keys/{key_name}")
    if status != 200:
        raise RuntimeError(f"Could not read Vault public key {key_name}: HTTP {status}: {body}")
    versions = body["data"]["keys"]
    public_pem = versions[max(versions, key=int)]["public_key"]
    jwk = public_pem_to_jwk(public_pem, key_name)

    status, response = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/issuer/register",
        {
            "issuer": {"organization": issuer, "commonName": issuer, "publicKey": jwk},
            "proof": {"type": "JWT", "proofValue": proof_jwt(issuer, issuer, jwk, key_name)},
        },
    )
    if status != 200 and not (status == 400 and "already exists" in json.dumps(response)):
        raise RuntimeError(f"Issuer registration failed: HTTP {status}: {response}")
    return jwk


def generate_agent_id(jwk: dict[str, str]) -> tuple[str, dict[str, Any]]:
    status, body = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/id/generate",
        {
            "issuer": {"organization": AGENT_CONTROL_ISSUER, "commonName": AGENT_CONTROL_ISSUER},
            "proof": {
                "type": "JWT",
                "proofValue": proof_jwt(AGENT_SUBJECT, AGENT_CONTROL_ISSUER, jwk, AGENT_CONTROL_KEY),
            },
        },
    )
    if status == 200:
        agent_id = body["resolverMetadata"]["id"]
    elif status == 400 and "ID_ALREADY_REGISTERED" in json.dumps(body):
        agent_id = f"AGNTCY-{AGENT_SUBJECT}"
    else:
        raise RuntimeError(f"Agent ID generation failed: HTTP {status}: {body}")
    status, resolved = json_http("POST", f"{IDENTITY}/v1alpha1/id/resolve", {"id": agent_id})
    if status != 200:
        raise RuntimeError(f"Agent ID resolution failed: HTTP {status}: {resolved}")
    return agent_id, resolved["resolverMetadata"]


def build_record(identity_subject: str, version: str = "1.0.0") -> dict[str, Any]:
    return {
        "name": AGENT_NAME,
        "schema_version": "1.1.0",
        "version": version,
        "description": "Autonomous agent that triages software dependency security findings",
        "authors": ["IdentityClaim Agent Badge PoC"],
        "created_at": "2026-10-01T00:00:00Z",
        "skills": [
            {"name": "language_processing/language_understanding/contextual_comprehension", "id": 10101},
            {"name": "language_processing/language_understanding/semantic_understanding", "id": 10102},
        ],
        "locators": [
            {"type": "url", "urls": ["https://security-agent.invalid/.well-known/agent-card.json"]}
        ],
        "annotations": {
            "agntcy.dir/identity": identity_subject,
            "agntcy.dir/identity-type": "agntcy",
        },
    }


def issue_badge(
    record: dict[str, Any],
    agent_id: str,
    agent_jwk: dict[str, str],
) -> tuple[dict[str, Any], str]:
    now = int(time.time())
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "AgentBadge"],
        "issuer": AGENT_CONTROL_ISSUER,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expirationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600)),
        "credentialSubject": {"id": agent_id, "badge": record},
    }
    # Identity Node v0.0.26 verifies this proof against credentialSubject.id's
    # ResolverMetadata key, not a separately resolved issuer key.
    badge_jws = sign_jws(credential, "JOSE", agent_jwk, AGENT_CONTROL_KEY)
    status, response = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/publish",
        {
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": badge_jws},
            "proof": {
                "type": "JWT",
                "proofValue": proof_jwt(
                    agent_id,
                    AGENT_CONTROL_ISSUER,
                    agent_jwk,
                    AGENT_CONTROL_KEY,
                ),
            },
        },
    )
    if status != 200:
        raise RuntimeError(f"Agent Badge publication failed: HTTP {status}: {response}")
    return credential, badge_jws


def make_claim(record_cid: str, subject: str, agent_jwk: dict[str, str]) -> dict[str, Any]:
    signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    canonical = f"{record_cid}|{subject}|{signed_at}".encode()
    return {
        "subject": subject,
        "signedAt": signed_at,
        "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
        "signature": sign_detached(canonical, agent_jwk, AGENT_CONTROL_KEY),
    }


def push_record(directory: str, record: dict[str, Any]) -> str:
    return grpc_json(directory, "agntcy.dir.store.v1.StoreService/Push", {"data": record})["cid"]


def push_claim(directory: str, record_cid: str, claim: dict[str, Any]) -> dict[str, Any]:
    return grpc_json(
        directory,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": CLAIM_TYPE,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": claim,
        },
    )


def identity_status(directory: str, record_cid: str) -> dict[str, Any]:
    return grpc_json(
        directory,
        "agntcy.dir.identity.v1.IdentityService/GetIdentityStatus",
        {"cid": record_cid},
    )


def search_cids(directory: str, queries: list[dict[str, str]]) -> list[str]:
    results = grpc_stream(
        directory,
        "agntcy.dir.search.v1.SearchService/SearchCIDs",
        {"queries": queries},
    )
    return [result["recordCid"] for result in results]


def main() -> None:
    wait_for("Vault", lambda: vault("GET", "sys/health")[0] in (200, 429, 472, 473))
    wait_for(
        "Identity Node",
        lambda: http("GET", f"{IDENTITY}/v1alpha1/issuer/__probe__/.well-known/jwks.json")[0]
        in (200, 400, 404),
    )
    wait_for(
        "patched Directory",
        lambda: grpcurl(PATCHED_DIRECTORY, "grpc.health.v1.Health/Check", {"service": ""}).returncode == 0,
    )
    wait_for(
        "stock PR #2125 Directory",
        lambda: grpcurl(STOCK_DIRECTORY, "grpc.health.v1.Health/Check", {"service": ""}).returncode == 0,
    )

    status, response = vault("POST", "sys/mounts/transit", {"type": "transit"})
    if status not in (200, 204) and "already in use" not in json.dumps(response):
        raise RuntimeError(f"Could not enable Vault Transit: HTTP {status}: {response}")

    agent_jwk = setup_issuer(AGENT_CONTROL_KEY, AGENT_CONTROL_ISSUER)
    agent_id, resolver_metadata = generate_agent_id(agent_jwk)
    identity_subject = f"agntcy:{agent_id}"

    record = build_record(identity_subject)
    patched_cid = push_record(PATCHED_DIRECTORY, record)
    stock_cid = push_record(STOCK_DIRECTORY, record)
    if patched_cid != stock_cid:
        raise RuntimeError("Stock and patched Directory calculated different CIDs")

    badge, badge_jws = issue_badge(record, agent_id, agent_jwk)
    badge_status, badge_verification = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/verify",
        {"vc": {"envelopeType": ENVELOPE_JOSE, "value": badge_jws}},
    )

    claim = make_claim(patched_cid, identity_subject, agent_jwk)
    claim_payload = f"{patched_cid}|{identity_subject}|{claim['signedAt']}".encode()
    stock_referrer = push_claim(STOCK_DIRECTORY, stock_cid, claim)
    patched_referrer = push_claim(PATCHED_DIRECTORY, patched_cid, claim)
    stock_status = identity_status(STOCK_DIRECTORY, stock_cid)
    patched_status = identity_status(PATCHED_DIRECTORY, patched_cid)

    replay_record = build_record(identity_subject, version="1.0.1")
    replay_cid = push_record(PATCHED_DIRECTORY, replay_record)
    push_claim(PATCHED_DIRECTORY, replay_cid, claim)
    replay_status = identity_status(PATCHED_DIRECTORY, replay_cid)

    verified_matches = search_cids(
        PATCHED_DIRECTORY,
        [
            {"type": "RECORD_QUERY_TYPE_NAME", "value": AGENT_NAME},
            {"type": "RECORD_QUERY_TYPE_IDENTITY_VERIFIED", "value": "true"},
        ],
    )
    declared_matches = search_cids(
        PATCHED_DIRECTORY,
        [{"type": "RECORD_QUERY_TYPE_IDENTITY", "value": identity_subject}],
    )

    status, well_known = json_http(
        "GET", f"{IDENTITY}/v1alpha1/vc/{agent_id}/.well-known/vcs.json"
    )
    if status != 200:
        raise RuntimeError(f"Agent Badge lookup failed: HTTP {status}: {well_known}")

    _, control_key_metadata = vault("GET", f"transit/keys/{AGENT_CONTROL_KEY}")
    private_material_exposed = "private_key" in json.dumps(control_key_metadata).lower()

    checks: dict[str, Any] = {
        "sameRecordCIDInStockAndPatched": patched_cid == stock_cid,
        "agentIDResolvedByIdentityNode": resolver_metadata.get("id") == agent_id,
        "resolverMetadataContainsAgentControlKey": any(
            method.get("publicKeyJwk", {}).get("n") == agent_jwk["n"]
            for method in resolver_metadata.get("verificationMethod", [])
        ),
        "identityClaimSignatureValidBeforeSubmission": verify_rs256_detached(
            claim["signature"], claim_payload, agent_jwk
        ),
        "identityV026VerifiedBadgeWithSubjectResolverKey": badge_status == 200
        and badge_verification.get("status") is True,
        "agentBadgeEmbedsExactDirectoryRecord": badge["credentialSubject"]["badge"] == record,
        "agentBadgeSubjectMatchesAgentID": badge["credentialSubject"]["id"] == agent_id,
        "identityNodeVerifiedAgentBadge": badge_status == 200 and badge_verification.get("status") is True,
        "identityNodePublishedAgentBadge": any(
            item.get("value") == badge_jws for item in well_known.get("vcs", [])
        ),
        "stockPR2125AcceptedIdentityClaimType": stock_referrer.get("success") is True,
        "stockPR2125CouldNotVerifyAgntcyIdentity": stock_status.get("identity", {}).get("verified") is not True,
        "patchedDirectoryAcceptedIdentityClaimType": patched_referrer.get("success") is True,
        "patchedDirectoryVerifiedIdentityClaim": patched_status.get("identity", {}).get("verified") is True,
        "patchedStatusReturnsAgentID": patched_status.get("identity", {}).get("subject") == identity_subject,
        "verifiedIdentitySearchFoundExactRecord": verified_matches == [patched_cid],
        "declaredIdentitySearchFoundBothVersions": set(declared_matches) == {patched_cid, replay_cid},
        "CIDBoundClaimRejectedOnDifferentRecord": replay_status.get("identity", {}).get("verified") is not True,
        "vaultPrivateKeysStayedInTransit": not private_material_exposed,
    }

    report = {
        "versions": {
            "directoryBase": f"PR #2125 commit {DIRECTORY_COMMIT}",
            "identity": "v0.0.26",
        },
        "artifacts": {
            "agentID": agent_id,
            "identitySubject": identity_subject,
            "recordCID": patched_cid,
            "replayRecordCID": replay_cid,
            "identityClaimReferrerCID": patched_referrer.get("referrerRef", {}).get("cid"),
        },
        "status": {
            "stockPR2125": stock_status,
            "patched": patched_status,
            "replayedClaim": replay_status,
        },
        "search": {
            "identityVerifiedTrue": verified_matches,
            "identitySubject": declared_matches,
        },
        "checks": checks,
        "conclusion": {
            "validated": [
                "Agent Badge can serve as resolver evidence for Directory identity.v1 without becoming the IdentityClaim itself.",
                "The agent proves control by signing the exact Directory CID with the key resolved from AGNTCY Identity ResolverMetadata.",
                "Directory can expose native identity_verified search after the claim, badge subject, badge proof, and embedded OASF definition all verify.",
                "A claim replayed onto a different Directory CID is not verified.",
            ],
            "qualified": [
                "identity.v1 is proposed in Directory PR #2125 and is not part of the pinned v1.7.1 release.",
                "The stock PR #2125 branch admits IdentityClaim but has no agntcy: resolver; this PoC adds that resolver.",
                "The configured Identity Node is a relying-party trust decision; Directory does not make every Identity Node globally trusted.",
                "Identity Node v0.0.26 verifies the Agent Badge with the credential subject's ResolverMetadata key; it does not independently resolve and validate a separate VC issuer key.",
                "A legal-entity credential remains supplementary evidence and is not required to prove control of the Agent ID.",
            ],
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    failed = [name for name, passed in checks.items() if passed is not True]
    if failed:
        raise SystemExit("Validation failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
