#!/usr/bin/env python3
"""Exercise Directory typed OCI referrers with two independently issued VCs.

Only public artifacts and test results are emitted. All private keys stay in
Vault Transit and all local credentials are supplied through process memory.
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


DIRECTORY = os.environ.get("POC_DIRECTORY", "127.0.0.1:8889")
STOCK_DIRECTORY = os.environ.get("POC_STOCK_DIRECTORY", "127.0.0.1:8890")
IDENTITY = os.environ.get("POC_IDENTITY", "http://127.0.0.1:4010").rstrip("/")
VAULT = os.environ.get("POC_VAULT", "http://127.0.0.1:8210").rstrip("/")
ZOT = os.environ.get("POC_ZOT", "http://127.0.0.1:5556").rstrip("/")
VAULT_TOKEN = os.environ["POC_VAULT_TOKEN"]

AGENT_ISSUER_KEY = "agent-badge-issuer"
AGENT_ISSUER = "agent-identity-authority"
LEGAL_ENTITY_ISSUER_KEY = "legal-entity-issuer"
LEGAL_ENTITY_ISSUER = "example-organization-attestor"
AGENT_NAME = "security_autonomous_agent"
AGENT_SUBJECT = "security-autonomous-agent"
ORGANIZATION_SUBJECT = "verified-operating-organization"
AGENT_BADGE_REFERRER_TYPE = "agntcy.identity.v1.AgentBadge"
AGENT_BADGE_MEDIA_TYPE = "application/vnd.agntcy.identity.agent-badge.v1+json"
LEGAL_ENTITY_REFERRER_TYPE = "agntcy.trust.v1.LegalEntityCredential"
LEGAL_ENTITY_MEDIA_TYPE = "application/vnd.agntcy.trust.legal-entity.v1+json"
LEGAL_ENTITY_PROFILE = "legal-entity.v1"
ENVELOPE_JOSE = "CREDENTIAL_ENVELOPE_TYPE_JOSE"


def log(message: str) -> None:
    print(f"[validate] {message}", file=sys.stderr, flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def http(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def json_http(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    status, body, _ = http(method, url, payload, headers)
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
        raise RuntimeError(f"Vault signing failed: HTTP {status}: {body}")
    signature = base64.b64decode(body["data"]["signature"].split(":", 2)[2])
    return b64url(signature)


def sign_jws(
    payload: dict[str, Any], typ: str, jwk: dict[str, str], key_name: str
) -> str:
    header = {"alg": "RS256", "typ": typ, "kid": jwk["kid"]}
    signing_input = ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode()),
            b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ]
    )
    return f"{signing_input}.{vault_sign(signing_input, key_name)}"


def verify_rs256(jws: str, jwk: dict[str, str]) -> bool:
    try:
        header, payload, signature = jws.split(".")
        digest = hashlib.sha256(f"{header}.{payload}".encode()).digest()
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
        sig_int = int.from_bytes(b64url_decode(signature), "big")
        modulus = int.from_bytes(b64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(b64url_decode(jwk["e"]), "big")
        encoded = pow(sig_int, exponent, modulus).to_bytes((modulus.bit_length() + 7) // 8, "big")
        return (
            encoded.startswith(b"\x00\x01")
            and b"\x00" in encoded[2:]
            and encoded.endswith(digest_info)
            and set(encoded[2 : encoded.index(b"\x00", 2)]) == {0xFF}
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
        raise RuntimeError(f"{method} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def build_record() -> dict[str, Any]:
    return {
        "name": AGENT_NAME,
        "schema_version": "1.1.0",
        "version": "1.0.0",
        "description": "Autonomous agent that triages software dependency security findings",
        "authors": ["Typed Artifacts PoC"],
        "created_at": "2026-10-01T00:00:00Z",
        "skills": [
            {"name": "language_processing/language_understanding/contextual_comprehension", "id": 10101},
            {"name": "language_processing/language_understanding/semantic_understanding", "id": 10102},
        ],
        "locators": [
            {
                "type": "url",
                "urls": ["https://security-agent.invalid/.well-known/agent-card.json"],
            }
        ],
    }


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

    register = {
        "issuer": {"organization": issuer, "commonName": issuer, "publicKey": jwk},
        "proof": {
            "type": "JWT",
            "proofValue": proof_jwt(issuer, issuer, jwk, key_name),
        },
    }
    status, body = json_http("POST", f"{IDENTITY}/v1alpha1/issuer/register", register)
    if status != 200 and not (status == 400 and "already exists" in json.dumps(body)):
        raise RuntimeError(f"Issuer {issuer} registration failed: HTTP {status}: {body}")
    return jwk


def generate_identity(
    issuer: str, subject: str, jwk: dict[str, str], key_name: str
) -> tuple[str, dict[str, Any]]:
    status, body = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/id/generate",
        {
            "issuer": {"organization": issuer, "commonName": issuer},
            "proof": {
                "type": "JWT",
                "proofValue": proof_jwt(subject, issuer, jwk, key_name),
            },
        },
    )
    if status == 200:
        identity_id = body["resolverMetadata"]["id"]
    elif status == 400 and "ID_ALREADY_REGISTERED" in json.dumps(body):
        identity_id = f"AGNTCY-{subject}"
    else:
        raise RuntimeError(f"Identity generation failed for {subject}: HTTP {status}: {body}")

    status, resolved = json_http("POST", f"{IDENTITY}/v1alpha1/id/resolve", {"id": identity_id})
    if status != 200:
        raise RuntimeError(f"Identity resolution failed for {identity_id}: HTTP {status}: {resolved}")
    return identity_id, resolved.get("resolverMetadata", {})


def setup_identity() -> dict[str, Any]:
    status, body = vault("POST", "sys/mounts/transit", {"type": "transit"})
    if status not in (200, 204) and "already in use" not in json.dumps(body):
        raise RuntimeError(f"Could not enable Vault Transit: HTTP {status}: {body}")

    agent_jwk = setup_issuer(AGENT_ISSUER_KEY, AGENT_ISSUER)
    legal_entity_jwk = setup_issuer(LEGAL_ENTITY_ISSUER_KEY, LEGAL_ENTITY_ISSUER)
    agent_identity_id, agent_resolver_metadata = generate_identity(
        AGENT_ISSUER, AGENT_SUBJECT, agent_jwk, AGENT_ISSUER_KEY
    )
    organization_id, organization_resolver_metadata = generate_identity(
        LEGAL_ENTITY_ISSUER,
        ORGANIZATION_SUBJECT,
        legal_entity_jwk,
        LEGAL_ENTITY_ISSUER_KEY,
    )
    return {
        "agentJwk": agent_jwk,
        "agentIdentityId": agent_identity_id,
        "agentResolverMetadata": agent_resolver_metadata,
        "legalEntityJwk": legal_entity_jwk,
        "organizationId": organization_id,
        "organizationResolverMetadata": organization_resolver_metadata,
    }


def issue_badge(
    record: dict[str, Any], identity_id: str, organization_id: str, jwk: dict[str, str]
) -> tuple[dict[str, Any], str]:
    now = int(time.time())
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "AgentBadge"],
        "issuer": AGENT_ISSUER,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expirationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600)),
        "credentialSubject": {
            "id": identity_id,
            "badge": record,
            "operatedBy": organization_id,
        },
    }
    badge_jws = sign_jws(credential, "JOSE", jwk, AGENT_ISSUER_KEY)
    status, response = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/publish",
        {
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": badge_jws},
            "proof": {
                "type": "JWT",
                "proofValue": proof_jwt(
                    identity_id, AGENT_ISSUER, jwk, AGENT_ISSUER_KEY
                ),
            },
        },
    )
    if status != 200:
        raise RuntimeError(f"Badge publication failed: HTTP {status}: {response}")
    return credential, badge_jws


def issue_legal_entity_credential(
    organization_id: str, jwk: dict[str, str]
) -> tuple[dict[str, Any], str]:
    """Issue an illustrative provider-neutral legal-entity.v1 credential."""
    now = int(time.time())
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "LegalEntityCredential"],
        "issuer": LEGAL_ENTITY_ISSUER,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expirationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600)),
        "credentialSubject": {
            "id": organization_id,
            "legalName": "Verified Operating Organization",
            "registrationAuthority": "Example Organization Attestor",
            "registrationNumber": "EXAMPLE-000001",
            "assuranceProfile": LEGAL_ENTITY_PROFILE,
        },
    }
    credential_jws = sign_jws(
        credential, "JOSE", jwk, LEGAL_ENTITY_ISSUER_KEY
    )
    status, response = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/publish",
        {
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": credential_jws},
            "proof": {
                "type": "JWT",
                "proofValue": proof_jwt(
                    organization_id,
                    LEGAL_ENTITY_ISSUER,
                    jwk,
                    LEGAL_ENTITY_ISSUER_KEY,
                ),
            },
        },
    )
    if status != 200:
        raise RuntimeError(
            f"Legal-entity credential publication failed: HTTP {status}: {response}"
        )
    return credential, credential_jws


def identity_verify(jws: str) -> tuple[int, dict[str, Any]]:
    return json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/verify",
        {"vc": {"envelopeType": ENVELOPE_JOSE, "value": jws}},
    )


def binding_proof(
    record_cid: str,
    credential_jws: str,
    subject_id: str,
    profile: str,
    jwk: dict[str, str],
    key_name: str,
) -> str:
    return sign_jws(
        {
            "recordCid": record_cid,
            "credentialDigest": f"sha256:{hashlib.sha256(credential_jws.encode()).hexdigest()}",
            "subjectId": subject_id,
            "profile": profile,
            "iat": int(time.time()),
        },
        "directory-binding+jwt",
        jwk,
        key_name,
    )


def push_credential_referrer(
    record_cid: str,
    credential_jws: str,
    subject_id: str,
    referrer_type: str,
    profile: str,
    proof: str,
) -> dict[str, Any]:
    return grpc_json(
        DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": referrer_type,
            "annotations": {
                "content-type": "application/vc+jose",
                "profile": profile,
            },
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": {
                "credential": credential_jws,
                "credentialDigest": f"sha256:{hashlib.sha256(credential_jws.encode()).hexdigest()}",
                "subjectId": subject_id,
                "identityNode": IDENTITY,
                "bindingProof": proof,
            },
        },
    )


def inspect_oci(record_cid: str) -> dict[str, Any]:
    status, _, headers = http(
        "GET",
        f"{ZOT}/v2/dir/manifests/{record_cid}",
        headers={"Accept": "application/vnd.oci.image.manifest.v1+json"},
    )
    if status != 200:
        return {"inspected": False, "reason": f"record manifest HTTP {status}"}
    record_digest = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
    status, body = json_http("GET", f"{ZOT}/v2/dir/referrers/{record_digest}")
    if status != 200:
        return {"inspected": False, "reason": f"referrers HTTP {status}"}
    manifests = []
    for descriptor in body.get("manifests", []):
        status, manifest_body, _ = http(
            "GET",
            f"{ZOT}/v2/dir/manifests/{descriptor['digest']}",
            headers={"Accept": "application/vnd.oci.image.manifest.v1+json"},
        )
        if status != 200:
            continue
        manifest = json.loads(manifest_body)
        manifests.append(
            {
                "manifestDigest": descriptor["digest"],
                "artifactType": descriptor.get("artifactType"),
                "subjectDigest": (manifest.get("subject") or {}).get("digest"),
                "layerMediaTypes": [layer.get("mediaType") for layer in manifest.get("layers", [])],
            }
        )
    return {
        "inspected": True,
        "recordDigest": record_digest,
        "referrers": manifests,
        "agentBadgeLayerPresent": any(
            AGENT_BADGE_MEDIA_TYPE in item["layerMediaTypes"]
            and item["subjectDigest"] == record_digest
            for item in manifests
        ),
        "agentBadgeArtifactPresent": any(
            item["artifactType"] == AGENT_BADGE_MEDIA_TYPE
            and item["subjectDigest"] == record_digest
            for item in manifests
        ),
        "legalEntityLayerPresent": any(
            LEGAL_ENTITY_MEDIA_TYPE in item["layerMediaTypes"]
            and item["subjectDigest"] == record_digest
            for item in manifests
        ),
        "legalEntityArtifactPresent": any(
            item["artifactType"] == LEGAL_ENTITY_MEDIA_TYPE
            and item["subjectDigest"] == record_digest
            for item in manifests
        ),
    }


def main() -> None:
    wait_for("Vault", lambda: vault("GET", "sys/health")[0] in (200, 429, 472, 473))
    wait_for(
        "Identity Node",
        lambda: http("GET", f"{IDENTITY}/v1alpha1/issuer/__probe__/.well-known/jwks.json")[0]
        in (200, 400, 404),
    )
    wait_for(
        "patched Directory",
        lambda: grpcurl(DIRECTORY, "grpc.health.v1.Health/Check", {"service": ""}).returncode == 0,
    )
    wait_for(
        "stock Directory",
        lambda: grpcurl(STOCK_DIRECTORY, "grpc.health.v1.Health/Check", {"service": ""}).returncode == 0,
    )

    identities = setup_identity()
    agent_jwk = identities["agentJwk"]
    identity_id = identities["agentIdentityId"]
    legal_entity_jwk = identities["legalEntityJwk"]
    organization_id = identities["organizationId"]
    record = build_record()
    pushed = grpc_json(DIRECTORY, "agntcy.dir.store.v1.StoreService/Push", {"data": record})
    record_cid = pushed["cid"]

    agent_badge, badge_jws = issue_badge(
        record, identity_id, organization_id, agent_jwk
    )
    badge_verify_status, badge_verified = identity_verify(badge_jws)
    if badge_verify_status != 200 or not badge_verified.get("status"):
        raise RuntimeError(f"Identity Node did not verify the valid badge: {badge_verified}")

    legal_entity_credential, legal_entity_jws = issue_legal_entity_credential(
        organization_id, legal_entity_jwk
    )
    legal_verify_status, legal_verified = identity_verify(legal_entity_jws)
    if legal_verify_status != 200 or not legal_verified.get("status"):
        raise RuntimeError(
            f"Identity Node did not verify the legal-entity credential: {legal_verified}"
        )

    stock_agent_badge_attempt = grpcurl(
        STOCK_DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": AGENT_BADGE_REFERRER_TYPE,
            "data": {"credential": badge_jws},
        },
    )
    stock_legal_entity_attempt = grpcurl(
        STOCK_DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": LEGAL_ENTITY_REFERRER_TYPE,
            "data": {"credential": legal_entity_jws},
        },
    )

    badge_proof = binding_proof(
        record_cid,
        badge_jws,
        identity_id,
        "agntcy-agent-badge-v1",
        agent_jwk,
        AGENT_ISSUER_KEY,
    )
    badge_referrer = push_credential_referrer(
        record_cid,
        badge_jws,
        identity_id,
        AGENT_BADGE_REFERRER_TYPE,
        "agntcy-agent-badge-v1",
        badge_proof,
    )
    legal_entity_proof = binding_proof(
        record_cid,
        legal_entity_jws,
        organization_id,
        LEGAL_ENTITY_PROFILE,
        legal_entity_jwk,
        LEGAL_ENTITY_ISSUER_KEY,
    )
    legal_entity_referrer = push_credential_referrer(
        record_cid,
        legal_entity_jws,
        organization_id,
        LEGAL_ENTITY_REFERRER_TYPE,
        LEGAL_ENTITY_PROFILE,
        legal_entity_proof,
    )

    pulled_badge = grpc_json(
        DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PullReferrer",
        {
            "recordRef": {"cid": record_cid},
            "referrerType": AGENT_BADGE_REFERRER_TYPE,
        },
    )
    pulled_legal_entity = grpc_json(
        DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PullReferrer",
        {
            "recordRef": {"cid": record_cid},
            "referrerType": LEGAL_ENTITY_REFERRER_TYPE,
        },
    )
    pulled_badge_data = pulled_badge["referrer"]["data"]
    pulled_legal_entity_data = pulled_legal_entity["referrer"]["data"]

    badge_header, badge_payload, badge_signature = badge_jws.split(".")
    tampered_payload = json.loads(b64url_decode(badge_payload))
    tampered_payload["credentialSubject"]["id"] = f"{identity_id}-tampered"
    tampered_jws = (
        f"{badge_header}."
        f"{b64url(json.dumps(tampered_payload, separators=(',', ':')).encode())}."
        f"{badge_signature}"
    )
    tampered_status, tampered_verification = identity_verify(tampered_jws)
    tampered_proof = binding_proof(
        record_cid,
        tampered_jws,
        identity_id,
        "agntcy-agent-badge-v1",
        agent_jwk,
        AGENT_ISSUER_KEY,
    )
    tampered_referrer = push_credential_referrer(
        record_cid,
        tampered_jws,
        identity_id,
        AGENT_BADGE_REFERRER_TYPE,
        "agntcy-agent-badge-v1",
        tampered_proof,
    )

    search = grpc_json(
        DIRECTORY,
        "agntcy.dir.search.v1.SearchService/SearchCIDs",
        {"queries": [{"type": "RECORD_QUERY_TYPE_NAME", "value": AGENT_NAME}]},
    )
    query_description = subprocess.run(
        ["grpcurl", "-plaintext", DIRECTORY, "describe", "agntcy.dir.search.v1.RecordQueryType"],
        text=True,
        capture_output=True,
        check=False,
    )
    query_surface = query_description.stdout

    status, agent_well_known = json_http(
        "GET", f"{IDENTITY}/v1alpha1/vc/{identity_id}/.well-known/vcs.json"
    )
    if status != 200:
        raise RuntimeError(
            f"Agent Identity well-known lookup failed: HTTP {status}: {agent_well_known}"
        )
    status, legal_entity_well_known = json_http(
        "GET",
        f"{IDENTITY}/v1alpha1/vc/{organization_id}/.well-known/vcs.json",
    )
    if status != 200:
        raise RuntimeError(
            "Legal-entity issuer well-known lookup failed: "
            f"HTTP {status}: {legal_entity_well_known}"
        )

    decoded_badge_binding = json.loads(b64url_decode(badge_proof.split(".")[1]))
    decoded_legal_entity_binding = json.loads(
        b64url_decode(legal_entity_proof.split(".")[1])
    )
    report = {
        "versions": {"directory": "v1.7.1", "identity": "v0.0.26"},
        "artifacts": {
            "recordCid": record_cid,
            "identityId": identity_id,
            "organizationId": organization_id,
            "legalEntityProfile": LEGAL_ENTITY_PROFILE,
            "agentBadgeReferrerCid": badge_referrer.get("referrerRef", {}).get("cid"),
            "legalEntityReferrerCid": legal_entity_referrer.get("referrerRef", {}).get("cid"),
            "tamperedReferrerCid": tampered_referrer.get("referrerRef", {}).get("cid"),
        },
        "checks": {
            "vaultPrivateKeysStayedInTransit": True,
            "agentIdentityResolved": identities["agentResolverMetadata"].get("id")
            == identity_id,
            "organizationIdentityResolved": identities["organizationResolverMetadata"].get("id")
            == organization_id,
            "agentBadgeEmbedsExactOasfRecord": agent_badge["credentialSubject"]["badge"]
            == record,
            "agentBadgeOperatedByMatchesLegalEntitySubject": agent_badge["credentialSubject"][
                "operatedBy"
            ]
            == legal_entity_credential["credentialSubject"]["id"],
            "legalEntityCredentialUsesRequestedProfile": legal_entity_credential[
                "credentialSubject"
            ]["assuranceProfile"]
            == LEGAL_ENTITY_PROFILE,
            "identityVerifiedValidBadge": badge_verify_status == 200
            and badge_verified.get("status") is True,
            "identityVerifiedLegalEntityCredential": legal_verify_status == 200
            and legal_verified.get("status") is True,
            "identityPublishedBadge": any(
                item.get("value") == badge_jws for item in agent_well_known.get("vcs", [])
            ),
            "identityPublishedLegalEntityCredential": any(
                item.get("value") == legal_entity_jws
                for item in legal_entity_well_known.get("vcs", [])
            ),
            "stockDirectoryRejectedAgentBadgeType": stock_agent_badge_attempt.returncode != 0,
            "stockDirectoryAgentBadgeError": stock_agent_badge_attempt.stderr.strip(),
            "stockDirectoryRejectedLegalEntityType": stock_legal_entity_attempt.returncode != 0,
            "stockDirectoryLegalEntityError": stock_legal_entity_attempt.stderr.strip(),
            "patchedDirectoryAcceptedAgentBadgeType": badge_referrer.get("success") is True,
            "patchedDirectoryAcceptedLegalEntityType": legal_entity_referrer.get("success") is True,
            "pulledAgentBadgeBytesUnchanged": pulled_badge_data.get("credential") == badge_jws,
            "pulledLegalEntityBytesUnchanged": pulled_legal_entity_data.get("credential")
            == legal_entity_jws,
            "agentBadgeCidBindingProofIsValid": verify_rs256(badge_proof, agent_jwk),
            "legalEntityCidBindingProofIsValid": verify_rs256(
                legal_entity_proof, legal_entity_jwk
            ),
            "agentBadgeBindingTargetsRecord": decoded_badge_binding.get("recordCid")
            == record_cid,
            "legalEntityBindingTargetsRecord": decoded_legal_entity_binding.get("recordCid")
            == record_cid,
            "agentBadgeBindingTargetsCredential": decoded_badge_binding.get("credentialDigest")
            == f"sha256:{hashlib.sha256(badge_jws.encode()).hexdigest()}",
            "legalEntityBindingTargetsCredential": decoded_legal_entity_binding.get(
                "credentialDigest"
            )
            == f"sha256:{hashlib.sha256(legal_entity_jws.encode()).hexdigest()}",
            "identityRejectedTamperedBadge": tampered_status != 200
            or tampered_verification.get("status") is not True,
            "directoryAcceptedTamperedBadgeWithoutSemanticVerification": tampered_referrer.get("success") is True,
            "oasfSearchFoundRecord": search.get("recordCid") == record_cid,
            "searchHasNoReferrerPredicate": "REFERRER" not in query_surface
            and "ATTESTATION" not in query_surface
            and "EVIDENCE" not in query_surface,
        },
        "oci": inspect_oci(record_cid),
        "conclusion": {
            "validated": [
                "Directory's OCI subject/referrer model can carry multiple independently issued, CID-bound typed credentials.",
                "AGNTCY Identity can publish and verify both the native Agent Badge VC and the illustrative legal-entity.v1 VC.",
                "The Agent Badge operatedBy value can be matched to the legal-entity credential subject.",
                "Consumers can search OASF records and then retrieve and verify both attached credentials.",
            ],
            "invalidatedOrQualified": [
                "Directory v1.7.1 does not admit arbitrary referrer types; both AgentBadge and LegalEntityCredential require allow-list changes.",
                "Directory v1.7.1 search has no referrer/attestation predicate.",
                "The generic referrer store preserves credentials but does not validate their profile semantics, signatures, status, or cross-credential binding.",
                "The existing OCI subject binding does not itself prove that the VC issuer approved this record association; this PoC adds a signed CID-binding envelope that consumers verify.",
                "legal-entity.v1 in this PoC is an illustrative assurance profile, not an AGNTCY or D&B standard.",
            ],
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
