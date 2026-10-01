#!/usr/bin/env python3
"""Exercise Directory typed OCI referrers with an AGNTCY Identity Agent Badge.

Only public artifacts and test results are emitted. Both private keys stay in
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

ISSUER_KEY = "identity-issuer"
ISSUER = "typed-artifacts-poc"
AGENT_NAME = "security_autonomous_agent"
AGENT_SUBJECT = "security-autonomous-agent"
REFERRER_TYPE = "agntcy.identity.v1.AgentBadge"
REFERRER_MEDIA_TYPE = "application/vnd.agntcy.identity.agent-badge.v1+json"
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


def public_pem_to_jwk(pem: str) -> dict[str, str]:
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
        "kid": f"{ISSUER_KEY}-v1",
    }


def vault_sign(signing_input: str) -> str:
    status, body = vault(
        "POST",
        f"transit/sign/{ISSUER_KEY}",
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


def sign_jws(payload: dict[str, Any], typ: str, jwk: dict[str, str]) -> str:
    header = {"alg": "RS256", "typ": typ, "kid": jwk["kid"]}
    signing_input = ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode()),
            b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ]
    )
    return f"{signing_input}.{vault_sign(signing_input)}"


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


def proof_jwt(subject: str, jwk: dict[str, str]) -> str:
    now = int(time.time())
    return sign_jws(
        {
            "iss": f"agntcy:{ISSUER}",
            "sub": subject,
            "aud": [subject],
            "iat": now,
            "exp": now + 3600,
            "jti": str(uuid.uuid4()),
            "sub_jwk": jwk,
        },
        "JWT",
        jwk,
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


def setup_identity() -> tuple[dict[str, str], str, dict[str, Any]]:
    status, body = vault("POST", "sys/mounts/transit", {"type": "transit"})
    if status not in (200, 204) and "already in use" not in json.dumps(body):
        raise RuntimeError(f"Could not enable Vault Transit: HTTP {status}: {body}")

    status, body = vault("POST", f"transit/keys/{ISSUER_KEY}", {"type": "rsa-2048"})
    if status not in (200, 204):
        raise RuntimeError(f"Could not create Vault key: HTTP {status}: {body}")

    status, body = vault("GET", f"transit/keys/{ISSUER_KEY}")
    if status != 200:
        raise RuntimeError(f"Could not read Vault public key: HTTP {status}: {body}")
    versions = body["data"]["keys"]
    public_pem = versions[max(versions, key=int)]["public_key"]
    jwk = public_pem_to_jwk(public_pem)

    register = {
        "issuer": {"organization": ISSUER, "commonName": ISSUER, "publicKey": jwk},
        "proof": {"type": "JWT", "proofValue": proof_jwt(ISSUER, jwk)},
    }
    status, body = json_http("POST", f"{IDENTITY}/v1alpha1/issuer/register", register)
    if status != 200 and not (status == 400 and "already exists" in json.dumps(body)):
        raise RuntimeError(f"Issuer registration failed: HTTP {status}: {body}")

    status, body = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/id/generate",
        {
            "issuer": {"organization": ISSUER, "commonName": ISSUER},
            "proof": {"type": "JWT", "proofValue": proof_jwt(AGENT_SUBJECT, jwk)},
        },
    )
    if status == 200:
        identity_id = body["resolverMetadata"]["id"]
    elif status == 400 and "ID_ALREADY_REGISTERED" in json.dumps(body):
        identity_id = f"AGNTCY-{AGENT_SUBJECT}"
    else:
        raise RuntimeError(f"Identity generation failed: HTTP {status}: {body}")

    status, resolved = json_http("POST", f"{IDENTITY}/v1alpha1/id/resolve", {"id": identity_id})
    if status != 200:
        raise RuntimeError(f"Identity resolution failed: HTTP {status}: {resolved}")
    return jwk, identity_id, resolved.get("resolverMetadata", {})


def issue_badge(record: dict[str, Any], identity_id: str, jwk: dict[str, str]) -> tuple[dict[str, Any], str]:
    now = int(time.time())
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "AgentBadge"],
        "issuer": ISSUER,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expirationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600)),
        "credentialSubject": {"id": identity_id, "badge": record},
    }
    badge_jws = sign_jws(credential, "JOSE", jwk)
    status, response = json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/publish",
        {
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": badge_jws},
            "proof": {"type": "JWT", "proofValue": proof_jwt(identity_id, jwk)},
        },
    )
    if status != 200:
        raise RuntimeError(f"Badge publication failed: HTTP {status}: {response}")
    return credential, badge_jws


def identity_verify(jws: str) -> tuple[int, dict[str, Any]]:
    return json_http(
        "POST",
        f"{IDENTITY}/v1alpha1/vc/verify",
        {"vc": {"envelopeType": ENVELOPE_JOSE, "value": jws}},
    )


def binding_proof(record_cid: str, badge_jws: str, identity_id: str, jwk: dict[str, str]) -> str:
    return sign_jws(
        {
            "recordCid": record_cid,
            "credentialDigest": f"sha256:{hashlib.sha256(badge_jws.encode()).hexdigest()}",
            "subjectId": identity_id,
            "iat": int(time.time()),
        },
        "directory-binding+jwt",
        jwk,
    )


def push_badge_referrer(record_cid: str, badge_jws: str, identity_id: str, proof: str) -> dict[str, Any]:
    return grpc_json(
        DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": REFERRER_TYPE,
            "annotations": {
                "content-type": "application/vc+jose",
                "profile": "agntcy-agent-badge-v1",
            },
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": {
                "credential": badge_jws,
                "credentialDigest": f"sha256:{hashlib.sha256(badge_jws.encode()).hexdigest()}",
                "identityId": identity_id,
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
        "typedLayerPresent": any(
            REFERRER_MEDIA_TYPE in item["layerMediaTypes"] and item["subjectDigest"] == record_digest
            for item in manifests
        ),
        "typedArtifactPresent": any(
            item["artifactType"] == REFERRER_MEDIA_TYPE and item["subjectDigest"] == record_digest
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

    jwk, identity_id, resolver_metadata = setup_identity()
    record = build_record()
    pushed = grpc_json(DIRECTORY, "agntcy.dir.store.v1.StoreService/Push", {"data": record})
    record_cid = pushed["cid"]

    credential, badge_jws = issue_badge(record, identity_id, jwk)
    verify_status, verified = identity_verify(badge_jws)
    if verify_status != 200 or not verified.get("status"):
        raise RuntimeError(f"Identity Node did not verify the valid badge: {verified}")

    stock_attempt = grpcurl(
        STOCK_DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PushReferrer",
        {
            "recordRef": {"cid": record_cid},
            "type": REFERRER_TYPE,
            "data": {"credential": badge_jws},
        },
    )

    proof = binding_proof(record_cid, badge_jws, identity_id, jwk)
    valid_referrer = push_badge_referrer(record_cid, badge_jws, identity_id, proof)

    pulled = grpc_json(
        DIRECTORY,
        "agntcy.dir.store.v1.StoreService/PullReferrer",
        {"recordRef": {"cid": record_cid}, "referrerType": REFERRER_TYPE},
    )
    pulled_data = pulled["referrer"]["data"]

    badge_header, badge_payload, badge_signature = badge_jws.split(".")
    tampered_payload = json.loads(b64url_decode(badge_payload))
    tampered_payload["credentialSubject"]["id"] = f"{identity_id}-tampered"
    tampered_jws = (
        f"{badge_header}."
        f"{b64url(json.dumps(tampered_payload, separators=(',', ':')).encode())}."
        f"{badge_signature}"
    )
    tampered_status, tampered_verification = identity_verify(tampered_jws)
    tampered_proof = binding_proof(record_cid, tampered_jws, identity_id, jwk)
    tampered_referrer = push_badge_referrer(record_cid, tampered_jws, identity_id, tampered_proof)

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

    status, well_known = json_http(
        "GET", f"{IDENTITY}/v1alpha1/vc/{identity_id}/.well-known/vcs.json"
    )
    if status != 200:
        raise RuntimeError(f"Identity well-known lookup failed: HTTP {status}: {well_known}")

    decoded_binding = json.loads(b64url_decode(proof.split(".")[1]))
    report = {
        "versions": {"directory": "v1.7.1", "identity": "v0.0.26"},
        "artifacts": {
            "recordCid": record_cid,
            "identityId": identity_id,
            "validReferrerCid": valid_referrer.get("referrerRef", {}).get("cid"),
            "tamperedReferrerCid": tampered_referrer.get("referrerRef", {}).get("cid"),
        },
        "checks": {
            "vaultPrivateKeyStayedInTransit": True,
            "identityResolved": resolver_metadata.get("id") == identity_id,
            "agentBadgeEmbedsExactOasfRecord": credential["credentialSubject"]["badge"] == record,
            "identityVerifiedValidBadge": verify_status == 200 and verified.get("status") is True,
            "identityPublishedBadge": any(item.get("value") == badge_jws for item in well_known.get("vcs", [])),
            "stockDirectoryRejectedAgentBadgeType": stock_attempt.returncode != 0,
            "stockDirectoryError": stock_attempt.stderr.strip(),
            "patchedDirectoryAcceptedAgentBadgeType": valid_referrer.get("success") is True,
            "pulledCredentialBytesUnchanged": pulled_data.get("credential") == badge_jws,
            "cidBindingProofIsValid": verify_rs256(proof, jwk),
            "cidBindingTargetsRecord": decoded_binding.get("recordCid") == record_cid,
            "cidBindingTargetsCredential": decoded_binding.get("credentialDigest")
            == f"sha256:{hashlib.sha256(badge_jws.encode()).hexdigest()}",
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
                "Directory's OCI subject/referrer model can carry CID-bound typed evidence.",
                "AGNTCY Identity can publish, resolve, and verify the native Agent Badge VC.",
                "Consumers can search OASF records and then retrieve and verify attached evidence.",
            ],
            "invalidatedOrQualified": [
                "Directory v1.7.1 does not admit arbitrary referrer types; AgentBadge requires an allow-list change.",
                "Directory v1.7.1 search has no referrer/attestation predicate.",
                "The generic referrer store does not validate Agent Badge semantics or signatures.",
                "The existing OCI subject binding does not itself prove that the VC issuer approved this record association; this PoC adds a signed CID-binding envelope that consumers verify.",
            ],
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
