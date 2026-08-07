# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Agent badge Verifiable Credentials, issued through the AGNTCY Identity Node.

The badge is a real W3C Verifiable Credential: built here, signed with the
org's Vault trust-authority key (the same key CIMD proofs use — the private
half never leaves Vault), enveloped as JOSE, and published to identity-node's
VC API.

Note the shape of that API — publish / verify / revoke / search, with no
`issue`. The node does not mint credentials; it registers ones the issuer has
already signed, which is why signing belongs here and the trust anchor is the
org's registered issuer key rather than any single service's keypair.

    POST /v1alpha1/vc/publish   {vc: EnvelopedCredential, proof?: Proof}
    POST /v1alpha1/vc/verify    {vc}  -> {status, document}
    GET  /v1alpha1/vc/{id}/.well-known/vcs.json

`proof` carries a Vault-signed proof JWT — the "Issuer is provided by an
external IdP" case the upstream proto anticipates.
"""

from __future__ import annotations

import json
import time
import uuid

import httpx

from . import VaultConfig
from .vault import b64url, build_proof_jwt, get_issuer_jwk, vault_sign_rs256

# CredentialEnvelopeType / CredentialContentType from
# agntcy/identity/core/v1alpha1/vc.proto
ENVELOPE_JOSE = "CREDENTIAL_ENVELOPE_TYPE_JOSE"
CONTENT_AGENT_BADGE = "CREDENTIAL_CONTENT_TYPE_AGENT_BADGE"

W3C_CREDENTIALS_CONTEXT = "https://www.w3.org/2018/credentials/v1"
BADGE_TYPE = "AgentBadge"

# CredentialStatusPurpose — the only non-unspecified value upstream defines.
# "This status is not reversible", per the proto.
REVOCATION_PURPOSE = "CREDENTIAL_STATUS_PURPOSE_REVOCATION"


class VcError(Exception):
    """Non-2xx response from the Identity Node's VC API."""

    def __init__(self, operation: str, status_code: int, body: str):
        self.operation = operation
        self.status_code = status_code
        self.body = body
        super().__init__(f"{operation} failed — HTTP {status_code}: {body[:300]}")


def _iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def build_badge_credential(
    cfg: VaultConfig,
    *,
    subject_id: str,
    caps: list[str],
    delegating_user: str,
    intent: str,
    act_chain: list[str],
    delegatable: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> dict:
    """The unsigned W3C credential asserting this agent's delegated capability.

    `caps` is what the agent may do itself; `delegatable` is what it may grant
    onward. They are genuinely different here — Triage acts under
    triage:create while delegating gitea:write/gitea:pr — so a credential
    carrying only one of them either understates the agent or misrepresents
    it. A leaf agent has an empty `delegatable`, which is a useful thing to be
    able to state.
    """
    now = int(time.time())
    context = [W3C_CREDENTIALS_CONTEXT]
    return {
        # "@context" is the JSON-LD keyword a W3C verifier reads; identity-node
        # reads the proto field name "context". Emit both so the signed payload
        # is well-formed either way.
        "@context": context,
        "context": context,
        "type": ["VerifiableCredential", BADGE_TYPE],
        "issuer": cfg.issuer,
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuanceDate": _iso(now),
        "expirationDate": _iso(now + ttl_seconds),
        # NOTE: no credentialStatus. Verified against identity-node 0.0.23,
        # the only entry it accepts for revocation (purpose=REVOCATION) makes
        # the credential *born revoked*; every other shape leaves it
        # unrevocable. There is no way to mint a live, revocable credential on
        # this version, so we issue live-and-unrevocable and rely on
        # publish-once + expiry. See revoke_badge()/supersede_badges().
        "credentialSubject": {
            "id": subject_id,
            "caps": caps,
            "delegating_user": delegating_user,
            "intent": intent,
            "act_chain": act_chain,
            "delegatable": list(delegatable or []),
        },
    }


async def sign_credential(client: httpx.AsyncClient, cfg: VaultConfig, credential: dict) -> str:
    """JOSE-envelope the credential, signed by the org's Vault key."""
    jwk = await get_issuer_jwk(client, cfg)
    header = {"alg": "RS256", "typ": "JOSE", "kid": jwk["kid"]}
    signing_input = (
        f'{b64url(json.dumps(header, separators=(",", ":")).encode())}.'
        f'{b64url(json.dumps(credential, separators=(",", ":")).encode())}'
    )
    return f"{signing_input}.{await vault_sign_rs256(client, cfg, signing_input)}"


async def publish_badge(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cfg: VaultConfig,
    jws: str,
    subject_id: str,
) -> None:
    """Register the signed credential with the Identity Node."""
    proof_jwt = await build_proof_jwt(client, cfg, subject_id)
    r = await client.post(
        f"{identity_node_url.rstrip('/')}/v1alpha1/vc/publish",
        json={
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": jws},
            "proof": {"type": "JWT", "proofValue": proof_jwt},
        },
    )
    if r.status_code != 200:
        raise VcError("vc/publish", r.status_code, r.text)


async def revoke_badge(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cfg: VaultConfig,
    jws: str,
    subject_id: str,
) -> None:
    """Revoke a credential. Irreversible, per the upstream status purpose.

    Only works if the credential was issued carrying a `credentialStatus`;
    the node cannot revoke one that has no revocation entry to flip.
    """
    proof_jwt = await build_proof_jwt(client, cfg, subject_id)
    r = await client.post(
        f"{identity_node_url.rstrip('/')}/v1alpha1/vc/revoke",
        json={
            "vc": {"envelopeType": ENVELOPE_JOSE, "value": jws},
            "proof": {"type": "JWT", "proofValue": proof_jwt},
        },
    )
    if r.status_code != 200:
        raise VcError("vc/revoke", r.status_code, r.text)


async def supersede_badges(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cfg: VaultConfig,
    subject_id: str,
    keep_jws: str,
) -> list[str]:
    """Revoke every other credential for this identity, keeping `keep_jws`.

    One identity, one live credential. Without this, .well-known accumulates
    valid but contradictory answers to "what may this agent do?" — and a
    relying party has no way to tell which is current.

    Returns the credential ids revoked. Failures are collected rather than
    raised: a credential issued before `credentialStatus` was emitted cannot
    be revoked, and that must not break issuance of the new one.
    """
    revoked: list[str] = []
    for enveloped in await well_known_badges(client, identity_node_url, subject_id):
        jws = enveloped.get("value") or ""
        if not jws or jws == keep_jws:
            continue
        try:
            await revoke_badge(client, identity_node_url, cfg, jws, subject_id)
            revoked.append(_credential_id(jws))
        except VcError:
            continue
    return revoked


def _credential_id(jws: str) -> str:
    parts = jws.split(".")
    if len(parts) != 3:
        return ""
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(_b64url_decode(padded)).get("id", "")
    except Exception:  # noqa: BLE001
        return ""


async def verify_badge(client: httpx.AsyncClient, identity_node_url: str, jws: str) -> dict:
    """Ask the Identity Node to verify signature, timestamps and proofs.

    Returns the raw VerificationResult: {"status": bool, "document": {...}}.
    """
    r = await client.post(
        f"{identity_node_url.rstrip('/')}/v1alpha1/vc/verify",
        json={"vc": {"envelopeType": ENVELOPE_JOSE, "value": jws}},
    )
    if r.status_code != 200:
        raise VcError("vc/verify", r.status_code, r.text)
    return r.json()


async def well_known_badges(
    client: httpx.AsyncClient, identity_node_url: str, subject_id: str
) -> list[dict]:
    """The publicly resolvable credentials for an id — what a relying party fetches."""
    r = await client.get(
        f"{identity_node_url.rstrip('/')}/v1alpha1/vc/{subject_id}/.well-known/vcs.json"
    )
    if r.status_code != 200:
        raise VcError("vc/.well-known", r.status_code, r.text)
    return r.json().get("vcs", []) or []


def _subject_matches(credential: dict, *, subject_id: str, caps: list[str],
                     delegating_user: str, intent: str,
                     delegatable: list[str] | None = None) -> bool:
    subject = (credential.get("credentialSubject") or {})
    return (
        subject.get("id") == subject_id
        and list(subject.get("caps") or []) == list(caps)
        and list(subject.get("delegatable") or []) == list(delegatable or [])
        and subject.get("delegating_user") == delegating_user
        and subject.get("intent") == intent
    )


def _still_valid(credential: dict) -> bool:
    """Check expiry ourselves — the node serves expired credentials from
    .well-known and /vc/verify returns status=true for them, so temporal
    validity is the caller's responsibility."""
    expires = credential.get("expirationDate")
    if not expires:
        return True
    try:
        return time.time() < time.mktime(time.strptime(expires, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return False


async def find_live_badge(
    client: httpx.AsyncClient,
    identity_node_url: str,
    *,
    subject_id: str,
    caps: list[str],
    delegating_user: str,
    intent: str,
    delegatable: list[str] | None = None,
) -> str | None:
    """The agent's current, still-valid credential for this grant, if any.

    Returns its JOSE envelope so the caller can present the *same* credential
    rather than minting another. One identity should resolve to one live
    credential; a relying party fetching .well-known must not have to guess
    which of several contradictory entries is current.
    """
    for enveloped in await well_known_badges(client, identity_node_url, subject_id):
        jws = enveloped.get("value") or ""
        parts = jws.split(".")
        if len(parts) != 3:
            continue
        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            credential = json.loads(_b64url_decode(padded))
        except Exception:  # noqa: BLE001
            continue
        if _still_valid(credential) and _subject_matches(
            credential, subject_id=subject_id, caps=caps,
            delegating_user=delegating_user, intent=intent, delegatable=delegatable,
        ):
            return jws
    return None


def _b64url_decode(segment: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(segment)


async def issue_badge(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cfg: VaultConfig,
    *,
    subject_id: str,
    caps: list[str],
    delegating_user: str,
    intent: str,
    act_chain: list[str],
    delegatable: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> dict:
    """Return this agent's live credential, issuing one only if none exists.

    One identity, one live credential. Re-publishing per task would leave
    .well-known serving a growing pile of valid, mutually contradictory
    answers to "what may this agent do?" — and since credentials are currently
    issued without a `credentialStatus`, the node refuses to revoke them, so
    that pile would be permanent. Per-task narrowing is carried by the ID-JAG
    assertion, which is what the policy layer actually enforces.
    """
    existing = await find_live_badge(
        client, identity_node_url,
        subject_id=subject_id, caps=caps, delegating_user=delegating_user, intent=intent,
        delegatable=delegatable,
    )
    if existing is not None:
        result = await verify_badge(client, identity_node_url, existing)
        return {
            "badge": existing,
            "credential_id": (result.get("document") or {}).get("id", ""),
            "issuer": cfg.issuer,
            "verified": bool(result.get("status")),
            "document": result.get("document", {}),
            "reused": True,
            "superseded": [],
        }

    credential = build_badge_credential(
        cfg,
        subject_id=subject_id,
        caps=caps,
        delegating_user=delegating_user,
        intent=intent,
        act_chain=act_chain,
        delegatable=delegatable,
        ttl_seconds=ttl_seconds,
    )
    jws = await sign_credential(client, cfg, credential)
    await publish_badge(client, identity_node_url, cfg, jws, subject_id)
    # Supersede-on-issue is intentionally NOT called: see build_badge_credential.
    # Credentials issued on this node version cannot be both live and
    # revocable, so revoking the predecessor is impossible. publish-once keeps
    # .well-known to a single live credential per grant in the meantime.
    superseded: list[str] = []
    result = await verify_badge(client, identity_node_url, jws)
    return {
        "badge": jws,
        "credential_id": credential["id"],
        "issuer": credential["issuer"],
        "verified": bool(result.get("status")),
        "document": result.get("document", {}),
        "reused": False,
        "superseded": superseded,
    }
