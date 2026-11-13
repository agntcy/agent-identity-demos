# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Native Directory identity claims, signed with the agent's Vault Transit key.

The badge remains in Identity Node. Directory stores the detached claim as an
OCI referrer and independently checks it through the external verifier.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone

import httpx

from . import VaultConfig, directory
from .vault import b64url, vault_sign_rs256

CLAIM_TYPE = "agntcy.dir.identity.v1.IdentityClaim"
CLAIM_ROLE = "CLAIM_ROLE_IDENTITY"


def canonical_payload(cid: str, subject: str, signed_at: str) -> bytes:
    # This field order and the explicit empty expiry match Claim.GetPayload.
    return json.dumps({
        "record_cid": cid,
        "role": CLAIM_ROLE,
        "subject": subject,
        "signed_at": signed_at,
        "expires_at": "",
    }, separators=(",", ":")).encode()


def push_claim(address: str, claim: dict) -> None:
    import grpc
    from agntcy.dir.core.v1 import record_pb2
    from agntcy.dir.store.v1 import store_service_pb2, store_service_pb2_grpc
    from google.protobuf.struct_pb2 import Struct

    data = Struct()
    data.update(claim)
    request = store_service_pb2.PushReferrerRequest(
        record_ref=record_pb2.RecordRef(cid=claim["recordCid"]),
        type=CLAIM_TYPE, created_at=claim["signedAt"], data=data,
    )
    with grpc.insecure_channel(address) as channel:
        responses = list(store_service_pb2_grpc.StoreServiceStub(channel).PushReferrer(
            iter([request]), timeout=15,
        ))
    if len(responses) != 1 or not responses[0].success:
        reason = responses[0].error_message if responses else "no response"
        raise RuntimeError(f"Directory rejected native claim: {reason}")


def identity_status(address: str, cid: str) -> dict:
    import grpc
    from agntcy.dir.identity.v1 import identity_service_pb2 as messages
    from agntcy.dir.identity.v1 import identity_service_pb2_grpc as service

    with grpc.insecure_channel(address) as channel:
        response = service.IdentityServiceStub(channel).GetIdentityStatus(
            messages.GetIdentityStatusRequest(cid=cid), timeout=5,
        )
    if not response.HasField("identity"):
        return {"cid": cid, "status": "pending", "verified": False}
    result = response.identity
    verified = result.status == messages.CLAIM_VERIFICATION_STATUS_VERIFIED
    return {
        "cid": cid, "subject": result.subject,
        "status": "verified" if verified else "failed", "verified": verified,
        "verified_at": result.verified_at.ToJsonString(), "error": result.error,
    }


def identity_cids(address: str, name: str, subject: str, *, verified: bool = False) -> list[str]:
    import grpc
    from agntcy.dir.search.v1 import search_service_pb2 as messages
    from agntcy.dir.search.v1 import search_service_pb2_grpc as service

    queries = [
        messages.RecordQuery(type=messages.RECORD_QUERY_TYPE_NAME, value=name),
        messages.RecordQuery(type=messages.RECORD_QUERY_TYPE_IDENTITY, value=subject),
    ]
    if verified:
        queries.append(messages.RecordQuery(
            type=messages.RECORD_QUERY_TYPE_IDENTITY_VERIFIED, value="true",
        ))
    with grpc.insecure_channel(address) as channel:
        responses = service.SearchServiceStub(channel).SearchCIDs(
            messages.SearchCIDsRequest(queries=queries, limit=100), timeout=5,
        )
        return [response.record_cid for response in responses]


async def publish_and_verify(
    client: httpx.AsyncClient, cfg: VaultConfig, address: str,
    record: dict, subject_id: str,
) -> dict:
    subject = "agntcy://" + subject_id
    if record.get("annotations", {}).get("agntcy.dir/identity") != subject:
        raise ValueError("native claim subject must match the record identity annotation")
    cid = await asyncio.to_thread(directory.push_record, address, record)
    if not cid:
        raise RuntimeError("Directory returned no record CID")

    # An already verified immutable record can reuse its stored native claim.
    status = await asyncio.to_thread(identity_status, address, cid)
    if not status["verified"]:
        signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        header = b64url(b'{"alg":"RS256"}')
        payload = b64url(canonical_payload(cid, subject, signed_at))
        signature = await vault_sign_rs256(client, cfg, header + "." + payload)
        await asyncio.to_thread(push_claim, address, {
            "role": CLAIM_ROLE, "recordCid": cid, "subject": subject,
            "signedAt": signed_at, "signature": header + ".." + signature,
        })

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = await asyncio.to_thread(identity_status, address, cid)
        if status["verified"]:
            matches = await asyncio.to_thread(
                identity_cids, address, record["name"], subject, verified=True,
            )
            if cid in matches:
                return {**status, "verified_search": True}
        await asyncio.sleep(2)
    raise TimeoutError(f"Directory native identity verification did not complete: {status}")
