# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
"""Opt-in live smoke test; run inside a configured demo service image.

Uses a dedicated agent identity and unique records. Requires real Vault,
Identity Node, Directory, and the external verifier. Prints no tokens or keys.
"""

import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timezone

import httpx

from agntcy_identity_client import VaultConfig, cimd, directory, native_claims, vc
from agntcy_identity_client.vault import b64url, vault_sign_rs256


async def run():
    address = os.environ["DIR_APISERVER_URL"]
    node = os.environ["IDENTITY_NODE_URL"]
    cfg = VaultConfig.from_env()
    async with httpx.AsyncClient(timeout=15) as client:
        identity = await cimd.generate_id(client, node, cfg, "directory-native-smoke")
        subject_id = identity["id"]
        subject = "agntcy://" + subject_id
        record = directory.build_agent_record("security-autonomous-agent", node, identity_id=subject_id)
        record["name"] = "example.com/native-smoke-" + uuid.uuid4().hex
        issued = await vc.issue_badge(
            client, node, cfg, subject_id=subject_id, caps=["scan"],
            delegating_user="native-smoke", intent="verify-directory-identity",
            act_chain=[], agent_definition=record, ttl_seconds=600,
        )
        positive = issued["directory_identity"]
        if not positive["verified"] or not positive["verified_search"]:
            raise AssertionError(f"positive verification failed: {positive}")

        # One Agent ID cannot reuse its valid badge for a different record CID.
        other = {**record, "name": record["name"] + "-mismatch"}
        cid = await asyncio.to_thread(directory.push_record, address, other)
        signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        header = b64url(b'{"alg":"RS256"}')
        signature = await vault_sign_rs256(
            client, cfg, header + "." + b64url(native_claims.canonical_payload(cid, subject, signed_at)),
        )
        await asyncio.to_thread(native_claims.push_claim, address, {
            "role": native_claims.CLAIM_ROLE, "recordCid": cid, "subject": subject,
            "signedAt": signed_at, "signature": header + ".." + signature,
        })
        deadline = time.monotonic() + 60
        negative = {}
        while time.monotonic() < deadline:
            negative = await asyncio.to_thread(native_claims.identity_status, address, cid)
            if negative["status"] == "failed":
                break
            await asyncio.sleep(2)
        if negative.get("status") != "failed":
            raise AssertionError(f"mismatched badge was not rejected: {negative}")
        matches = await asyncio.to_thread(
            native_claims.identity_cids, address, other["name"], subject, verified=True,
        )
        if cid in matches:
            raise AssertionError("mismatched record appeared in verified search")
        print(json.dumps({"positive": positive, "badge_mismatch": negative}, indent=2))


if __name__ == "__main__":
    asyncio.run(run())
