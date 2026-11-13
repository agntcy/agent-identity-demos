# Copyright 2026 AGNTCY Contributors
# SPDX-License-Identifier: Apache-2.0
"""A small demo driver for two existing workload identities; no remediation calls."""
import asyncio
from datetime import datetime, timezone
import json
import os
import httpx
import jwt
from agntcy_identity_client import VaultConfig, cimd, directory, native_claims, vc

RUN_LOCK = asyncio.Lock()


def event(step, state, detail, **evidence):
    return json.dumps({"step": step, "state": state, "detail": detail, "evidence": evidence}) + "\n"


async def login(client, base, realm, client_id, secret):
    endpoint = f"{base}/realms/{realm}/protocol/openid-connect/token"
    response = await client.post(endpoint, data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})
    response.raise_for_status()
    token = response.json()["access_token"]
    discovery = await client.get(f"{base}/realms/{realm}/.well-known/openid-configuration")
    discovery.raise_for_status()
    keys = await client.get(f"{base}/realms/{realm}/protocol/openid-connect/certs")
    keys.raise_for_status()
    header = jwt.get_unverified_header(token)
    jwk = next((k for k in keys.json()["keys"] if k.get("kid") == header.get("kid") and k.get("use", "sig") == "sig"), None)
    if jwk is None:
        raise ValueError("Keycloak signing key was not found")
    claims = jwt.decode(token, jwt.PyJWK.from_dict(jwk).key, algorithms=["RS256"], issuer=discovery.json()["issuer"], options={"verify_aud": False, "require": ["exp", "iat", "iss", "sub", "azp"]})
    # This proves token issuance for this workload; it grants no downstream API access.
    if claims.get("azp") != client_id or claims.get("preferred_username") != "service-account-" + client_id:
        raise ValueError("Keycloak token names an unexpected workload identity")
    return {"client": client_id, "realm": realm, "signature_verified": True, "expires_at": claims["exp"]}



async def run():
    if RUN_LOCK.locked():
        yield event(-1, "error", "A demo is already running. Please wait for it to finish.")
        return
    async with RUN_LOCK:
        step = 0
        node = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
        address = os.environ.get("DIR_APISERVER_URL", "")
        pub = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")
        con = os.environ.get("SECURITY_AUTONOMOUS_AGENT_CLIENT_ID", "security-autonomous-agent")
        cfg_a = VaultConfig.from_env()
        cfg_b = VaultConfig(cfg_a.vault_addr, cfg_a.vault_token, "org-b-issuer", "org-b")
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                yield event(step, "running", "Publisher agent authenticates with Keycloak")
                auth = await login(client, os.environ.get("KC_B_URL", "http://keycloak-b:8080"), os.environ.get("KC_B_REALM", "org-b"), pub, os.environ.get("TRIAGE_CLIENT_SECRET", ""))
                yield event(step, "ok", "Keycloak confirmed the publisher workload", **auth)
                step = 1
                yield event(step, "running", "Registering and resolving the publisher identity")
                identity = await cimd.generate_id(client, node, cfg_b, pub)
                publisher_id = identity["id"]
                resolved = await cimd.resolve_id(client, node, publisher_id)
                if resolved.get("id") != publisher_id:
                    raise ValueError("Resolved publisher identity does not match")
                yield event(step, "ok", "Publisher identity resolved with public verification material", identity=publisher_id, reused=identity["already_registered"])
                step = 2
                yield event(step, "running", "Publishing a Vault-signed Agent Badge")
                record = directory.build_agent_record(pub, node, identity_id=publisher_id)
                args = dict(subject_id=publisher_id, caps=["directory:publish"], delegating_user="service-account-" + pub, intent="Publish a discoverable agent identity", delegatable=[], agent_definition=record)
                badge = await vc.find_live_badge(client, node, **args)
                reused = badge is not None
                if not badge:
                    credential = vc.build_badge_credential(cfg_b, **args, act_chain=[], ttl_seconds=3600)
                    badge = await vc.sign_credential(client, cfg_b, credential)
                    await vc.publish_badge(client, node, cfg_b, badge, publisher_id)
                checked = await vc.verify_badge(client, node, badge)
                if not checked.get("status"):
                    raise ValueError("Identity Node rejected the publisher badge")
                yield event(step, "ok", "Identity verified the badge for this exact agent description", identity=publisher_id, badge_verified=True, reused=reused, signer="Vault Transit / org-b-issuer")
                step = 3
                yield event(step, "running", "Publishing the record and claim; waiting for Directory verification")
                status = await native_claims.publish_and_verify(client, cfg_b, address, record, publisher_id)
                if not status.get("verified") or not status.get("verified_search"):
                    raise ValueError("Directory has not verified the identity claim")
                yield event(step, "ok", "Directory confirmed the identity claim through its verifier", **status)
                step = 4
                yield event(step, "running", "Consumer agent authenticates and resolves its own identity")
                auth = await login(client, os.environ.get("KC_A_URL", "http://keycloak-a:8080"), os.environ.get("KC_A_REALM", "org-a"), con, os.environ.get("SECURITY_AUTONOMOUS_AGENT_CLIENT_SECRET", ""))
                consumer = await cimd.generate_id(client, node, cfg_a, con)
                consumer_metadata = await cimd.resolve_id(client, node, consumer["id"])
                if consumer_metadata.get("id") != consumer["id"]:
                    raise ValueError("Resolved consumer identity does not match")
                yield event(step, "ok", "Consumer is ready to discover a verified publisher", identity=consumer["id"], **auth)
                step = 5
                yield event(step, "running", "Consumer searches Directory for the verified publisher")
                cids = await asyncio.to_thread(native_claims.identity_cids, address, record["name"], "agntcy://" + publisher_id, verified=True)
                if status["cid"] not in cids:
                    raise ValueError("Publisher is absent from verified search")
                records = await asyncio.to_thread(directory.search_agents_by_name, address, record["name"])
                found = next((r for r in records if directory.canonical_oasf(r) == directory.canonical_oasf(record)), None)
                if found is None:
                    raise ValueError("Directory did not return the matching canonical record")
                yield event(step, "ok", "Consumer found the publisher in verified search", cid=status["cid"], publisher=publisher_id, annotations=found["annotations"])
                step = 6
                yield event(step, "running", "Consumer retrieves and verifies the publisher's badge")
                retrieved = await vc.find_live_badge(client, node, **{**args, "agent_definition": found})
                if not retrieved:
                    raise ValueError("No current badge matches the discovered record")
                checked = await vc.verify_badge(client, node, retrieved)
                document = checked.get("document") or {}
                subject = document.get("content") or document.get("credentialSubject") or {}
                expires = datetime.fromisoformat(document["expirationDate"].replace("Z", "+00:00"))
                if expires <= datetime.now(timezone.utc):
                    raise ValueError("Publisher badge has expired")
                if not checked.get("status") or subject.get("id") != publisher_id or directory.canonical_oasf(subject.get("badge") or {}) != directory.canonical_oasf(found):
                    raise ValueError("Publisher badge failed identity or record binding checks")
                latest = await asyncio.to_thread(native_claims.identity_status, address, status["cid"])
                if not latest.get("verified"):
                    raise ValueError("Directory verification is no longer valid")
                yield event(step, "ok", "Consumer verified the discovered publisher and matching record", publisher=publisher_id, consumer=consumer["id"], cid=status["cid"], badge_verified=True, verified_at=latest.get("verified_at"))
                yield event(step, "complete", "Agent A discovered and verified Agent B", publisher=publisher_id, consumer=consumer["id"], cid=status["cid"])
        except Exception as exc:
            # Do not return response bodies, tokens or credentials to the browser.
            if isinstance(exc, httpx.HTTPStatusError):
                detail = f"Service returned HTTP {exc.response.status_code}; see server logs for diagnosis."
            else:
                detail = str(exc)[:250] if isinstance(exc, (ValueError, TimeoutError)) else f"{type(exc).__name__}: service operation failed."
            yield event(step, "error", detail)
