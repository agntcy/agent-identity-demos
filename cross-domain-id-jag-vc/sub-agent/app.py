# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Sub-Agent (Org B) — bounded-privilege agent with its own identity lifecycle.

Spawned by Triage with a narrowed sub-badge, and follows the same lifecycle
OpenCode (Org A) and Triage (Org B) do: verify inbound credentials → register
own identity → work under the credential policy allows → record the turn.

Run lifecycle (POST /api/run):
  s1   Verify the sub-badge ITSELF against Keycloak B's JWKS before redeeming
       it — signature, issuer, audience, typ, target client, act-chain, scope,
       signed resource and intent. Fail closed: a badge that doesn't verify is
       never presented to Keycloak B.
  s2   Sub-Agent registers ITS OWN identity: CIMD generate/resolve
       AGNTCY-sub-agent at the Identity Node under the org-b trust authority
       (Vault-signed proof — the same authority that attests Triage)
  s3   jwt-bearer exchange (assertion=sub-badge) → Keycloak B access token
       carrying gitea:write gitea:pr and nothing else
  s4   Carry both credentials (access token + original sub-badge) to the
       Org B resource boundary
  s5   The work: push the fix, open the PR, and demonstrate that policy beats
       scope on a deny-listed repo — all through Envoy + inline OPA
  s6   Push its own turn record to the AGNTCY Directory → CID
  s7   PR created ✓ — causal audit: Sarah → OpenCode → Triage → Sub-Agent

The sub-badge carries a nested act-chain: Sarah → OpenCode → Triage → Sub-Agent.
Any hop deeper than the parent's delegation depth is refused by the policy layer.
"""

from __future__ import annotations

import asyncio
import os
import secrets

import httpx
import jwt as pyjwt
from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import cimd as cimd_api
from agntcy_identity_client import directory as dir_api
from agntcy_identity_client import vc as vc_api
from tracing import setup_tracing, step_span
from fastapi.responses import JSONResponse
from pydantic import BaseModel

KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")
SUB_AGENT_CLIENT_ID = os.environ.get("SUB_AGENT_CLIENT_ID", "sub-agent")
SUB_AGENT_CLIENT_SECRET = os.environ.get("SUB_AGENT_CLIENT_SECRET", "")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
GITEA_GATEWAY_URL = os.environ.get(
    "GITEA_GATEWAY_URL", "http://envoy-org-b:10001"
).rstrip("/")
GITEA_ADMIN_USER = os.environ.get("GITEA_ADMIN_USER", "demo-admin")

# The only scopes this agent may ever hold. The sub-badge is refused if it
# grants anything outside this set — a narrowing bug upstream (or a forged
# wider badge) is caught here, not just at the gateway.
ALLOWED_SCOPES = {"openid", "gitea:write", "gitea:pr"}
ID_JAG_TYP = "oauth-id-jag+jwt"

VAULT_CFG = VaultConfig.from_env()  # org-b trust authority (ORG_COMMON_NAME=org-b)

KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"
KC_B_TOKEN_EP = f"{KC_B_ISSUER}/protocol/openid-connect/token"
KC_B_JWKS_URL = f"{KC_B_ISSUER}/protocol/openid-connect/certs"

app = FastAPI(title="Sub-Agent (Org B) — identity lifecycle", version="0.2.0")
setup_tracing("sub-agent")
FastAPIInstrumentor.instrument_app(app)

_jwks_client: pyjwt.PyJWKClient | None = None


def _get_jwks_client() -> pyjwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = pyjwt.PyJWKClient(KC_B_JWKS_URL, cache_keys=True)
    return _jwks_client


class RunRequest(BaseModel):
    sub_badge: str
    repo: str = "demo-admin/payments-service"
    intent: str = "create-pr-fix"
    act_chain: list[str] = []
    ticket_id: str = ""


@app.get("/health")
def health():
    return {"status": "ok", "agent": "sub-agent", "realm": KC_B_REALM}


@app.get("/api/config")
def config():
    return {
        "kc_b": KC_B_URL, "kc_b_realm": KC_B_REALM,
        "sub_agent_client": SUB_AGENT_CLIENT_ID,
        "identity_node": IDENTITY_NODE_URL,
        "dir_apiserver": DIR_APISERVER_URL or "not configured",
        "gitea_gateway": GITEA_GATEWAY_URL,
        "vault_key_name": VAULT_CFG.key_name,
        "org_common_name": VAULT_CFG.common_name,
    }


def _decode_jwt_payload_unverified(token: str) -> dict:
    """Decode a JWT's payload for display only — no signature check. Used
    purely so the webapp's step toast has claims to show; never used for a
    trust decision (this token is independently, cryptographically verified
    server-side — Keycloak B issued it, and Envoy validates it against
    Keycloak B's JWKS at the resource boundary next)."""
    import base64
    import json

    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return {}


def _expected_outcome(step: dict) -> bool:
    if step.get("id") == "denied-pr-attempt":
        return step.get("status") == "denied"
    return step.get("status") == "ok"


def _verify_subbadge_sync(token: str, body: RunRequest) -> dict:
    """Verify the inbound sub-badge against Keycloak B's JWKS + delegation claims.

    Raises on any failure; returns the verified claims. Sync (PyJWKClient uses
    urllib) — call via executor.

    Note on `sub`: Keycloak B mints the sub-badge from the inbound
    Sarah-federated access token, so `sub` is a KC-B user id rather than
    sarah@org-a.example. It must be present, but its exact value isn't pinned.
    """
    header = pyjwt.get_unverified_header(token)
    if header.get("typ") != ID_JAG_TYP:
        raise ValueError(f"not an ID-JAG assertion: typ={header.get('typ')}")

    signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
    claims = pyjwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=KC_B_ISSUER,
        issuer=KC_B_ISSUER,
        options={"require": ["exp", "iat", "aud", "iss", "sub"]},
    )

    # The badge must be addressed to THIS agent.
    if claims.get("client_id") != SUB_AGENT_CLIENT_ID:
        raise ValueError(f"sub-badge targets {claims.get('client_id')}, not {SUB_AGENT_CLIENT_ID}")

    # The signed chain is the parent chain; this agent is the hop being added.
    act = claims.get("act") or {}
    signed_chain = act.get("act_chain") or []
    if not body.act_chain or body.act_chain[-1] != SUB_AGENT_CLIENT_ID:
        raise ValueError("spawn act_chain does not end at this agent")
    if signed_chain != body.act_chain[:-1]:
        raise ValueError(
            f"act_chain mismatch: signed {signed_chain} vs spawn {body.act_chain[:-1]}"
        )

    # Narrowing must have actually happened: no scope beyond what this agent
    # is ever allowed to hold (in particular, no triage:create).
    granted = {s for s in (claims.get("scope") or "").split(" ") if s}
    if not granted:
        raise ValueError("sub-badge carries no scope")
    if not granted <= ALLOWED_SCOPES:
        raise ValueError(f"sub-badge grants scopes outside this agent's bound: {sorted(granted - ALLOWED_SCOPES)}")

    # The badge is bound to a repository and an intent — both must cover the
    # work this agent was actually spawned to do.
    resources = claims.get("resource") or []
    if body.repo not in resources:
        raise ValueError(f"repo {body.repo} is not in the sub-badge's signed resource {resources}")
    if body.intent not in (claims.get("intent") or []):
        raise ValueError("spawn intent not present in the sub-badge's signed intent")

    return claims


async def _cimd_register(client: httpx.AsyncClient) -> list[dict]:
    """s2 — Sub-Agent registers its own identity under the org-b trust authority."""
    steps: list[dict] = []
    s: dict = {
        "id": "cimd-generate-id",
        "title": f"s2. Sub-Agent registers its identity — generate id for {SUB_AGENT_CLIENT_ID} "
                 f"(Vault-signed proof, {VAULT_CFG.common_name} trust authority) → Identity Node",
        "detail": f"POST {IDENTITY_NODE_URL}/v1alpha1/id/generate  iss={VAULT_CFG.issuer}  sub={SUB_AGENT_CLIENT_ID}",
    }
    res = None
    try:
        res = await cimd_api.generate_id(client, IDENTITY_NODE_URL, VAULT_CFG, SUB_AGENT_CLIENT_ID)
        result: dict = {"id": res["id"]}
        if res["already_registered"]:
            result["note"] = "already registered"
        else:
            result["controller"] = res["controller"]
        s.update(status="ok", result=result)
        steps.append(s)
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
        steps.append(s)
        return steps

    cimd_id = res["id"] or f"AGNTCY-{SUB_AGENT_CLIENT_ID}"
    s = {
        "id": "cimd-resolve-id",
        "title": f"s2b. Resolve id {cimd_id} → ResolverMetadata + JWK",
        "detail": f"POST {IDENTITY_NODE_URL}/v1alpha1/id/resolve  id={cimd_id}",
    }
    try:
        rm = await cimd_api.resolve_id(client, IDENTITY_NODE_URL, cimd_id)
        vm = (rm.get("verificationMethod") or [{}])[0]
        s.update(status="ok", result={
            "id": rm.get("id", ""),
            "controller": rm.get("controller", ""),
            "verification_method_id": vm.get("id", ""),
            "public_key_kid": (vm.get("publicKeyJwk") or {}).get("kid", ""),
        })
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    steps.append(s)
    return steps


async def _dir_push_turn(body: RunRequest, branch: str, pr_url: str) -> dict:
    s: dict = {
        "id": "dir-push",
        "title": "s6. Directory: push Sub-Agent turn record (OASF) → CID",
        "detail": f"gRPC Push({DIR_APISERVER_URL})  ticket={body.ticket_id}",
    }
    if not DIR_APISERVER_URL:
        s.update(status="ok", result={"cid": "", "note": "directory not configured"})
        return s
    try:
        from datetime import datetime, timezone
        record_dict = {
            "name": "sub-agent",
            "version": "0.2.0",
            "schema_version": dir_api.OASF_SCHEMA_VERSION,
            "description": f"Sub-agent turn: {body.intent} on {body.repo} (ticket {body.ticket_id})",
            "authors": ["cross-domain-demo"],
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "skills": [
                {"name": "software_engineering/code_quality/code_review", "id": 60701},
            ],
            "domains": [
                {"name": "technology/security", "id": 107},
            ],
            "annotations": {
                "repo": body.repo,
                "ticket": body.ticket_id,
                "branch": branch,
                "pull_request": pr_url,
                "act_chain": " → ".join(body.act_chain),
                "turn": "sub-agent",
            },
        }
        cid = await asyncio.get_event_loop().run_in_executor(
            None, dir_api.push_record, DIR_APISERVER_URL, record_dict
        )
        s.update(status="ok", result={"cid": cid, "agent": "sub-agent"})
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    return s


@app.post("/api/run")
async def run(body: RunRequest):
    """Drive the Sub-Agent lifecycle: verify → register identity → redeem → work."""
    steps: list[dict] = []

    # Parse owner/repo from the full_name passed by Triage
    parts = body.repo.split("/", 1)
    owner = parts[0] if len(parts) == 2 else GITEA_ADMIN_USER
    repo_slug = parts[1] if len(parts) == 2 else body.repo
    branch = f"sub-agent/fix-{secrets.token_hex(3)}"

    # ── s1: verify the sub-badge BEFORE redeeming it ───────────────────────
    # Envoy will verify it again at the resource boundary, but this agent
    # doesn't hand an unverified assertion to Keycloak B in the first place —
    # the same defense-in-depth check Triage does on the inbound ID-JAG.
    s: dict = {
        "id": "verify-subbadge",
        "title": "s1. Sub-Agent verifies the sub-badge itself — signature vs Keycloak B JWKS + narrowing claims",
        "detail": f"JWKS {KC_B_JWKS_URL}  expect iss={KC_B_ISSUER}  client_id={SUB_AGENT_CLIENT_ID}",
    }
    with step_span("verify-subbadge"):
        if not body.sub_badge:
            s.update(status="error", error="no sub_badge supplied — nothing to verify or redeem")
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps})
        try:
            claims = await asyncio.get_event_loop().run_in_executor(
                None, _verify_subbadge_sync, body.sub_badge, body
            )
            s.update(status="ok", result={
                "iss": claims.get("iss"),
                "client_id": claims.get("client_id"),
                "scope": claims.get("scope"),
                "resource": claims.get("resource"),
                "intent": claims.get("intent"),
                "act_chain": (claims.get("act") or {}).get("act_chain", []),
                "note": (
                    "verified in-agent against Keycloak B's JWKS, independently of Envoy — "
                    "narrowing confirmed (no triage:create) and bound to this repo"
                ),
            })
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=f"in-agent sub-badge verification failed: {exc}")
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps})
    steps.append(s)

    async with httpx.AsyncClient(timeout=20) as client:

        # ── s2: register own identity (org-b trust authority) ──────────────
        with step_span("cimd-register"):
            cimd_steps = await _cimd_register(client)
        steps.extend(cimd_steps)
        if any(cs.get("status") == "error" for cs in cimd_steps):
            return JSONResponse({"ok": False, "steps": steps})
        sub_cimd_id = next(
            (cs["result"]["id"] for cs in cimd_steps
             if cs.get("id") == "cimd-generate-id" and (cs.get("result") or {}).get("id")),
            f"AGNTCY-{SUB_AGENT_CLIENT_ID}",
        )

        # ── s2c: publish the Sub-Agent's own agent badge ───────────────────
        # The leaf of the chain gets a resolvable credential too: anyone can
        # ask the Identity Node what this agent is permitted to do, rather
        # than that being knowable only from a token in flight.
        s = {
            "id": "resolve-badge",
            "title": f"s2c. Publish Sub-Agent's agent badge VC (caps from the verified sub-badge) — org-b Vault-signed",
            "detail": f"POST {IDENTITY_NODE_URL}/v1alpha1/vc/publish  issuer={VAULT_CFG.issuer}  subject={sub_cimd_id}",
        }
        with step_span("resolve-badge"):
            try:
                granted = [c for c in str(claims.get("scope") or "").split(" ") if c]
                issued = await vc_api.issue_badge(
                    client, IDENTITY_NODE_URL, VAULT_CFG,
                    subject_id=sub_cimd_id,
                    caps=granted,
                    # The leaf of the chain: it delegates to nobody, and the
                    # credential states that rather than leaving it implied.
                    delegatable=[],
                    delegating_user="sarah@org-a.example",
                    intent=body.intent,
                    act_chain=body.act_chain,
                )
                s.update(status="ok" if issued["verified"] else "error", result={
                    "credential_id": issued["credential_id"],
                    "issuer": issued["issuer"],
                    "reused_existing_credential": issued.get("reused", False),
                    "verified_by": "identity-node /v1alpha1/vc/verify",
                    "well_known": f"{IDENTITY_NODE_URL}/v1alpha1/vc/{sub_cimd_id}/.well-known/vcs.json",
                    "claims": issued["document"],
                })
                if not issued["verified"]:
                    s["error"] = "identity-node reported the published badge as invalid"
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)
        if s.get("status") == "error":
            return JSONResponse({"ok": False, "steps": steps})

        # ── s2d: resolve the SENDER's credential ───────────────────────────
        # Triage handed us an assertion; the Identity Node independently says
        # what Triage is authorised to do. Require the two to agree.
        #
        # What this can honestly prove: org-b issued a credential about the
        # identifier Triage claims, and its act-chain is the prefix of ours.
        # What it CANNOT prove: that the process we spoke to holds that
        # identifier's key — CIMD registers no per-agent keypair, so every
        # org-b agent resolves to the same org key. Process-to-identity
        # binding comes from Keycloak client credentials, not from here.
        parent_id = f"AGNTCY-{body.act_chain[-2]}" if len(body.act_chain) >= 2 else ""
        s = {
            "id": "verify-sender-badge",
            "title": f"s2d. Resolve the delegating agent's credential ({parent_id}) and check it agrees with the sub-badge",
            "detail": f"GET {IDENTITY_NODE_URL}/v1alpha1/vc/{parent_id}/.well-known/vcs.json",
        }
        with step_span("verify-sender-badge"):
            try:
                sender_vcs = await vc_api.well_known_badges(client, IDENTITY_NODE_URL, parent_id)
                sender = None
                for enveloped in sender_vcs:
                    doc = _decode_jwt_payload_unverified(enveloped.get("value", ""))
                    if doc.get("credentialSubject", {}).get("id") == parent_id:
                        sender = doc
                        break
                if sender is None:
                    raise ValueError(f"{parent_id} has no resolvable credential")
                sender_subject = sender.get("credentialSubject", {})
                sender_chain = list(sender_subject.get("act_chain") or [])
                # The sender's chain must be exactly our chain minus this hop.
                if sender_chain != body.act_chain[:-1]:
                    raise ValueError(
                        f"delegating agent's credential says act_chain={sender_chain}, "
                        f"but the sub-badge we hold says {body.act_chain[:-1]}"
                    )
                # It must not contradict the assertion: the sender cannot have
                # granted us authority it does not itself hold.
                # Compare against what the sender may DELEGATE, not what it
                # holds: Triage acts under triage:create while granting
                # gitea:write/pr. Conflating the two would reject every
                # legitimate narrowing.
                may_delegate = {c for c in (sender_subject.get("delegatable") or [])}
                ours = {c for c in str(claims.get("scope") or "").split(" ") if c}
                if not ours <= may_delegate:
                    raise ValueError(
                        f"sub-badge grants {sorted(ours - may_delegate)} which the delegating "
                        f"agent's credential does not permit it to delegate"
                    )
                s.update(status="ok", result={
                    "delegating_agent": parent_id,
                    "credential_issuer": sender.get("issuer"),
                    "credential_caps": sorted(sender_subject.get("caps") or []),
                    "credential_delegatable": sorted(may_delegate),
                    "credential_act_chain": sender_chain,
                    "note": "the credential agrees with the assertion; this is not proof of "
                            "possession — CIMD registers no per-agent key",
                })
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)
        if s.get("status") == "error":
            return JSONResponse({"ok": False, "steps": steps})

        # ── s3: jwt-bearer exchange at Keycloak B ──────────────────────────
        s = {
            "id": "kc-b-exchange",
            "title": (
                "s3. jwt-bearer exchange (assertion=verified sub-badge) → Keycloak B"
                f"  [act_chain={body.act_chain}]"
            ),
            "detail": f"POST {KC_B_TOKEN_EP}  client={SUB_AGENT_CLIENT_ID}  scope=gitea:write gitea:pr",
        }
        with step_span("kc-b-exchange"):
            try:
                r = await client.post(KC_B_TOKEN_EP, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": body.sub_badge,
                    "client_id": SUB_AGENT_CLIENT_ID,
                    "client_secret": SUB_AGENT_CLIENT_SECRET,
                    "scope": "openid gitea:write gitea:pr",
                })
                if r.status_code == 200:
                    access_token = r.json()["access_token"]
                    s.update(status="ok", token_preview=access_token[:48] + "…", token=access_token,
                             result={"claims": _decode_jwt_payload_unverified(access_token)})
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                    steps.append(s)
                    return JSONResponse({"ok": False, "steps": steps})
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps})
        steps.append(s)

        # ── s4: carry both credentials to the resource boundary ───────────
        with step_span("idjag-gitea"):
            steps.append({
                "id": "idjag-gitea",
                "title": "s4. Resource credentials — scoped access token + verified sub-badge",
                "status": "ok",
                "result": {
                    "note": (
                        "The sub-badge was scoped to gitea:write gitea:pr when minted by Triage. "
                        "The Sub-Agent sends both that original badge and the resulting Keycloak B "
                        "access token to Envoy for independent verification."
                    ),
                },
            })

        resource_headers = {
            "Authorization": f"Bearer {access_token}",
            "X-AGNTCY-Actor-Token": f"Bearer {body.sub_badge}",
        }
        resource_context = {
            "intent": body.intent,
            "act_chain": body.act_chain,
            "ticket_id": body.ticket_id,
        }

        # ── s5a: Push fix file to feature branch ──────────────────────────
        s = {
            "id": "push-file",
            "title": f"s5a. Push fix file to {branch} (needs gitea:write) → gitea-gateway",
            "detail": f"POST {GITEA_GATEWAY_URL}/api/gitea/push/{owner}/{repo_slug}",
        }
        with step_span("push-file"):
            try:
                r = await client.post(
                    f"{GITEA_GATEWAY_URL}/api/gitea/push/{owner}/{repo_slug}",
                    headers=resource_headers,
                    json=resource_context,
                )
                if r.status_code in (200, 201):
                    s.update(status="ok", result=r.json())
                    # gateway returns the branch it used; prefer that over our generated name
                    branch = r.json().get("pushed", {}).get("branch", branch)
                elif r.status_code == 403:
                    s.update(status="denied", result=r.json())
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)

        # ── s5b: Open PR ───────────────────────────────────────────────────
        s = {
            "id": "open-pr",
            "title": f"s5b. Open PR ({branch} → main, needs gitea:pr) → gitea-gateway",
            "detail": f"POST {GITEA_GATEWAY_URL}/api/gitea/pulls/{owner}/{repo_slug}",
        }
        with step_span("open-pr"):
            try:
                r = await client.post(
                    f"{GITEA_GATEWAY_URL}/api/gitea/pulls/{owner}/{repo_slug}",
                    headers=resource_headers,
                    json={
                        "head": branch,
                        "base": "main",
                        "title": (
                            f"fix: remediate {body.intent}"
                            f" [ticket={body.ticket_id or 'TRIAGE'}]"
                            f" [act-chain={' → '.join(body.act_chain)}]"
                        ),
                        **resource_context,
                    },
                )
                if r.status_code in (200, 201):
                    s.update(status="ok", result=r.json())
                elif r.status_code == 403:
                    s.update(status="denied", result=r.json())
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)

        # ── s5c: Attempt a PR against the deny-listed repo — always
        # refused by gitea-gateway's policy layer, even though this same
        # access token just successfully opened a PR elsewhere with the
        # identical gitea:pr scope. Demonstrates: policy beats scope.
        s = {
            "id": "denied-pr-attempt",
            "title": "s5c. Attempt PR on demo-protected (deny-listed — refused regardless of scope)",
            "detail": f"POST {GITEA_GATEWAY_URL}/api/gitea/pulls/{owner}/demo-protected",
        }
        with step_span("denied-pr-attempt"):
            try:
                r = await client.post(
                    f"{GITEA_GATEWAY_URL}/api/gitea/pulls/{owner}/demo-protected",
                    headers=resource_headers,
                    json={
                        "head": branch,
                        "base": "main",
                        "title": "fix: attempted change to a protected repo (expected to be denied)",
                        **resource_context,
                    },
                )
                if r.status_code == 403:
                    s.update(status="denied", result=r.json())
                elif r.status_code in (200, 201):
                    s.update(
                        status="error",
                        error="expected 403 policy_deny but the PR succeeded — deny-list not enforced",
                        result=r.json(),
                    )
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)

        # ── s5d: real Envoy + inline OPA resource decision ─────────────────
        policy = next(
            (
                step.get("result", {}).get("policy")
                for step in steps
                if step.get("id") in {"push-file", "open-pr"}
                and step.get("result", {}).get("policy")
            ),
            {},
        )
        with step_span("opa-egress"):
            steps.append({
                "id": "opa-egress",
                "title": (
                    "s5d. Envoy + OPA resource boundary: both JWTs ✓  depth ✓"
                    "  sub-scope ✓  signed intent ✓  repository ✓  → ALLOW"
                ),
                "status": "ok" if policy.get("decision") == "ALLOW" else "error",
                "result": {
                    "decision": policy.get("decision"),
                    "enforced_by": policy.get("enforced_by"),
                    "rule": policy.get("rule"),
                    "action": policy.get("action"),
                    "repository": policy.get("repository"),
                    "delegation_depth": policy.get("delegation_depth"),
                    "sub_scope_subset": True,
                    "note": "decision headers were injected by the Built On Envoy inline OPA filter",
                },
            })

    pr_step = next((s for s in steps if s["id"] == "open-pr"), {})
    pr_url = pr_step.get("result", {}).get("pull_request", {}).get("html_url", "")

    # ── s6: this agent's own Directory turn record ──────────────────────────
    # The leaf of the delegation chain gets an audit entry too, alongside
    # OpenCode's (Org A) and Triage's (Org B).
    with step_span("dir-push"):
        steps.append(await _dir_push_turn(body, branch, pr_url))

    # ── s7: PR created summary ──────────────────────────────────────────────
    with step_span("pr-created"):
        steps.append({
            "id": "pr-created",
            "title": "s7. PR created ✓ — causal audit: Sarah → OpenCode → Triage → Sub-Agent",
            "status": "ok" if pr_step.get("status") == "ok" else "error",
            "result": {
                "pr_url": pr_url,
                "act_chain": body.act_chain,
                "ticket": body.ticket_id,
                "otel_note": "OpenTelemetry trace_id would link every hop in production",
            },
        })

    return JSONResponse({
        "ok": all(_expected_outcome(step) for step in steps),
        "steps": steps,
    })
