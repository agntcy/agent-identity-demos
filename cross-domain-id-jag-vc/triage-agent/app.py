# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Triage Agent (Org B) — remediation coordinator with AGNTCY identity lifecycle.

Receives a cross-domain remediation ticket from OpenCode (Org A) and follows
the same lifecycle the Org A agent does: verify inbound credentials →
register own identity → policy-scoped credential → work → delegate narrower.

Ticket lifecycle (POST /api/ticket):
  t1   Envoy + inline OPA already verified both JWTs (enforcement gate);
       Triage additionally verifies the ID-JAG actor token ITSELF against
       Keycloak A's JWKS — defense in depth, no blind header trust
  t2   Triage registers ITS OWN identity: CIMD generate/resolve
       AGNTCY-triage-agent at the Identity Node under the org-b trust
       authority (Vault-signed proof — org-b attests its own agents)
  t3   Sub-badge scope check: present the inbound (Sarah-federated) access
       token + requested narrowing to Envoy B + inline OPA
       (/api/subbadge-scope-check) → ALLOW + policy-approved scope/resource
  t4   Plan the remediation (mock string; real LLM plan is a later milestone)
  t5   Mint the narrowed sub-badge NATIVELY at Keycloak B (keycloak-idjag-spi,
       requested_token_type=id-jag, subject_token=the inbound access token) —
       scope/resource are the policy-approved values from t3
  t6   Push a turn record to the AGNTCY Directory
  t7   Spawn the Sub-Agent with the narrowed sub-badge
"""

from __future__ import annotations

import asyncio
import os

import httpx
import jwt as pyjwt
from fastapi import FastAPI, Header, HTTPException
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import cimd as cimd_api
from agntcy_identity_client import directory as dir_api
from tracing import setup_tracing, step_span
from fastapi.responses import JSONResponse
from pydantic import BaseModel

KC_A_URL = os.environ.get("KC_A_URL", "http://keycloak-a:8080").rstrip("/")
KC_A_REALM = os.environ.get("KC_A_REALM", "org-a")
KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")
TRIAGE_CLIENT_ID = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")
TRIAGE_CLIENT_SECRET = os.environ.get("TRIAGE_CLIENT_SECRET", "")
SUB_AGENT_CLIENT_ID = os.environ.get("SUB_AGENT_CLIENT_ID", "sub-agent")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
SUB_AGENT_URL = os.environ.get("SUB_AGENT_URL", "http://sub-agent:8300").rstrip("/")
SUBBADGE_PDP_URL = os.environ.get("SUBBADGE_PDP_URL", "http://envoy-org-b:10000").rstrip("/")

SUBBADGE_SCOPE_REQUEST = "openid gitea:write gitea:pr"

VAULT_CFG = VaultConfig.from_env()  # org-b trust authority (ORG_COMMON_NAME=org-b)

KC_A_ISSUER = f"{KC_A_URL}/realms/{KC_A_REALM}"
KC_A_JWKS_URL = f"{KC_A_ISSUER}/protocol/openid-connect/certs"
KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"
KC_B_TOKEN_EP = f"{KC_B_ISSUER}/protocol/openid-connect/token"

app = FastAPI(title="Triage Agent (Org B) — identity lifecycle", version="0.2.0")
setup_tracing("triage-agent")
FastAPIInstrumentor.instrument_app(app)

_jwks_client: pyjwt.PyJWKClient | None = None


def _get_jwks_client() -> pyjwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = pyjwt.PyJWKClient(KC_A_JWKS_URL, cache_keys=True)
    return _jwks_client


class TicketRequest(BaseModel):
    cve: str
    severity: str = "HIGH"
    repo: str = "demo-admin/payments-service"
    intent: str = "create-pr-fix"
    delegating_agent: str = ""
    act_chain: list[str] = []
    plan: str = ""  # OpenCode's remediation plan (optional, from Org A)


@app.get("/health")
def health():
    return {"status": "ok", "agent": "triage", "realm": KC_B_REALM}


@app.get("/api/config")
def config():
    return {
        "kc_a": KC_A_URL, "kc_a_realm": KC_A_REALM,
        "kc_b": KC_B_URL, "kc_b_realm": KC_B_REALM,
        "triage_client": TRIAGE_CLIENT_ID,
        "sub_agent_client": SUB_AGENT_CLIENT_ID,
        "identity_node": IDENTITY_NODE_URL,
        "dir_apiserver": DIR_APISERVER_URL or "not configured",
        "subbadge_pdp": SUBBADGE_PDP_URL,
        "sub_agent": SUB_AGENT_URL,
        "vault_key_name": VAULT_CFG.key_name,
        "org_common_name": VAULT_CFG.common_name,
    }


@app.get("/.well-known/agent.json")
def agent_card():
    """A2A agent card — discoverable description of this agent."""
    return {
        "name": "triage-agent",
        "description": "Org B AI remediation agent — creates tickets, plans fixes, spawns sub-agents",
        "url": "http://triage-agent:8200",
        "version": "0.2.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "remediation",
                "name": "CVE Remediation",
                "description": "Receive cross-domain CVE alerts and remediate via PR",
                "tags": ["security", "remediation", "cross-domain"],
            }
        ],
    }


def _decode_jwt_payload_unverified(token: str) -> dict:
    """Decode a JWT's payload for display only — no signature check. Used
    purely so the webapp's step toast has claims to show; never used for a
    trust decision (every token here is independently, cryptographically
    verified server-side by the service that consumes it)."""
    import base64
    import json

    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return {}


def _verify_idjag_sync(token: str, body: TicketRequest) -> dict:
    """Verify the inbound ID-JAG against Keycloak A's JWKS + delegation claims.

    Raises on any failure; returns the verified claims. Sync (PyJWKClient
    uses urllib) — call via executor.
    """
    signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
    claims = pyjwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=KC_B_ISSUER,
        issuer=KC_A_ISSUER,
        options={"require": ["exp", "iat", "aud", "iss", "sub"]},
    )
    act = claims.get("act") or {}
    if claims.get("sub") != "sarah@org-a.example":
        raise ValueError(f"unexpected delegating subject: {claims.get('sub')}")
    if act.get("act_chain") != body.act_chain:
        raise ValueError("act_chain mismatch between ticket body and signed ID-JAG")
    if body.intent not in (claims.get("intent") or []):
        raise ValueError("ticket intent not present in signed ID-JAG intent")
    if "triage:create" not in (claims.get("scope") or "").split(" "):
        raise ValueError("ID-JAG scope does not include triage:create")
    return claims


async def _cimd_register(client: httpx.AsyncClient) -> list[dict]:
    """t2 — Triage registers its own identity under the org-b trust authority."""
    steps: list[dict] = []
    s: dict = {
        "id": "cimd-generate-id",
        "title": f"t2. Triage registers its identity — generate id for {TRIAGE_CLIENT_ID} "
                 f"(Vault-signed proof, {VAULT_CFG.common_name} trust authority) → Identity Node",
        "detail": f"POST {IDENTITY_NODE_URL}/v1alpha1/id/generate  iss={VAULT_CFG.issuer}  sub={TRIAGE_CLIENT_ID}",
    }
    res = None
    try:
        res = await cimd_api.generate_id(client, IDENTITY_NODE_URL, VAULT_CFG, TRIAGE_CLIENT_ID)
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

    cimd_id = res["id"] or f"AGNTCY-{TRIAGE_CLIENT_ID}"
    s = {
        "id": "cimd-resolve-id",
        "title": f"t2b. Resolve id {cimd_id} → ResolverMetadata + JWK",
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


async def _dir_push_turn(cve: str, repo: str, ticket_id: str) -> dict:
    s: dict = {
        "id": "dir-push",
        "title": "t6. Directory: push Triage turn record (OASF) → CID",
        "detail": f"gRPC Push({DIR_APISERVER_URL})  ticket={ticket_id}",
    }
    if not DIR_APISERVER_URL:
        s.update(status="ok", result={"cid": "", "note": "directory not configured"})
        return s
    try:
        from datetime import datetime, timezone
        record_dict = {
            "name": "triage-agent",
            "version": "0.2.0",
            "schema_version": dir_api.OASF_SCHEMA_VERSION,
            "description": f"Triage agent turn: ticket {ticket_id} for {cve} in {repo}",
            "authors": ["cross-domain-demo"],
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "skills": [
                {"name": "cybersecurity/vulnerability_management/dependency_security", "id": 100304},
                {"name": "software_engineering/code_quality/code_review", "id": 60701},
            ],
            "domains": [
                {"name": "technology/security", "id": 107},
            ],
            "annotations": {"cve": cve, "repo": repo, "ticket": ticket_id, "turn": "triage"},
        }
        cid = await asyncio.get_event_loop().run_in_executor(
            None, dir_api.push_record, DIR_APISERVER_URL, record_dict
        )
        s.update(status="ok", result={"cid": cid, "agent": "triage-agent"})
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    return s


@app.post("/api/ticket")
async def receive_ticket(
    body: TicketRequest,
    authorization: str | None = Header(default=None),
    actor_token_header: str | None = Header(default=None, alias="x-agntcy-actor-token"),
    policy_decision: str | None = Header(
        default=None, alias="x-agntcy-policy-decision"
    ),
    policy_rule: str | None = Header(default=None, alias="x-agntcy-policy-rule"),
    policy_enforcer: str | None = Header(
        default=None, alias="x-agntcy-policy-enforcer"
    ),
    delegation_depth: str | None = Header(
        default=None, alias="x-agntcy-delegation-depth"
    ),
):
    """Receive a remediation ticket and drive the Org B lifecycle."""
    steps: list[dict] = []

    # Envoy has already verified both tokens against JWKS and run the inline
    # OPA policy. Keep fail-closed guards for accidental direct requests.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if policy_decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail="ticket requests must pass the Org B Envoy policy gateway",
        )
    access_token = authorization.split(" ", 1)[1]

    # ── t1: Envoy/OPA gate (echo) ─────────────────────────────────────────
    with step_span("opa-ingress"):
        steps.append({
            "id": "opa-ingress",
            "title": "t1. Envoy + OPA ingress: both JWTs ✓  chain ✓  scope ✓  action ∈ signed intent ✓  → ALLOW",
            "status": "ok",
            "result": {
                "decision": policy_decision,
                "enforced_by": policy_enforcer,
                "rule": policy_rule,
                "delegation_depth": int(delegation_depth or "0"),
                "note": "decision headers were injected by the Built On Envoy inline OPA filter",
            },
        })

    # ── t1b: in-agent ID-JAG verification (defense in depth) ──────────────
    s: dict = {
        "id": "verify-idjag",
        "title": "t1b. Triage verifies the ID-JAG itself — signature vs Keycloak A JWKS + delegation claims",
        "detail": f"JWKS {KC_A_JWKS_URL}  expect iss={KC_A_ISSUER}  aud={KC_B_ISSUER}",
    }
    actor_raw = ""
    if actor_token_header and actor_token_header.lower().startswith("bearer "):
        actor_raw = actor_token_header.split(" ", 1)[1]
    with step_span("verify-idjag"):
        if not actor_raw:
            s.update(status="error",
                     error="X-AGNTCY-Actor-Token header missing — cannot verify in-agent")
            steps.append(s)
            return JSONResponse({"ok": False, "ticket_id": "", "steps": steps})
        try:
            claims = await asyncio.get_event_loop().run_in_executor(
                None, _verify_idjag_sync, actor_raw, body
            )
            s.update(status="ok", result={
                "token": actor_raw,
                "claims": claims,
                "note": "verified in-agent, independently of Envoy (defense in depth) — "
                        "claims shown here are from the real, signature-verified decode "
                        "(pyjwt.decode), not an unverified base64 read",
            })
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=f"in-agent ID-JAG verification failed: {exc}")
            steps.append(s)
            return JSONResponse({"ok": False, "ticket_id": "", "steps": steps})
    steps.append(s)

    ticket_id = f"TRIAGE-{body.cve.replace('CVE-', '')}"
    parent_chain = list(body.act_chain) or [body.delegating_agent]

    async with httpx.AsyncClient(timeout=20) as client:

        # ── t2: register own identity (org-b trust authority) ─────────────
        with step_span("cimd-register"):
            cimd_steps = await _cimd_register(client)
        steps.extend(cimd_steps)
        if any(cs.get("status") == "error" for cs in cimd_steps):
            return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})

        # ── t3: sub-badge scope check (Org B PDP — Envoy + inline OPA) ────
        s = {
            "id": "subbadge-scope-check",
            "title": "t3. Sub-badge scope check — may this delegation be narrowed? → Envoy B + OPA",
            "detail": (
                f"POST {SUBBADGE_PDP_URL}/api/subbadge-scope-check"
                f"  scope={SUBBADGE_SCOPE_REQUEST}  repo={body.repo}  intent={body.intent}"
            ),
        }
        with step_span("subbadge-scope-check"):
            try:
                r = await client.post(
                    f"{SUBBADGE_PDP_URL}/api/subbadge-scope-check",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "x-agntcy-requested-scope": SUBBADGE_SCOPE_REQUEST,
                        "x-agntcy-requested-repo": body.repo,
                        "x-agntcy-requested-intent": body.intent,
                    },
                )
                if r.status_code == 200:
                    scoped_scope = r.headers.get("x-agntcy-scoped-scope", SUBBADGE_SCOPE_REQUEST)
                    scoped_resource = r.headers.get("x-agntcy-scoped-resource", body.repo)
                    s.update(status="ok", result={
                        "decision": "ALLOW",
                        "scoped_scope": scoped_scope,
                        "scoped_resource": scoped_resource,
                        "rule": r.headers.get("x-agntcy-policy-rule", ""),
                        "note": "policy approved the narrowing before the sub-badge exists",
                    })
                else:
                    s.update(status="error",
                             error=f"HTTP {r.status_code}: {r.text[:300]}",
                             result={"decision": "DENY"})
                    steps.append(s)
                    return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
                steps.append(s)
                return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})
        steps.append(s)

        # ── t4: plan the remediation ──────────────────────────────────────
        with step_span("plan"):
            steps.append({
                "id": "plan",
                "title": "t4. Create ticket, plan remediation, decide sub-agent",
                "status": "ok",
                "result": {
                    "ticket_id": ticket_id,
                    "plan": f"bump-dependency-{body.cve}",
                    "opencode_plan": (body.plan or "")[:500],
                    "sub_agent": SUB_AGENT_CLIENT_ID,
                    "repo": body.repo,
                },
            })

        # ── t5: mint narrowed sub-badge NATIVELY at Keycloak B ────────────
        # subject_token is the inbound Sarah-federated access token — the SPI
        # verifies its signature for real. Scope/resource come from t3's
        # policy decision, act-chain extends Sarah → OpenCode → Triage.
        sub_chain = parent_chain + [TRIAGE_CLIENT_ID]
        s = {
            "id": "mint-sub-badge",
            "title": "t5. Mint narrowed sub-badge natively at Keycloak B (keycloak-idjag-spi)",
            "detail": (
                f"POST {KC_B_TOKEN_EP}  grant_type=token-exchange  requested_token_type=id-jag"
                f"  scope={scoped_scope}  resource={scoped_resource}  act_chain={sub_chain}"
            ),
        }
        sub_badge = ""
        with step_span("mint-sub-badge"):
            try:
                r = await client.post(KC_B_TOKEN_EP, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": TRIAGE_CLIENT_ID,
                    "client_secret": TRIAGE_CLIENT_SECRET,
                    "subject_token": access_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                    "audience": KC_B_ISSUER,
                    "scope": scoped_scope,
                    "target_client_id": SUB_AGENT_CLIENT_ID,
                    "act_chain": ",".join(sub_chain),
                    "intent": body.intent,
                    "resource": scoped_resource,
                })
                if r.status_code == 200:
                    sub_badge = r.json()["access_token"]
                    s.update(status="ok",
                             token_preview=sub_badge[:48] + "…",
                             token=sub_badge,
                             result={
                                 "issued_token_type": r.json().get("issued_token_type", ""),
                                 "claims": _decode_jwt_payload_unverified(sub_badge),
                             })
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                    steps.append(s)
                    return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
                steps.append(s)
                return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})
        steps.append(s)

        # ── t6: Directory turn record ─────────────────────────────────────
        with step_span("dir-push"):
            steps.append(await _dir_push_turn(body.cve, body.repo, ticket_id))

        # ── t7: spawn Sub-Agent with the narrowed sub-badge ───────────────
        s = {
            "id": "spawn-sub-agent",
            "title": "t7. Spawn sub-agent with narrowed sub-badge + intent → Sub-Agent /api/run",
            "detail": f"POST {SUB_AGENT_URL}/api/run  sub_badge=…  repo={body.repo}",
        }
        with step_span("spawn-sub-agent"):
            try:
                r = await client.post(
                    f"{SUB_AGENT_URL}/api/run",
                    json={
                        "sub_badge": sub_badge,
                        "repo": body.repo,
                        "intent": body.intent,
                        "act_chain": sub_chain + [SUB_AGENT_CLIENT_ID],
                        "ticket_id": ticket_id,
                    },
                    timeout=60,
                )
                if r.status_code in (200, 201):
                    s.update(status="ok", result=r.json())
                else:
                    s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
            except Exception as exc:  # noqa: BLE001
                s.update(status="error", error=str(exc))
        steps.append(s)

    all_ok = all(s.get("status") in ("ok", "denied") for s in steps)
    return JSONResponse({
        "ok": all_ok,
        "ticket_id": ticket_id,
        "steps": steps,
    })
