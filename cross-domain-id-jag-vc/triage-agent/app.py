# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Triage Agent (mock) — Org B remediation agent.

Receives a cross-domain remediation ticket from OpenCode (Org A), plans the
fix, requests a narrowed sub-badge, and spawns the Sub-Agent.

Sequence steps handled here:
  13. Receive ticket (access token + badge + intent) — from OpenCode
  14-15. Policy check — Envoy verifies both JWTs and inline OPA enforces the
         delegation scope, chain, signed intent, method, path, and repository
  16. Create ticket, plan remediation, decide sub-agent
  17-18. Request narrowed sub-badge (caps ⊆ parent, nested act-chain) → idjag-issuer
  19. Spawn sub-agent with narrowed badge + intent
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, Header, HTTPException
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from tracing import setup_tracing
from fastapi.responses import JSONResponse
from pydantic import BaseModel

KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")
TRIAGE_CLIENT_ID = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")
SUB_AGENT_CLIENT_ID = os.environ.get("SUB_AGENT_CLIENT_ID", "sub-agent")
IDJAG_ISSUER_URL = os.environ.get("IDJAG_ISSUER_URL", "http://idjag-issuer:9000").rstrip("/")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
SUB_AGENT_URL = os.environ.get("SUB_AGENT_URL", "http://sub-agent:8300").rstrip("/")

KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"

app = FastAPI(title="Triage Agent (mock)", version="0.1.0")
setup_tracing("triage-agent")
FastAPIInstrumentor.instrument_app(app)


class TicketRequest(BaseModel):
    cve: str
    severity: str = "HIGH"
    repo: str = "demo-admin/payments-service"
    intent: str = "create-pr-fix"
    delegating_agent: str = ""
    act_chain: list[str] = []


@app.get("/health")
def health():
    return {"status": "ok", "agent": "triage", "realm": KC_B_REALM}


@app.get("/api/config")
def config():
    return {
        "kc_b": KC_B_URL, "kc_b_realm": KC_B_REALM,
        "triage_client": TRIAGE_CLIENT_ID,
        "sub_agent_client": SUB_AGENT_CLIENT_ID,
        "idjag_issuer": IDJAG_ISSUER_URL,
        "sub_agent": SUB_AGENT_URL,
    }


@app.get("/.well-known/agent.json")
def agent_card():
    """A2A agent card — consumed by identity-node when issuing a badge."""
    return {
        "name": "triage-agent",
        "description": "Org B AI remediation agent — creates tickets, plans fixes, spawns sub-agents",
        "url": "http://triage-agent:8200",
        "version": "0.1.0",
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


@app.post("/api/ticket")
async def receive_ticket(
    body: TicketRequest,
    authorization: str | None = Header(default=None),
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
    """Receive a remediation ticket from OpenCode and drive the Org B side of the flow."""
    steps: list[dict] = []

    # Envoy has already verified the bearer token against KC-B JWKS. Keep a
    # minimal downstream guard so accidentally direct requests fail closed.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if policy_decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail="ticket requests must pass the Org B Envoy policy gateway",
        )

    # ── Steps 14-15: Policy check (real Envoy + inline OPA ALLOW) ─────────
    steps.append({
        "id": "opa-ingress",
        "title": "14-15. Envoy + OPA ingress: both JWTs ✓  chain ✓  scope ✓  action ∈ signed intent ✓  → ALLOW",
        "status": "ok",
        "result": {
            "decision": policy_decision,
            "enforced_by": policy_enforcer,
            "rule": policy_rule,
            "delegation_depth": int(delegation_depth or "0"),
            "checks": {
                "access_token_signature": True,
                "actor_token_signature": True,
                "act_chain": body.act_chain,
                "required_scope": "triage:create",
                "action_in_intent": True,
            },
            "note": "decision headers were injected by the Built On Envoy inline OPA filter",
        },
    })

    # ── Step 16: Create ticket + plan ─────────────────────────────────────
    ticket_id = f"TRIAGE-{body.cve.replace('CVE-', '')}"
    steps.append({
        "id": "plan",
        "title": "16. Create ticket, plan remediation, decide sub-agent",
        "status": "ok",
        "result": {
            "ticket_id": ticket_id,
            "plan": f"bump-dependency-{body.cve}",
            "sub_agent": SUB_AGENT_CLIENT_ID,
            "repo": body.repo,
        },
    })

    # ── Steps 17-18: Request narrowed sub-badge ────────────────────────────
    # caps ⊆ parent (gitea:write gitea:pr only — no triage:create),
    # nested act-chain: Sarah → OpenCode → Triage → Sub-Agent
    parent_chain = list(body.act_chain) or [body.delegating_agent]
    sub_scope = "openid gitea:write gitea:pr"

    s: dict = {
        "id": "mint-sub-badge",
        "title": "17-18. Request narrowed sub-badge (caps ⊆ parent, nested act-chain) → idjag-issuer",
        "detail": (
            f"POST {IDJAG_ISSUER_URL}/mint  sub=sarah@org-a.example"
            f"  act_chain={parent_chain + [TRIAGE_CLIENT_ID]}  scope={sub_scope}"
            f"  resource={body.repo}"
        ),
    }
    sub_badge = ""
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.post(f"{IDJAG_ISSUER_URL}/mint", json={
                "sub": "sarah@org-a.example",
                "aud": KC_B_ISSUER,
                "client_id": SUB_AGENT_CLIENT_ID,
                "act_chain": parent_chain + [TRIAGE_CLIENT_ID],
                "scope": sub_scope,
                "intent": [body.intent],
                "resource": [body.repo],
            })
            if r.status_code == 200:
                sub_badge = r.json()["assertion"]
                s.update(status="ok",
                         token_preview=sub_badge[:48] + "…",
                         token=sub_badge,
                         claims=r.json().get("claims", {}))
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({
                    "ok": False, "ticket_id": ticket_id, "steps": steps,
                })
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "ticket_id": ticket_id, "steps": steps})
        steps.append(s)

        # ── Step 19: Spawn sub-agent with narrowed badge + intent ──────────
        s = {
            "id": "spawn-sub-agent",
            "title": "19. Spawn sub-agent with narrowed badge + intent → Sub-Agent /api/run",
            "detail": f"POST {SUB_AGENT_URL}/api/run  sub_badge=…  repo={body.repo}",
        }
        try:
            r = await client.post(
                f"{SUB_AGENT_URL}/api/run",
                json={
                    "sub_badge": sub_badge,
                    "repo": body.repo,
                    "intent": body.intent,
                    "act_chain": parent_chain + [TRIAGE_CLIENT_ID, SUB_AGENT_CLIENT_ID],
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
