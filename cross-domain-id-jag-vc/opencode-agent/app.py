# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""OpenCode Agent (mock) — Org A AI coding agent.

Drives Phase A + Discovery + Phase B of the cross-domain remediation sequence:
  Phase A (local, no cross-domain auth):
    1. Sarah signs in via OIDC password grant → Keycloak A (org-a realm)
    2. Mock: scan repo, find CVE, decide to remediate cross-domain
  Discovery + Identity:
    3-6. Resolve + verify a VC badge from vc-issuer (real signed vc+jwt)
  Phase B (cross-domain begins):
    7. RFC 8693 exchange (subject=Sarah, actor_token=badge) → Keycloak A
       (real call; Keycloak validates subject_token but does not itself
       process actor_token into an "act" claim — see the inline note)
    8. Mint ID-JAG assertion for Org B triage-agent → idjag-issuer
  9-10. Egress PDP check — may Sarah delegate this scope to Org B? → Envoy A + OPA
   11. Redeem ID-JAG at Keycloak B → scoped access token (triage:create)
   13. Create remediation ticket → Triage agent (Org B)

Step 7 (RFC 8693 exchange) remains mocked per demo scope.
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from pydantic import BaseModel

from tracing import current_trace_id, setup_tracing

KC_A_URL = os.environ.get("KC_A_URL", "http://keycloak-a:8080").rstrip("/")
KC_A_REALM = os.environ.get("KC_A_REALM", "org-a")
KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")
OPENCODE_CLIENT_ID = os.environ.get("OPENCODE_CLIENT_ID", "opencode-agent")
OPENCODE_CLIENT_SECRET = os.environ.get("OPENCODE_CLIENT_SECRET", "")
TRIAGE_CLIENT_ID = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")
TRIAGE_CLIENT_SECRET = os.environ.get("TRIAGE_CLIENT_SECRET", "")
SARAH_USER = os.environ.get("SARAH_USER", "sarah")
SARAH_PASSWORD = os.environ.get("SARAH_PASSWORD", "")
SARAH_EMAIL = os.environ.get("SARAH_EMAIL", "sarah@org-a.example")
VC_ISSUER_URL = os.environ.get("VC_ISSUER_URL", "http://vc-issuer:9003").rstrip("/")
IDJAG_ISSUER_URL = os.environ.get("IDJAG_ISSUER_URL", "http://idjag-issuer:9000").rstrip("/")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
EGRESS_PDP_URL = os.environ.get("EGRESS_PDP_URL", "http://envoy-org-a:12000").rstrip("/")
TRIAGE_AGENT_URL = os.environ.get("TRIAGE_AGENT_URL", "http://triage-agent:8200").rstrip("/")
SCAN_REPO = os.environ.get("SCAN_REPO", "demo-admin/payments-service")

KC_A_TOKEN_EP = f"{KC_A_URL}/realms/{KC_A_REALM}/protocol/openid-connect/token"
KC_B_TOKEN_EP = f"{KC_B_URL}/realms/{KC_B_REALM}/protocol/openid-connect/token"
KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"

app = FastAPI(title="OpenCode Agent (mock)", version="0.1.0")
setup_tracing("opencode-agent")
FastAPIInstrumentor.instrument_app(app)


class RunRequest(BaseModel):
    repo: str = ""
    cve_override: str = ""


def _s(id: str, title: str, detail: str = "") -> dict:
    return {"id": id, "title": title, "detail": detail}


def _ok(status: str) -> bool:
    return status in ("ok", "denied")


@app.get("/health")
def health():
    return {"status": "ok", "agent": "opencode", "realm": KC_A_REALM}


@app.get("/api/config")
def config():
    return {
        "kc_a": KC_A_URL, "kc_a_realm": KC_A_REALM,
        "kc_b": KC_B_URL, "kc_b_realm": KC_B_REALM,
        "opencode_client": OPENCODE_CLIENT_ID,
        "triage_client": TRIAGE_CLIENT_ID,
        "vc_issuer": VC_ISSUER_URL,
        "idjag_issuer": IDJAG_ISSUER_URL,
        "identity_node": IDENTITY_NODE_URL,
        "egress_pdp": EGRESS_PDP_URL,
        "triage_agent": TRIAGE_AGENT_URL,
    }


@app.post("/api/run")
async def run(body: RunRequest | None = None):
    """Drive the full Phase A + B sequence (steps 1-13)."""
    repo = (body.repo if body else "") or SCAN_REPO
    cve = (body.cve_override if body else "") or "CVE-2024-XXXX"
    steps: list[dict] = []

    async with httpx.AsyncClient(timeout=20) as client:

        # ── Step 1: Sarah signs in (OIDC password grant → Keycloak A) ──────
        s = _s("sarah-login",
               "1. Sarah signs in — OIDC password grant → Keycloak A (org-a)",
               f"POST {KC_A_TOKEN_EP}  client={OPENCODE_CLIENT_ID}  user={SARAH_USER}")
        try:
            r = await client.post(KC_A_TOKEN_EP, data={
                "grant_type": "password",
                "client_id": OPENCODE_CLIENT_ID,
                "client_secret": OPENCODE_CLIENT_SECRET,
                "username": SARAH_USER,
                "password": SARAH_PASSWORD,
                "scope": "openid profile email",
            })
            if r.status_code == 200:
                sarah_token = r.json()["access_token"]
                s.update(status="ok", token_preview=sarah_token[:48] + "…")
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        steps.append(s)

        # ── Step 2: Mock scan ───────────────────────────────────────────────
        s = _s("scan",
               f"2. Scan repo → {cve} found (HIGH), decide cross-domain remediation",
               f"mock scan of {repo}")
        s.update(status="ok", result={
            "repo": repo, "cve": cve, "severity": "HIGH",
            "description": "Dependency with known RCE vulnerability",
            "decision": "cross-domain-remediation → Org B Triage",
        })
        steps.append(s)

        # ── Steps 3-6: Resolve + verify VC badge from vc-issuer ─────────────
        # identity-node's real REST API has no badge concept (CIMD id
        # generate/resolve only — see README's "How CIMD actually works"),
        # so vc-issuer plays this role the same way idjag-issuer stands in
        # for the ID-JAG issuer: a real signed vc+jwt, really verified.
        s = _s("resolve-badge",
               "3-6. Resolve + verify VC badge from vc-issuer",
               f"POST {VC_ISSUER_URL}/vc/issue  +  POST {VC_ISSUER_URL}/vc/verify")
        try:
            r = await client.post(f"{VC_ISSUER_URL}/vc/issue", json={
                "id": OPENCODE_CLIENT_ID,
                "caps": ["scan", "remediate", "delegate"],
                "delegating_user": SARAH_EMAIL,
                "intent": "cross-domain-remediation",
                "act_chain": [OPENCODE_CLIENT_ID],
            })
            if r.status_code != 200:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps})
            badge = r.json()["badge"]

            r = await client.post(f"{VC_ISSUER_URL}/vc/verify", json={"badge": badge})
            if r.status_code == 200 and r.json().get("valid"):
                s.update(status="ok", token_preview=badge[:48] + "…",
                         result={"badge_claims": r.json()["claims"]})
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps})
        steps.append(s)

        # ── Step 7: RFC 8693 token exchange at Keycloak A ───────────────────
        # NOTE: Keycloak 26.7's standard token exchange (standard.token.
        # exchange.enabled) validates subject_token for real, but does not
        # itself verify actor_token or emit an RFC 8693 "act" claim — this
        # was confirmed by testing live: passing a garbage or absent
        # actor_token produces a byte-identical response, and keycloak-a
        # logs nothing either way. That's a real platform behavior, not a
        # shortcut here. The actor_token (badge) was already independently,
        # cryptographically verified against vc-issuer in the previous step,
        # and delegation semantics continue to be carried by the (real)
        # act_chain claim on the ID-JAG minted in the next step.
        s = _s("kc-a-exchange",
               "7. RFC 8693 exchange (subject=Sarah, actor_token=badge) → Keycloak A",
               f"POST {KC_A_TOKEN_EP}  grant_type=token-exchange")
        try:
            r = await client.post(KC_A_TOKEN_EP, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": OPENCODE_CLIENT_ID,
                "client_secret": OPENCODE_CLIENT_SECRET,
                "subject_token": sarah_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "actor_token": badge,
                "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            })
            if r.status_code == 200:
                exchanged_token = r.json()["access_token"]
                s.update(status="ok", token_preview=exchanged_token[:48] + "…", result={
                    "subject": SARAH_EMAIL,
                    "actor": OPENCODE_CLIENT_ID,
                    "note": (
                        "Keycloak validated subject_token and issued this token for "
                        "real; it does not itself process actor_token into an act "
                        "claim (see README) — the verified badge's delegation claims "
                        "are carried forward via the ID-JAG's act_chain next"
                    ),
                })
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps})
        steps.append(s)

        # ── Step 8: Mint ID-JAG assertion for Org B triage-agent ───────────
        s = _s("mint-idjag",
               "8. Mint ID-JAG assertion for Org B triage-agent (scoped to triage:create)",
               f"POST {IDJAG_ISSUER_URL}/mint  sub={SARAH_EMAIL}  aud={KC_B_ISSUER}  scope=triage:create")
        try:
            r = await client.post(f"{IDJAG_ISSUER_URL}/mint", json={
                "sub": SARAH_EMAIL,
                "aud": KC_B_ISSUER,
                "client_id": TRIAGE_CLIENT_ID,
                "act_chain": [OPENCODE_CLIENT_ID],
                "scope": "openid triage:create",
                "intent": ["create-pr-fix"],
            })
            if r.status_code == 200:
                assertion = r.json()["assertion"]
                s.update(status="ok", token_preview=assertion[:48] + "…",
                         claims=r.json().get("claims", {}))
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        steps.append(s)

        # ── Steps 9-10: Org A egress PDP check (Envoy + OPA) ────────────────
        # May Sarah delegate this scope to Org B? Envoy verifies the ID-JAG's
        # signature against idjag-issuer's JWKS; OPA checks scope, intent,
        # and delegation-chain depth before the assertion ever leaves Org A.
        s = _s("egress-check",
               "9-10. Egress PDP check — may Sarah delegate this scope to Org B? → Envoy A + OPA",
               f"POST {EGRESS_PDP_URL}/api/egress-check  Bearer=<id-jag>")
        try:
            r = await client.post(
                f"{EGRESS_PDP_URL}/api/egress-check",
                headers={"Authorization": f"Bearer {assertion}"},
            )
            if r.status_code == 200:
                s.update(status="ok", result=r.json() if r.content else {"decision": "ALLOW"})
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps})
        steps.append(s)

        # ── Step 11: Redeem ID-JAG at Keycloak B ───────────────────────────
        s = _s("kc-b-exchange",
               "11. Redeem ID-JAG at Keycloak B → scoped access token (triage:create, Sarah propagated)",
               f"POST {KC_B_TOKEN_EP}  grant_type=jwt-bearer  client={TRIAGE_CLIENT_ID}")
        try:
            r = await client.post(KC_B_TOKEN_EP, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
                "client_id": TRIAGE_CLIENT_ID,
                "client_secret": TRIAGE_CLIENT_SECRET,
                "scope": "openid triage:create",
            })
            if r.status_code == 200:
                triage_token = r.json()["access_token"]
                s.update(status="ok", token_preview=triage_token[:48] + "…")
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})
        steps.append(s)

        # ── Step 13: Create ticket at Triage agent ──────────────────────────
        s = _s("create-ticket",
               "13. Create remediation ticket → Triage agent (Org B)  [access token + badge + intent]",
               f"POST {TRIAGE_AGENT_URL}/api/ticket  Bearer=triage_token")
        try:
            r = await client.post(
                f"{TRIAGE_AGENT_URL}/api/ticket",
                headers={
                    "Authorization": f"Bearer {triage_token}",
                    "X-AGNTCY-Actor-Token": f"Bearer {assertion}",
                    "Content-Type": "application/json",
                },
                json={
                    "cve": cve,
                    "severity": "HIGH",
                    "repo": repo,
                    "intent": "create-pr-fix",
                    "delegating_agent": OPENCODE_CLIENT_ID,
                    "act_chain": [OPENCODE_CLIENT_ID],
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

    return JSONResponse({
        "ok": all(_ok(s.get("status", "error")) for s in steps),
        "steps": steps,
        "trace_id": current_trace_id(),
    })
