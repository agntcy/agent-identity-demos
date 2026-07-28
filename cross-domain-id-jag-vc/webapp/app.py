# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# assisted-by claude code claude-sonnet-4-6
"""Cross-Domain AI Agent Remediation Demo — webapp UI backend.

This file has no task-lifecycle logic of its own: /api/run proxies straight
to the real OpenCode Agent (opencode-agent, port 8100) and the webapp
animates whatever steps that real run actually produced. See
opencode-agent/app.py for the authoritative lifecycle — authenticate →
register own identity (CIMD) → policy-scoped badge (Envoy A + OPA) → work
(real OpenCode) → delegate cross-domain (ID-JAG). An earlier version of
this file reimplemented that whole lifecycle a second time for the diagram;
that duplicated copy silently drifted out of sync once the real lifecycle
was rewritten, so it was replaced with this proxy — the diagram can no
longer show a step that didn't really happen.

Endpoints
---------
GET  /                  — serve index.html
GET  /api/health        — liveness probe
GET  /api/config        — all service URLs / client IDs (informational)
POST /api/run           — proxy to opencode-agent's /api/run
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from tracing import current_trace_id, setup_tracing
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agntcy_identity_client import VaultConfig

# ── Configuration ─────────────────────────────────────────────────────────────
KC_A_URL = os.environ.get("KC_A_URL", "http://keycloak-a:8080").rstrip("/")
KC_A_REALM = os.environ.get("KC_A_REALM", "org-a")
KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")

OPENCODE_CLIENT_ID = os.environ.get("OPENCODE_CLIENT_ID", "opencode-agent")
TRIAGE_CLIENT_ID = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")

SARAH_USER = os.environ.get("SARAH_USER", "sarah")
SARAH_EMAIL = os.environ.get("SARAH_EMAIL", "sarah@org-a.example")

IDJAG_ISSUER_URL = os.environ.get("IDJAG_ISSUER_URL", "http://idjag-issuer:9000").rstrip("/")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
TRIAGE_AGENT_URL = os.environ.get("TRIAGE_AGENT_URL", "http://envoy-org-b:10000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
VC_ISSUER_URL = os.environ.get("VC_ISSUER_URL", "http://vc-issuer:9003").rstrip("/")
EGRESS_PDP_URL = os.environ.get("EGRESS_PDP_URL", "http://envoy-org-a:12000").rstrip("/")
JAEGER_UI_URL = os.environ.get("JAEGER_UI_URL", "")  # e.g. "http://localhost:16686" — blank hides the trace link

# The real task lifecycle — this is the only service /api/run actually calls.
OPENCODE_AGENT_URL = os.environ.get("OPENCODE_AGENT_URL", "http://opencode-agent:8100").rstrip("/")
OPENCODE_MODEL = os.environ.get("OPENCODE_MODEL", "ollama/qwen2.5-coder:7b")
# Headroom over the agent's own OPENCODE_TIMEOUT (its opencode-plan LLM-call
# budget) plus the rest of the lifecycle that runs after it.
RUN_TIMEOUT = float(os.environ.get("OPENCODE_TIMEOUT", "240")) + 60

# Public reference links for the "Access these services" legend — separate
# from KC_A_URL/KC_B_URL above (those are for internal token calls). Blank
# hides the corresponding legend entry.
GITEA_UI_URL = os.environ.get("GITEA_UI_URL", "")
GITEA_ADMIN_USER = os.environ.get("GITEA_ADMIN_USER", "demo-admin")
KC_A_UI_URL = os.environ.get("KC_A_UI_URL", "")
KC_B_UI_URL = os.environ.get("KC_B_UI_URL", "")

# CIMD — org-a's local trust authority, backed by a Vault transit signing key
# (see identity-node-init.py for the registration bootstrap this depends on).
# Only VAULT_CFG.key_name/common_name are shown here for reference; the
# actual CIMD calls happen inside opencode-agent now.
VAULT_CFG = VaultConfig.from_env()
ORG_A_COMMON_NAME = VAULT_CFG.common_name

SCAN_REPO = os.environ.get("SCAN_REPO", "demo-admin/payments-service")

KC_A_ISSUER = f"{KC_A_URL}/realms/{KC_A_REALM}"
KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Cross-Domain Demo", version="0.1.0")
setup_tracing("webapp")
FastAPIInstrumentor.instrument_app(app)


class RunBody(BaseModel):
    cve: str = "CVE-2024-12345"
    repo: str = SCAN_REPO


# ── /api/run — proxy to the real OpenCode Agent ───────────────────────────────

@app.post("/api/run")
async def run_all(body: RunBody) -> JSONResponse:
    """Run the real task lifecycle at opencode-agent and return its steps
    verbatim for the webapp to animate."""
    try:
        async with httpx.AsyncClient(timeout=RUN_TIMEOUT) as client:
            r = await client.post(
                f"{OPENCODE_AGENT_URL}/api/run",
                json={"repo": body.repo, "cve_override": body.cve},
            )
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"ok": False, "steps": [], "trace_id": current_trace_id(), "error": str(exc)},
            status_code=502,
        )


# ── Utility endpoints ─────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/api/config")
def config() -> JSONResponse:
    return JSONResponse({
        "kc_a_url": KC_A_URL,
        "kc_a_realm": KC_A_REALM,
        "kc_a_issuer": KC_A_ISSUER,
        "kc_b_url": KC_B_URL,
        "kc_b_realm": KC_B_REALM,
        "kc_b_issuer": KC_B_ISSUER,
        "opencode_client_id": OPENCODE_CLIENT_ID,
        "triage_client_id": TRIAGE_CLIENT_ID,
        "sarah_user": SARAH_USER,
        "sarah_email": SARAH_EMAIL,
        "opencode_agent_url": OPENCODE_AGENT_URL,
        "opencode_model": OPENCODE_MODEL,
        "idjag_issuer_url": IDJAG_ISSUER_URL,
        "identity_node_url": IDENTITY_NODE_URL,
        "vc_issuer_url": VC_ISSUER_URL,
        "egress_pdp_url": EGRESS_PDP_URL,
        "triage_agent_url": TRIAGE_AGENT_URL,
        "dir_apiserver_url": DIR_APISERVER_URL or "not configured",
        "org_a_common_name": ORG_A_COMMON_NAME,
        "vault_key_name": VAULT_CFG.key_name,
        "scan_repo": SCAN_REPO,
        "jaeger_ui_url": JAEGER_UI_URL,
        "gitea_ui_url": GITEA_UI_URL,
        "gitea_admin_user": GITEA_ADMIN_USER,
        "kc_a_ui_url": KC_A_UI_URL,
        "kc_b_ui_url": KC_B_UI_URL,
    })


# ── Static files & SPA root ───────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse("static/index.html")
