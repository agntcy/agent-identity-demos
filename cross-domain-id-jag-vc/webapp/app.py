# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# assisted-by claude code claude-sonnet-4-6
"""Cross-Domain AI Agent Remediation Demo — webapp UI backend.

This file has no task-lifecycle logic of its own: /api/run sends an A2A task
directly to the Security Autonomous Agent. OpenCode is an internal planning
engine used by that agent, not a second agent or delegation hop. The webapp
animates the steps produced by the live agent. See opencode-agent/app.py for
the authoritative lifecycle — A2A dispatch → OAuth → CIMD + Agent Badge VC →
secondary Organization VC → two-VC VP verification → work → cross-domain
ID-JAG delegation. The UI therefore cannot show a security or A2A step that
did not run.

Endpoints
---------
GET  /                  — serve index.html
GET  /api/health        — liveness probe
GET  /api/config        — all service URLs / client IDs (informational)
POST /api/run           — A2A task to the Security Autonomous Agent
GET  /api/plan-stream   — live SSE relay of the agent's internal OpenCode planner
GET  /api/vault-keys    — read-only Transit key metadata (no key material)
GET  /api/registered-agents — Directory records + CIMD ids + published credentials
"""

from __future__ import annotations

import base64
import asyncio
import json
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from tracing import current_trace_id, setup_tracing
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import a2a
from agntcy_identity_client import directory as dir_api

# ── Configuration ─────────────────────────────────────────────────────────────
KC_A_URL = os.environ.get("KC_A_URL", "http://keycloak-a:8080").rstrip("/")
KC_A_REALM = os.environ.get("KC_A_REALM", "org-a")
KC_B_URL = os.environ.get("KC_B_URL", "http://keycloak-b:8080").rstrip("/")
KC_B_REALM = os.environ.get("KC_B_REALM", "org-b")

TRIAGE_CLIENT_ID = os.environ.get("TRIAGE_CLIENT_ID", "triage-agent")
SUB_AGENT_CLIENT_ID = os.environ.get("SUB_AGENT_CLIENT_ID", "sub-agent")

SECURITY_AUTONOMOUS_AGENT_CLIENT_ID = os.environ.get(
    "SECURITY_AUTONOMOUS_AGENT_CLIENT_ID", "security-autonomous-agent"
)
SECURITY_AUTONOMOUS_AGENT_PRINCIPAL = os.environ.get(
    "SECURITY_AUTONOMOUS_AGENT_PRINCIPAL",
    "service-account-security-autonomous-agent",
)

IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
TRIAGE_AGENT_URL = os.environ.get("TRIAGE_AGENT_URL", "http://envoy-org-b:10000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
EGRESS_PDP_URL = os.environ.get("EGRESS_PDP_URL", "http://envoy-org-a:12000").rstrip("/")
JAEGER_UI_URL = os.environ.get("JAEGER_UI_URL", "")  # e.g. "http://localhost:16686" — blank hides the trace link

# The merged Security Autonomous Agent owns the A2A endpoint and task
# lifecycle. OpenCode remains its private planning runtime.
SECURITY_AUTONOMOUS_AGENT_URL = os.environ.get(
    "SECURITY_AUTONOMOUS_AGENT_URL", "http://security-autonomous-agent:8100"
).rstrip("/")
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
# actual CIMD calls happen inside the Security Autonomous Agent.
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
    use_real_opencode: bool = True


# ── /api/run — A2A dispatch to the Security Autonomous Agent ─────────────────

@app.post("/api/run")
async def run_all(body: RunBody) -> JSONResponse:
    """Send an A2A task to the Security Autonomous Agent and animate the
    resulting cross-agent workflow artifacts."""
    try:
        async with httpx.AsyncClient(timeout=RUN_TIMEOUT) as client:
            result, task = await a2a.send_message(
                client,
                f"{SECURITY_AUTONOMOUS_AGENT_URL}/a2a",
                {
                    "repo": body.repo,
                    "cve": body.cve,
                    "use_real_opencode": body.use_real_opencode,
                },
            )
        dispatch_step = {
            "id": "a2a-autonomous-dispatch",
            "title": "0. A2A SendMessage → Security Autonomous Agent",
            "status": "ok",
            "detail": f"POST {SECURITY_AUTONOMOUS_AGENT_URL}/a2a  method=SendMessage",
            "result": {
                "a2a_protocol": a2a.A2A_VERSION,
                "remote_agent": "Security Autonomous Agent",
                "task_id": task.get("id"),
                "task_state": (task.get("status") or {}).get("state"),
                "role": "A2A server for the inbound task; A2A client when delegating to Triage",
            },
        }
        result["steps"] = [dispatch_step, *(result.get("steps") or [])]
        result.setdefault("a2a", {}).update({
            "webapp_task_id": task.get("id"),
            "webapp_task_state": (task.get("status") or {}).get("state"),
        })
        return JSONResponse(result, status_code=200 if result.get("ok") else 502)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"ok": False, "steps": [], "trace_id": current_trace_id(), "error": str(exc)},
            status_code=502,
        )


# ── /api/plan-stream — live token stream for the opencode-plan step ───────────
# Pure byte relay of the Security Autonomous Agent's SSE relay —
# no re-parsing, so the SSE framing is preserved exactly hop to hop.

@app.get("/api/plan-stream")
async def plan_stream():
    async def relay():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{SECURITY_AUTONOMOUS_AGENT_URL}/api/plan-stream") as r:
                    async for chunk in r.aiter_raw():
                        yield chunk
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'kind': 'error', 'error': str(exc)[:200]})}\n\n".encode()

    return StreamingResponse(relay(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── /api/vault-keys — read-only Transit engine visualization ──────────────────
# Transit never exposes private key material via any API call — signing
# happens inside Vault (see vault.py's vault_sign_rs256) and only a signature
# ever comes back out. So there is nothing secret in this response: it shows
# exactly what "the private key never leaves Vault" means operationally.

@app.get("/api/vault-keys")
async def vault_keys() -> JSONResponse:
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            r = await client.get(
                f"{VAULT_CFG.vault_addr}/v1/transit/keys",
                params={"list": "true"},
                headers={"X-Vault-Token": VAULT_CFG.vault_token},
            )
            r.raise_for_status()
            names = r.json().get("data", {}).get("keys", [])
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"reachable": False, "vault_addr": VAULT_CFG.vault_addr,
                                  "error": str(exc)[:200], "keys": []})

        keys = []
        for name in names:
            try:
                kr = await client.get(
                    f"{VAULT_CFG.vault_addr}/v1/transit/keys/{name}",
                    headers={"X-Vault-Token": VAULT_CFG.vault_token},
                )
                kr.raise_for_status()
            except Exception:  # noqa: BLE001
                continue
            d = kr.json().get("data", {})
            versions = d.get("keys", {})
            latest = str(d.get("latest_version", ""))
            keys.append({
                "name": name,
                "type": d.get("type"),
                "latest_version": d.get("latest_version"),
                "version_count": len(versions),
                "created": versions.get(latest, {}).get("creation_time"),
                "exportable": d.get("exportable"),
                "deletion_allowed": d.get("deletion_allowed"),
                "supports_signing": d.get("supports_signing"),
            })

    return JSONResponse({"reachable": True, "vault_addr": VAULT_CFG.vault_addr, "keys": keys})


# ── /api/registered-agents — CIMD ids + published credentials ─────────────────
# The W3C VC roles, mapped onto this demo's real components: the org's Vault
# trust authority is the Issuer (signs via /transit/sign — the private key
# never leaves Vault); the agent named below is the Holder (built its own
# credential, published it, and presents it at handoffs); the Verifier is
# whoever checks it before trusting it — the Identity Node on /vc/verify,
# Keycloak A's SPI before minting an ID-JAG, and the other side of every
# handoff since M14. There is no "list all registered identities" API on
# either the Identity Node or the Directory, so this is a curated view over
# this demo's known agents rather than a live enumeration.
_KNOWN_AGENTS = [
    ("Security Autonomous Agent", SECURITY_AUTONOMOUS_AGENT_CLIENT_ID, "org-a"),
    ("Triage Agent", TRIAGE_CLIENT_ID, "org-b"),
    ("Sub-Agent", SUB_AGENT_CLIENT_ID, "org-b"),
]


def _decode_jws_payload_unverified(jws: str) -> dict:
    """Decode a JOSE-enveloped VC's payload without checking its signature —
    display only, mirroring the same pattern used for JWTs elsewhere."""
    try:
        payload_b64 = jws.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return {}


def _parse_vc_timestamp(value: str | None) -> datetime:
    """Parse a W3C VC timestamp for display-time credential selection."""
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _current_credential_payload(vcs: list[dict]) -> dict:
    """Select the newest unexpired VC from Identity Node's history.

    Identity Node 0.0.23 returns newest credentials first and retains expired,
    unrevocable credentials.  Never assume the final array entry is current.
    """
    payloads = [
        _decode_jws_payload_unverified(enveloped.get("value", ""))
        for enveloped in vcs
    ]
    payloads = [payload for payload in payloads if payload]
    if not payloads:
        return {}
    now = datetime.now(timezone.utc)
    current = [
        payload for payload in payloads
        if not payload.get("expirationDate")
        or _parse_vc_timestamp(payload.get("expirationDate")) > now
    ]
    return max(
        current or payloads,
        key=lambda payload: _parse_vc_timestamp(payload.get("issuanceDate")),
    )


@app.get("/api/registered-agents")
async def registered_agents() -> JSONResponse:
    async with httpx.AsyncClient(timeout=5) as client:
        agents = []
        for name, client_id, org in _KNOWN_AGENTS:
            cimd_id = f"AGNTCY-{client_id}"
            entry = {
                "name": name, "client_id": client_id, "org": org,
                "holder_id": cimd_id, "resolved": False, "credential": None,
                "vcs_url": f"{IDENTITY_NODE_URL}/v1alpha1/vc/{cimd_id}/.well-known/vcs.json",
                "directory_record": None,
            }
            if DIR_APISERVER_URL:
                try:
                    records = await asyncio.get_event_loop().run_in_executor(
                        None, dir_api.search_agents_by_name, DIR_APISERVER_URL, client_id
                    )
                    record = next(
                        (
                            candidate for candidate in records
                            if (candidate.get("annotations") or {}).get("identity_id") == cimd_id
                        ),
                        None,
                    )
                    if record:
                        entry["directory_record"] = {
                            "record_type": (record.get("annotations") or {}).get("record_type", ""),
                            "identity_id": (record.get("annotations") or {}).get("identity_id", ""),
                            "badge_url": (record.get("annotations") or {}).get("badge_url", ""),
                            "oasf_digest": dir_api.oasf_digest(record),
                            "skills": record.get("skills", []),
                            "domains": record.get("domains", []),
                            "locators": record.get("locators", []),
                        }
                except Exception:  # noqa: BLE001
                    pass
            try:
                r = await client.post(f"{IDENTITY_NODE_URL}/v1alpha1/id/resolve",
                                       json={"id": cimd_id})
                if r.status_code == 200:
                    rm = r.json().get("resolverMetadata", {})
                    vm = (rm.get("verificationMethod") or [{}])[0]
                    entry["resolved"] = True
                    entry["verification_method_id"] = vm.get("id", "")
                    entry["issuer_kid"] = (vm.get("publicKeyJwk") or {}).get("kid", "")
            except Exception:  # noqa: BLE001
                pass
            try:
                r = await client.get(entry["vcs_url"])
                if r.status_code == 200:
                    vcs = r.json().get("vcs", [])
                    if vcs:
                        payload = _current_credential_payload(vcs)
                        subj = payload.get("credentialSubject", {})
                        entry["credential"] = {
                            "issuer": payload.get("issuer"),
                            "issuanceDate": payload.get("issuanceDate"),
                            "expirationDate": payload.get("expirationDate"),
                            "caps": subj.get("caps", []),
                            "delegatable": subj.get("delegatable", []),
                            "act_chain": subj.get("act_chain", []),
                        }
            except Exception:  # noqa: BLE001
                pass
            agents.append(entry)

    return JSONResponse({"identity_node_url": IDENTITY_NODE_URL, "agents": agents})


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
        "triage_client_id": TRIAGE_CLIENT_ID,
        "security_autonomous_agent_client_id": SECURITY_AUTONOMOUS_AGENT_CLIENT_ID,
        "security_autonomous_agent_principal": SECURITY_AUTONOMOUS_AGENT_PRINCIPAL,
        "security_autonomous_agent_url": SECURITY_AUTONOMOUS_AGENT_URL,
        "opencode_model": OPENCODE_MODEL,
        "identity_node_url": IDENTITY_NODE_URL,
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
