# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""OpenCode Agent (Org A) — real OpenCode + AGNTCY identity harness.

The agent's LLM work comes from a real OpenCode (opencode.ai) instance
running headless in the opencode-server container; this service is the
agent's identity harness, executing the task lifecycle Sarah delegates:
authenticate → register identity → policy-scoped badge → work → delegate.

Task lifecycle (POST /api/run):
  1    Sarah OIDC password grant → Keycloak A → delegated access token
  2    OpenCode registers ITS OWN identity: CIMD generate id
       AGNTCY-opencode-agent at the Identity Node (Vault-signed proof,
       org-a trust authority)
  3    resolve id → ResolverMetadata + JWK
  4    badge request with Sarah's access token → Envoy A + inline OPA
       (/api/badge-scope-check) → ALLOW + scoped-down intent for THIS task
  5    vc-issuer mints the task-scoped badge (intent from the OPA decision,
       e.g. scan-remediate:demo-admin/payments-service) + verify
  6    Only now, the work: scan (mocked) …
  6b   … and the real OpenCode agent produces the remediation analysis
       (non-fatal: status=skipped when Ollama/API key is unavailable)
  7    Directory: push turn record (OASF) → CID
  8    Directory: discover triage-agent
  9    RFC 8693 exchange (subject=Sarah, actor_token=badge) → Keycloak A
  10   Mint ID-JAG natively at Keycloak A (keycloak-idjag-spi,
       requested_token_type=id-jag, act_chain=[opencode],
       scope=triage:create)
  10b  Org A egress PDP check on the ID-JAG (Envoy A + OPA) before it
       leaves the org
  11   jwt-bearer redemption at Keycloak B → scoped access token
  12   POST /api/ticket → Org B (Envoy ingress OPA → Triage → Sub-Agent → PR)
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from pydantic import BaseModel

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import cimd as cimd_api
from agntcy_identity_client import directory as dir_api
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
TRIAGE_AGENT_URL = os.environ.get("TRIAGE_AGENT_URL", "http://envoy-org-b:10000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
SCAN_REPO = os.environ.get("SCAN_REPO", "demo-admin/payments-service")

# Real OpenCode (headless) + its model provider
OPENCODE_SERVER_URL = os.environ.get("OPENCODE_SERVER_URL", "http://opencode-server:4096").rstrip("/")
OPENCODE_MODEL = os.environ.get("OPENCODE_MODEL", "ollama/qwen2.5-coder:7b")
OPENCODE_TIMEOUT = float(os.environ.get("OPENCODE_TIMEOUT", "240"))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1").rstrip("/")

REQUESTED_ACTION = "scan-remediate"

VAULT_CFG = VaultConfig.from_env()

KC_A_TOKEN_EP = f"{KC_A_URL}/realms/{KC_A_REALM}/protocol/openid-connect/token"
KC_B_TOKEN_EP = f"{KC_B_URL}/realms/{KC_B_REALM}/protocol/openid-connect/token"
KC_B_ISSUER = f"{KC_B_URL}/realms/{KC_B_REALM}"

app = FastAPI(title="OpenCode Agent (Org A) — real OpenCode + identity harness",
              version="0.2.0")
setup_tracing("opencode-agent")
FastAPIInstrumentor.instrument_app(app)


class RunRequest(BaseModel):
    repo: str = ""
    cve_override: str = ""
    # Real-LLM fallback: the identity/delegation chain (steps 1-5, 7-12) is
    # unaffected by model-provider reliability — only opencode-plan (step 6b)
    # makes a real LLM call. When the provider is flaky, callers can request
    # a fast, clearly-labeled mock plan instead of waiting out a real attempt.
    use_real_opencode: bool = True


def _s(id: str, title: str, detail: str = "") -> dict:
    return {"id": id, "title": title, "detail": detail}


def _ok(status: str) -> bool:
    return status in ("ok", "denied", "skipped")


def _model_parts() -> tuple[str, str]:
    provider, _, model_id = OPENCODE_MODEL.partition("/")
    return provider, model_id or OPENCODE_MODEL


@app.get("/health")
def health():
    return {"status": "ok", "agent": "opencode", "realm": KC_A_REALM}


@app.get("/api/config")
async def config():
    opencode_status: dict = {"reachable": False}
    ollama_status: dict = {"reachable": False}
    async with httpx.AsyncClient(timeout=3) as client:
        try:
            r = await client.get(f"{OPENCODE_SERVER_URL}/global/health")
            if r.status_code == 200:
                opencode_status = {"reachable": True, **r.json()}
        except Exception:  # noqa: BLE001
            pass
        try:
            r = await client.get(f"{OLLAMA_BASE_URL}/models")
            ollama_status = {"reachable": r.status_code == 200}
        except Exception:  # noqa: BLE001
            pass
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
        "dir_apiserver": DIR_APISERVER_URL or "not configured",
        "vault_key_name": VAULT_CFG.key_name,
        "org_a_common_name": VAULT_CFG.common_name,
        "opencode_server_url": OPENCODE_SERVER_URL,
        "opencode_model": OPENCODE_MODEL,
        "opencode_server": opencode_status,
        "ollama": ollama_status,
    }


# ── Steps 2-3: the agent registers its own identity (Identity Node) ───────────

async def _cimd_generate(client: httpx.AsyncClient, sub: str) -> dict:
    s = _s("cimd-generate-id",
           f"2. OpenCode registers its identity — generate id for {sub} "
           f"(Vault-signed proof, {VAULT_CFG.common_name} trust authority) → Identity Node",
           f"POST {IDENTITY_NODE_URL}/v1alpha1/id/generate  iss={VAULT_CFG.issuer}  sub={sub}")
    try:
        res = await cimd_api.generate_id(client, IDENTITY_NODE_URL, VAULT_CFG, sub)
        result: dict = {"id": res["id"]}
        if res["already_registered"]:
            result["note"] = "already registered"
        else:
            result["controller"] = res["controller"]
        s.update(status="ok", result=result)
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    return s


async def _cimd_resolve(client: httpx.AsyncClient, cimd_id: str) -> dict:
    s = _s("cimd-resolve-id",
           f"3. Resolve id {cimd_id} → ResolverMetadata + JWK",
           f"POST {IDENTITY_NODE_URL}/v1alpha1/id/resolve  id={cimd_id}")
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
    return s


# ── Step 6b: real OpenCode remediation analysis ───────────────────────────────

async def _opencode_plan(client: httpx.AsyncClient, cve: str, repo: str,
                         scoped_intent: str, use_real: bool = True) -> dict:
    """Ask the real OpenCode agent (read-only `plan` agent) for a remediation plan.

    Non-fatal by design: reviewers without Ollama running still get a green
    identity-chain run; this step then reports status=skipped. Callers can
    also request use_real=False up front — a deliberate, instant fallback to
    a clearly-labeled mock plan, independent of whatever's currently making
    the real model provider unreliable.
    """
    provider, model_id = _model_parts()
    s = _s("opencode-plan",
           f"6b. OpenCode ({'real agent, ' + OPENCODE_MODEL if use_real else 'mocked'}) analyzes the CVE → remediation plan",
           f"POST {OPENCODE_SERVER_URL}/session + /session/<id>/message  agent=plan")

    if not use_real:
        s.update(status="ok", result={
            "mock": True,
            "model": "mock",
            "plan": (
                "[MOCKED — real OpenCode call skipped by request]\n"
                "- Affected dependency: example-lib (illustrative — not a real scan)\n"
                "- Fix: bump to latest patched version\n"
                f"- Branch: fix/{cve.lower()}\n"
                f"- PR title: Security: remediate {cve} in {repo}\n"
                "- Sub-agent: bump the dependency version and open the PR"
            ),
        })
        return s

    # Cheap pre-probe so a missing local Ollama skips fast instead of timing out.
    if provider == "ollama":
        try:
            r = await client.get(f"{OLLAMA_BASE_URL}/models", timeout=2)
            r.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            s.update(status="skipped", result={
                "note": f"Ollama not reachable at {OLLAMA_BASE_URL} — plan skipped, "
                        "identity chain continues (start Ollama on the host to enable)",
                "error": str(exc)[:200],
            })
            return s

    prompt = (
        f"Remediation plan needed: {cve} (HIGH, known RCE) in repository "
        f"{repo}, scope={scoped_intent}. No file or tool access is "
        f"available — do not read files or run tools; reason from general "
        f"knowledge only. Reply in plain text, at most 5 short lines: "
        f"affected dependency, fix (version bump), branch name, PR title, "
        f"the change a sub-agent should make."
    )
    try:
        r = await client.post(
            f"{OPENCODE_SERVER_URL}/session",
            json={"title": f"remediate {cve} in {repo}"},
            timeout=15,
        )
        r.raise_for_status()
        session_id = r.json()["id"]

        r = await client.post(
            f"{OPENCODE_SERVER_URL}/session/{session_id}/message",
            json={
                "model": {"providerID": provider, "modelID": model_id},
                "agent": "plan",
                "parts": [{"type": "text", "text": prompt}],
            },
            timeout=OPENCODE_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        # OpenCode returns 200 with an embedded error when the provider/model
        # fails (e.g. model not pulled in Ollama) — treat that as skipped.
        info_error = (data.get("info") or {}).get("error")
        if info_error:
            message = (info_error.get("data") or {}).get("message", str(info_error))
            s.update(status="skipped", result={
                "note": f"OpenCode provider error — plan skipped ({message[:200]}). "
                        f"If using Ollama: `ollama pull {_model_parts()[1]}`",
            })
            return s
        parts = data.get("parts", [])
        plan_text = "\n".join(
            p.get("text", "") for p in parts if p.get("type") == "text" and p.get("text")
        ).strip()
        if not plan_text:
            s.update(status="skipped", result={
                "note": "OpenCode returned no text parts — plan skipped",
            })
            return s
        s.update(status="ok", result={
            "model": OPENCODE_MODEL,
            "session_id": session_id,
            "plan": plan_text[:2000],
        })
    except Exception as exc:  # noqa: BLE001
        s.update(status="skipped", result={
            "note": "OpenCode plan failed — step skipped, identity chain continues",
            "error": str(exc)[:300],
        })
    return s


# ── Live token stream for opencode-plan ───────────────────────────────────────
#
# opencode-server exposes a real SSE event stream (GET /event) with genuine
# incremental deltas (message.part.delta, field=text/reasoning) as the model
# generates — this relays just those, reduced to a minimal shape, so the
# webapp can show the actual plan text appearing live instead of a generic
# spinner for the couple of minutes _opencode_plan's blocking call can take.
# Not session-scoped: fine for this demo's single-operator use, not a
# multi-tenant guarantee.

async def _plan_event_gen():
    yield "retry: 2000\n\n"
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", f"{OPENCODE_SERVER_URL}/event") as r:
                async for line in r.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    try:
                        evt = json.loads(line[len("data: "):])
                    except ValueError:
                        continue
                    etype = evt.get("type", "")
                    props = evt.get("properties", {}) or {}
                    if etype == "message.part.delta" and props.get("field") == "text":
                        yield f"data: {json.dumps({'kind': 'delta', 'text': props.get('delta', '')})}\n\n"
                    elif etype == "message.part.updated":
                        part = props.get("part") or {}
                        if part.get("type") == "reasoning":
                            yield f"data: {json.dumps({'kind': 'reasoning', 'text': part.get('text', '')})}\n\n"
                    elif etype == "session.next.step.started":
                        yield f"data: {json.dumps({'kind': 'step', 'agent': props.get('agent', '')})}\n\n"
                    elif etype == "server.heartbeat":
                        yield ": heartbeat\n\n"
    except Exception as exc:  # noqa: BLE001
        yield f"data: {json.dumps({'kind': 'error', 'error': str(exc)[:200]})}\n\n"


@app.get("/api/plan-stream")
async def plan_stream():
    return StreamingResponse(_plan_event_gen(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Steps 7-8: AGNTCY Directory ───────────────────────────────────────────────

async def _dir_push(cve: str, repo: str) -> dict:
    s = _s("dir-push", "7. Directory: push OpenCode turn record (OASF) → CID",
           f"gRPC Push({DIR_APISERVER_URL})  cve={cve}  repo={repo}")
    if not DIR_APISERVER_URL:
        s.update(status="ok", result={"cid": "", "note": "directory not configured"})
        return s
    try:
        from datetime import datetime, timezone
        record_dict = {
            "name": "opencode-agent",
            "version": "0.2.0",
            "schema_version": dir_api.OASF_SCHEMA_VERSION,
            "description": f"OpenCode agent turn: {cve} in {repo}",
            "authors": ["cross-domain-demo"],
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "skills": [
                {"name": "cybersecurity/vulnerability_management/dependency_security", "id": 100304},
                {"name": "software_engineering/code_quality/code_review", "id": 60701},
            ],
            "domains": [
                {"name": "technology/security", "id": 107},
            ],
            "annotations": {"cve": cve, "repo": repo, "turn": "remediation"},
        }
        cid = await asyncio.get_event_loop().run_in_executor(
            None, dir_api.push_record, DIR_APISERVER_URL, record_dict
        )
        s.update(status="ok", result={
            "cid": cid,
            "schema_version": dir_api.OASF_SCHEMA_VERSION,
            "agent": "opencode-agent",
        })
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    return s


async def _dir_search(agent_name: str = "triage-agent") -> dict:
    s = _s("dir-search", f"8. Directory: search name={agent_name} → agent record",
           f"gRPC SearchRecords({DIR_APISERVER_URL})  name={agent_name}")
    if not DIR_APISERVER_URL:
        s.update(status="ok", result={"found": False, "note": "directory not configured"})
        return s
    try:
        records = await asyncio.get_event_loop().run_in_executor(
            None, dir_api.search_by_name, DIR_APISERVER_URL, agent_name
        )
        found = len(records) > 0
        s.update(status="ok", result={
            "found": found,
            "record_name": records[0].get("name", "") if found else "",
            "count": len(records),
        })
    except Exception as exc:  # noqa: BLE001
        s.update(status="error", error=str(exc))
    return s


# ── Full task lifecycle ───────────────────────────────────────────────────────

@app.post("/api/run")
async def run(body: RunRequest | None = None):
    """Execute the task Sarah delegated: authenticate → register identity →
    policy-scoped badge → work → delegate cross-domain (steps 1-12)."""
    repo = (body.repo if body else "") or SCAN_REPO
    cve = (body.cve_override if body else "") or "CVE-2024-XXXX"
    use_real_opencode = body.use_real_opencode if body else True
    steps: list[dict] = []

    def _fail() -> JSONResponse:
        return JSONResponse({"ok": False, "steps": steps, "trace_id": current_trace_id()})

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
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Steps 2-3: OpenCode registers ITS OWN identity ──────────────────
        generate_step = await _cimd_generate(client, OPENCODE_CLIENT_ID)
        steps.append(generate_step)
        if generate_step.get("status") != "ok":
            return _fail()
        cimd_id = (generate_step.get("result") or {}).get("id", f"AGNTCY-{OPENCODE_CLIENT_ID}")
        resolve_step = await _cimd_resolve(client, cimd_id)
        steps.append(resolve_step)
        if resolve_step.get("status") != "ok":
            return _fail()

        # ── Step 4: badge request → Envoy A + OPA → scoped-down intent ─────
        # The agent presents Sarah's delegated access token plus the task it
        # wants a badge for; Org A's PDP verifies the token (KC-A JWKS) and
        # inline OPA decides whether — and how narrowly — to allow it.
        requested_intent = f"{REQUESTED_ACTION}:{repo}"
        s = _s("badge-scope-check",
               "4. Badge request — Sarah's OAuth token → Envoy A + OPA → scoped-down intent",
               f"POST {EGRESS_PDP_URL}/api/badge-scope-check  action={REQUESTED_ACTION}  repo={repo}")
        try:
            r = await client.post(
                f"{EGRESS_PDP_URL}/api/badge-scope-check",
                headers={
                    "Authorization": f"Bearer {sarah_token}",
                    "x-agntcy-requested-action": REQUESTED_ACTION,
                    "x-agntcy-requested-repo": repo,
                },
            )
            if r.status_code == 200:
                scoped_intent = r.headers.get("x-agntcy-scoped-intent", requested_intent)
                s.update(status="ok", result={
                    "decision": "ALLOW",
                    "scoped_intent": scoped_intent,
                    "rule": r.headers.get("x-agntcy-policy-rule", ""),
                    "enforced_by": r.headers.get("x-agntcy-policy-enforcer", ""),
                    "note": "policy scoped the badge to this task before any work ran",
                })
            else:
                s.update(status="error",
                         error=f"HTTP {r.status_code}: {r.text[:300]}",
                         result={"decision": "DENY"})
                steps.append(s)
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 5: vc-issuer mints the task-scoped badge ───────────────────
        # identity-node's REST API has no badge endpoints (CIMD id only), so
        # vc-issuer stands in with a real signed vc+jwt. The intent is the
        # policy-scoped one from step 4 — the badge is valid for THIS task.
        s = _s("resolve-badge",
               f"5. Task-scoped VC badge (intent={scoped_intent}) issue + verify → vc-issuer",
               f"POST {VC_ISSUER_URL}/vc/issue  +  POST {VC_ISSUER_URL}/vc/verify")
        try:
            r = await client.post(f"{VC_ISSUER_URL}/vc/issue", json={
                "id": OPENCODE_CLIENT_ID,
                "caps": ["scan", "remediate", "delegate"],
                "delegating_user": SARAH_EMAIL,
                "intent": scoped_intent,
                "act_chain": [OPENCODE_CLIENT_ID],
            })
            if r.status_code != 200:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return _fail()
            badge = r.json()["badge"]

            r = await client.post(f"{VC_ISSUER_URL}/vc/verify", json={"badge": badge})
            if r.status_code == 200 and r.json().get("valid"):
                s.update(status="ok", token_preview=badge[:48] + "…",
                         result={"badge_claims": r.json()["claims"]})
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 6: the work begins — scan (mocked) ─────────────────────────
        s = _s("scan",
               f"6. Scan repo (under task-scoped badge) → {cve} found (HIGH)",
               f"mock scan of {repo}")
        s.update(status="ok", result={
            "repo": repo, "cve": cve, "severity": "HIGH",
            "description": "Dependency with known RCE vulnerability",
            "decision": "cross-domain-remediation → Org B Triage",
            "badge_intent": scoped_intent,
            "note": "mocked scanner",
        })
        steps.append(s)

        # ── Step 6b: real OpenCode produces the remediation analysis ────────
        plan_step = await _opencode_plan(client, cve, repo, scoped_intent, use_real_opencode)
        steps.append(plan_step)
        plan_text = (plan_step.get("result") or {}).get("plan", "")

        # ── Steps 7-8: Directory turn record + triage-agent discovery ───────
        steps.append(await _dir_push(cve, repo))
        steps.append(await _dir_search(TRIAGE_CLIENT_ID))

        # ── Step 9: RFC 8693 token exchange at Keycloak A ───────────────────
        # NOTE: Keycloak 26.7's standard token exchange validates subject_token
        # for real, but does not itself verify actor_token or emit an RFC 8693
        # "act" claim (see README). The badge was independently verified against
        # vc-issuer in step 5; delegation semantics are carried forward via the
        # ID-JAG's act_chain claim.
        s = _s("kc-a-exchange",
               "9. RFC 8693 exchange (subject=Sarah, actor_token=badge) → Keycloak A",
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
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 10: Mint ID-JAG assertion for Org B triage-agent ──────────
        # Keycloak A itself mints this now, via a real grant_type=
        # token-exchange call (keycloak-idjag-spi), instead of the separate
        # idjag-issuer mock — see
        # https://github.com/agntcy/agent-identity-demos/discussions/18.
        # subject_token is step 9's real exchanged token, not a client-
        # supplied free-text email — Keycloak verifies its signature for
        # real (session.tokens().decode(...)).
        s = _s("mint-idjag",
               "10. Mint ID-JAG natively at Keycloak A (keycloak-idjag-spi, act_chain=[opencode], aud=KC-B, scope=triage:create)",
               f"POST {KC_A_TOKEN_EP}  grant_type=token-exchange  requested_token_type=id-jag  aud={KC_B_ISSUER}  scope=triage:create")
        try:
            r = await client.post(KC_A_TOKEN_EP, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": OPENCODE_CLIENT_ID,
                "client_secret": OPENCODE_CLIENT_SECRET,
                "subject_token": exchanged_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "audience": KC_B_ISSUER,
                "scope": "openid triage:create",
                "target_client_id": TRIAGE_CLIENT_ID,
                "act_chain": OPENCODE_CLIENT_ID,
                "intent": "create-pr-fix",
            })
            if r.status_code == 200:
                assertion = r.json()["access_token"]
                s.update(status="ok", token_preview=assertion[:48] + "…")
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 10b: Org A egress PDP check (Envoy A + inline OPA) ─────────
        # May Sarah delegate this scope to Org B? Envoy verifies the ID-JAG's
        # signature against Keycloak A's JWKS (it is minted natively by the
        # keycloak-idjag-spi now); OPA checks scope, intent, and
        # delegation-chain depth before the assertion ever leaves Org A.
        s = _s("egress-check",
               "10b. Egress PDP check — may Sarah delegate this scope to Org B? → Envoy A + OPA",
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
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 11: Redeem ID-JAG at Keycloak B ───────────────────────────
        s = _s("kc-b-exchange",
               "11. jwt-bearer grant at Keycloak B → scoped access token (triage:create, Sarah propagated)",
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
                return _fail()
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Step 12: Create ticket at Triage agent (via Org B Envoy) ────────
        s = _s("create-ticket",
               "12. POST /api/ticket → Org B (access token + ID-JAG actor token, intent=create-pr-fix)",
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
                    "plan": plan_text,
                },
                timeout=90,
            )
            if r.status_code in (200, 201):
                triage_data = r.json()
                s.update(status="ok" if triage_data.get("ok") else "error",
                         result={"ticket_id": triage_data.get("ticket_id", ""),
                                 "ok": triage_data.get("ok")})
                steps.append(s)
                # Flatten the Org B steps (triage + nested sub-agent) so the
                # full cross-domain run reads as one sequence.
                for ts in triage_data.get("steps", []):
                    steps.append(ts)
                    if ts.get("id") == "spawn-sub-agent" and isinstance(ts.get("result"), dict):
                        steps.extend(ts["result"].get("steps", []))
            else:
                s.update(status="error", error=f"HTTP {r.status_code}: {r.text[:300]}")
                steps.append(s)
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)

    return JSONResponse({
        "ok": all(_ok(s.get("status", "error")) for s in steps),
        "steps": steps,
        "trace_id": current_trace_id(),
    })
