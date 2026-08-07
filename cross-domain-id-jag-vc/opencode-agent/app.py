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
  5    Task-scoped agent badge: a W3C Verifiable Credential built here,
       signed with org-a's Vault trust-authority key, published to the
       Identity Node (/v1alpha1/vc/publish) and verified back by it
  5b-5e Reading Org B's source is itself a cross-domain act, so it gets its
       OWN narrower assertion: mint (gitea:read, repo-bound, intent=
       scan-source) → Org A egress PDP → redeem at Keycloak B → fetch the
       file through Envoy B + inline OPA
  6    The work: OpenCode analyses that real source → CWE finding …
  6b   … and the real OpenCode agent produces the remediation analysis
       (non-fatal: status=skipped when Ollama/API key is unavailable)
  7    Directory: push turn record (OASF) → CID
  8    Directory: discover triage-agent
  9    RFC 8693 exchange (subject=Sarah, actor_token=badge) → Keycloak A
       (Keycloak's standard exchange; it does not process actor_token)
  10   Mint ID-JAG natively at Keycloak A (keycloak-idjag-spi,
       requested_token_type=id-jag, act_chain=[opencode],
       scope=triage:create). The badge rides along as actor_token here too —
       this is where authority is created, and the SPI verifies the badge
       against the org issuer's published JWKS and binds it to Sarah before
       signing.
  10b  Org A egress PDP check on the ID-JAG (Envoy A + OPA) before it
       leaves the org
  11   jwt-bearer redemption at Keycloak B → scoped access token
  12   POST /api/ticket → Org B (Envoy ingress OPA → Triage → Sub-Agent → PR)
"""

from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from pydantic import BaseModel

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import cimd as cimd_api
from agntcy_identity_client import directory as dir_api
from agntcy_identity_client import vc as vc_api
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
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000").rstrip("/")
EGRESS_PDP_URL = os.environ.get("EGRESS_PDP_URL", "http://envoy-org-a:12000").rstrip("/")
TRIAGE_AGENT_URL = os.environ.get("TRIAGE_AGENT_URL", "http://envoy-org-b:10000").rstrip("/")
DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "")  # e.g. "dir-apiserver:8888"
SCAN_REPO = os.environ.get("SCAN_REPO", "demo-admin/payments-service")
# Org B's resource boundary (Envoy B listener 10001), through which the source
# is fetched under a read-scoped assertion — never Gitea directly.
GITEA_RESOURCE_URL = os.environ.get("GITEA_RESOURCE_URL", "http://envoy-org-b:10001").rstrip("/")
SCAN_SOURCE_PATH = os.environ.get(
    "SCAN_SOURCE_PATH", "src/main/java/com/example/payments/PaymentLookupRepository.java")

# Real OpenCode (headless) + its model provider
OPENCODE_SERVER_URL = os.environ.get("OPENCODE_SERVER_URL", "http://opencode-server:4096").rstrip("/")
OPENCODE_MODEL = os.environ.get("OPENCODE_MODEL", "ollama/qwen2.5-coder:7b")
OPENCODE_TIMEOUT = float(os.environ.get("OPENCODE_TIMEOUT", "240"))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1").rstrip("/")
# Any OpenAI-compatible model server: local Ollama by default, or an on-prem
# vLLM/TGI/SGLang deployment (see opencode-server/entrypoint.sh).
LLM_BASE_URL = (os.environ.get("LLM_BASE_URL") or OLLAMA_BASE_URL).rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
BUILTIN_PROVIDERS = {
    "anthropic", "openai", "azure", "google", "vertex",
    "bedrock", "openrouter", "groq", "mistral", "deepseek", "xai",
}

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


def _decode_jwt_payload_unverified(token: str) -> dict:
    """Decode a JWT's payload for display only — no signature check. Used
    purely so the webapp's step toast has real claims to show; never used
    for a trust decision (every token here is independently, cryptographically
    verified server-side by the service that consumes it)."""
    import base64

    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return {}


def _model_parts() -> tuple[str, str]:
    provider, _, model_id = OPENCODE_MODEL.partition("/")
    return provider, model_id or OPENCODE_MODEL


def _llm_headers() -> dict:
    return {"Authorization": f"Bearer {LLM_API_KEY}"} if LLM_API_KEY else {}


@app.get("/health")
def health():
    return {"status": "ok", "agent": "opencode", "realm": KC_A_REALM}


@app.get("/api/config")
async def config():
    opencode_status: dict = {"reachable": False}
    llm_status: dict = {"reachable": False}
    async with httpx.AsyncClient(timeout=3) as client:
        try:
            r = await client.get(f"{OPENCODE_SERVER_URL}/global/health")
            if r.status_code == 200:
                opencode_status = {"reachable": True, **r.json()}
        except Exception:  # noqa: BLE001
            pass
        provider, _ = _model_parts()
        if provider in BUILTIN_PROVIDERS:
            llm_status = {"provider": provider, "type": "built-in cloud provider",
                          "note": "credentials come from the provider's env var"}
        else:
            llm_status = {"provider": provider, "base_url": LLM_BASE_URL,
                          "authenticated": bool(LLM_API_KEY), "reachable": False}
            try:
                r = await client.get(f"{LLM_BASE_URL}/models", headers=_llm_headers())
                llm_status["reachable"] = r.status_code == 200
            except Exception:  # noqa: BLE001
                pass
    return {
        "kc_a": KC_A_URL, "kc_a_realm": KC_A_REALM,
        "kc_b": KC_B_URL, "kc_b_realm": KC_B_REALM,
        "opencode_client": OPENCODE_CLIENT_ID,
        "triage_client": TRIAGE_CLIENT_ID,
        "identity_node": IDENTITY_NODE_URL,
        "egress_pdp": EGRESS_PDP_URL,
        "triage_agent": TRIAGE_AGENT_URL,
        "dir_apiserver": DIR_APISERVER_URL or "not configured",
        "vault_key_name": VAULT_CFG.key_name,
        "org_a_common_name": VAULT_CFG.common_name,
        "opencode_server_url": OPENCODE_SERVER_URL,
        "opencode_model": OPENCODE_MODEL,
        "opencode_server": opencode_status,
        "llm": llm_status,
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

    # Cheap pre-probe so an unreachable model server skips fast instead of
    # timing out. Applies to any self-hosted OpenAI-compatible endpoint
    # (local Ollama, on-prem vLLM/TGI/SGLang); built-in cloud providers
    # authenticate via their own env vars and are not probed here.
    if provider not in BUILTIN_PROVIDERS:
        try:
            r = await client.get(f"{LLM_BASE_URL}/models", headers=_llm_headers(), timeout=3)
            r.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            s.update(status="skipped", result={
                "note": f"model endpoint not reachable at {LLM_BASE_URL} — plan skipped, "
                        "identity chain continues",
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


# ── Step 6: the scan — OpenCode analyses source fetched through the chain ─────

_MOCK_FINDING = {
    "id": "CWE-89",
    "title": "SQL injection via string-concatenated query",
    "severity": "HIGH",
    "file": SCAN_SOURCE_PATH,
    "detail": "User input is concatenated directly into a SQL statement.",
}


def _parse_finding(text: str) -> dict:
    """Pull a structured finding out of the model's reply.

    Kept forgiving on purpose: a local model's JSON is not reliable enough to
    hard-fail an identity demo over. If a JSON object is present we use it; a
    bare CWE reference is enough to still report a real, model-derived id.
    """
    match = re.search(r"\{.*\}", text, re.S)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict) and parsed.get("id"):
                return {k: parsed.get(k) for k in ("id", "title", "severity", "file", "detail")
                        if parsed.get(k)}
        except json.JSONDecodeError:
            pass
    cwe = re.search(r"CWE[-\s]?(\d+)", text, re.I)
    if cwe:
        return {"id": f"CWE-{cwe.group(1)}", "title": text.strip().splitlines()[0][:160],
                "severity": "HIGH", "file": SCAN_SOURCE_PATH}
    return {}


async def _opencode_scan(client: httpx.AsyncClient, repo: str, source: str,
                         scoped_intent: str, use_real: bool = True) -> dict:
    """Have OpenCode analyse the source that was fetched under the read assertion.

    This is the scan: a real agent reading real code obtained through the
    delegation chain, not a hardcoded CVE constant. Reported as a CWE, since a
    weakness we authored into a demo fixture has no CVE id.
    """
    s = _s("scan",
           f"6. OpenCode analyses {SCAN_SOURCE_PATH} (fetched under the read assertion)",
           f"{len(source)} bytes from {repo}  agent=plan  model={OPENCODE_MODEL}")
    if not source:
        s.update(status="error", error="no source was fetched — nothing to analyse")
        return s

    if not use_real:
        s.update(status="ok", result={
            "repo": repo, "mock": True, "badge_intent": scoped_intent,
            "finding": dict(_MOCK_FINDING),
            "note": "[MOCKED analysis] source really was fetched through the trust chain; "
                    "only the model call is skipped",
        })
        return s

    provider, model_id = _model_parts()
    prompt = (
        "You are a security code reviewer. Analyse the Java source below and "
        "identify the single most serious security weakness.\n"
        "Do not read files or run tools — everything you need is inline.\n"
        "Reply with ONLY a JSON object: "
        '{"id":"CWE-<n>","title":"<short>","severity":"HIGH|MEDIUM|LOW",'
        f'"file":"{SCAN_SOURCE_PATH}","detail":"<one sentence>"}}\n\n'
        f"```java\n{source[:6000]}\n```"
    )
    try:
        r = await client.post(f"{OPENCODE_SERVER_URL}/session",
                              json={"title": f"scan {repo}"}, timeout=15)
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
        info_error = (data.get("info") or {}).get("error")
        if info_error:
            message = (info_error.get("data") or {}).get("message", str(info_error))
            s.update(status="ok", result={
                "repo": repo, "mock": True, "badge_intent": scoped_intent,
                "finding": dict(_MOCK_FINDING),
                "note": f"model unavailable ({message[:150]}) — source was still fetched "
                        f"through the trust chain; finding fell back to the known fixture",
            })
            return s
        text = "\n".join(p.get("text", "") for p in data.get("parts", [])
                         if p.get("type") == "text" and p.get("text")).strip()
        finding = _parse_finding(text)
        if not finding:
            s.update(status="ok", result={
                "repo": repo, "mock": True, "badge_intent": scoped_intent,
                "finding": dict(_MOCK_FINDING), "raw": text[:400],
                "note": "model reply was not parseable as a finding — fell back to the "
                        "known fixture; the source itself was genuinely fetched and sent",
            })
            return s
        s.update(status="ok", result={
            "repo": repo, "model": OPENCODE_MODEL, "session_id": session_id,
            "badge_intent": scoped_intent, "finding": finding,
            "decision": "cross-domain-remediation → Org B Triage",
            "note": "real analysis of source read from Org B under a gitea:read assertion",
        })
    except Exception as exc:  # noqa: BLE001
        s.update(status="ok", result={
            "repo": repo, "mock": True, "badge_intent": scoped_intent,
            "finding": dict(_MOCK_FINDING), "error": str(exc)[:200],
            "note": "model call failed — source was still fetched through the trust chain",
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
                s.update(status="ok", token_preview=sarah_token[:48] + "…",
                         result={"token": sarah_token,
                                 "claims": _decode_jwt_payload_unverified(sarah_token)})
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

        # ── Step 5: the task-scoped agent badge ─────────────────────────────
        # The intent is the policy-scoped one from step 4 — the credential is
        # valid for THIS task and no other.
        # The badge is a real W3C Verifiable Credential: built here, signed
        # with org-a's Vault trust-authority key (the same key CIMD proofs
        # use), published to the Identity Node's VC API, and verified back by
        # the node. The node has no "issue" verb — it registers credentials
        # the issuer already signed — so the trust anchor is org-a's
        # registered issuer key, not any single service's keypair.
        s = _s("resolve-badge",
               f"5. Task-scoped agent badge VC (intent={scoped_intent}) — Vault-signed, published to identity-node",
               f"POST {IDENTITY_NODE_URL}/v1alpha1/vc/publish  +  /v1alpha1/vc/verify  (issuer={VAULT_CFG.issuer})")
        try:
            issued = await vc_api.issue_badge(
                client, IDENTITY_NODE_URL, VAULT_CFG,
                subject_id=cimd_id or f"AGNTCY-{OPENCODE_CLIENT_ID}",
                caps=["scan", "remediate", "delegate", "gitea:read"],
                # What OpenCode may grant onward — the scope Keycloak A permits
                # it to assert for Triage. Distinct from what it does itself.
                delegatable=["openid", "triage:create"],
                delegating_user=SARAH_EMAIL,
                intent=scoped_intent,
                act_chain=[OPENCODE_CLIENT_ID],
            )
            if not issued["verified"]:
                s.update(status="error", error="identity-node reported the published badge as invalid")
                steps.append(s)
                return _fail()
            badge = issued["badge"]
            s.update(status="ok", token_preview=badge[:48] + "…", result={
                "token": badge,
                "credential_id": issued["credential_id"],
                "issuer": issued["issuer"],
                # One identity, one live credential: an existing valid one is
                # reused rather than piling up contradictory entries under the
                # same id. Per-task narrowing lives in the ID-JAG assertion.
                "reused_existing_credential": issued.get("reused", False),
                # Superseded credentials are revoked at the registry so one
                # identity resolves to one live credential; the Directory
                # keeps the full history for audit.
                "superseded_credentials": issued.get("superseded", []),
                "verified_by": "identity-node /v1alpha1/vc/verify",
                "well_known": f"{IDENTITY_NODE_URL}/v1alpha1/vc/"
                              f"{cimd_id or 'AGNTCY-' + OPENCODE_CLIENT_ID}/.well-known/vcs.json",
                "claims": issued["document"],
            })
        except Exception as exc:  # noqa: BLE001
            s.update(status="error", error=str(exc))
            steps.append(s)
            return _fail()
        steps.append(s)

        # ── Steps 5b-5e: obtain Org B source through the trust chain ────────
        # The repository belongs to Org B, so reading it is itself a
        # cross-domain privileged act. It gets its OWN assertion, minted
        # narrower than the remediation one: gitea:read, bound to this repo,
        # intent=scan-source. Two minimal assertions rather than one broad.
        read_assertion = ""
        s = _s("mint-read-idjag",
               f"5b. Mint READ assertion at Keycloak A — scope=gitea:read, resource={repo}",
               f"POST {KC_A_TOKEN_EP}  requested_token_type=id-jag  scope=openid gitea:read")
        try:
            r = await client.post(KC_A_TOKEN_EP, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": OPENCODE_CLIENT_ID,
                "client_secret": OPENCODE_CLIENT_SECRET,
                "subject_token": sarah_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                # Same badge gate as the remediation mint (see keycloak-idjag-spi).
                "actor_token": badge,
                "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "audience": KC_B_ISSUER,
                "scope": "openid gitea:read",
                "target_client_id": OPENCODE_CLIENT_ID,
                "act_chain": OPENCODE_CLIENT_ID,
                "intent": "scan-source",
                "resource": repo,
            })
            if r.status_code == 200:
                read_assertion = r.json()["access_token"]
                s.update(status="ok", token_preview=read_assertion[:48] + "…", result={
                    "assertion": read_assertion,
                    "claims": _decode_jwt_payload_unverified(read_assertion),
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

        s = _s("read-egress-check",
               "5c. Org A egress PDP on the READ assertion — may Sarah delegate a read to Org B?",
               f"POST {EGRESS_PDP_URL}/api/egress-check  Bearer=<read assertion>")
        try:
            r = await client.post(f"{EGRESS_PDP_URL}/api/egress-check",
                                  headers={"Authorization": f"Bearer {read_assertion}"})
            if r.status_code == 200:
                s.update(status="ok", result={
                    "decision": r.headers.get("x-agntcy-policy-decision", "ALLOW"),
                    "rule": r.headers.get("x-agntcy-policy-rule", ""),
                    "enforced_by": r.headers.get("x-agntcy-policy-enforcer", ""),
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

        read_token = ""
        s = _s("kc-b-read-exchange",
               "5d. Redeem the READ assertion at Keycloak B → access token carrying gitea:read only",
               f"POST {KC_B_TOKEN_EP}  grant_type=jwt-bearer  client={OPENCODE_CLIENT_ID}")
        try:
            r = await client.post(KC_B_TOKEN_EP, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": read_assertion,
                "client_id": OPENCODE_CLIENT_ID,
                "client_secret": OPENCODE_CLIENT_SECRET,
                "scope": "openid gitea:read",
            })
            if r.status_code == 200:
                read_token = r.json()["access_token"]
                s.update(status="ok", token_preview=read_token[:48] + "…", result={
                    "token": read_token,
                    "claims": _decode_jwt_payload_unverified(read_token),
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

        source_text = ""
        s = _s("fetch-source",
               f"5e. Fetch {SCAN_SOURCE_PATH} from Org B through Envoy B + inline OPA",
               f"GET {GITEA_RESOURCE_URL}/api/gitea/source/{repo}/{SCAN_SOURCE_PATH}")
        try:
            r = await client.get(
                f"{GITEA_RESOURCE_URL}/api/gitea/source/{repo}/{SCAN_SOURCE_PATH}",
                headers={
                    "Authorization": f"Bearer {read_token}",
                    "X-AGNTCY-Actor-Token": f"Bearer {read_assertion}",
                },
            )
            if r.status_code == 200:
                payload = r.json()
                source_text = payload.get("file", {}).get("source", "")
                s.update(status="ok", result={
                    "repository": payload.get("file", {}).get("repository"),
                    "path": payload.get("file", {}).get("path"),
                    "bytes": payload.get("file", {}).get("size"),
                    "policy": payload.get("policy"),
                    "source": source_text,
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

        # ── Step 6: the work begins — OpenCode analyses the real source ─────
        scan_step = await _opencode_scan(client, repo, source_text, scoped_intent, use_real_opencode)
        steps.append(scan_step)
        finding = (scan_step.get("result") or {}).get("finding") or {}
        cve = finding.get("id") or cve

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
        # the Identity Node in step 5; delegation semantics are carried via the
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
                    "token": exchanged_token,
                    "claims": _decode_jwt_payload_unverified(exchanged_token),
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
                # The badge travels with the request that MINTS authority, not
                # just with step 9's standard exchange (which Keycloak ignores).
                # keycloak-idjag-spi verifies it against the org issuer's JWKS and
                # requires that it attests delegation by this same subject.
                "actor_token": badge,
                "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "audience": KC_B_ISSUER,
                "scope": "openid triage:create",
                "target_client_id": TRIAGE_CLIENT_ID,
                "act_chain": OPENCODE_CLIENT_ID,
                "intent": "create-pr-fix",
            })
            if r.status_code == 200:
                assertion = r.json()["access_token"]
                s.update(status="ok", token_preview=assertion[:48] + "…", result={
                    "assertion": assertion,
                    "claims": _decode_jwt_payload_unverified(assertion),
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
                result = r.json() if r.content else {"decision": "ALLOW"}
                result.update({
                    "rule": r.headers.get("x-agntcy-policy-rule", ""),
                    "enforced_by": r.headers.get("x-agntcy-policy-enforcer", ""),
                    "delegation_depth": r.headers.get("x-agntcy-delegation-depth", ""),
                })
                s.update(status="ok", result=result)
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
                s.update(status="ok", token_preview=triage_token[:48] + "…",
                         result={"token": triage_token,
                                 "claims": _decode_jwt_payload_unverified(triage_token)})
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
