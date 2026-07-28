# Milestone: Real OpenCode agent (Org A) + policy-scoped badge lifecycle

Goal: replace the mock `opencode-agent` with the REAL open-source OpenCode
(headless `opencode-ai@1.18.7`, Ollama qwen2.5-coder:7b by default — free,
local, no API key) driven by an identity harness executing the confirmed
task lifecycle:

> OAuth → register own identity (CIMD) → Envoy A OPA scopes intent →
> task-scoped VC badge → work (scan mock + real OpenCode plan) →
> Directory → RFC 8693 → ID-JAG → egress OPA → KC-B → ticket

Triage and Sub-Agent stay mocks. Scan stays mocked.
`POST :8100/api/run` contract ({ok, steps[], trace_id}) preserved.

## Tasks

- [x] Shared lib `cross-domain-id-jag-vc/agntcy_identity_client/`
      (VaultConfig, vault.py, cimd.py, directory.py) extracted from webapp
- [x] Proto consolidation: shared `cross-domain-id-jag-vc/proto/` used by
      webapp, agent-dir-init, opencode-agent via compose additional_contexts
- [x] Refactor webapp/app.py to import the shared lib (behavior unchanged)
- [x] New `opencode-server/` — real OpenCode image (node:22 slim +
      opencode-ai@1.18.7; entrypoint generates opencode.json from env;
      plan agent, edit/bash denied; healthcheck /global/health)
- [x] Rewrite `opencode-agent/app.py` as identity harness with lifecycle:
      sarah-login → cimd-generate-id (opencode-agent's OWN id) →
      cimd-resolve-id → badge-scope-check (NEW, fatal on deny) →
      resolve-badge (task-scoped intent) → scan → opencode-plan (non-fatal)
      → dir-push → dir-search → kc-a-exchange → mint-idjag → egress-check
      → kc-b-exchange → create-ticket (+ flattened Org B steps)
- [x] Envoy A badge-scope PDP: new route /api/badge-scope-check, KC-A JWKS
      provider, badge-scope allow rule in egress.rego + 6 tests (16/16)
- [x] opencode-agent Dockerfile/requirements (+grpc, protoc, shared contexts)
- [x] Compose: opencode-server service; opencode-agent env/depends_on;
      envoy-org-a depends on keycloak-a; additional_contexts everywhere
- [x] .env.example: OLLAMA_BASE_URL, OPENCODE_MODEL, ANTHROPIC_API_KEY
      (optional), OPENCODE_TIMEOUT
- [x] README: real-OpenCode intro + lifecycle, Ollama prerequisite,
      Milestone 8 paragraph, ports/table/repo-layout updates, new reviewer
      verification section, webapp-divergence note, egress suite 16/16
- [x] Verify: OPA suites, compose config, image builds, stack run
      (with + without Ollama)

## Review

All verified live on 2026-07-28:

- OPA egress suite 16/16 (10 egress + 6 badge-scope); vc-issuer 9/9;
  `envoy --mode validate` OK; compose config OK; all 5 images built
- Full stack up (25 containers; one transient dir-zot panic on first cold
  start after volume reset — restart fixed it, documented behavior)
- `POST :8100/api/run` → **ok=true, 25 steps**, exact lifecycle order:
  sarah-login → cimd-generate-id (**AGNTCY-opencode-agent**, own identity) →
  cimd-resolve-id → badge-scope-check (**ALLOW +
  scan-remediate:demo-admin/payments-service**) → resolve-badge (badge
  intent = the scoped intent) → scan → opencode-plan → dir-push (real CID)
  → dir-search → kc-a-exchange → mint-idjag → egress-check → kc-b-exchange
  → create-ticket → Org B nested steps → PR created; denied-pr-attempt
  correctly `denied`
- Badge-scope PDP negative tests at Envoy A: 403 repo outside allowlist,
  403 disallowed action, 401 garbage token (JWT filter before OPA),
  200 in-policy
- opencode-server healthy, real OpenCode v1.18.7; Ollama reachable but
  model not pulled → opencode-plan correctly `skipped` with actionable
  note (fixed harness to detect OpenCode's 200-with-embedded-error)
- webapp (8090, old flow) regression: ok=true, 0 failed
- Jaeger trace: 52 spans across 5 services under one trace_id

Caveat: the OPA `x-agntcy-scoped-intent` response header is not echoed
through Envoy's direct_response to the caller; harness constructs the
identical value on 200 (validated: badge claim matches policy tests).
To get a real Qwen plan: `ollama pull qwen2.5-coder:7b` and re-run.

## Notes / follow-up milestones

- webapp (8090) still animates the OLD flow — unify with new lifecycle later
- Real CVE scan (repo has no dependency manifest yet — gitea/init.sh would
  need to seed one) — later milestone
- Repeat the identity lifecycle for triage-agent and sub-agent — later
- Badge↔CIMD binding (verify badge subject against resolved JWK) — later
