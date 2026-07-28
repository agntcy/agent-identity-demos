# Milestone 9: Triage agent identity lifecycle (Org B)

Goal: give the Org B Triage agent the same lifecycle OpenCode got in M8 —
verify inbound credentials → register own identity → policy-scoped
credential → work → delegate narrower — plus a real Org B trust authority
and native Keycloak B sub-badge minting.

## Tasks

- [x] identity-node-init: multi-issuer (ISSUERS="org-a-issuer:org-a,
      org-b-issuer:org-b"); each org gets its own Vault Transit key and
      registers as its own trust authority
- [x] agntcy_identity_client: generic ORG_COMMON_NAME (ORG_A_COMMON_NAME
      kept as fallback)
- [x] keycloak-b built with keycloak-idjag-spi (keycloak-b/Dockerfile);
      org-b realm: triage-agent gains standard.token.exchange.enabled +
      idjag.allowed.scopes/audiences; new self-referential IdP
      id-jag-keycloak-b; sub-agent redeems against it; Sarah federated
- [x] Envoy B: idjag_actor_token forward:true (Triage can verify in-agent);
      new /api/subbadge-scope-check route + jwt rule (access token only);
      listener 10001 idjag_sub_badge repointed idjag-issuer → Keycloak B;
      idjag_issuer_jwks cluster removed
- [x] ticket-ingress.rego: org-b-subbadge-scope rule (scope allowlist,
      intent allowlist, repo allowlist, no escalation) + 6 tests (15/15)
- [x] triage-agent rewritten: verify-idjag (KC-A JWKS, in-agent),
      cimd-generate/resolve under org-b, subbadge-scope-check, plan,
      native KC-B mint-sub-badge, dir-push, spawn-sub-agent;
      Dockerfile/requirements/compose wiring (Vault, Dir, PDP, KC-A)
- [x] README: M9 paragraph, real-vs-mock row, services table, repo layout,
      sequence diagram, reviewer verification section
- [x] Live verification

## Review

Verified live on 2026-07-28 (full stack, 25 containers):

- OPA: ticket-ingress **15/15** (9 + 6 new sub-badge scope), resource-access
  13/13, egress 16/16 unchanged. `envoy --mode validate` OK; compose config
  OK; keycloak-b/triage-agent/envoy-org-b images build.
- End-to-end `POST :8100/api/run` → **ok=true, 30 steps** (was 25 — five
  new Triage steps). Evidence:
  - CIMD identities registered: `AGNTCY-opencode-agent` (org-a authority)
    **and `AGNTCY-triage-agent` (org-b authority)**
  - `verify-idjag` = ok — iss `keycloak-a/realms/org-a`, sub
    `sarah@org-a.example`, act_chain `[opencode-agent]`, verified in-agent
  - `subbadge-scope-check` = ALLOW, scoped_scope `openid gitea:write
    gitea:pr`, scoped_resource `demo-admin/payments-service`
  - sub-badge **minted by Keycloak B**: iss
    `http://keycloak-b:8080/keycloak-b/realms/org-b`, typ
    `oauth-id-jag+jwt`, scope = policy-approved, resource =
    `[demo-admin/payments-service]`, act
    `{sub: triage-agent, act_chain: [opencode-agent, triage-agent]}`
  - Triage pushes its own Directory turn record (real CID)
  - Sub-Agent push/PR still green through the repointed listener 10001;
    `denied-pr-attempt` still correctly `denied`
- Org B is a real registered trust authority (identity-node returns org-b
  JWKS with kid `org-b-issuer-v1`).

Operational notes seen during verification (not code defects):
- identity-node-init timed out once while identity-postgres was in crash
  recovery after an abrupt restart; re-running the one-shot succeeded
  (registration is idempotent).
- Running several `docker compose up` invocations concurrently leaves
  services stuck in `Created`; use one.

## Follow-up milestones

- M10: Sub-Agent identity lifecycle (own CIMD id; verify the sub-badge it
  receives before redeeming)
- M11: real work in Org B (LLM plan; gitea-gateway accepting caller-supplied
  patch content so the Sub-Agent pushes OpenCode's actual fix)
- M12: real CVE scan; badge↔CIMD binding; unify the webapp UI with the new
  lifecycle (8090 still animates the older flow)
