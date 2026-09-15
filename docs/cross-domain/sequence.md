# Sequence

Every hop below actually happens against the real services in this stack (Keycloak, Vault, identity-node, dir-apiserver, Gitea) — including the scan, which analyses source genuinely read out of the Org B repository under its own read-scoped assertion. All four Envoy enforcement points — badge-scope, egress, ticket ingress, and resource access — are real. This is the same flow the webapp's UI animates step by step.

Phases, matching the [demo-local sequence diagram](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/docs/architecture.md):

1. **Local** — the Security Autonomous Agent initiates; no cross-domain auth yet
2. **Discovery + identity** — CIMD register/resolve, policy-scoped VC badge
3. **Cross-domain** — ID-JAG mint, Org A egress PDP, Keycloak B redemption, Org B ingress
4. **Sub-agent spawn** — narrowed assertion, bounded Gitea write/PR, audit

```mermaid
sequenceDiagram
    autonumber
    actor SAA as Security Autonomous Agent
    participant OC as OpenCode (Org A)
    participant KCA as Keycloak A
    participant Dir as AGNTCY Directory
    participant IdNode as Identity Node
    participant Vault
    participant VC as VC Badge
    participant OCS as opencode-server (real OpenCode)
    participant EnvoyA as Envoy A + OPA (egress)
    participant KCB as Keycloak B
    participant Envoy as Built On Envoy + OPA
    participant Triage as Triage (Org B)
    participant Sub as Sub-Agent (Org B)
    participant GW as Gitea Gateway
    participant Gitea

    SAA->>OC: "Fix the CVE in the Org B repo"
    OC->>KCA: OAuth client_credentials grant
    KCA-->>OC: access token

    Note over OC,IdNode: OpenCode registers its OWN identity — before any work
    OC->>Vault: sign proof JWT (transit/sign)
    Vault-->>OC: RS256 signature — private key never leaves Vault
    OC->>IdNode: generate id (proof JWT, org-a authority)
    IdNode-->>OC: id = AGNTCY-opencode-agent
    OC->>IdNode: resolve id
    IdNode-->>OC: ResolverMetadata + public key

    OC->>EnvoyA: POST /api/badge-scope-check (Security Autonomous Agent token + requested task)
    Note over EnvoyA: verify KC-A JWT; OPA scopes the task down
    EnvoyA-->>OC: ALLOW + x-agntcy-scoped-intent

    OC->>VC: issue credential (id, caps, delegating_user, policy-scoped intent, act_chain)
    VC-->>OC: signed AgentBadge
    OC->>VC: verify credential
    VC-->>OC: valid=true + claims

    Note over OC: only now, under the task-scoped badge, does work begin
    Note over OC,Envoy: scanning reads Org B's source — a cross-domain act,<br/>so it gets its own narrower assertion
    OC->>KCA: mint READ assertion (scope=gitea:read, resource=repo, intent=scan-source)
    KCA-->>OC: signed read assertion (RS256)
    OC->>EnvoyA: POST /api/egress-check (read assertion)
    EnvoyA-->>OC: ALLOW — rule=org-a-egress-source-read
    OC->>KCB: jwt-bearer grant (read assertion)
    KCB-->>OC: access token (gitea:read only)
    OC->>Envoy: GET /api/gitea/source/... (access token + read assertion)
    Note over Envoy: verify both JWTs; require gitea:read, forbid write/PR,<br/>bind to the repository signed into the assertion
    Envoy->>GW: ALLOW read
    GW->>Gitea: read file
    Gitea-->>GW: source
    GW-->>OC: PaymentLookupRepository.java
    Note over OC: OpenCode analyses the real source → CWE-89 (SQL injection)
    OC->>OCS: remediation plan request (real agent, real LLM call)
    OCS-->>OC: remediation plan (or skipped if no model provider)

    OC->>Dir: push turn record (OASF)
    Dir-->>OC: CID
    OC->>Dir: search "triage-agent"
    Dir-->>OC: agent record

    OC->>KCA: token-exchange (subject_token=Security Autonomous Agent, actor_token=badge)
    Note over KCA: validates subject_token; does not process actor_token<br/>into an act claim (real Keycloak behavior)
    KCA-->>OC: exchanged access token
    OC->>KCA: mint assertion (token-exchange, native SPI; sub=Security Autonomous Agent, scope=triage:create, intent=create-pr-fix)
    KCA-->>OC: signed assertion (RS256)

    OC->>EnvoyA: POST /api/egress-check (assertion as Bearer)
    EnvoyA->>KCA: fetch/cached JWKS
    Note over EnvoyA: verify JWT; enforce scope, intent, act-chain depth
    EnvoyA-->>OC: ALLOW + policy decision headers

    OC->>KCB: jwt-bearer grant
    KCB-->>OC: scoped access token

    OC->>Envoy: POST /api/ticket (access token + actor token)
    Envoy->>KCB: fetch/cached JWKS
    Envoy->>KCA: fetch/cached JWKS
    Note over Envoy: verify both JWTs; enforce scope, chain, signed intent, repo
    Envoy->>Triage: ALLOW + policy decision headers

    Note over Triage,IdNode: Triage runs the same lifecycle, one org over
    Triage->>KCA: fetch JWKS — re-verify the ID-JAG in-agent (defense in depth)
    KCA-->>Triage: JWKS → signature ✓ iss ✓ aud ✓ act_chain ✓
    Triage->>Vault: sign proof JWT (org-b key)
    Vault-->>Triage: RS256 signature
    Triage->>IdNode: generate + resolve id (org-b authority)
    IdNode-->>Triage: id = AGNTCY-triage-agent
    Triage->>Envoy: POST /api/subbadge-scope-check (may this be narrowed?)
    Envoy-->>Triage: ALLOW + scoped scope/resource
    Triage->>KCB: mint sub-badge natively (token-exchange, requested_token_type=id-jag)
    KCB-->>Triage: sub-badge (act_chain: Security Autonomous Agent→OpenCode→Triage)
    Triage->>Dir: push Triage turn record (OASF)
    Dir-->>Triage: CID
    Triage->>Dir: search "sub-agent"
    Dir-->>Triage: agent record
    Triage->>Sub: spawn with sub-badge

    Note over Sub,IdNode: the leaf of the chain has an identity too
    Sub->>KCB: fetch JWKS — verify the sub-badge BEFORE redeeming it
    KCB-->>Sub: JWKS → typ ✓ client_id ✓ act_chain ✓ scope ⊆ bound ✓ repo ✓
    Sub->>Vault: sign proof JWT (org-b key)
    Vault-->>Sub: RS256 signature
    Sub->>IdNode: generate + resolve id (org-b authority)
    IdNode-->>Sub: id = AGNTCY-sub-agent
    Sub->>KCB: jwt-bearer exchange
    KCB-->>Sub: scoped token (gitea:write, gitea:pr)
    Sub->>Envoy: push fix (access token + signed sub-badge)
    Note over Envoy: verify both JWTs; enforce chain, scope, intent, operation, repo
    Envoy->>GW: ALLOW push + policy decision headers
    GW->>Gitea: create branch + commit
    Gitea-->>GW: ok
    GW-->>Sub: branch created
    Sub->>Envoy: open PR (access token + signed sub-badge)
    Envoy->>GW: ALLOW PR + policy decision headers
    GW->>Gitea: create PR
    Gitea-->>GW: ok
    GW-->>Sub: PR created ✓

    Sub->>Envoy: open PR on demo-protected (same token, same scope)
    Envoy--xSub: 403 policy_deny — outside signed resource

    Note over Sub,Triage: resource OPA decision is real and inline
    Sub->>Dir: push Sub-Agent turn record (OASF)
    Dir-->>Sub: CID
    Sub-->>Triage: PR link + denied-attempt result
    Triage-->>OC: ticket complete
    OC-->>SAA: PR ready — full act-chain audit trail
```

OpenTelemetry `trace_id` links every hop. Full causal audit: Security Autonomous Agent → OpenCode → Triage → Sub-Agent. Envoy + OPA is the Policy Decision Point at each boundary.

See also [credentials vs assertions](credentials.md) and the [demo README sequence flow](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md#sequence-flow).
