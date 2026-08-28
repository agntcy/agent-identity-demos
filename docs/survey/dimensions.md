# The Ten Dimensions

Each dimension answers one design question. Mechanisms listed are **examples** —
any specific implementation in a column should be swappable without forcing
changes in the other columns (modulo [coupling edges](composition.md)).

## Summary table

| # | Dimension | Core question | Example mechanisms |
|---|-----------|---------------|-------------------|
| 1 | [Human principal authentication](#1-human-principal-authentication) | Who is the accountable human? | OIDC, WebAuthn, SAML, MFA |
| 2 | [Agent / workload identification](#2-agent--workload-identification) | What is this non-human actor? | SPIFFE/SVID, CIMD, DID, OAuth CIMD |
| 3 | [Delegation model & provenance](#3-delegation-model--provenance) | How does authority flow and get recorded? | `act` claim, act-chain, macaroon caveats |
| 4 | [Inter-domain trust](#4-inter-domain-trust--foreign-credential-acceptance) | Why accept a foreign domain's credentials? | JWKS federation, ID-JAG receiver, SPIFFE federation |
| 5 | [Authorization language](#5-authorization-language--constraints) | What actions are permitted? | OAuth scopes, RAR, OPA/Cedar, intent objects |
| 6 | [Proof of possession](#6-proof-of-possession--sender-binding) | Is the caller the legitimate holder? | DPoP, mTLS-bound tokens, `cnf` |
| 7 | [Enforcement placement](#7-policy-enforcement-placement) | Where are allow/deny decisions made? | Envoy ext_authz, API gateway, resource server |
| 8 | [Discovery & registry](#8-discovery--registry) | How are parties and capabilities found? | AGNTCY Directory, MCP discovery, DNS-SD |
| 9 | [Credential lifecycle](#9-credential-lifecycle--revocation) | When does trust end? | Short TTL, refresh rotation, VC status lists |
| 10 | [Observability & audit](#10-observability-audit--evidence) | Can actions be reconstructed and correlated? | OTel traces, act-chain logs, signed PDP decisions |

---

## 1. Human principal authentication

**Core question:** Which human (if any) is ultimately accountable for agent actions?

### Outline content (to write)

- Distinction from agent authentication — different threat model, different UX
- Session vs token-based human auth; step-up for high-risk delegation
- Mapping human identity across domains (federated `sub`, email, pairwise IDs)

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Password grant → WebAuthn | None on agent ID, delegation, or PoP |
| Single IdP → federated OIDC | Triggers inter-domain trust (#4) for cross-org `sub` mapping |

### Standards & systems

- OIDC Core, FIDO2/WebAuthn, SAML 2.0
- Keycloak, Auth0, Okta

### Open questions

- How to bind ephemeral agent sessions to durable human accountability?
- Delegation consent UX at machine speed

---

## 2. Agent / workload identification

**Core question:** What is this agent, in a machine-verifiable and resolvable way?

### Outline content (to write)

- Stable vs ephemeral agent identities
- Proof-of-ownership before minting (Vault Transit, node attestation)
- Relationship to OAuth `client_id` — when is a client credential sufficient?

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| SPIFFE SVID → CIMD resolvable ID | May affect inter-domain trust (#4) if trust authority is bundled with ID registry |
| Static registration → per-session agent ID | Affects audit (#10) and lifecycle (#9) |

### Standards & systems

- SPIFFE/SPIRE, AGNTCY CIMD / Identity Node, DIDs
- OAuth Client ID Metadata (CIMD), WIMSE workload credentials

### Open questions

- Per-agent keypairs vs shared OAuth client credentials
- Identity for ephemeral sub-agents spawned at runtime

---

## 3. Delegation model & provenance

**Core question:** Through whom was authority transferred, and can each hop be verified?

Includes **subject–actor separation** and **progressive privilege reduction** as
properties of this dimension, not separate axes.

### Outline content (to write)

- Single-hop vs multi-hop delegation (`act`, nested act-chain)
- Attenuation rules: `child_scope ⊆ parent_scope`, delegation depth limits
- Delegation vs impersonation semantics

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Flat `act` claim → full act-chain JWT | Audit semantics (#10) must capture chain; authz language (#5) unchanged |
| OAuth delegation → macaroon caveats | **Coupling:** authorization (#5) moves into credential encoding |

### Standards & systems

- RFC 8693 (`act` claim), ID-JAG, OAuth token exchange delegation
- Macaroons, AGNTCY act-chain in VC badges

### Open questions

- Maximum delegation depth; cycle detection
- Standard act-chain encoding across JWT and VC

---

## 4. Inter-domain trust & foreign credential acceptance

**Core question:** Why should domain B accept an assertion or identity minted in domain A?

Absorbs **cross-trust-zone authorization** and **trust establishment**.

### Outline content (to write)

- Issuer registration, JWKS discovery, trust bundles
- Assertion redemption (ID-JAG `jwt-bearer`, federated token exchange)
- Subject mapping across realms

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Bilateral JWKS trust → SPIFFE federation | Agent ID (#2) may use same trust roots |
| ID-JAG receiver → custom assertion validator | Delegation (#3) encoding unchanged if assertion format stable |

### Standards & systems

- ID-JAG (Cross-App Access), OpenID Federation, SPIFFE federation
- Keycloak identity providers, AGNTCY local trust authorities

### Open questions

- Dynamic trust vs pre-registered issuers
- Cross-cloud trust lifecycle and audit

---

## 5. Authorization language & constraints

**Core question:** What is the agent allowed to do, expressed in evaluable form?

Absorbs **intent & task binding** (e.g. `action ∈ intent`) as richer constraint types.

### Outline content (to write)

- Coarse scopes vs Rich Authorization Requests (RAR)
- ABAC/ReBAC (OPA, Cedar, FGA) vs OAuth scope strings
- Task-bound and intent-bound policies

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| OAuth scopes → Cedar policies | Enforcement (#7) needs Cedar-capable PDP; delegation (#3) unchanged |
| Static scopes → parameterized/task scopes | May require richer delegation metadata (#3) |

### Standards & systems

- OAuth 2.0 scopes, RAR, UMA
- OPA/Rego, Cedar, OpenFGA, Keycloak authorization services

### Open questions

- Standard encoding for agent *intent* across vendors
- Subset/refinement operations for cross-hop downscoping

---

## 6. Proof of possession / sender binding

**Core question:** Is the presenter of a credential the party it was issued to?

### Outline content (to write)

- Bearer token threat model vs sender-constrained tokens
- DPoP proof JWT, mTLS client certs, certificate-bound access tokens
- Interaction with token lifetime (#9)

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Bearer → DPoP | Minimal impact on scopes, delegation, or agent ID |
| DPoP → mTLS-bound tokens | May affect enforcement placement (#7) if TLS terminates early |

### Standards & systems

- DPoP (RFC 9449), Mutual TLS OAuth, `cnf` / `x5t#S256` claims
- Token binding (historical)

### Open questions

- PoP for multi-hop delegation (which key signs which hop?)
- Agent workloads without stable TLS endpoints

---

## 7. Policy enforcement placement

**Core question:** Where in the architecture are allow/deny decisions enforced?

### Outline content (to write)

- PEP at egress, ingress, API gateway, sidecar, resource server
- Split PDP/PEP: centralized policy vs inline OPA
- Deny-by-default resource gateways (scope + resource deny-lists)

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Monolithic gateway → Envoy ext_authz + OPA | Policy language (#5) unchanged if same Rego/Cedar |
| Ingress-only → ingress + egress PDP | Audit (#10) gains more decision points |

### Standards & systems

- Envoy ext_authz, Istio authorization, API gateway OAuth plugins
- Built On Envoy + OPA (as in cross-domain demo)

### Open questions

- Consistent policy across heterogeneous PEPs
- Latency vs security tradeoffs for inline authz

---

## 8. Discovery & registry

**Core question:** How does an agent find a counterparty, tool, or capability before delegating?

### Outline content (to write)

- Agent directories vs service catalogs vs DNS
- Metadata carried in discovery records (identity hints, endpoints, skills)
- Relationship to identity registries — separate or unified?

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Static config → AGNTCY Directory (OASF) | None on token format or PoP |
| Central directory → federated discovery | Triggers inter-domain trust (#4) for directory authenticity |

### Standards & systems

- AGNTCY Directory / OASF, MCP server discovery
- DNS-SD, service mesh registries, DID document resolution

### Open questions

- Trust in directory records vs trust in credentials
- Discovery of policy requirements before delegation

---

## 9. Credential lifecycle & revocation

**Core question:** How long is a credential valid, and how is trust withdrawn?

### Outline content (to write)

- Access token TTL, refresh token rotation, assertion expiry
- Revocation: OCSP, CRL, VC status lists, session revocation at IdP
- SVID rotation in SPIFFE

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Long-lived bearer → short-lived + rotation | Reduces reliance on PoP (#6) — strategic coupling |
| Opaque refresh → no refresh (assertion per action) | Increases load on inter-domain trust (#4) redemption path |

### Standards & systems

- OAuth token lifecycle, SPIFFE SVID TTL
- W3C VC status lists, RFC 7009 token revocation

### Open questions

- Revoking mid-delegation-chain without invalidating upstream human session
- Revocation latency in cross-domain settings

---

## 10. Observability, audit & evidence

**Core question:** Can every hop be reconstructed: human → agents → resource → outcome?

Distinguish **log infrastructure** (orthogonal) from **log semantics** (follows delegation #3).

### Outline content (to write)

- Causal act-chain audit vs point-in-time access logs
- Correlation: OpenTelemetry trace_id across trust boundaries
- Immutable / content-addressed evidence (OASF records)
- Signed PDP decision logs

### Swap examples

| Swap | Impact on other dimensions |
|------|---------------------------|
| Plain logs → OTel distributed tracing | None on auth mechanisms |
| Unstructured logs → act-chain schema | Schema driven by delegation model (#3) |

### Standards & systems

- OpenTelemetry, AGNTCY Directory turn records
- Sigstore, immutable audit logs, W3C VC presentation trails

### Open questions

- Privacy vs auditability for human delegators
- Standard act-chain serialization for cross-vendor correlation
