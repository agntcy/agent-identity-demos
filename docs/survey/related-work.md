# Related Work Matrix

Template for §VI of the survey. Score each system **F** (full), **P** (partial),
**N** (none), or **—** (not applicable).

## Comparison table (to populate)

| System / standard | 1 Human | 2 Agent ID | 3 Delegation | 4 Inter-domain | 5 Authz | 6 PoP | 7 Enforcement | 8 Discovery | 9 Lifecycle | 10 Audit |
|-------------------|---------|------------|--------------|----------------|---------|-------|---------------|-------------|-------------|----------|
| OAuth 2.0 / OIDC | F | P (client_id) | P (`act`) | N | F (scopes) | P (DPoP optional) | P (RS) | N | F | P |
| RFC 8693 token exchange | — | — | F | P | P | — | — | — | P | — |
| ID-JAG (Cross-App Access) | — | — | F | F | F | P | P | — | P | — |
| SPIFFE / SPIRE | — | F | N | F (federation) | N | P (mTLS) | P (mesh) | P | F (SVID TTL) | P |
| WIMSE | — | F | P | P | P | F | P | — | F | — |
| W3C Verifiable Credentials | — | F | P (claims) | P | P (caps) | P | — | P (DID) | P (status) | P |
| AGNTCY Identity (CIMD + VC) | P | F | F | P | F | P | P (Envoy demo) | F (Directory) | P | F |
| DPoP (RFC 9449) | — | — | — | — | — | F | — | — | — | — |
| OPA / Envoy ext_authz | — | — | — | — | F | — | F | — | — | P |
| IETF AI Agent Auth draft | P | F | F | F | F | P | P | P | P | P |
| Keycloak (ID-JAG receiver) | F | P | F | F | F | P | P | — | F | P |

> **Note:** Scores are preliminary placeholders for the outline. Each cell needs
> a citation and nuance footnote in the full paper.

## Related work sections (outline)

### §VI.1 Workload & agent identity

- SPIFFE/SPIRE — trust domains, SVID rotation, federation
- WIMSE — OAuth workload identity tokens
- AGNTCY CIMD — resolvable IDs, Vault-backed proof-of-ownership
- DIDs and verifiable agent profiles

**Comparison axis:** static registration vs runtime attestation; centralized vs federated registry

### §VI.2 Human delegation & OAuth

- RFC 8693 token exchange and `act` claim
- OAuth delegation extensions (experimental)
- ID-JAG — cross-app access on behalf of a user
- Rich Authorization Requests (RAR)

**Comparison axis:** user-as-subject propagation; actor claim handling across receivers

### §VI.3 Verifiable credentials for agents

- W3C VC Data Model; JOSE envelope (`vc+jwt`)
- AGNTCY AgentBadge / McpBadge
- MCP Client ID Metadata (CIMD) proposals
- Presentation vs issuance; selective disclosure (future)

**Comparison axis:** what is proven (identity vs capability vs delegation)

### §VI.4 Cross-domain trust & federation

- OpenID Federation, trust frameworks
- ID-JAG receiver configuration (Keycloak)
- SPIFFE federation; trust bundle distribution
- AGNTCY local trust authorities

**Comparison axis:** bilateral vs federation; dynamic vs pre-registered issuers

### §VI.5 Sender-constrained credentials

- DPoP; mTLS-bound tokens; mutual TLS OAuth
- Certificate-bound access tokens (`cnf`)
- Comparison with short-TTL bearer mitigation

**Comparison axis:** deployment friction vs theft resistance

### §VI.6 Policy engines & enforcement

- OPA/Rego; Cedar; OpenFGA / Zanzibar
- Envoy ext_authz; Istio; API gateway plugins
- Task-based authorization patterns

**Comparison axis:** PEP placement; policy language expressiveness

### §VI.7 Agent interoperability

- [IETF AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) ([editor's copy](https://PieterKas.github.io/agent2agent-auth-framework/))
- A2A protocol auth considerations
- MCP authentication patterns

**Comparison axis:** alignment with WIMSE + OAuth + SPIFFE vs novel protocols

### §VI.8 Demo systems (implementation references)

| Demo / stack | Primary contribution to survey |
|--------------|-------------------------------|
| [Cross-domain ID-JAG + VC](../cross-domain/overview.md) | End-to-end composition of dimensions 1–5, 7–8, 10 |
| AGNTCY identity-service | Reference implementation of CIMD + VC |
| Keycloak ID-JAG SPI | Native assertion minting + badge attestation |

## Evaluation criteria (for §VI synthesis)

When comparing systems across dimensions, use consistent criteria:

1. **Standards basis** — IETF/W3C/OIDC vs proprietary
2. **Swap cost** — how many other dimensions change when this one is replaced
3. **Operational maturity** — production deployments vs experimental
4. **Agent-native** — first-class agent principal vs repurposed OAuth client
5. **Cross-domain** — single-realm vs federated by design
