# Open Problems

Research and engineering gaps keyed to each dimension. Use in §VIII.

## Per-dimension open problems

### 1. Human principal authentication

- [ ] Standard delegation consent flows at agent invocation speed
- [ ] Step-up auth triggered by authorization policy, not just IdP rules
- [ ] Privacy-preserving cross-domain human identity correlation

### 2. Agent / workload identification

- [ ] Per-agent cryptographic identity vs shared OAuth client credentials — when is each sufficient?
- [ ] Identity lifecycle for ephemeral sub-agents (spawn → act → terminate)
- [ ] Binding agent identity to runtime attestation (TEE, image digest) without tight coupling

### 3. Delegation model & provenance

- [ ] Standard act-chain encoding interoperable across JWT, VC, and macaroon
- [ ] Maximum delegation depth and cycle detection in federated settings
- [ ] Formal semantics: delegation vs impersonation vs on-behalf-of

### 4. Inter-domain trust & foreign credential acceptance

- [ ] Dynamic trust establishment vs pre-registration tradeoffs
- [ ] Cross-cloud issuer rotation without breaking in-flight delegations
- [ ] Unified trust framework spanning OIDC federation, SPIFFE, and VC issuers

### 5. Authorization language & constraints

- [ ] Standard intent representation for LLM agent tasks
- [ ] Scope subset algebra enforced consistently across IdP, PDP, and resource server
- [ ] Mapping natural-language user requests to machine-evaluable constraints

### 6. Proof of possession / sender binding

- [ ] DPoP (or equivalent) across multi-hop delegation — per-hop keys vs end-to-end
- [ ] PoP for agents without stable HTTP endpoints (async, queue-based agents)
- [ ] Operational cost of mTLS vs DPoP at scale

### 7. Policy enforcement placement

- [ ] Consistent policy across heterogeneous PEPs (Envoy, app middleware, SaaS APIs)
- [ ] Egress PDP adoption — orgs rarely enforce outbound delegation policy today
- [ ] Sub-millisecond authz for high-throughput agent tool calls

### 8. Discovery & registry

- [ ] Trust model for directory records (signed metadata, federated directories)
- [ ] Discovery of policy requirements before delegation (what will Org B require?)
- [ ] Unified agent + tool + policy discovery

### 9. Credential lifecycle & revocation

- [ ] Revoke mid-chain without invalidating upstream human session
- [ ] Cross-domain revocation propagation latency
- [ ] Refresh token handling for long-running autonomous agents

### 10. Observability, audit & evidence

- [ ] Privacy-preserving audit (prove delegation without exposing user data)
- [ ] Cross-vendor trace correlation for act-chains
- [ ] Tamper-evident audit with standard formats

## Cross-cutting themes

| Theme | Dimensions affected | Problem statement |
|-------|--------------------|--------------------|
| **Standardization gap** | 3, 4, 5, 10 | No single RFC covers agent delegation end-to-end |
| **Composition vs convenience** | All | Bundled credentials reduce round-trips but break orthogonality |
| **Production readiness** | 4, 6, 7 | ID-JAG, DPoP, ext_authz are experimental or unevenly adopted |
| **Agent-native UX** | 1, 3, 5 | OAuth flows designed for human browser login, not machine agents |
| **Evaluation methodology** | All | No shared benchmark scenarios or conformance suite for agent identity |

## Suggested benchmark scenarios (for community)

Proposed in §VIII as call-to-action:

1. **S1:** Single-org cross-app read (ID-JAG baseline)
2. **S2:** Cross-org ticket creation with act-chain audit
3. **S3:** Sub-agent spawn with narrowed scope and deny-list enforcement
4. **S4:** Token theft simulation (bearer vs DPoP)
5. **S5:** Rogue directory entry / agent impersonation
6. **S6:** Mid-flight revocation during multi-hop delegation

Map each benchmark to dimension coverage checklist in [Dimensions](dimensions.md).

## Future work: optional eleventh concern

**Runtime attestation & environment binding** was considered as a dimension but
deferred — it couples heavily with agent identification (#2). Revisit if TEE /
confidential computing becomes mainstream for agents:

- SGX/TDX attestation bound to SVID or VC
- Policy on container image digest + signature
