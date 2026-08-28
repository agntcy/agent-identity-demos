# Survey: Orthogonal Dimensions of Agent Identity & Authorization

> **Status:** Outline (work in progress)  
> **Audience:** Researchers and architects building multi-agent, cross-domain AI systems  
> **Basis:** AGNTCY Identity demos and related standards (OAuth/OIDC, SPIFFE, W3C VC, ID-JAG, IETF A2A draft)

## Abstract (placeholder)

Multi-agent systems require identity and authorization mechanisms that go beyond
single-user OAuth. Existing work addresses pieces of the problem — workload
identity, delegated access, verifiable credentials, sender binding — but lacks a
shared vocabulary for comparing solutions. This survey organizes the design space
into **ten largely orthogonal dimensions**: independent axes where a mechanism
can be swapped (like replacing tires without changing wipers) without forcing
redesign of the others. We map standards, systems, and open problems to this
framework and identify residual coupling edges where orthogonality breaks down.

## How to read this wiki

| Page | Contents |
|------|----------|
| [Methodology](methodology.md) | Orthogonality principle; critique of a 15-dimension split; merges |
| [Dimensional framework](dimensions.md) | The ten dimensions — definitions, swap examples, standards |
| [Composition & couplings](composition.md) | Non-orthogonal concerns (credential encoding, scenarios) |
| [Related work matrix](related-work.md) | Template for comparing papers and systems |
| [Threat model](threats.md) | Attacks mapped to dimensions |
| [Open problems](open-problems.md) | Research gaps per dimension |
| [References](references.md) | Bibliography structure |

## Paper outline

### I. Introduction

1. **Motivation**
   - Rise of autonomous AI agents acting on behalf of users across apps and orgs
   - Failure modes of treating agents as opaque OAuth clients or as human users
   - Need for a comparison framework, not another protocol

2. **Scope**
   - In scope: machine agents (AI agents, automation, MCP servers, workloads) acting with delegated human authority
   - In scope: cross-app, cross-org, and cross-trust-zone scenarios
   - Out of scope: model safety / alignment, agent reasoning, non-security identity (personality, memory)

3. **Contributions**
   - Ten-dimensional orthogonal framework with explicit swap criteria
   - Analysis of where orthogonality holds and where it breaks (coupling edges)
   - Mapping of representative standards and systems to dimensions
   - Open problem catalog keyed to dimensions

4. **Running example (scenario, not a dimension)**
   - Cross-org CVE remediation: human → agent A → agent B → sub-agent → protected resource
   - Used throughout to illustrate interactions between dimensions
   - See [cross-domain demo](../cross-domain/overview.md) for a runnable instance

### II. Background & terminology

1. **Parties**
   - Human principal, agent/workload, resource server, authorization server, identity provider, policy decision point

2. **Artifacts**
   - Access tokens, assertions, verifiable credentials, SVIDs, proof-of-possession mechanisms
   - Clarify: *credential encoding* is composition, not a dimension (see [Composition](composition.md))

3. **Standards landscape (high level)**
   - OAuth 2.0 / OIDC, RFC 8693 token exchange, DPoP, ID-JAG, SPIFFE/SPIRE, W3C VC, WIMSE, RAR

### III. Methodology: defining orthogonal dimensions

→ Full treatment in [Methodology](methodology.md)

1. **The swap test** — replace one mechanism without impacting others
2. **Critique of finer-grained splits** — subject/actor vs delegation chain, intent vs scope language, cross-zone vs trust establishment
3. **Resulting ten dimensions** — summary table

### IV. The ten dimensions

→ Full treatment in [Dimensions](dimensions.md)

One subsection per dimension:

1. Human principal authentication
2. Agent / workload identification
3. Delegation model & provenance
4. Inter-domain trust & foreign credential acceptance
5. Authorization language & constraints
6. Proof of possession / sender binding
7. Policy enforcement placement
8. Discovery & registry
9. Credential lifecycle & revocation
10. Observability, audit & evidence

Each subsection covers:

- Core question the dimension answers
- Representative mechanisms and standards
- Swap examples (what changes, what stays stable)
- Evaluation criteria for practitioners
- Known limitations

### V. Composition layer & coupling edges

→ Full treatment in [Composition & couplings](composition.md)

1. **Credential encoding as packaging** — JWT vs VC vs macaroon vs SVID
2. **Scenario taxonomy** — cross-org remediation, cross-app ID-JAG, enterprise XAA (use cases, not dimensions)
3. **Documented coupling edges**
   - Authorization language ↔ delegation model
   - Agent ID ↔ inter-domain trust (CIMD trust authority vs SPIFFE trust domain)
   - Lifecycle ↔ sender binding (TTL vs PoP tradeoff)
   - Audit semantics ↔ delegation model

### VI. Related work

→ Template in [Related work matrix](related-work.md)

1. **Workload identity** — SPIFFE, WIMSE, service accounts
2. **OAuth delegation & cross-app access** — ID-JAG, RFC 8693, token exchange
3. **Verifiable credentials for agents** — AGNTCY, MCP CIMD, agent badges
4. **Sender-constrained tokens** — DPoP, mTLS-bound tokens, mutual TLS OAuth
5. **Policy engines & service mesh authz** — OPA, Envoy ext_authz, Cedar, FGA
6. **Agent interoperability drafts** — IETF AI Agent Auth, A2A
7. **Comparison table** — rows = systems/standards, columns = dimensions (full / partial / none)

### VII. Threat model

→ Full treatment in [Threat model](threats.md)

1. Token theft and replay
2. Confused deputy / scope escalation
3. Delegation chain forgery or truncation
4. Cross-domain issuer impersonation
5. Sub-agent over-privilege
6. Audit tampering / repudiation

### VIII. Open problems & research directions

→ Full treatment in [Open problems](open-problems.md)

Per-dimension gaps; cross-cutting themes (standardization, UX, operational cost)

### IX. Conclusion

1. Summary of the dimensional framework
2. Recommendations for system designers (minimum viable coverage per scenario)
3. Call for benchmark scenarios and shared evaluation criteria

### X. References

→ Structure in [References](references.md)

## Appendix (planned)

- **A.** Glossary
- **B.** Dimension ↔ demo component mapping (AGNTCY cross-domain stack)
- **C.** RFC and spec quick-reference table
