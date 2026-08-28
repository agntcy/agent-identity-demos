# References

Bibliography structure for §X. Expand with full citations during writing.

## Standards & RFCs

| ID | Reference | Dimensions |
|----|-----------|------------|
| [RFC6749] | OAuth 2.0 Authorization Framework | 1, 5, 9 |
| [OIDC] | OpenID Connect Core 1.0 | 1 |
| [RFC8693] | OAuth 2.0 Token Exchange | 3, 4 |
| [RFC9449] | OAuth 2.0 DPoP | 6 |
| [ID-JAG] | Identity Assertion JWT Authorization Grant (Keycloak / OIDF) | 3, 4, 5 |
| [RAR] | OAuth 2.0 Rich Authorization Requests | 5 |
| [SPIFFE] | SPIFFE Verifiable Identity Document | 2, 4, 9 |
| [WIMSE] | Workload Identity in Multi-System Environments (draft) | 2, 4 |
| [VC-DM] | W3C Verifiable Credentials Data Model | 2, 3, 5, 9 |
| [RFC7009] | OAuth 2.0 Token Revocation | 9 |

## IETF / industry drafts

| ID | Reference | Dimensions |
|----|-----------|------------|
| [A2A-AUTH] | [draft-klrc-aiagent-auth](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) — AI Agent Authentication and Authorization | All |
| [CIMD] | OAuth Client ID Metadata (CIMD) — agent/client identity | 2 |
| [TOKEN-DELEG] | OAuth 2.0 Token Exchange delegation extensions | 3 |

## Systems & implementations

| ID | Reference | Dimensions |
|----|-----------|------------|
| [AGNTCY-SPEC] | [AGNTCY Identity Specification](https://spec.identity.agntcy.org) | 2, 3, 5, 8, 10 |
| [AGNTCY-IS] | [agntcy/identity-service](https://github.com/agntcy/identity-service) | 2, 8, 10 |
| [KC-IDJAG] | Keycloak ID-JAG receiver + token exchange | 3, 4, 5 |
| [SPIRE] | SPIRE / SPIFFE implementation | 2, 4, 9 |
| [OPA] | Open Policy Agent | 5, 7 |
| [ENVOY-EXT] | Envoy External Authorization (ext_authz) | 7 |

## Demo & wiki references (this repo)

| ID | Reference | Notes |
|----|-----------|-------|
| [DEMO-XDOM] | [Cross-domain ID-JAG + VC demo](../cross-domain/overview.md) | Running example |
| [DEMO-A2A] | [A2A auth framework mapping](../related/a2a-auth-framework.md) | Draft ↔ demo |
| [DEMO-ARCH] | [Cross-domain architecture](../cross-domain/architecture.md) | Sequence & phases |

## Survey methodology references (to add)

- Multidimensional framework papers in federated identity (e.g., SAML vs OIDC comparisons)
- Zero-trust architecture decomposition literature
- Capability-based security surveys (for macaroon / attenuation comparison)

## Citation format

Use consistent inline tags: `[RFC8693]`, `[SPIFFE]`, `[AGNTCY-SPEC]`, etc.

Group bibliography by:

1. Standards track (IETF, W3C, OIDF)
2. Drafts and proposals
3. Academic papers (to be added)
4. Systems and open-source implementations
