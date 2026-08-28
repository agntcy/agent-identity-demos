# Agent Identity & Authorization — Survey Dimensions

Ten largely orthogonal dimensions for comparing agent identity and authorization
systems. Each axis is a replaceable design choice: swapping one mechanism should
not force redesign of the others.

| # | Dimension | Core question | Examples |
|---|-----------|---------------|----------|
| 1 | Human principal authentication | Who is the accountable human? | OIDC, WebAuthn, SAML |
| 2 | Agent / workload identification | What is this non-human actor? | SPIFFE/SVID, CIMD, DID |
| 3 | Delegation model & provenance | How does authority flow and get recorded? | `act` claim, act-chain, macaroon caveats |
| 4 | Inter-domain trust | Why accept a foreign domain's credentials? | JWKS federation, ID-JAG, SPIFFE federation |
| 5 | Authorization language | What actions are permitted? | OAuth scopes, RAR, OPA/Cedar, intent |
| 6 | Proof of possession | Is the caller the legitimate holder? | DPoP, mTLS-bound tokens, `cnf` |
| 7 | Enforcement placement | Where are allow/deny decisions made? | Envoy ext_authz, API gateway, resource server |
| 8 | Discovery & registry | How are parties and capabilities found? | AGNTCY Directory, MCP discovery |
| 9 | Credential lifecycle | When does trust end? | Short TTL, refresh rotation, VC status lists |
| 10 | Observability & audit | Can actions be reconstructed end-to-end? | OTel traces, act-chain logs |

## Notes

- **#3** includes subject–actor separation and progressive privilege reduction.
- **#5** includes intent and task binding (`action ∈ intent`).
- **#4** includes cross-trust-zone authorization and issuer trust bootstrapping.
- **Credential format** (JWT, VC, SVID) is composition, not a separate dimension — it bundles several of the above.
