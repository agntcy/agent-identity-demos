# Credentials vs assertions

The demo moves two different signed objects around. Both have historically been called a "badge"; they are not the same thing.

| | **Credential** (agent badge) | **Assertion** (ID-JAG) |
|---|---|---|
| Header | `typ=JOSE`, type `AgentBadge` | `typ=oauth-id-jag+jwt` |
| Signed by | the org's Vault trust-authority key | Keycloak A or B (`keycloak-idjag-spi`) |
| Registered where | published to the Identity Node, resolvable at `/v1alpha1/vc/{id}/.well-known/vcs.json` | not registered — it is a bearer token |
| Lifetime | ~1 hour, one live credential per identity | ~5 minutes, minted per task |
| Answers | *what is this agent, and what may it do or delegate?* | *is this particular request authorised?* |

**The credential describes standing capability; the assertion authorises a request.** Policy enforcement (Envoy + OPA at all four boundaries) acts on the **assertion**. The credential is what an agent publishes about itself and what a counterparty resolves independently before trusting a handoff.

Where a name says "sub-badge" it means an **assertion** — Triage's narrowed ID-JAG for the Sub-Agent — not a credential. Step ids still carry the older "badge" wording in places; the type in the JWT header is always authoritative.

Every agent (OpenCode, Triage, Sub-Agent) publishes its own credential. Each side of a handoff resolves the other's and requires it to agree with the assertion presented.

Known limitations of the issuer-side credential check (capability containment, `act_chain` construction, proof of possession, revocation) are documented in the [demo README](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md#two-artifacts-both-historically-called-badge).
