# Agent Identity Demos

Runnable demos for [AGNTCY Identity](https://github.com/agntcy/identity-service) — covering agent authentication, delegation, verifiable credentials, and cross-domain authorization using [ID-JAG](https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant) and the AGNTCY Identity Node (CIMD).

Each demo is self-contained Docker Compose stack that you can run locally.

## Demos

### [`cross-domain-id-jag-vc`](./cross-domain-id-jag-vc)

The most complete demo. Shows a full cross-domain agent delegation scenario:

- **Sarah** (Org A engineer) asks her AI agent **OpenCode** to fix a security weakness in a repo owned by **Org B**
- OpenCode reads the real source through the delegation chain, under its own read-scoped assertion, before analyzing it
- OpenCode can't act in Org B directly — it asserts Sarah's delegation cross-domain using a natively-minted ID-JAG (Keycloak's own token-exchange grant, no separate mock issuer)
- Org B's **Triage** agent narrows the privilege further and spawns a bounded **Sub-Agent** to open the PR
- Every agent publishes a real W3C Verifiable Credential (Vault-signed, registered at the Identity Node), and each side of a handoff resolves and checks the other's before trusting it
- Every step is audited via the **AGNTCY Directory Node** (OASF records) and identities are minted/resolved through the **AGNTCY Identity Node** with Vault-backed cryptographic proof

23 services total. The whole identity/authorization/audit path is real
(Keycloak, Vault, identity-node, Gitea, Directory, and two Built On Envoy
inline OPA boundaries) — the only optional mock is the remediation LLM call
itself, toggleable to a fast, clearly-labeled stand-in when a model backend
isn't available.

→ [Full walkthrough and quick start](./cross-domain-id-jag-vc/README.md)

---

## Related

- [agntcy/identity-service](https://github.com/agntcy/identity-service) — the Identity Service these demos run against
- [AGNTCY Identity spec](https://spec.identity.agntcy.org) — the underlying identity specification
