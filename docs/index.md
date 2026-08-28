# Agent Identity Demos

Runnable demos for [AGNTCY Identity](https://github.com/agntcy/identity-service) — covering agent authentication, delegation, verifiable credentials, and cross-domain authorization using [ID-JAG](https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant) and the AGNTCY Identity Node (CIMD).

Each demo is a self-contained Docker Compose stack that you can run locally.

This wiki is the navigable overview. Operational detail (commands, reviewer checklists, reverse-proxy recipes) stays in the demo README.

## Survey (work in progress)

Orthogonal dimensions of **agent identity and authorization** — a survey paper outline organized for literature review and system comparison.

- [Survey overview](survey/index.md) — abstract, full paper outline (§I–§X)
- [Methodology](survey/methodology.md) — swap test, 15→10 dimension merge
- [Ten dimensions](survey/dimensions.md) — definitions, standards, open questions per axis

## Demos

### Cross-domain ID-JAG + VC

The most complete demo. **Sarah** (Org A engineer) asks her AI agent **OpenCode** to fix a security weakness in a repo owned by **Org B**.

- OpenCode reads the real source through the delegation chain, under its own read-scoped assertion, before analyzing it
- OpenCode can't act in Org B directly — it asserts Sarah's delegation cross-domain using a natively-minted ID-JAG
- Org B's **Triage** agent narrows the privilege further and spawns a bounded **Sub-Agent** to open the PR
- Every agent publishes a real W3C Verifiable Credential, and each side of a handoff resolves and checks the other's before trusting it

23 services total. The identity, authorization, and audit path is real (Keycloak, Vault, identity-node, Gitea, Directory, and two Built On Envoy inline OPA boundaries).

- [Overview](cross-domain/overview.md)
- [Architecture](cross-domain/architecture.md)
- [Quick start](cross-domain/quick-start.md)
- [Full walkthrough (demo README)](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md)

## Related

- [agntcy/identity-service](https://github.com/agntcy/identity-service) — the Identity Service these demos run against
- [AGNTCY Identity spec](https://spec.identity.agntcy.org) — the underlying identity specification
- [AI Agent Authentication and Authorization](related/a2a-auth-framework.md) — IETF individual draft this demo relates to
