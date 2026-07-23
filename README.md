# Agent Identity Demos

Runnable demos for [AGNTCY Identity](https://github.com/agntcy/identity-service) — covering agent authentication, delegation, verifiable credentials, and cross-domain authorization using [ID-JAG](https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant) and the AGNTCY Identity Node (CIMD).

Each demo is self-contained Docker Compose stack that you can run locally.

## Demos

### [`cross-domain-id-jag-vc`](./cross-domain-id-jag-vc)

The most complete demo. Shows a full cross-domain agent delegation scenario:

- **Sarah** (Org A engineer) asks her AI agent **OpenCode** to fix a CVE in a repo owned by **Org B**
- OpenCode can't act in Org B directly — it asserts Sarah's delegation cross-domain using ID-JAG
- Org B's **Triage** agent narrows the privilege further and spawns a bounded **Sub-Agent** to open the PR
- Every step is audited via the **AGNTCY Directory Node** (OASF records) and identities are minted/resolved through the **AGNTCY Identity Node** with Vault-backed cryptographic proof

18 services total. Most steps are real (Keycloak, Vault, identity-node, Gitea); CVE scan and OPA policy checks are intentionally mocked.

→ [Full walkthrough and quick start](./cross-domain-id-jag-vc/README.md)

---

### [`archive/single-org-id-jag-app-access`](./archive/single-org-id-jag-app-access)

The original CNCF conference demo (archived). Shows ID-JAG cross-app access within a single org:

- A **Requesting App** obtains a narrow-scoped token on behalf of a signed-in user via ID-JAG
- A **Gitea Gateway** enforces the narrow scope (`gitea:read` / `gitea:write`) before proxying to Gitea
- The animated web UI walks through each hop step by step

Still referenced by `cross-domain-id-jag-vc` (shares the `idjag-issuer` and `gitea-gateway` builds). Superseded for new work by the two-org scenario above.

→ [Full walkthrough and quick start](./archive/single-org-id-jag-app-access/README.md)

---

### [`cncf-demo`](./cncf-demo) _(placeholder)_

Upcoming CNCF conference demo stack. Will cover Envoy + `ext_authz` task-based authorization with the AGNTCY Identity Service.

→ [Planned contents and related issues](./cncf-demo/README.md)

---

### [`xaa-multi-enterprise`](./xaa-multi-enterprise) _(placeholder)_

Upcoming cross-enterprise (XAA) multi-enterprise demo. Will show agent identity and authorization across multiple enterprises.

→ [Planned contents and related issues](./xaa-multi-enterprise/README.md)

---

## Related

- [agntcy/identity-service](https://github.com/agntcy/identity-service) — the Identity Service these demos run against
- [AGNTCY Identity spec](https://spec.identity.agntcy.org) — the underlying identity specification
