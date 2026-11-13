# Cross-domain ID-JAG + VC

A cross-domain agent delegation scenario: the **Security Autonomous Agent** in **Org A** asks **OpenCode** (its Org A execution agent) to fix a security weakness in a repo owned by **Org B**. OpenCode reads the real source through the delegation chain, under its own read-scoped assertion, and reports what it actually finds — a CWE, not a hardcoded CVE. Org B has its own Keycloak realm and access control, so OpenCode can't act there directly — it asserts the Security Autonomous Agent's delegation cross-domain using **ID-JAG** (Identity Assertion JWT Authorization Grant), then Triage further delegates a *narrowed* privilege to a bounded Sub-Agent that actually opens the pull request.

[![Demo walkthrough](https://gist.githubusercontent.com/sriaradhyula/24f325e4a51ed74d682692cefcd8eff2/raw/demo.gif)](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/docs/demo.mp4)

Click the GIF above for the [full-quality video](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/docs/demo.mp4).

OpenCode is the **real open-source OpenCode agent** ([opencode.ai](https://opencode.ai), pinned `opencode-ai@1.18.7`) running headless in the `opencode-server` container, driven by an **identity harness** (`opencode-agent`, port 8100) that executes the task lifecycle initiated by the Security Autonomous Agent:

> **OAuth → register own identity (CIMD) → policy-scoped badge → work → delegate cross-domain**

Before any task work runs, the harness presents the Security Autonomous Agent's delegated access token to **Envoy A + inline OPA** (`/api/badge-scope-check`), which verifies the token against Keycloak A's JWKS and answers with a **scoped-down intent** (e.g. `scan-remediate:demo-admin/payments-service`); only then is the VC badge minted — bound to that one task — and only then does the agent work.

Two AGNTCY components are wired in for real:

- **AGNTCY Directory Node** — every remediation turn is pushed as a content-addressed OASF record (immutable audit trail); agents are discoverable by name.
- **AGNTCY Identity Node (CIMD)** — Org A is registered as a real, **Vault-backed local trust authority**; agent identities are minted and resolved through identity-node's actual cryptographic proof-of-ownership flow, not a mock.

The only optional mock is the remediation LLM call itself, toggleable to a fast, clearly-labeled stand-in when a model backend isn't available.

## What's real vs. mocked

| Step(s) | What | Real or mocked |
|---|---|---|
| 1 | Security Autonomous Agent's client-credentials grant at Keycloak A | **Real** |
| 2 | Code scan — OpenCode analyses source fetched from the Org B repo | **Real** agent analysis of real source; reports a CWE (falls back to the known fixture finding when no model is reachable) |
| — | Read chain: read-scoped ID-JAG mint → Org A egress PDP → Keycloak B redemption → source fetch through Envoy B | **Real** — a second, narrower assertion (`gitea:read`, repo-bound) minted and enforced end to end |
| — | OpenCode remediation plan (headless `opencode-server`, Ollama/Anthropic) | **Real** agent + LLM call (`skipped` without a provider) |
| — | Badge-scope PDP at Envoy A — verify the autonomous agent's KC-A token, return task-scoped badge intent | **Real** JWT verification + inline OPA |
| 3–4 | AGNTCY Directory push + search (gRPC) | **Real** |
| 5–6 | CIMD generate/resolve id + agent badge issued as a **W3C Verifiable Credential** | **Real** |
| — | Every agent publishes its own credential; each side of a handoff resolves the other's | **Real** |
| 7 | RFC 8693 token exchange at Keycloak A | **Real** call |
| 8 | ID-JAG mint for Org B triage-agent | **Real** |
| 9–10 | Org A egress PDP — may the Security Autonomous Agent delegate this scope to Org B? | **Real** |
| 11 | Keycloak B `jwt-bearer` redemption | **Real** |
| 12–13 | Envoy ingress, ticket creation, OPA check, plan, sub-badge mint | **Real** |
| — | Triage identity lifecycle (in-agent ID-JAG verification, org-b CIMD, native KC-B mint) | **Real** |
| 14–20 | Sub-Agent spawn, verification, Gitea push/PR, resource-boundary OPA, audit | **Real** |
| — | OpenTelemetry `trace_id` linking every hop | **Real** |

How each piece became real, known limitations of the `actor_token` check, and reviewer verification steps live in the [demo README](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md).

## Next

- [Architecture](architecture.md) — services and trust boundaries
- [Credentials vs assertions](credentials.md) — the two artifacts both historically called "badge"
- [Sequence](sequence.md) — hop-by-hop flow
- [Quick start](quick-start.md) — run the stack locally
