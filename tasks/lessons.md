# Lessons

## 2026-07-28 — Agent identity lifecycle ordering (cross-domain-id-jag-vc)

**Correction:** I treated the identity steps as a demo script wrapped around
the agent and buried the badge attestation mid-sequence. The intended model:
the AGENT owns its task lifecycle, and credentials come BEFORE work —
**OAuth → register own identity (CIMD) → policy scopes the intent (Envoy A
OPA) → task-scoped VC badge → only then work → then delegate cross-domain.**

**Pattern to apply:**
- Identity attestation is part of task start, not a mid-flow detail.
- The badge must be scoped per task by POLICY (PDP decision), not by the
  agent choosing its own caps.
- Each agent registers ITS OWN CIMD identity (opencode-agent registers
  AGNTCY-opencode-agent, not its counterpart's).
- When the user shares the sequence diagram, match it exactly — don't
  invent orderings; ask when the code and diagram disagree.

## 2026-07-28 — "Client lib" naming confusion

`agntcy_identity_client/` = client-side SDK for calling the real
identity-node + Vault. Not a service, not in compose as a container — baked
into images via build additional_contexts. Explain lib-vs-service placement
up front when introducing shared packages.
