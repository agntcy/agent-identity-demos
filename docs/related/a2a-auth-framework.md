# AI Agent Authentication and Authorization

This demo is an implementation of cross-domain agent authentication and authorization using existing standards. The closest written framework is the IETF individual Internet-Draft [AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) ([editor's copy](https://PieterKas.github.io/agent2agent-auth-framework/), [source](https://github.com/PieterKas/agent2agent-auth-framework)).

That draft describes best practices for agent-to-agent auth by applying WIMSE, OAuth, and SPIFFE rather than inventing new protocols. This repo does not publish that draft; it shows a runnable stack that follows the same idea.

## What this demo implements

| Draft concern | In this demo |
|---|---|
| Agent identity as a first-class principal | Each agent (OpenCode, Triage, Sub-Agent) registers its own CIMD id at the AGNTCY Identity Node, under a Vault-backed org trust authority |
| Credentials describing what an agent is | W3C Verifiable Credentials (`AgentBadge`), Vault-signed, published and resolved at identity-node |
| Delegated authorization for a specific request | ID-JAG (`typ=oauth-id-jag+jwt`) minted by Keycloak via RFC 8693 token exchange (`keycloak-idjag-spi`) |
| Cross-domain trust | Org A mints; Org B redeems (`jwt-bearer`); Envoy + OPA at both org boundaries |
| Least privilege / narrowed onward grant | Triage mints a sub-assertion whose scope is a subset of the inbound ID-JAG; Sub-Agent cannot exceed it |
| Workload as the subject of delegation | The Security Autonomous Agent's Keycloak token is the `subject_token`; `act_chain` carries Security Autonomous Agent → OpenCode → Triage → Sub-Agent |

## What this demo does not implement

The draft leans on WIMSE workload credentials and SPIFFE SVIDs as the workload identity layer. This stack uses **Keycloak client credentials + Vault Transit + CIMD** instead of SPIFFE. Process-to-identity binding is at the OAuth layer, not a per-agent keypair (see [identity](../cross-domain/identity.md) and the credential limitations in the [demo README](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md)).

## See also

- [Overview](../cross-domain/overview.md)
- [Credentials vs assertions](../cross-domain/credentials.md)
- [AGNTCY Identity spec](https://spec.identity.agntcy.org)
