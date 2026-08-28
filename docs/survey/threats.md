# Threat Model

Maps threats to the dimension(s) that primarily mitigate them. Use in §VII.

## Threat catalog

| ID | Threat | Description | Primary dimension(s) | Secondary |
|----|--------|-------------|---------------------|-----------|
| T1 | **Bearer token theft** | Stolen access token reused by attacker | 6 PoP, 9 Lifecycle | 7 Enforcement |
| T2 | **Token replay** | Legitimate token replayed outside intended context | 6 PoP, 9 Lifecycle | 5 Authz (audience binding) |
| T3 | **Confused deputy** | Agent uses user's broad token for unintended action | 5 Authz, 3 Delegation | 7 Enforcement |
| T4 | **Scope escalation** | Downstream agent exceeds upstream grant | 3 Delegation, 5 Authz | 7 Enforcement |
| T5 | **Delegation chain forgery** | Fake or truncated act-chain | 3 Delegation, 4 Inter-domain trust | 10 Audit |
| T6 | **Foreign issuer impersonation** | Attacker mints assertions from fake issuer | 4 Inter-domain trust | 2 Agent ID |
| T7 | **Agent impersonation** | Workload claims wrong agent identity | 2 Agent ID, 6 PoP | 4 Inter-domain trust |
| T8 | **Sub-agent over-privilege** | Spawned agent exceeds parent's narrowed grant | 3 Delegation, 5 Authz | 7 Enforcement |
| T9 | **Discovery poisoning** | Malicious agent record in directory | 8 Discovery, 4 Inter-domain trust | 2 Agent ID |
| T10 | **Audit tampering / repudiation** | Actor denies delegation or action | 10 Audit | 1 Human auth |
| T11 | **Stale credential use** | Revoked or expired credential still accepted | 9 Lifecycle | 7 Enforcement |
| T12 | **Cross-domain subject confusion** | Wrong human mapped across realms | 4 Inter-domain trust, 1 Human auth | 3 Delegation |

## Threat ↔ dimension coverage matrix

Rows = threats; columns = dimensions that **mitigate** (●) or **detect** (○).

| Threat | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|--------|---|---|---|---|---|---|---|---|---|---|
| T1 Token theft | | | | | | ● | ○ | | ● | |
| T2 Replay | | | | | ○ | ● | | | ● | |
| T3 Confused deputy | ○ | | ● | | ● | | ● | | | ○ |
| T4 Scope escalation | | | ● | | ● | | ● | | | ○ |
| T5 Chain forgery | | | ● | ● | | | | | | ● |
| T6 Issuer impersonation | | ○ | | ● | | | | | | |
| T7 Agent impersonation | | ● | | ● | | ● | | | | |
| T8 Sub-agent over-privilege | | | ● | | ● | | ● | | | |
| T9 Discovery poisoning | | ● | | ● | | | | ● | | |
| T10 Audit tampering | ● | | | | | | | | | ● |
| T11 Stale credential | | | | | | | ● | | ● | |
| T12 Subject confusion | ● | | ● | ● | | | | | | ○ |

## Attack narratives (outline for §VII)

Each narrative walks through a cross-domain scenario and identifies which
dimension fails if unaddressed.

### Narrative A: Stolen bearer at Org B gateway

1. Attacker intercepts Org B access token (no PoP)
2. Replays at Gitea gateway — **mitigated by #6, #9**
3. If gateway only checks scope, attacker may write — **#5, #7**

### Narrative B: Malicious sub-agent escalation

1. Triage spawns sub-agent with narrowed badge
2. Sub-agent modifies badge before exchange — **mitigated by #3, #4 (signature)**
3. Sub-agent calls resource outside narrowed scope — **mitigated by #5, #7**

### Narrative C: Fake agent in directory

1. Attacker publishes rogue "triage-agent" OASF record — **mitigated by #8, #4**
2. OpenCode delegates to wrong endpoint — **#2 VC verify before trust**

## Assumptions & non-goals

Document explicitly in §VII:

- TLS protects data in transit (out of scope unless mTLS used for #6)
- IdP and Vault are trusted infrastructure
- Agent runtime compromise is out of scope (attestation is future work)
- LLM prompt injection leading to unauthorized delegation — partial overlap with #5 (intent) and UX, not fully solved by identity layer
