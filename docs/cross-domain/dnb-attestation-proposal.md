# Supporting D&B attestations with AGNTCY

**Status:** Proposed extension, not implemented  
**Date:** November 10, 2026  
**Baseline:** [Current AGNTCY demo sequences](agntcy-sequences.md)

This proposal extends the current agent-identity flow with an organization attestation issued by D&B. D&B would supply evidence about an organization. AGNTCY Identity would continue to establish agent identity and serve Agent Badges. Directory would make the agent record and its attestation reference discoverable. A marketplace, or its chosen verifier, would evaluate the evidence under its own trust policy.

All D&B interactions below are conceptual. They do not describe an existing D&B API, credential schema, signing algorithm, status protocol or integration commitment. Those contracts must be agreed with D&B and the pilot marketplace. No pilot or partner integration is asserted to be operational.

## Proposed responsibility split

| Component | Proposed responsibility |
|---|---|
| Agent operator | Obtain the organization attestation and establish the authorized relationship between organization and agent |
| D&B | Verify the agreed organization facts, issue signed evidence and supply its verification and lifecycle mechanisms |
| Vault Transit | Continue signing the demo's registration proofs, Agent Badges, native claims and presentations |
| Identity Node | Continue registering and resolving agent identities and serving signed Agent Badges |
| Directory | Store the canonical agent record and agreed attestation-reference metadata, plus existing native identity claims |
| Directory identity verifier | Continue checking native identity control and the matching Agent Badge |
| Marketplace attestation verifier | Validate D&B evidence, organization binding, freshness and marketplace acceptance policy |
| Marketplace | Decide what the accepted attestation means for listing, filtering, display or access |

The existing demo's two-credential Trust Verifier is a starting point for the marketplace verifier role. The Directory identity verifier remains a separate service with a separate result meaning.

## 1. Configure trust and an interoperable credential profile

**What would happen:** The marketplace chooses which D&B issuer identities, credential types, claims and verification mechanisms it accepts. The pilot agrees how an attestation reference is represented in an agent record.

**Why:** A discoverable link needs a shared interpretation before multiple marketplaces can consume the credential consistently.

```mermaid
sequenceDiagram
    autonumber
    participant DB as D&B
    participant M as Marketplace operator
    participant T as Marketplace attestation verifier
    participant D as Directory integration
    DB-->>M: Agree issuer identity and attestation semantics
    DB-->>M: Agree credential, key and status mechanisms
    M->>T: Configure approved issuer and verification policy
    M->>D: Agree interoperable attestation-reference profile
    Note over M,D: Proposed schema and consumer contract<br/>must be agreed for the pilot
    Note over DB: D&B retains its own signing-key management
```

AGNTCY's existing issuer bootstrap and internal TLS setup remain as described in the current-demo document. D&B does not automatically need to register as an Identity Node issuer: the proposed organization credential can be verified independently by the consumer. Registering it with Node would be a separate compatibility decision.

## 2. Register the agent identity and obtain organization evidence

**What would happen:** The agent follows the existing Vault-backed identity registration flow. Separately, its operator obtains D&B's signed attestation about the organization.

**Why:** These establish different facts. The agent controls its registered identity; D&B attests the specific organization facts covered by the agreed product and credential profile.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent and operator
    participant V as Vault Transit
    participant N as Identity Node
    participant DB as D&B
    A->>V: Sign agent registration proof
    V-->>A: Signature
    A->>N: Register or reuse agent identity
    N-->>A: Agent ID
    A->>N: Resolve agent identity
    N-->>A: Verification metadata
    A->>DB: Request agreed organization attestation
    DB->>DB: Perform agreed business-verification process
    DB->>DB: Sign organization evidence with D&B-controlled key
    DB-->>A: Organization credential and retrieval information
    Note over DB: Actual API, evidence and issuance policy<br/>remain to be agreed
```

A D&B organization credential alone would not prove that a particular agent is authorized to represent that organization. The pilot must establish which issuer or enrollment process is trusted to make the agent-to-organization assertion. The current demo uses configured trust relationships; a general marketplace needs an explicit equivalent.

## 3. Bind the agent record, badge and attestation reference

**What would happen:** The canonical record includes the agreed reference to D&B evidence. The Agent Badge signs that exact description and names the operating organization. The Organization credential's subject must be mapped to the same organization identifier.

**Why:** Consumers need to connect a discovered agent to the correct organization evidence, without accepting an unrelated company's credential.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent and trusted badge issuer
    participant V as Vault Transit
    participant N as Identity Node
    participant D as Directory
    A->>A: Establish authorized agent-to-organization relationship
    A->>A: Map organization IDs using the agreed profile
    A->>A: Build OASF record with attestation reference
    Note over A: Reference identifies evidence and issuer<br/>Field names and placement are proposed
    A->>A: Build badge with operatedBy and exact OASF description
    A->>V: Sign Agent Badge
    V-->>A: Badge signature
    A->>V: Sign credential-publication proof
    V-->>A: Proof signature
    A->>N: Publish signed Agent Badge
    N-->>A: Publication result
    A->>N: Verify Agent Badge
    N-->>A: Verification result
    A->>D: Push exact canonical OASF record
    D-->>A: Record CID
```

The reference must be included before finalizing the signed description if it is part of the canonical record. Adding or changing it later changes the record CID and requires a matching badge and native claim for the new record. An existing D&B credential could remain usable if its subject, validity and permitted use still satisfy policy.

The pilot should choose whether the reference identifies a particular credential version, a status-aware retrieval endpoint, or another signed evidence artifact. A schema-recognized link is useful even when verification remains entirely consumer-side. A neutral discovery format does not require every consumer to adopt the demo's presentation protocol.

## 4. Complete the existing native Directory identity verification

**What would happen:** The record's native identity claim follows the same flow as today, even when the record contains an external attestation reference.

**Why:** Directory must still establish which agent identity claims that exact record. This result is distinct from the marketplace's acceptance of D&B evidence.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant V as Vault Transit
    participant D as Directory
    participant E as Directory identity verifier
    participant N as Identity Node through TLS proxy
    A->>V: Sign native claim for agent subject and record CID
    V-->>A: Claim signature
    A->>D: Publish claim as OCI referrer
    D->>E: Request native identity verification over HTTPS
    E->>N: Resolve keys and matching Agent Badge
    N-->>E: Identity and badge evidence
    E->>E: Verify native claim and exact badge match
    E-->>D: Signed request-bound observation
    D->>D: Validate observation and claim signature
    A->>D: Query identity status and verified search
    D-->>A: Verified identity result for this CID
    Note over D: Native identity verification does not<br/>automatically validate D&B business claims
```

The verifier observation still uses its configured private result key. Directory's pinned-key and freshness checks continue to apply. A separate D&B acceptance status must not be inferred from native `verified=true`.

## 5. Discover and verify the D&B evidence at the marketplace

**What would happen:** A marketplace discovers the agent record, reads its attestation reference, obtains the evidence through the agreed mechanism and validates it using approved D&B trust material.

**Why:** Directory can stay neutral while marketplaces consume independently issued evidence through a consistent profile.

```mermaid
sequenceDiagram
    autonumber
    participant M as Marketplace
    participant D as Directory
    participant R as Agreed credential retrieval service
    participant DB as D&B trust and status mechanisms
    participant N as Identity Node
    participant T as Marketplace attestation verifier
    M->>D: Discover agent and request identity verification status
    D-->>M: Agent record, CID and attestation reference
    M->>T: Evaluate agent record and referenced evidence
    T->>R: Retrieve credential with required authorization
    R-->>T: Signed organization credential
    T->>DB: Obtain approved verification material
    DB-->>T: Keys or equivalent trust evidence
    T->>T: Verify issuer, signature, type and supported claims
    T->>DB: Check status if required by the agreed profile
    DB-->>T: Status evidence
    T->>N: Resolve agent and retrieve Agent Badge
    N-->>T: Identity metadata and badge
    T->>T: Verify badge and canonical record binding
    T->>T: Validate authorized agent-to-organization binding
    T->>T: Match D&B credential subject to that organization
    T->>T: Check validity, freshness and marketplace policy
    T-->>M: Accept, reject or report unavailable evidence
    M->>M: Apply listing, display or access policy
```

The retrieval service could be D&B, an operator-controlled service or another location permitted by the agreed credential profile. A URL alone is not proof of issuer authenticity. The consumer must authenticate the credential and its subject using approved trust material and policy.

D&B attestations may also have access, redistribution and commercial restrictions. The pilot must agree whether Directory stores only references and permitted metadata, and how authorized marketplaces retrieve the underlying evidence.

## 6. Optionally extend the existing two-credential presentation

**What would happen:** When the marketplace needs the agent to prove possession during an interaction, the agent presents its badge and the D&B organization credential together, following an agreed presentation profile.

**Why:** This extends the current challenge-bound demonstration. It is an optional interaction pattern, not a prerequisite for attaching an external attestation reference to a record.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant V as Vault Transit
    participant T as Marketplace attestation verifier
    participant N as Identity Node
    participant DB as D&B verification mechanisms
    participant D as Directory
    A->>T: Request challenge and expected audience
    T-->>A: Fresh challenge and audience
    A->>A: Assemble badge and D&B credential in presentation
    A->>V: Sign presentation with configured holder key
    V-->>A: Presentation signature
    A->>T: Submit presentation
    T->>N: Resolve holder key and verify badge
    N-->>T: Verification evidence
    T->>DB: Obtain approved issuer and status evidence
    DB-->>T: Verification material
    T->>D: Retrieve canonical record
    D-->>T: Description and attestation reference
    T->>T: Verify presentation signature, challenge and audience
    T->>T: Verify D&B credential using agreed format and policy
    T->>T: Check holder, organization binding and record match
    T->>T: Consume challenge after successful verification
    T-->>A: Acceptance result
```

The current code expects a particular Organization credential type and JWT format. Supporting D&B requires implementing its agreed format, subject mapping, key resolution and lifecycle checks rather than simply replacing the issuer URL.

## 7. Handle change and preserve separate decisions

**What would happen:** The marketplace refreshes its acceptance result as credentials expire, statuses change or record content is updated. Agents continue peer discovery and audit publication using the existing AGNTCY paths.

**Why:** A valid identity binding and an accepted business attestation can change independently. A single permanent “verified” badge would hide that distinction.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent and operator
    participant DB as D&B
    participant D as Directory
    participant T as Marketplace attestation verifier
    participant M as Marketplace
    DB-->>A: Renewed credential or updated evidence reference
    alt Canonical record changes
        A->>A: Build updated description and matching Agent Badge
        A->>D: Publish new record and signed native claim
        D-->>A: New CID and subsequent identity result
    else Credential changes behind an unchanged permitted reference
        Note over A,D: Existing record CID may remain unchanged<br/>Consumer still checks the retrieved credential
    end
    M->>T: Re-evaluate evidence under freshness policy
    T->>DB: Obtain required validity and status evidence
    DB-->>T: Current evidence or retrieval failure
    T->>T: Validate subject binding and current acceptance policy
    T-->>M: Updated acceptance result
    M->>M: Update listing or access according to policy
    Note over M,D: Track native identity status separately<br/>from D&B attestation acceptance
```

Polling, notifications, cache lifetimes and the treatment of unavailable status services are design decisions, not implemented guarantees. Record updates must still follow badge publication and native claim verification from steps 3 and 4.

## What exists and what needs agreement

| Capability | Current demo | Proposed D&B work |
|---|---|---|
| Agent registration and badge publication | Implemented with Node and Vault | Reuse the existing path |
| Native Directory claim verification | Implemented | Reuse with the exact referenced record |
| Independent Organization credential | Demo issuer with configured organization data | Replace with D&B-issued evidence under an agreed profile |
| Agent-to-organization trust | Explicit demo issuer and organization configuration | Define accepted enrollment or issuer authority and identifier mapping |
| Credential reference in Directory | Agent Badge reference exists | Agree schema, placement and metadata for external organization attestations |
| Two-credential presentation | Implemented for the demo's credential format | Optional adaptation to the agreed D&B presentation profile |
| Issuer keys and credential status | Demo-specific verification | Agree D&B verification material, status, rotation and caching |
| Marketplace acceptance | Demo Trust Verifier applies configured policy | Define each marketplace's acceptance and failure behavior |

## Proposed pilot acceptance criteria

1. A consumer discovers the D&B evidence reference through the agreed record profile.
2. An authorized consumer retrieves evidence and authenticates the approved issuer.
3. The credential concerns the organization bound to the discovered agent by an accepted authority.
4. Wrong-organization, altered, unsupported, expired and unacceptable-status evidence is rejected.
5. Record changes invalidate the old record/badge association until the matching evidence is published and verified.
6. Retrieval or status failures produce the agreed unavailable or rejection outcome, without silently upgrading trust.
7. Native identity verification and organization-attestation acceptance remain separately observable.
8. A second marketplace can consume the same profile, with documented verification and acceptance behavior.

## Discussion with the Directory team

The request to the Directory team is to agree how external attestations are represented and exposed, how their subjects bind to agent records, and whether any generic verification-result mechanism is needed beyond consumer-side verification. D&B retains responsibility for its attestation semantics and issuance. Marketplaces retain responsibility for accepting that evidence and deciding its effect.

The smallest pilot can begin with discoverable references plus consumer-side verification. Directory-side reconciliation of business attestations would be a separate extension with an explicit schema, verifier interface and result meaning.
