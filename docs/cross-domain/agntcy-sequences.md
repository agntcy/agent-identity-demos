# AGNTCY identity and Directory: the demo sequence

**Status:** Implemented in the demo  
**Date:** November 10, 2026

This walkthrough follows the AGNTCY identity, credential and Directory paths in the demo, including Vault signing and the supporting verification services. Keycloak, Envoy, OPA, OpenCode and Gitea are outside these diagrams. Requests are grouped where necessary for readability; the diagrams explain application behavior rather than individual database queries.

For the proposed organization-attestation extension, see [Supporting D&B attestations](dnb-attestation-proposal.md).

## Components and responsibilities

| Component | Responsibility |
|---|---|
| Bootstrap | Configure organization issuers and signing keys |
| Vault Transit | Hold organization private keys and produce requested signatures |
| Identity Node | Register and resolve identities, publish badges, verify credential evidence |
| Directory | Store descriptions and claim referrers, reconcile identity and serve search |
| Directory identity verifier | Check the native identity claim and matching badge, return a signed observation |
| Node TLS proxy | Provide internal HTTPS access to the existing Node HTTP API |
| Secondary organization issuer | Issue the demo's separate Organization credential with a separate Vault key |
| Two-credential Trust Verifier | Check the presentation, both credentials, organization binding and configured trust policy |

Org A and Org B have separate issuer keys. In this demo, Triage and the Sub-Agent use Org B's configured issuer key; these diagrams do not imply a separate private key for every agent. The deployment shares an Identity Node service.

## 1. Initialize issuer keys and registrations

**What happens:** Startup creates or reuses the configured issuer keys, obtains their public keys and registers the issuers with Identity Node.

**Why:** Node needs the registered public key to validate subsequent registration and credential-publication proofs. Private key material stays in Vault.

```mermaid
sequenceDiagram
    autonumber
    participant B as Bootstrap
    participant V as Vault Transit
    participant N as Identity Node
    B->>V: Enable Transit signing
    loop Org A, Org B and secondary issuer
        B->>V: Create or reuse issuer RSA key
        V-->>B: Public key
        B->>B: Convert public key to JWK
        B->>V: Sign issuer registration proof
        V-->>B: Proof signature
        B->>N: Check existing issuer registration
        B->>B: Require existing key to match if registered
        B->>N: Register issuer, public key and proof
        N->>N: Validate registration proof
        N-->>B: Registered or already configured
    end
    Note over V: Private signing keys remain in Vault
```

### Initialize Directory verification trust

A separate startup task establishes the internal TLS and result-verification material. Its generated verifier private key is distinct from the organization keys in Vault.

```mermaid
sequenceDiagram
    autonumber
    participant I as Directory trust initializer
    participant S as Persistent secret and trust volumes
    participant D as Directory
    participant E as Directory identity verifier
    participant P as Node TLS proxy
    I->>S: Create or reuse internal CA
    I->>S: Issue or renew verifier and proxy TLS certificates
    I->>S: Create or reuse verifier result key and bearer token
    S-->>D: CA certificate, public result key and token
    S-->>E: TLS material, private result key and token
    S-->>P: Proxy TLS certificate and private key
    Note over D,E: Requests use authenticated HTTPS
    Note over D: Directory cannot read the verifier private key
```

## 2. Register and resolve each agent identity

**What happens:** Each agent obtains a Vault-signed proof, registers its identity and resolves the returned ID to public verification metadata.

**Why:** A published name or endpoint alone does not demonstrate key control. Resolution lets another component obtain the verification key associated with the identity.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant V as Vault Transit
    participant N as Identity Node
    A->>V: Read issuer public key if not cached
    V-->>A: Public key
    A->>A: Build proof JWT for agent subject
    A->>V: Sign proof JWT
    V-->>A: Signature
    A->>N: POST /v1alpha1/id/generate with proof
    N->>N: Validate proof and register identity
    N-->>A: Agent identity ID
    Note over A,N: Existing registration is reused
    A->>N: POST /v1alpha1/id/resolve
    N-->>A: Resolver metadata and public verification key
```

This path runs for the Security Autonomous Agent, Triage Agent and Sub-Agent. Re-registration is idempotent in the client.

## 3. Create, publish and verify the Agent Badge

**What happens:** The client looks for a matching live badge. If none exists, issuer code constructs it, Vault signs it, and Node publishes it. Node then verifies the selected badge.

**Why:** The signed badge binds the agent identity to its canonical description and operating organization. A matching live badge can be reused without issuing another credential for every task.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent and issuer code
    participant V as Vault Transit
    participant N as Identity Node
    A->>N: Retrieve published badges for agent
    N-->>A: Existing credential envelopes
    A->>A: Check validity and matching description
    alt Matching live badge exists
        A->>A: Reuse signed badge
    else New badge needed
        A->>A: Build Agent Badge credential
        Note over A: Identity, capabilities, operatedBy,<br/>canonical OASF description and digest
        A->>V: Sign Agent Badge
        V-->>A: Badge signature
        A->>V: Sign fresh publication proof
        V-->>A: Proof signature
        A->>N: POST /v1alpha1/vc/publish
        N-->>A: Publication accepted
    end
    A->>N: POST /v1alpha1/vc/verify
    N-->>A: Credential verification result
    Note over A: Rejecting the badge prevents native claim publication
```

The issuer constructs and signs the Agent Badge; Identity Node supplies publication and verification. On the tested Node version, the demo relies on credential expiry and reuse rather than claiming a working badge-revocation flow.

## 4. Bind identity to the Directory record

**What happens:** The agent pushes the OASF record, signs a claim for its CID and publishes that claim as an OCI referrer. Directory reconciles the claim through an authenticated verifier, validates the observation and checks the claim signature locally.

**Why:** A verified identity must be associated with the exact record being discovered. A matching badge is required in this deployment.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant V as Vault Transit
    participant D as Directory
    participant E as Directory identity verifier
    participant P as Node TLS proxy
    participant N as Identity Node
    A->>D: Push canonical OASF record
    D-->>A: Record CID
    A->>D: Get identity status for CID
    D-->>A: Current status
    alt Record not already verified
        A->>A: Build claim for subject, CID and signing time
        A->>V: Sign detached claim JWS
        V-->>A: Claim signature
        A->>D: Push claim as OCI referrer
        D->>E: Authenticated request-bound verification
        E->>P: Request assertion keys and badge evidence
        P->>N: Forward evidence requests
        N-->>P: Identity metadata and badges
        P-->>E: Evidence over HTTPS
        E->>E: Check claim signature and matching badge
        E->>E: Sign verification observation
        E-->>D: Signed result
        D->>D: Validate pinned result key and request binding
        D->>D: Verify claim signature locally
        D->>D: Persist identity verification result
    end
    loop Until verified or timeout
        A->>D: Get identity status
        D-->>A: Verification status
        opt Identity status is verified
            A->>D: Search by name, identity and verified=true
            D-->>A: Matching record CIDs
        end
    end
    Note over A: Success requires verified status<br/>and this CID in verified search
```

The record declares `agntcy.dir/identity: agntcy://<agent-id>`. The signed claim binds the record CID, claim role, subject, signing time and expiry field. Directory stores the claim under `agntcy.dir.identity.v1.IdentityClaim`.

The verifier signs observations using its persisted result key, not Vault. Identity reconciliation runs every ten seconds; maximum verification age is five minutes, with observations also bounded by badge validity. PostgreSQL backs Directory's query state and Zot stores OCI content; their internal operations are omitted above.

## 5. Obtain the separate Organization credential and sign a presentation

**What happens:** The secondary issuer signs a credential for an organization in its configured demo registry. The agent combines that credential with its Agent Badge in a challenge-bound, holder-signed presentation.

**Why:** Agent identity and the organization operating the agent are separate assertions. Presenting both makes the relationship available for relying-party verification.

```mermaid
sequenceDiagram
    autonumber
    participant A as Security Autonomous Agent
    participant S as Secondary organization issuer
    participant V as Vault Transit
    participant T as Two-credential Trust Verifier
    A->>S: Request credential for operating organization
    S->>S: Look up organization in configured registry
    S->>S: Build Organization credential
    S->>V: Sign with secondary issuer key
    V-->>S: Signature
    S-->>A: Signed Organization credential
    A->>T: Request presentation challenge
    T-->>A: Fresh challenge and expected audience
    A->>A: Combine Agent Badge and Organization credential
    A->>V: Sign presentation as the agent holder
    V-->>A: Presentation signature
    A->>T: Submit signed presentation
```

The secondary issuer performs a configured lookup in the current implementation. It is not connected to an external business-verification provider.

## 6. Verify the presentation and the operator relationship

**What happens:** The Trust Verifier resolves the holder through Node, verifies both credentials, checks the operator relationship and compares the signed description with Directory.

**Why:** Two valid credentials must refer to the same claimed relationship. Merely placing unrelated credentials in a presentation is insufficient.

```mermaid
sequenceDiagram
    autonumber
    participant A as Security Autonomous Agent
    participant T as Two-credential Trust Verifier
    participant N as Identity Node
    participant S as Secondary organization issuer
    participant D as Directory
    T->>T: Check challenge, audience and presentation structure
    T->>N: Resolve holder identity
    N-->>T: Holder public verification key
    T->>T: Verify presentation signature and validity
    T->>T: Require one badge and one organization credential
    T->>N: Verify Agent Badge
    N-->>T: Badge verification result
    T->>T: Check badge signature, issuer and validity
    T->>S: Fetch configured issuer JWKS
    S-->>T: Secondary issuer public key
    T->>T: Verify organization credential signature and validity
    T->>T: Check badge subject equals presentation holder
    T->>T: Check operatedBy equals organization subject
    T->>T: Apply configured issuer and organization trust policy
    T->>D: Search canonical agent record
    D-->>T: Agent description
    T->>T: Compare signed description and digest
    T->>T: Consume successful challenge
    T-->>A: Accept or reject with check results
```

The two-credential Trust Verifier supplies the relying-party decision. Directory's identity verifier has a narrower responsibility: validating the native identity claim and matching badge. Native Directory verification does not label the Organization credential as independently accepted by a marketplace.

## 7. Discover peers, verify their badges and publish audit records

**What happens:** Agents discover their delegation targets through Directory. Receiving agents verify sender evidence against Node and the canonical Directory description. Each agent publishes its own workflow audit records at the applicable points in execution.

**Why:** The trust checks and evidence continue across agent handoffs.

```mermaid
sequenceDiagram
    autonumber
    participant A as Security Autonomous Agent
    participant T as Triage Agent
    participant S as Sub-Agent
    participant D as Directory
    participant N as Identity Node
    A->>D: Find Triage by name
    D-->>A: Description, identity and endpoint
    Note over A,T: Task handoff through the authorization path
    T->>D: Retrieve sender canonical record
    D-->>T: Security agent description
    T->>N: Retrieve and verify sender badge
    N-->>T: Badge and verification result
    T->>T: Compare signed description and digest
    Note over T: Run identity registration, badge publication<br/>and native Directory verification from steps 2 to 4
    T->>D: Find Sub-Agent by name
    D-->>T: Description, identity and endpoint
    Note over T,S: Bounded task handoff
    Note over S: Run identity registration, badge publication<br/>and native Directory verification from steps 2 to 4
    S->>D: Retrieve parent canonical record
    D-->>S: Triage description
    S->>N: Retrieve and verify parent badge
    N-->>S: Badge and verification result
    S->>S: Compare signed description and digest
    Note over A,D: At applicable workflow points, each agent<br/>publishes its own audit records
    A->>D: Publish security agent audit record
    D-->>A: Audit record CID
    T->>D: Publish triage audit record
    D-->>T: Audit record CID
    S->>D: Publish sub-agent audit record
    D-->>S: Audit record CID
```

Audit records describe activity. They are separate from canonical identity-bearing agent records and do not acquire verified identity status merely by being uploaded.

## Implementation references

- [Identity registration and resolution client](https://github.com/agntcy/agent-identity-demos/blob/codex/demo-merged-directory/cross-domain-id-jag-vc/agntcy_identity_client/cimd.py)
- [Vault signing client](https://github.com/agntcy/agent-identity-demos/blob/codex/demo-merged-directory/cross-domain-id-jag-vc/agntcy_identity_client/vault.py)
- [Agent Badge publication and reuse](https://github.com/agntcy/agent-identity-demos/blob/codex/demo-merged-directory/cross-domain-id-jag-vc/agntcy_identity_client/vc.py)
- [Native Directory claim client](https://github.com/agntcy/agent-identity-demos/blob/codex/demo-merged-directory/cross-domain-id-jag-vc/agntcy_identity_client/native_claims.py)
- [Two-credential Trust Verifier](https://github.com/agntcy/agent-identity-demos/blob/codex/demo-merged-directory/cross-domain-id-jag-vc/trust-verifier/app.py)
- [Whitepaper and test evidence](whitepaper.md)
