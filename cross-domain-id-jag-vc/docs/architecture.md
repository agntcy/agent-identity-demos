# Cross-Domain Agent Remediation — Live Sequence

This diagram describes the implemented webapp path. “Secondary VC” is a
generic independently issued Organization Credential; it is intentionally not
named after any commercial organization identifier.

```mermaid
sequenceDiagram
    autonumber
    participant UI as Webapp
    participant A as Security Autonomous Agent
    participant KA as Keycloak A
    participant D as AGNTCY Directory
    participant O as OpenCode Engine (internal tool)
    participant ID as AGNTCY Identity Node / CIMD
    participant SI as Secondary VC Issuer
    participant V as Trust Verifier
    participant EA as Envoy + OPA A
    participant KB as Keycloak B
    participant EB as Envoy + OPA B
    participant T as Triage A2A Agent
    participant R as Remediation A2A Agent
    participant G as Gitea

    rect rgb(232, 248, 242)
        Note over UI,O: One A2A agent; OpenCode is an internal planning tool
        UI->>A: A2A SendMessage(remediation request)
        A->>KA: client_credentials
        KA-->>A: Security Autonomous Agent access token
    end

    rect rgb(238, 244, 255)
        Note over A,V: Two independently issued VCs assembled into one VP
        A->>ID: generate / resolve CIMD id
        A->>EA: authorize task-scoped badge intent
        EA-->>A: ALLOW + narrowed intent
        A->>ID: publish and verify Agent Badge VC
        A->>SI: request Organization VC
        SI-->>A: signed Organization VC
        A->>V: request nonce + audience
        V-->>A: challenge + domain
        A->>A: assemble two-VC VP and sign with CIMD key
        A->>V: present VP
        V->>ID: resolve holder key + verify Agent Badge
        V->>SI: resolve secondary issuer JWKS
        V->>D: resolve signed OASF description
        V->>V: verify nonce, audience, expiry, both issuers,<br/>holder, operatedBy, issuer policy, OASF and digest
        V-->>A: ACCEPT
    end

    rect rgb(255, 248, 230)
        Note over A,T: Cross-enterprise request authorization
        A->>KA: mint repo-bound read ID-JAG
        A->>EA: egress policy check
        A->>KB: redeem ID-JAG
        A->>EB: read source through protected gateway
        EB-->>A: authorized source
        A->>O: scan and prepare remediation plan
        O-->>A: analysis (internal API, no A2A identity)
        A->>D: discover Triage Agent Card
        A->>KA: mint triage:create ID-JAG
        A->>EA: egress policy check
        A->>KB: redeem ID-JAG
        A->>EB: A2A SendMessage + access token + ID-JAG
        EB->>EB: JWT + OPA delegation checks
        EB->>T: forward A2A request
    end

    rect rgb(245, 240, 252)
        Note over T,G: Narrowed A2A delegation and protected resource action
        T->>ID: publish own Agent Badge VC
        T->>D: discover Remediation Agent Card
        T->>KB: mint narrowed gitea:write + gitea:pr ID-JAG
        T->>R: A2A SendMessage + narrowed ID-JAG
        R->>ID: publish own Agent Badge VC
        R->>KB: redeem narrowed ID-JAG
        R->>EB: push fix and open PR
        EB->>EB: verify token, scope, intent, chain, repo and deny-list
        EB->>G: authorized write + PR
        G-->>R: PR created
        R-->>T: completed A2A Task
        T-->>A: completed A2A Task
        A-->>UI: completed workflow artifacts
    end
```

The trust anchors are verifier configuration—not the VP itself:

- the trusted Agent Badge issuer key resolved through AGNTCY Identity;
- the trusted secondary Organization VC issuer key;
- the approved issuer-to-enterprise binding policy;
- the CIMD holder key used for the VP signature;
- the signed OASF payload and digest matched against AGNTCY Directory.

The Directory remains discovery and audit infrastructure. An OASF record is
not accepted as authorization, and neither VCs, VPs, nor ID-JAGs are copied
into runtime Directory audit records.
