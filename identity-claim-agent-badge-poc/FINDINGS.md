# Findings

## Result

The implementation validates an external-verifier form of the proposal: an Agent Badge can back an AGNTCY-specific verifier in Directory's proposed `identity.v1` architecture, while the agent still signs the Directory CID with its own resolved key and Directory remains independent of AGNTCY credential internals.

This produces a meaningful native Directory status:

```text
identity_verified =
    configured external verifier returned a valid signed result
    AND result is fresh and bound to the complete Directory request
    AND verifier established agent control of the resolved Agent ID key
    AND verifier established Agent Badge validity under its configured Identity Node policy
    AND verifier matched badge subject and OASF definition to the Agent ID and Directory CID
```

It is materially different from merely storing the Agent Badge as a generic OCI referrer. Generic storage can preserve and retrieve evidence, but it does not automatically make the record's identity verified.

## Baseline limitation

The implementation is based on proposed Directory PR #2125, not a released API. The tested stock commit already provides the `IdentityClaim` referrer, cached claim status, `IdentityService`, and `identity_verified` search filter. It does not recognize `agntcy:` subjects or integrate with an AGNTCY-aware external verifier.

## Security properties demonstrated

- The IdentityClaim subject must match the identity declared inside the CID-addressed OASF record.
- The agent signature covers the exact record CID, Agent ID, and signing time.
- ResolverMetadata supplies the agent control public key; the claim does not carry a self-asserted key.
- AGNTCY-specific resolution and credential verification execute outside Directory.
- Directory accepts only a signed verifier result checked against an administrator-pinned public key.
- The signed result is bound to the complete request digest, subject, record CID, profile, and a short validity window.
- The badge is verified by AGNTCY Identity v0.0.26 against the credential subject's ResolverMetadata key.
- The badge subject and embedded OASF definition are matched to the claim and record CID.
- Reusing a valid claim with a different record CID fails.
- The agent key remains inside Vault Transit.

## Remaining production work

- Define the normative `agntcy:` subject syntax.
- Define the external-verifier request/result profile and interoperable service contract.
- Define how Directory configures accepted verifiers and rotates their result-signing keys.
- Define how relying parties configure accepted Identity Nodes and Agent Badge issuers inside verifier policy.
- Add explicit VC issuer resolution and policy if the trust model requires an issuer key distinct from the credential subject's Agent ID key; Identity Node v0.0.26 does not perform that check.
- Specify credential status/revocation and stale-cache behavior.
- Apply SSRF and egress policy to the verifier's administrator-configured Identity Node endpoints.
- Authenticate Directory to the verifier and protect the verifier endpoint against unauthorized use and denial of service.
- Protect the verifier result-signing key with a KMS/HSM or workload-bound signing service; the PoC uses an ephemeral local key and pins only its public half in Directory.
- Decide whether a valid Agent Badge is mandatory for every AGNTCY identity claim or selected through an assurance profile.
- Complete interoperability and lifecycle tests against the final form of PR #2125.
- Keep supplementary legal-entity credentials separate from native proof-of-control status unless a future assurance policy explicitly composes them.
