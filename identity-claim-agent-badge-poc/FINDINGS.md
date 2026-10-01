# Findings

## Result

The implementation validates the stronger form of the attached proposal: an Agent Badge can back an AGNTCY-specific resolver in Directory's proposed `identity.v1` architecture, while the agent still signs the Directory CID with its own resolved key.

This produces a meaningful native Directory status:

```text
identity_verified =
    agent controls resolved Agent ID key
    AND Agent Badge verifies under configured Identity Node policy
    AND badge subject equals Agent ID
    AND badge OASF definition hashes to Directory CID
```

It is materially different from merely storing the Agent Badge as a generic OCI referrer. Generic storage can preserve and retrieve evidence, but it does not automatically make the record's identity verified.

## Baseline limitation

The current implementation is based on proposed Directory PR #2125, not a released API. The tested stock commit already provides the `IdentityClaim` referrer, cached claim status, `IdentityService`, and `identity_verified` search filter. It does not recognize `agntcy:` subjects or integrate with AGNTCY Identity.

## Security properties demonstrated

- The IdentityClaim subject must match the identity declared inside the CID-addressed OASF record.
- The agent signature covers the exact record CID, Agent ID, and signing time.
- ResolverMetadata supplies the agent control public key; the claim does not carry a self-asserted key.
- The badge is verified by AGNTCY Identity v0.0.26 against the credential subject's ResolverMetadata key.
- The badge subject and embedded OASF definition are matched to the claim and record CID.
- Reusing a valid claim with a different record CID fails.
- The agent key remains inside Vault Transit.

## Remaining production work

- Define the normative `agntcy:` subject syntax and resolver contract.
- Define how relying parties configure accepted Identity Nodes and Agent Badge issuers.
- Add explicit VC issuer resolution and policy if the trust model requires an issuer key distinct from the credential subject's Agent ID key; Identity Node v0.0.26 does not perform that check.
- Specify credential status/revocation and stale-cache behavior.
- Apply SSRF and egress policy appropriate to administrator-configured Identity Node endpoints.
- Decide whether a valid Agent Badge is mandatory for every AGNTCY identity claim or selected through an assurance profile.
- Complete interoperability and lifecycle tests against the final form of PR #2125.
- Keep supplementary legal-entity credentials separate from the native proof-of-control status unless a future assurance policy explicitly composes them.
