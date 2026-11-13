# Two-VC / VP trust-bundle PoC

This standalone PoC implements the architecture shown in
`/Users/sraradhy/Downloads/db_seq_diagram.png` with real RSA signatures:

```text
Secondary organization-VC issuer signing key
  └─ Organization Verification VC: organization URI → verified organization

Org Identity Service signing key
  └─ Agent Badge VC: CIMD agent ID → OASF/A2A card + operatedBy organization

Security Autonomous Agent CIMD key
  └─ VP: holder-signed presentation containing both VCs
```

The verifier is configured with the trust framework. The VP is not the trust
anchor; it is signed evidence from the holder. Verification requires:

- the secondary organization-VC issuer key to be trusted;
- the organization Identity Service issuer key to be trusted for that organization;
- the CIMD resolver to be trusted;
- the VP signature to validate with the agent's CIMD/JWKS key;
- the Agent Badge `credentialSubject.id` to equal the VP holder;
- `credentialSubject.operatedBy` to equal the Organization VC subject ID; and
- the embedded CIMD bytes to match the badge's `relatedResource` digest.

## Run

From the repository root:

```bash
python -m pip install -r two-vc-vp-poc/requirements.txt
python two-vc-vp-poc/poc.py --pretty
```

The output includes the Organization VC, Agent Badge VC, VP, trust anchors, and
every verifier check. Private keys are generated in memory and are never
included in the output.

Run the tests with:

```bash
python -m unittest discover -s two-vc-vp-poc/tests -p 'test_*.py'
```

## Mapping to the diagram

1. `IdentityService.publish_cimd()` publishes the CIMD document and JWKS.
2. `IdentityService.issue_agent_badge()` signs the Agent Badge VC containing
   the Security Autonomous Agent card, `operatedBy`, and the CIMD digest.
3. `SecondaryVcIssuer.issue_organization_vc()` signs the secondary Organization VC.
4. `Verifier.request_trust_bundle()` creates the challenge and domain.
5. `IdentityService.create_vp()` assembles both VCs and signs the VP with the
   agent's CIMD key.
6. `Verifier.verify_bundle()` resolves the CIMD key and applies all trust and
   binding checks before accepting the agent.

This is a PoC trust model, not a production organization-verification integration.
Replace the mock secondary issuer, local key storage, and in-memory resolver with the enterprise
services and AGNTCY Identity Node deployment used in production.
