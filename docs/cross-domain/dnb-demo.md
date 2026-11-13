# D&B concept demo

Open the deployed demo with `/?mode=dnb`, or select **D&B attestation · simulated** from the demo menu. Choose an evidence scenario and click **Run D&B concept**. The step delay defaults to two seconds; the diagram can expand into a modal. The upper-right console labels the source of every operation.

## What runs live

The existing publisher and consumer authenticate with Keycloak. AGNTCY Identity and Vault register/resolve identities and sign/publish a matching Agent Badge. Directory stores the OASF record, verifies its native identity claim through the identity verifier, and returns the exact record in verified search. The record includes proposed evidence references in existing annotations, creating its own CID and matching badge/claim.

## What is simulated

A local fixture represents a possible D&B organization credential, issuer key, status source and trusted organization-enrollment mapping. It uses a reserved `.invalid` URL and an ephemeral local RSA key. No D&B endpoint is contacted, and neither the credential format nor the annotation names are agreed D&B contracts. Actual signature and policy code evaluates these synthetic inputs.

The simulated marketplace tests valid, revoked, expired, stale, unavailable, wrong-organization and tampered evidence. It requires a matching organization, approved fixture issuer, valid signature, unexpired credential, active available status and a status age below five minutes. Unavailable status does not refresh a prior successful result. The demo grants no real business-resource access.

The results deliberately separate **live native identity verification** from **simulated business acceptance**. A rejected attestation does not invalidate the native identity. Directory freshness hooks and D&B-aware search/enforcement remain proposed; this demo neither implements those hooks nor changes Directory policy.

## Quick presentation

1. Run **Valid evidence**: show the real OASF annotations and CID, then the simulated business acceptance.
2. Run **Revoked**: the identity remains verified while the marketplace withholds business acceptance.
3. Run **Status unavailable** or **Stale status**: show why an old successful check cannot stand in for current assurance.
4. Use **Wrong organization** or **Tampered credential** to explain subject binding and signature checks.

See the [proposal and responsibility split](dnb-attestation-proposal.md) for the work needed to replace the fixtures with an agreed provider integration.

## Presenter controls

Choose **Next step** to start manual playback, then click it to reveal each completed operation. **Resume automatic** resumes timed playback. These controls are also available in the expanded diagram. The backend continues executing while the presentation waits; this is not a server-side debugger. **Show console** opens the full scrollable operation output in the upper-right corner.
