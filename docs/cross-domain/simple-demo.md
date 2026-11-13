# Simple identity and discovery demo

Select **Simple discovery** on the demo site, or open `/?mode=simple`. Click **Run live demo**. Use **Reset view** to clear the display without deleting identities or records. **Full agent workflow** returns to the existing remediation demo.

Set `DEMO_MODE=simple` in the Compose environment to make simple mode the default. `DEMO_MODE=full` restores the original landing page. Recreate only `webapp` after changing the environment setting.

The demo driver performs two paths with existing workload identities:

1. Publisher (`triage-agent`, Org B) obtains a real Keycloak client-credentials token. The driver validates its signature, issuer, expiry and workload identity using that realm's discovery document and keys.
2. Publisher registers or reuses its AGNTCY identity through a Vault-signed proof and resolves its public verification material.
3. Publisher creates or reuses an Agent Badge for its canonical OASF description. Vault signs new badges and Identity Node publishes and verifies them.
4. Publisher pushes the record and signed native identity claim. Directory's reconciler and configured Identity Verifier establish verification status and verified-search inclusion.
5. Consumer (`security-autonomous-agent`, Org A) authenticates with Keycloak and registers/resolves its own identity.
6. Consumer searches for the verified publisher, retrieves the matching canonical record, then retrieves and verifies the publisher's badge and record binding. The final result contains the real identities, CID and verification time.

The NDJSON response drives the sequence diagram by completed operation. Internal verifier arrows illustrate the protocol rather than individual captured RPCs. A repeated run can reuse an existing badge and native verification result; the background reconciler continues checking claims. Failures stop the run and never produce a successful discovery result. Raw tokens and private key material are not returned to the page.

Simple mode makes no Envoy, OPA, remediation, LLM, secondary credential or cross-agent delegation calls. The existing services remain available for full mode. Vault, database, OCI storage and internal TLS remain dependencies of the identity/Directory stack. Keycloak authentication establishes workload identity in this driver; its token is not claimed to authorize the Directory gRPC calls, which retain the demo's existing internal transport. No business-resource authorization or agent-task invocation is demonstrated.

## Validation

The live smoke test must finish with `state: complete` from `POST /api/simple/run`, all seven operations successful, the publisher CID present in verified search, and the consumer's badge binding check successful. Unit tests cover rejected workload client/issuer/expiry, accepted signed workload tokens, and the existing badge/native-claim checks. The UI must support switching to full mode and resetting the view.
