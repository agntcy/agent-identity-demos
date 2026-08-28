# How CIMD actually works

identity-node's real REST API has **no** `/apps` or `/badges` endpoints — it needs a **self-issued proof JWT** to call `/v1alpha1/id/generate` or `/v1alpha1/id/resolve`:

1. `identity-node-init` creates an RSA-2048 key in Vault's **Transit** engine (`org-a-issuer`) — the private key never leaves Vault.
2. It reads back the public key, builds a JWK (parsing the PEM by hand — no crypto library needed since Vault does the signing), and self-signs a proof JWT (`iss=agntcy:org-a`, a `sub_jwk` claim carrying that public key) via Vault's `/transit/sign` API.
3. It registers **org-a** as a local trust authority with that proof (`POST /v1alpha1/issuer/register`). The same flow registers **org-b**.
4. Every subsequent CIMD call — including the ones the webapp makes live — signs a **fresh** proof JWT the same way to mint (`AGNTCY-<agent>`) or resolve an id under the org's authority.

Two non-obvious requirements if you're extending this:

- identity-node validates the submitted public key on registration (`ValidatePubKey`)
- `jws.Verify` requires a matching `kid` on both the JWK and the JWS header — omit either and you'll get an opaque failure with no useful error message

## Vault restart gotcha

`identity-vault` runs in dev mode, so its transit keys are in-memory and are destroyed whenever that container restarts (a laptop sleeping is enough), while identity-node's registrations live on a persistent volume and survive. Re-running the bootstrap then mints a *fresh* keypair while registration is skipped as "already exists", leaving identity-node verifying every agent's proof JWT against a public key whose private half no longer exists.

`identity-node-init` detects this and **fails at bootstrap with the remedy**. The fix is to drop the stale registrations only — see the [demo README troubleshooting](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md#troubleshooting).

## Credentials on top of CIMD

Agent badges are W3C Verifiable Credentials signed with the org's Vault trust-authority key and published to identity-node's VC API. The credential subject is the agent's CIMD id. [Credentials vs assertions](credentials.md) separates that standing credential from the per-request ID-JAG.
