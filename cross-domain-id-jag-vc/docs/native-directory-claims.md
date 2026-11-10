# Native Directory identity verification

The demo builds Directory from the merged
[PR #2292](https://github.com/agntcy/dir/pull/2292), pinned at
`9ad81444be3d213e2c84e2a4299021728da742ec`. The `dir-apiserver` service now
runs `dirctl daemon start`, including the indexer and identity reconciler,
against the existing PostgreSQL database and Zot registry.

The companion external verifier remains experimental. Its build is pinned to
[identity#182](https://github.com/agntcy/identity/pull/182), commit
`53ec1e34049ddb34e8caed9762b4ab0ae5516838`. This demo's existing Node `0.0.23`
supports its Vault-backed identities and assertion keys; the live smoke test
checks that combination. It does not depend on the controller response field
from the separate OIDC-enrollment example.

## What a successful badge step proves

1. The canonical OASF record declares `agntcy.dir/identity: agntcy://<Agent ID>`.
2. The agent publishes an Agent Badge containing that exact record to Identity
   Node. Its signing key remains inside Vault Transit.
3. The agent pushes the record to Directory and signs the native five-field
   claim payload with Vault. The detached JWS is stored as an
   `agntcy.dir.identity.v1.IdentityClaim` OCI referrer.
4. Directory calls the external verifier over authenticated HTTPS. The verifier
   resolves the agent's assertion keys, verifies the claim and matching badge,
   and returns a signed, request-bound observation.
5. Directory authenticates that observation and checks the claim signature
   locally. The agent waits for verified status **and** inclusion in verified
   identity search before reporting success.

The badge step's result includes `directory_identity`. The registered-agents
panel reads the current status and CID from Directory; it does not infer
verification from a successful record upload or badge publication.

The existing two-VC Trust Verifier still applies Org B's organization and
delegation policy. Native Directory verification proves agent control and
record/badge consistency; it does not grant repository access, accredit the
organization, or replace the cross-domain authorization checks.

## Configuration and persisted state

`dir/daemon.yaml` reconciles every 10 seconds, with a five-minute maximum age.
The external verifier signs observations valid for at most five minutes,
also bounded by badge expiry. Identity status and verified search exclude
expired observations. Stored policy verdicts are invalidated on successful
reconciliation writes; this is not an independent wall-clock policy gate.

The one-shot `directory-trust-init` service creates an internal CA, TLS keys,
verifier signing key and bearer token in named Docker volumes. Directory mounts
only the public verifier key, CA certificate and bearer token. The verifier's
private signing key is in a separate volume. `identity-node-tls` terminates TLS
for Node's existing HTTP API; it performs no verification itself. None of these
internal services publishes a host port.

The internal TLS certificates are reissued when the init service is rerun with
less than 30 days remaining; restart the proxy and verifier afterward. The
verifier signing key and token persist across ordinary rebuilds. Public-site
TLS is separately managed by the deployment's reverse proxy.

`DIRECTORY_NATIVE_CLAIMS=true` enables claim publication in the agent services.
Missing configuration, rejected evidence and verification timeout fail the
badge step. Existing audit records remain separate from canonical agent records.

## Validate locally or on the demo host

Run the ordinary Compose build and start commands from the demo directory:

```sh
docker compose build
docker compose up -d
```

The smoke test enrolls a dedicated agent, publishes a matching badge and claim,
then submits a second CID under the same identity without a matching badge. It
requires the first to appear in verified search and the second to be rejected.
It prints status/CIDs, never JWTs or private keys. Test records and credentials
remain in the selected test deployment, so prefer an isolated database and OCI
repository when testing against a shared host.

```sh
docker compose run --rm --no-deps -T --entrypoint python webapp - \
  < tests/live_native_claims.py
```

Unit tests cover the Directory wire vector, cryptographic CID binding, rejected
badge handling, catalog/badge consistency, A2A behavior and the existing
two-credential trust logic:

```sh
PYTHONPATH=. python -m unittest discover -s tests -v
```

Before upgrading an existing deployment, preserve its environment/overrides and
take a database dump and source backup. Build images before restarting services.
Do not run `docker compose down -v` during an upgrade: those volumes contain
the existing database, registry, Vault state and verifier keys.
