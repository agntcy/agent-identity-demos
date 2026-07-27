# Cross-Domain AI Agent Remediation Demo (ID-JAG + VC)

A cross-domain agent delegation scenario: **Sarah** (an engineer at **Org A**)
asks **OpenCode** (her Org A AI agent) to fix a CVE found in a repo owned by
**Org B**. Org B has its own Keycloak realm and access control, so OpenCode
can't act there directly — it asserts Sarah's delegation cross-domain using
**ID-JAG** (Identity Assertion JWT Authorization Grant), then Triage further
delegates a *narrowed* privilege to a bounded Sub-Agent that actually opens
the pull request.

It also wires in two AGNTCY components for real:

- **AGNTCY Directory Node** — every remediation turn is pushed as a
  content-addressed OASF record (immutable audit trail); agents are
  discoverable by name.
- **AGNTCY Identity Node (CIMD)** — Org A is registered as a real,
  **Vault-backed local trust authority**; agent identities are minted and
  resolved through identity-node's actual cryptographic proof-of-ownership
  flow, not a mock.

## What's real vs. mocked

| Step(s) | What | Real or mocked |
|---|---|---|
| 1 | Sarah's OIDC login at Keycloak A | **Real** |
| 2 | CVE scan | Mocked (no scanner integration) |
| 3–4 | AGNTCY Directory push + search (gRPC) | **Real** |
| 5–6 | CIMD generate/resolve id (Vault-signed proof JWT → identity-node) + VC badge issue/verify (signed `vc+jwt` → vc-issuer) | **Real** |
| 7 | RFC 8693 token exchange at Keycloak A | **Real** call; see note below on `act` claims |
| 8 | ID-JAG mint for Org B triage-agent | **Real** |
| 9–10 | Org A egress PDP — may Sarah delegate this scope to Org B? | **Real** single-token JWT verification + inline OPA policy |
| 11 | Keycloak B `jwt-bearer` redemption | **Real** |
| 12–13 | Envoy ingress, ticket creation, OPA check, plan, sub-badge mint | **Real** two-token JWT verification + inline delegation-aware OPA policy |
| 14 | Sub-Agent spawned with the narrowed badge | **Real** |
| 15–18 | Sub-Agent `jwt-bearer` exchange, Envoy resource enforcement, push file, open PR | **Real** |
| 19 | Resource-boundary OPA decision | **Real** two-token JWT verification + repository-bound policy |
| 20 | PR created, causal act-chain audit | **Real** |
| — | OpenTelemetry `trace_id` linking every hop | **Real** — see [Viewing traces](#viewing-traces) |

Milestone 1 provisioned the Built On Envoy gateway and inline OPA module.
Milestone 2 protects ticket ingress by verifying the Keycloak B access token
and the original ID-JAG actor token, then enforcing signed scope, delegation
chain, intent, and repository constraints. Milestone 3 protects the resource
path: the narrowed sub-badge is signed for one repository, Sub-Agent sends it
with its access token through listener `10001`, and inline OPA allows only the
specific push and pull-request operations. Milestone 4 protects the Org A
egress boundary: before OpenCode ever redeems the ID-JAG at Keycloak B, Envoy
A verifies the freshly-minted assertion against idjag-issuer's JWKS and inline
OPA checks its scope, intent, and delegation-chain depth — a policy violation
never leaves Org A. Milestone 5 replaces the hardcoded
VC badge mock with vc-issuer, a real signed-`vc+jwt` issuer/verifier standing
in for identity-node's (nonexistent) badge API. Milestone 6 makes the RFC
8693 exchange at Keycloak A a real network call instead of a static mock —
see the note below on what Keycloak's standard token exchange does and does
not do with the `actor_token`. Milestone 7 adds real distributed tracing:
every service exports OpenTelemetry spans via OTLP to a local Jaeger container,
and standard `httpx`/FastAPI auto-instrumentation propagates the W3C
`traceparent` header across every hop (including transparently through Envoy,
which just forwards it as an ordinary header) — so one browser-triggered run
produces one real, inspectable trace end to end.

**A note on `actor_token` and the `act` claim**: Keycloak 26.7's standard
token exchange (`standard.token.exchange.enabled`) validates `subject_token`
for real, but this was confirmed live (garbage or absent `actor_token`
produces a byte-identical response, and keycloak-a logs nothing either way)
to not itself verify `actor_token` or emit an RFC 8693 `act` claim — that is
a genuine platform behavior in this configuration, not a shortcut taken
here. Getting Keycloak to emit its own `act` claim would require a custom
protocol-mapper SPI (compiled Java, mounted into the container) — a much
larger, riskier undertaking than closing the "no HTTP call was ever made"
gap this milestone addresses. The badge (`actor_token`) is independently,
cryptographically verified against vc-issuer one step earlier, and
delegation semantics continue to be carried forward for real via the
ID-JAG's `act_chain` claim, unaffected by this limitation.

## Architecture

```mermaid
flowchart TB
    Sarah(("Sarah"))

    subgraph OrgA[" Org A "]
        KCA["Keycloak A\norg-a realm"]
        OC["OpenCode Agent"]
        EnvoyA["Built On Envoy\ninline OPA — egress"]
    end

    subgraph AGNTCY[" AGNTCY shared infrastructure "]
        Dir["Directory Node\ngRPC, OASF records"]
        IdNode["Identity Node\nCIMD"]
        Vault[("Vault\ntransit engine")]
        VC["VC Badge Issuer"]
        IDJAG["ID-JAG Issuer"]
    end

    subgraph OrgB[" Org B "]
        KCB["Keycloak B\norg-b realm"]
        Envoy["Built On Envoy\ninline OPA"]
        Triage["Triage Agent"]
        Sub["Sub-Agent\nbounded privilege"]
        GW["Gitea Gateway\nscope + deny-list"]
        Gitea[("Gitea")]
    end

    Sarah -->|"OIDC login"| OC
    OC -->|"push / search records"| Dir
    OC -->|"generate / resolve id"| IdNode
    IdNode -.->|"proof JWT signing"| Vault
    OC -->|"issue + verify badge"| VC
    OC -->|"mint assertion"| IDJAG
    OC -->|"egress check: assertion"| EnvoyA
    EnvoyA -->|"verify JWT + enforce scope, intent, chain"| OC
    OC -->|"jwt-bearer exchange"| KCB
    OC -->|"POST /api/ticket"| Envoy
    Envoy -->|"verify both JWTs + enforce delegation"| Triage
    Triage -->|"mint narrowed sub-badge"| IDJAG
    Triage -->|"spawn"| Sub
    Sub -->|"jwt-bearer exchange"| KCB
    Sub -->|"access token + sub-badge"| Envoy
    Envoy -->|"enforce operation + signed repository"| GW
    GW -->|"admin API"| Gitea

    classDef orgA fill:#dbe9fe,stroke:#1f6feb,color:#0d1117;
    classDef orgB fill:#dafbe1,stroke:#1a7f37,color:#0d1117;
    classDef shared fill:#f1e4ff,stroke:#8250df,color:#0d1117;
    class KCA,OC,EnvoyA orgA;
    class KCB,Triage,Sub,GW,Gitea orgB;
    class Dir,IdNode,Vault,VC,IDJAG shared;
```

22 services on one Docker network (`cd-net`):

| Service | Image | Host port(s) | Purpose |
|---|---|---|---|
| `keycloak-a` | `quay.io/keycloak/keycloak:26.7` | `8082` | Org A IdP (`org-a` realm), authenticates Sarah |
| `kc-a-init` | `quay.io/keycloak/keycloak:26.7` | _(one-shot)_ | Registers `triage:create` optional scope |
| `keycloak-b` | `quay.io/keycloak/keycloak:26.7` | `8083` | Org B IdP (`org-b` realm), redeems ID-JAG assertions |
| `kc-b-init` | `quay.io/keycloak/keycloak:26.7` | _(one-shot)_ | Registers `triage:create`/`gitea:*` optional scopes |
| `vc-issuer` | built from `./vc-issuer` | `9003` | Issues + verifies signed VC badges (stand-in — identity-node has no badge API) |
| `idjag-issuer` | built from `../archive/single-org-id-jag-app-access/idjag-issuer` | `9002` | Mints ID-JAG assertions (stand-in issuer) |
| `identity-postgres` | `postgres:16` | _(internal)_ | DB for identity-node |
| `identity-vault` | `hashicorp/vault:1.17` | _(internal)_ | Holds the org-a trust-authority signing key (Transit engine) |
| `identity-node` | `ghcr.io/agntcy/identity/node:0.0.23` | `4005` (REST), `4006` (gRPC) | AGNTCY identity node — CIMD id generate/resolve |
| `identity-node-init` | `python:3.12-slim` | _(one-shot)_ | Bootstraps Vault Transit + registers org-a as trust authority |
| `dir-postgres` | `postgres:16` | _(internal)_ | Search index DB for the Directory |
| `dir-zot` | `ghcr.io/project-zot/zot:v2.1.17` | `5556` | OCI registry backing the Directory's content-addressed storage |
| `dir-apiserver` | `ghcr.io/agntcy/dir-apiserver:v1.6.0` | `8888` | AGNTCY Directory Node (gRPC only) |
| `agent-dir-init` | built from `./agent-dir-init` | _(one-shot)_ | Pushes static OASF records for all 3 demo agents |
| `gitea` | `gitea/gitea:1.22` | `3002` (HTTP), `2223` (SSH) | Protected resource (repo server) |
| `gitea-init` | `gitea/gitea:1.22` | _(one-shot)_ | Seeds the Gitea admin + demo repo |
| `gitea-gateway` | built from `../archive/single-org-id-jag-app-access/gitea-gateway` | _(internal only)_ | Requires Envoy policy metadata, then rechecks token scope before using Gitea admin credentials |
| `envoy-org-a` | built from `./envoy-org-a` (Envoy + Built On Envoy Composer) | `12000`; admin `127.0.0.1:9902` | Org A gateway; egress JWT + inline OPA policy (may Sarah delegate this scope to Org B?) |
| `envoy-org-b` | built from `./envoy` (Envoy + Built On Envoy Composer) | `10000`, `10001`; admin `127.0.0.1:9901` | Org B gateway; separate ticket-ingress and resource-access JWT + inline OPA policies |
| `opencode-agent` | built from `./opencode-agent` | `8101` | Org A mock agent (Phase A/B driver) |
| `triage-agent` | built from `./triage-agent` | _(internal only)_ | Org B mock agent; reachable from outside `cd-net` only through Envoy |
| `sub-agent` | built from `./sub-agent` | `8300` | Org B bounded-privilege mock agent (push + PR) |
| `webapp` | built from `./webapp` | `8090` | Animated sequence-diagram demo UI |
| `jaeger` | `jaegertracing/all-in-one:1.65.0` | `16686` | OpenTelemetry trace backend — collector (OTLP) + UI + storage |

## Sequence flow

Every hop below actually happens against the real services in this stack
(Keycloak, Vault, identity-node, vc-issuer, dir-apiserver, Gitea). Only the
CVE scan is mocked. All three Envoy enforcement points — egress, ticket
ingress, and resource access — are real. This is the same
flow the webapp's UI animates step by step.

```mermaid
sequenceDiagram
    autonumber
    actor Sarah
    participant OC as OpenCode (Org A)
    participant KCA as Keycloak A
    participant Dir as AGNTCY Directory
    participant IdNode as Identity Node
    participant Vault
    participant VC as VC Badge Issuer
    participant IDJAG as ID-JAG Issuer
    participant EnvoyA as Envoy A + OPA (egress)
    participant KCB as Keycloak B
    participant Envoy as Built On Envoy + OPA
    participant Triage as Triage (Org B)
    participant Sub as Sub-Agent (Org B)
    participant GW as Gitea Gateway
    participant Gitea

    Sarah->>OC: "Fix the CVE in the Org B repo"
    OC->>KCA: OIDC password grant
    KCA-->>OC: access token
    Note over OC: mock CVE scan → HIGH severity (mocked)

    OC->>Dir: push turn record (OASF)
    Dir-->>OC: CID
    OC->>Dir: search "triage-agent"
    Dir-->>OC: agent record

    OC->>Vault: sign proof JWT (transit/sign)
    Vault-->>OC: RS256 signature — private key never leaves Vault
    OC->>IdNode: generate id (proof JWT)
    IdNode-->>OC: id = AGNTCY-triage-agent
    OC->>IdNode: resolve id
    IdNode-->>OC: ResolverMetadata + public key

    OC->>VC: POST /vc/issue (id, caps, delegating_user, intent, act_chain)
    VC-->>OC: signed badge (vc+jwt)
    OC->>VC: POST /vc/verify (badge)
    VC-->>OC: valid=true + claims

    OC->>KCA: token-exchange (subject_token=Sarah, actor_token=badge)
    Note over KCA: validates subject_token; does not process actor_token<br/>into an act claim (real Keycloak behavior, see README note)
    KCA-->>OC: exchanged access token
    OC->>IDJAG: mint assertion (sub=Sarah, scope=triage:create, intent=create-pr-fix)
    IDJAG-->>OC: signed assertion (RS256)

    OC->>EnvoyA: POST /api/egress-check (assertion as Bearer)
    EnvoyA->>IDJAG: fetch/cached JWKS
    Note over EnvoyA: verify JWT; enforce scope, intent, act-chain depth
    EnvoyA-->>OC: ALLOW + policy decision headers

    OC->>KCB: jwt-bearer grant
    KCB-->>OC: scoped access token

    OC->>Envoy: POST /api/ticket (access token + actor token)
    Envoy->>KCB: fetch/cached JWKS
    Envoy->>IDJAG: fetch/cached JWKS
    Note over Envoy: verify both JWTs; enforce scope, chain, signed intent, repo
    Envoy->>Triage: ALLOW + policy decision headers
    Triage->>IDJAG: mint sub-badge (gitea:write/pr, resource=target repo)
    IDJAG-->>Triage: sub-badge (act_chain: Sarah→OpenCode→Triage→Sub-Agent)
    Triage->>Sub: spawn with sub-badge

    Sub->>KCB: jwt-bearer exchange
    KCB-->>Sub: scoped token (gitea:write, gitea:pr)
    Sub->>Envoy: push fix (access token + signed sub-badge)
    Note over Envoy: verify both JWTs; enforce chain, scope, intent, operation, repo
    Envoy->>GW: ALLOW push + policy decision headers
    GW->>Gitea: create branch + commit
    Gitea-->>GW: ok
    GW-->>Sub: branch created
    Sub->>Envoy: open PR (access token + signed sub-badge)
    Envoy->>GW: ALLOW PR + policy decision headers
    GW->>Gitea: create PR
    Gitea-->>GW: ok
    GW-->>Sub: PR created ✓

    Sub->>Envoy: open PR on demo-protected (same token, same scope)
    Envoy--xSub: 403 policy_deny — outside signed resource

    Note over Sub,Triage: resource OPA decision is real and inline
    Sub-->>Triage: PR link + denied-attempt result
    Triage-->>OC: ticket complete
    OC-->>Sarah: PR ready — full act-chain audit trail
```

## Quick start

```bash
cd cross-domain-id-jag-vc
cp .env.example .env
# SARAH_PASSWORD / OPENCODE_CLIENT_SECRET / TRIAGE_CLIENT_SECRET /
# SUB_AGENT_CLIENT_SECRET must stay as the .env.example defaults (or be
# changed to match keycloak-a/org-a-realm.json + keycloak-b/org-b-realm.json)
# — everything else can be freely changed.

docker compose up -d --build
```

The first build pulls the pinned Envoy base image and Built On Envoy Composer
artifact. To deliberately refresh those pinned inputs:

```bash
docker compose build --pull envoy-org-a envoy-org-b
docker compose up -d envoy-org-a envoy-org-b
```

First boot takes ~3–5 minutes (Keycloak + identity-node + Directory cold
start). Watch it settle:

```bash
docker compose logs -f
```

Wait until these one-shot containers exit 0: `kc-a-init`, `kc-b-init`,
`gitea-init`, `identity-node-init`, `agent-dir-init`.

## Viewing traces

Every service exports OpenTelemetry spans via OTLP to a local Jaeger
all-in-one container — no external tracing backend or extra setup needed.

1. Trigger a run (`curl -X POST http://localhost:8100/api/run ...`, or via
   the webapp).
2. Open **http://localhost:16686**, select a service (e.g. `opencode-agent`)
   in the left panel, and click **Find Traces**.
3. Open the most recent trace to see the full waterfall — `opencode-agent`'s
   own spans plus every downstream call it made via `httpx` (`vc-issuer`,
   `idjag-issuer`, Keycloak A/B, Envoy, …), all under one `trace_id`, because
   standard `httpx`/FastAPI auto-instrumentation propagates the W3C
   `traceparent` header on every hop automatically — no manual wiring.

`opencode-agent`'s `/api/run` response also includes a top-level `trace_id`
field, so you can jump straight to a specific run:
`http://localhost:16686/trace/<trace_id>`.

Note: Envoy hops (`envoy-org-b`) forward the `traceparent` header like any
other header, so the trace stays continuous through them, but Envoy itself
doesn't emit its own spans (no Envoy-side tracing filter is configured) —
the fan-out is visible per-service, just not per-Envoy-hop.

## Testing

### Envoy Milestones 2–3 reviewer verification

This procedure is self-contained. It verifies both Rego policies, the
digest-pinned image, both listeners, successful ticket and resource
delegations, independent resource-denial cases, metrics, and non-bypassable
service exposure. Run it from the repository root with Docker, Docker Compose,
`curl`, and `jq`.

1. Run the two policy suites independently:

   ```bash
   docker run --rm \
     -v "$PWD/cross-domain-id-jag-vc/envoy/policies:/policies:ro" \
     openpolicyagent/opa:1.8.0 \
     test /policies/ticket-ingress.rego \
          /policies/ticket-ingress_test.rego -v

   docker run --rm \
     -v "$PWD/cross-domain-id-jag-vc/envoy/policies:/policies:ro" \
     openpolicyagent/opa:1.8.0 \
     test /policies/resource-access.rego \
          /policies/resource-access_test.rego -v

   docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
     -v "$PWD/archive/single-org-id-jag-app-access/gitea-gateway:/src" \
     -w /src python:3.12-slim sh -c \
     'pip install -q -r requirements-dev.txt &&
      pytest -q -p no:cacheprovider'

   docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
     -v "$PWD/archive/single-org-id-jag-app-access/idjag-issuer:/src" \
     -w /src python:3.12-slim sh -c \
     'pip install -q -r requirements-dev.txt &&
      pytest -q -p no:cacheprovider'
   ```

   Expected: ticket ingress passes 9/9, resource access passes 13/13, Gitea
   Gateway passes 15 tests, and the ID-JAG issuer passes 10 tests.

2. Create the environment file, validate Compose, build the gateway, validate
   its bootstrap, and start the stack:

   ```bash
   cd cross-domain-id-jag-vc
   test -f .env || cp .env.example .env
   docker compose config --quiet
   docker compose build --pull envoy-org-b
   docker run --rm cd-envoy-boe:milestone3 \
     envoy --mode validate -c /etc/envoy/envoy.yaml
   docker compose up -d --build
   ```

   If this Compose project was started before and its demo data does not need
   to be preserved, run `docker compose down --volumes` before
   `docker compose up`. The identity demo stores generated proof material in
   volumes; reusing it with rebuilt issuer containers can produce a stale
   `ERROR_REASON_INVALID_PROOF` at the unrelated CIMD step.

3. Allow 3–5 minutes for a cold start, then inspect service state and both
   listeners:

   ```bash
   docker compose ps -a
   curl --fail --silent --show-error http://localhost:10000/health | jq .
   curl --fail --silent --show-error http://localhost:10001/healthz | jq .
   curl --fail --silent --show-error http://127.0.0.1:9901/ready
   docker compose ps gitea-gateway
   if docker compose exec -T sub-agent python -c \
     'import socket; socket.gethostbyname("gitea-gateway")' 2>/dev/null; then
     echo "ERROR: Sub-Agent can bypass Envoy"
     exit 1
   else
     echo "OK: Gitea Gateway is isolated behind Envoy"
   fi
   ```

   Long-running services should be healthy and all five one-shot services
   should exit 0. Both listener requests return 200, readiness prints `LIVE`.
   The Gitea Gateway row shows only `9100/tcp`, with no host address or
   published port. The final check confirms the Sub-Agent cannot resolve the
   gateway on its network; Envoy reaches it through the isolated resource
   network instead.

4. Run the complete sequence and retain the narrowed resource credentials:

   ```bash
   RUN_OUTPUT="$(mktemp)"
   curl --fail --silent --show-error \
     -X POST http://localhost:8090/api/run \
     -H 'Content-Type: application/json' \
     -d '{"cve":"CVE-2024-12345","repo":"demo-admin/payments-service"}' \
     -o "$RUN_OUTPUT"

   jq '{
     ok,
     failed_steps: [.steps[] | select(.status == "error") | .id],
     ticket_policy: [first(.steps[] | select(.id == "opa-ingress")) |
       .result | {decision, rule, delegation_depth}],
     resource_policy: [first(.steps[] | select(.id == "opa-egress")) |
       .result | {decision, rule, action, repository, delegation_depth}],
     protected_repo: [first(.steps[] |
       select(.id == "denied-pr-attempt")) | {status, result}]
   }' "$RUN_OUTPUT"

   SUB_ACCESS_TOKEN="$(jq -r 'last([.steps[] |
     select(.id == "kc-b-exchange")]) | .token' "$RUN_OUTPUT")"
   SUB_BADGE="$(jq -r 'first(.steps[] |
     select(.id == "mint-sub-badge")) | .token' "$RUN_OUTPUT")"
   ```

   Expected: `ok=true`, no failed steps, both policy decisions are `ALLOW`,
   the resource rule is `org-b-resource-delegation`, the signed repository is
   `demo-admin/payments-service`, delegation depth is 2, and the protected
   repository attempt has status `denied`.

5. Prove that changing the requested intent is denied before Gitea Gateway:

   ```bash
   curl --silent --show-error --include \
     -X POST http://localhost:10001/api/gitea/push/demo-admin/payments-service \
     -H "Authorization: Bearer $SUB_ACCESS_TOKEN" \
     -H "X-AGNTCY-Actor-Token: Bearer $SUB_BADGE" \
     -H 'Content-Type: application/json' \
     -d '{"intent":"delete-repository",
          "act_chain":["opencode-agent","triage-agent","sub-agent"],
          "ticket_id":"TRIAGE-2024-12345"}'
   ```

   Expected: HTTP 403 with `error=policy_denied`.

6. Prove that the signed sub-badge and signed repository restriction are both
   mandatory:

   ```bash
   curl --silent --show-error --include \
     -X POST http://localhost:10001/api/gitea/push/demo-admin/payments-service \
     -H "Authorization: Bearer $SUB_ACCESS_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"intent":"create-pr-fix",
          "act_chain":["opencode-agent","triage-agent","sub-agent"],
          "ticket_id":"TRIAGE-2024-12345"}'

   curl --silent --show-error --include \
     -X POST http://localhost:10001/api/gitea/push/demo-admin/other-service \
     -H "Authorization: Bearer $SUB_ACCESS_TOKEN" \
     -H "X-AGNTCY-Actor-Token: Bearer $SUB_BADGE" \
     -H 'Content-Type: application/json' \
     -d '{"intent":"create-pr-fix",
          "act_chain":["opencode-agent","triage-agent","sub-agent"],
          "ticket_id":"TRIAGE-2024-12345"}'
   ```

   Expected: the missing sub-badge returns HTTP 401; the repository outside
   the signed `resource` claim returns HTTP 403.

7. Prove that administrative operations are outside the policy:

   ```bash
   curl --silent --show-error --include \
     -X POST http://localhost:10001/api/gitea/repos \
     -H "Authorization: Bearer $SUB_ACCESS_TOKEN" \
     -H "X-AGNTCY-Actor-Token: Bearer $SUB_BADGE" \
     -H 'Content-Type: application/json' \
     -d '{"name":"not-allowed"}'
   ```

   Expected: HTTP 403. Only `push` and `pulls` routes are eligible for allow.

8. Confirm metrics and access logs:

   ```bash
   curl --fail --silent --show-error \
     'http://127.0.0.1:9901/stats?filter=opa_requests_total'
   curl --fail --silent --show-error \
     'http://127.0.0.1:9901/stats?filter=jwt_authn'
   docker compose logs --since=5m envoy-org-b | grep gitea_gateway
   rm "$RUN_OUTPUT"
   ```

   OPA and JWT counters should include allowed and denied decisions. Successful
   push and PR requests have `gitea_gateway` as the upstream cluster; policy
   denials do not. Credential and verified-payload headers are excluded from
   access logs.

If a port is allocated, change the corresponding `ENVOY_*_PORT` value in
`.env`. For startup failures, inspect `docker compose logs envoy-org-b` and
`docker compose logs triage-agent sub-agent gitea-gateway`.

When finished, `docker compose down` preserves demo data. Use
`docker compose down -v` only when intentionally deleting all demo data.

### OpenTelemetry / Jaeger reviewer verification

Verifies traces are actually flowing end to end, not just that the SDK
imports cleanly.

1. Bring up the stack (includes `jaeger`) and confirm it's healthy:

   ```bash
   cd cross-domain-id-jag-vc
   docker compose up -d --build
   curl --fail --silent --show-error -o /dev/null -w '%{http_code}\n' http://localhost:16686
   ```

2. Trigger a run and capture its `trace_id`:

   ```bash
   RUN_OUTPUT="$(mktemp)"
   curl --fail --silent --show-error -X POST http://localhost:8100/api/run \
     -H 'Content-Type: application/json' \
     -d '{"repo":"demo-admin/payments-service"}' -o "$RUN_OUTPUT"
   TRACE_ID="$(jq -r .trace_id "$RUN_OUTPUT")"
   echo "trace_id: $TRACE_ID"
   rm "$RUN_OUTPUT"
   ```

   Expected: a 32-character hex string, not `null`.

3. Confirm Jaeger actually received spans for that trace, across multiple
   services (proving propagation, not just that `opencode-agent` traces
   itself):

   ```bash
   curl --fail --silent --show-error "http://localhost:16686/api/traces/$TRACE_ID" \
     | jq '{
         spanCount: (.data[0].spans | length),
         services: [.data[0].processes[].serviceName] | unique
       }'
   ```

   Expected: `spanCount` > 1, and `services` includes at minimum
   `opencode-agent`, `vc-issuer` (or `idjag-issuer`), and `keycloak`-adjacent
   spans — i.e. more than one service name, proving the `traceparent` header
   really propagated across the `httpx` calls rather than each service
   starting an unrelated, disconnected trace.

4. Run the existing unit test suites and confirm no regressions from adding
   instrumentation:

   ```bash
   docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
     -v "$PWD/../archive/single-org-id-jag-app-access/idjag-issuer:/src" \
     -w /src python:3.12-slim sh -c \
     'pip install -q -r requirements-dev.txt && pytest -q -p no:cacheprovider'

   docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
     -v "$PWD/../archive/single-org-id-jag-app-access/gitea-gateway:/src" \
     -w /src python:3.12-slim sh -c \
     'pip install -q -r requirements-dev.txt && pytest -q -p no:cacheprovider'
   ```

   Expected: 10/10 and 15/15 pass (same counts as before this PR). You'll see
   `Transient error ... exporting traces to jaeger:4317` warnings in the
   output — expected, since these unit tests run standalone without Jaeger
   reachable; they don't affect the test results.

### Envoy Milestone 4 reviewer verification

Verifies the egress Rego policy, the digest-pinned image, the egress
listener, a full successful run through the egress check, and an
independent egress-denial case. Run it from the repository root with
Docker, Docker Compose, `curl`, and `jq`.

1. Run the egress policy suite:

   ```bash
   docker run --rm \
     -v "$PWD/cross-domain-id-jag-vc/envoy-org-a/policies:/policies:ro" \
     openpolicyagent/opa:1.8.0 \
     test /policies/egress.rego /policies/egress_test.rego -v
   ```

   Expected: 10/10 tests pass.

2. Validate Compose, build the gateway, and validate its native config:

   ```bash
   cd cross-domain-id-jag-vc
   docker compose config --quiet
   docker compose build --pull envoy-org-a
   docker run --rm cd-envoy-boe-a:milestone4 \
     envoy --mode validate -c /etc/envoy/envoy.yaml
   docker compose up -d --build
   ```

3. Confirm the listener and admin port are healthy:

   ```bash
   curl --fail --silent --show-error http://localhost:12000/health | jq .
   curl --fail --silent --show-error http://127.0.0.1:9902/ready
   ```

4. Run the full sequence and confirm the egress check passed:

   ```bash
   RUN_OUTPUT="$(mktemp)"
   curl --fail --silent --show-error -X POST http://localhost:8100/api/run \
     -H 'Content-Type: application/json' \
     -d '{"repo":"demo-admin/payments-service"}' -o "$RUN_OUTPUT"
   jq '{ok, egress: [.steps[] | select(.id == "egress-check")][0]}' "$RUN_OUTPUT"
   rm "$RUN_OUTPUT"
   ```

   Expected: `ok=true`, the `egress-check` step has `status=ok`.

5. Prove a policy violation never leaves Org A — mint an assertion with an
   unsupported intent directly via `idjag-issuer` and present it straight to
   the egress listener:

   ```bash
   BAD_ASSERTION="$(curl --silent --show-error -X POST http://localhost:9002/mint \
     -H 'Content-Type: application/json' \
     -d '{"sub":"sarah@org-a.example","aud":"http://keycloak-b:8080/realms/org-b",
          "client_id":"triage-agent","act_chain":["opencode-agent"],
          "scope":"openid","intent":["delete-repository"]}' | jq -r .assertion)"

   curl --silent --show-error --include -X POST http://localhost:12000/api/egress-check \
     -H "Authorization: ******"
   ```

   Expected: HTTP 403 with `error=policy_denied`. This is a policy denial, not
   a JWT-signature failure — the assertion is validly signed by idjag-issuer,
   it just doesn't carry an allowed scope/intent.

6. Confirm metrics show both decisions:

   ```bash
   curl --fail --silent --show-error \
     'http://127.0.0.1:9902/stats?filter=opa_requests_total'
   ```

### VC badge issuer reviewer verification

Verifies the badge issuer's own test suite, that it builds and starts
cleanly, and that `opencode-agent`'s badge-resolution step now issues and
verifies a real signed badge instead of returning a hardcoded mock.

1. Run the badge issuer's unit tests:

   ```bash
   docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
     -v "$PWD/cross-domain-id-jag-vc/vc-issuer:/src" \
     -w /src python:3.12-slim sh -c \
     'pip install -q -r requirements-dev.txt && pytest -q -p no:cacheprovider'
   ```

   Expected: 9/9 tests pass.

2. Validate Compose and start the stack:

   ```bash
   cd cross-domain-id-jag-vc
   docker compose config --quiet
   docker compose up -d --build
   ```

3. Confirm the issuer is healthy and its JWKS is well-formed:

   ```bash
   curl --fail --silent --show-error http://localhost:9003/healthz | jq .
   curl --fail --silent --show-error http://localhost:9003/jwks | jq .
   ```

4. Issue and verify a badge directly, confirming it is a real signed `vc+jwt`
   (not the old hardcoded mock):

   ```bash
   BADGE="$(curl --silent --show-error -X POST http://localhost:9003/vc/issue \
     -H 'Content-Type: application/json' \
     -d '{"id":"opencode-agent","caps":["scan","remediate","delegate"],
          "delegating_user":"sarah@org-a.example",
          "intent":"cross-domain-remediation","act_chain":["opencode-agent"]}' \
     | jq -r .badge)"

   curl --silent --show-error -X POST http://localhost:9003/vc/verify \
     -H 'Content-Type: application/json' \
     -d "{\"badge\":\"$BADGE\"}" | jq .
   ```

   Expected: `valid: true`, claims matching the request, and a `typ: vc+jwt`
   header (`echo "$BADGE" | cut -d. -f1 | base64 -d`).

5. Run the full sequence and confirm the badge step used the real issuer:

   ```bash
   RUN_OUTPUT="$(mktemp)"
   curl --fail --silent --show-error -X POST http://localhost:8100/api/run \
     -H 'Content-Type: application/json' \
     -d '{"repo":"demo-admin/payments-service"}' -o "$RUN_OUTPUT"

   jq '{ok, badge: [.steps[] | select(.id == "resolve-badge")][0]}' "$RUN_OUTPUT"
   rm "$RUN_OUTPUT"
   ```

   Expected: `ok=true`, the `resolve-badge` step has `status=ok` and a
   `token_preview` (the real signed badge), not the old static mock claims.

### Keycloak A token exchange reviewer verification

Verifies the RFC 8693 exchange at Keycloak A is a real network call, and
transparently demonstrates the real Keycloak platform behavior documented
above: `subject_token` is validated, `actor_token` is not.

1. Run the full sequence and confirm the exchange step is real:

   ```bash
   cd cross-domain-id-jag-vc
   docker compose up -d --build

   RUN_OUTPUT="$(mktemp)"
   curl --fail --silent --show-error -X POST http://localhost:8100/api/run \
     -H 'Content-Type: application/json' \
     -d '{"repo":"demo-admin/payments-service"}' -o "$RUN_OUTPUT"

   jq '{ok, kc_a_exchange: [.steps[] | select(.id == "kc-a-exchange")][0]}' "$RUN_OUTPUT"
   rm "$RUN_OUTPUT"
   ```

   Expected: `ok=true`, the `kc-a-exchange` step has `status=ok` and a
   `token_preview` (a real Keycloak-issued access token, not a static mock).

2. Confirm Keycloak validates `subject_token` for real — an invalid one is
   rejected:

   ```bash
   curl --silent --show-error -o /dev/null -w '%{http_code}\n' \
     -X POST http://localhost:8082/realms/org-a/protocol/openid-connect/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d client_id=opencode-agent \
     -d client_secret=demo-opencode-secret-change-me \
     -d subject_token=not-a-real-token \
     -d subject_token_type=urn:ietf:params:oauth:token-type:access_token
   ```

   Expected: non-200 (Keycloak rejects the malformed subject token).

3. Demonstrate the documented `actor_token` platform behavior directly —
   run the same exchange with a garbage `actor_token` and with none at all,
   using a real `subject_token` from step 1's Sarah login:

   ```bash
   SARAH_TOKEN="$(curl --silent --show-error -X POST \
     http://localhost:8082/realms/org-a/protocol/openid-connect/token \
     -d grant_type=password -d client_id=opencode-agent \
     -d client_secret=demo-opencode-secret-change-me \
     -d username=sarah -d ****** \
     -d 'scope=openid profile email' | jq -r .access_token)"

   curl --silent --show-error -o /dev/null -w 'with garbage actor_token: %{http_code}\n' \
     -X POST http://localhost:8082/realms/org-a/protocol/openid-connect/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d client_id=opencode-agent -d client_secret=demo-opencode-secret-change-me \
     -d "subject_token=$SARAH_TOKEN" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
     -d actor_token=not-a-real-jwt-at-all \
     -d actor_token_type=urn:ietf:params:oauth:token-type:jwt

   curl --silent --show-error -o /dev/null -w 'with no actor_token:      %{http_code}\n' \
     -X POST http://localhost:8082/realms/org-a/protocol/openid-connect/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d client_id=opencode-agent -d client_secret=demo-opencode-secret-change-me \
     -d "subject_token=$SARAH_TOKEN" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:access_token
   ```

   Expected: both return `200` — identical to a request with a real,
   verified badge as `actor_token`. This is not a bug in this PR; it is the
   real behavior of Keycloak 26.7's standard token exchange in this
   configuration, documented above.


### Via the webapp (recommended)

Open **http://localhost:8090**. Click **Run (animated)** to watch all 20
steps execute with live sequence-diagram highlighting and a step-by-step
explainer toast, or **Next step ▶** to step through manually.

### Via the API directly

```bash
# Full sequence
curl -s -X POST http://localhost:8090/api/run \
  -H 'Content-Type: application/json' \
  -d '{"cve":"CVE-2024-12345","repo":"demo-admin/payments-service"}' | jq .

curl -s http://localhost:8090/api/health
curl -s http://localhost:8090/api/config | jq .

# Individual steps (step-through mode)
curl -s -X POST http://localhost:8090/api/step/cimd-generate-id \
  -H 'Content-Type: application/json' -d '{"sub":"triage-agent"}' | jq .
```

You can re-run `/api/run` repeatedly — every push branch is randomized
server-side, so repeat runs don't collide with a prior run's branch/PR.

### Spot-checking individual services

```bash
curl http://localhost:8082/realms/org-a/.well-known/openid-configuration | jq .issuer
curl http://localhost:8083/realms/org-b/.well-known/openid-configuration | jq .issuer
curl http://localhost:9002/jwks | jq .
curl http://localhost:4005/v1alpha1/issuer/org-a/.well-known/jwks.json | jq .
curl http://localhost:10000/health
curl http://localhost:10001/healthz
curl http://127.0.0.1:9901/ready
curl 'http://127.0.0.1:9901/stats?filter=opa_requests_total'
grpcurl -plaintext localhost:8888 list   # Directory gRPC services (needs `brew install grpcurl`)
```

## How CIMD actually works (the identity-node "gotcha")

identity-node's real REST API has **no** `/apps` or `/badges` endpoints — it
needs a **self-issued proof JWT** to call `/v1alpha1/id/generate` or
`/v1alpha1/id/resolve`:

1. `identity-node-init` creates an RSA-2048 key in Vault's **Transit** engine
   (`org-a-issuer`) — the private key never leaves Vault.
2. It reads back the public key, builds a JWK (parsing the PEM by hand — no
   crypto library needed since Vault does the signing), and self-signs a
   proof JWT (`iss=agntcy:org-a`, a `sub_jwk` claim carrying that public key)
   via Vault's `/transit/sign` API.
3. It registers **org-a** as a local trust authority with that proof
   (`POST /v1alpha1/issuer/register`).
4. Every subsequent CIMD call — including the ones the webapp makes live —
   signs a **fresh** proof JWT the same way to mint (`AGNTCY-<agent>`) or
   resolve an id under org-a's authority.

Two non-obvious requirements if you're extending this: identity-node
validates the submitted public key on registration (`ValidatePubKey`), and
`jws.Verify` requires a matching `kid` on both the JWK and the JWS header —
omit either and you'll get an opaque failure with no useful error message.

## Troubleshooting

- **`dir-zot` / `dir-apiserver` show no healthcheck / stay "starting"** — both
  images are distroless (no shell, no `nc`, no `wget`). Their `depends_on`
  conditions are `service_started`, not `service_healthy`, by design.
- **`gitea-init` fails with "not supposed to be run as root"** — make sure
  `user: git` is set on the `gitea-init` service (already in the compose
  file); Gitea refuses to run its CLI as root otherwise.
- **`identity-node-init` loops on HTTP 404** — this is expected during
  startup; the probe just checks the REST gateway is routing at all (any
  structured response, even 404, means it's up).
- **CIMD steps return `ERROR_REASON_INVALID_PROOF` / `INVALID_ISSUER`** — the
  proof JWT's `iss` common name must exactly match a *registered* issuer's
  common name, and the JWK must include a `kid` (see above).
  If this appears after recreating containers while retaining old volumes,
  the persisted identity-node registration may refer to the previous
  ephemeral Vault key. Intentionally reset the demo with
  `docker compose down -v`, then start it again. This deletes all local demo
  data, including seeded Gitea state.
- **Directory push fails with an OASF schema validation error** — the real
  `schema.oasf.agntcy.org` may not resolve from your network; the compose
  file points `DIRECTORY_SERVER_OASF_API_VALIDATION_SCHEMA_URL` at
  `https://schema.oasf.outshift.com` instead. Skill/domain names must be
  real OASF taxonomy entries (e.g. `software_engineering/code_quality/code_review`),
  not made-up strings.
- **Repeat `/api/run` calls fail at push-file/open-pr with "branch already
  exists"** — `gitea-gateway` (shared with the archived `single-org-id-jag-app-access`
  demo) now randomizes the branch name per push; if you're on an older image,
  rebuild it (`docker compose build gitea-gateway`).
- **Port already in use** — this stack's default ports are chosen to avoid
  colliding with `single-org-id-jag-app-access`'s defaults; if something else
  on your machine still collides, override the `*_PORT` variables in `.env`.

## Repo layout

```
cross-domain-id-jag-vc/
├── docker-compose.yaml        # the 22-service stack (source of truth)
├── .env.example
├── envoy-org-a/                # Org A egress gateway: Built On Envoy image + egress.rego
├── envoy/                     # Built On Envoy image, JWT filters, and Rego policies/tests
├── vc-issuer/                  # VC badge issuer (stand-in for identity-node's badge API)
├── identity-node-init.py      # Vault Transit bootstrap + org-a issuer registration
├── keycloak-a/, keycloak-b/   # realm import JSON + scope bootstrap scripts
├── gitea/                     # Gitea admin/repo seed script
├── dir/                       # Zot OCI registry config
├── agent-dir-init/            # one-shot: pushes static OASF records for all agents
├── opencode-agent/            # Org A mock agent (Phase A/B)
├── triage-agent/              # Org B mock agent (ticket → sub-badge → spawn)
├── sub-agent/                 # Org B bounded-privilege mock agent
└── webapp/                    # animated sequence-diagram demo UI (FastAPI + vanilla JS)
```
