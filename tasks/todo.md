# Milestone 12: policy-gated code scan — OpenCode reads Org B's repo through the trust chain

Goal: replace the hardcoded `scan` step with a real one. OpenCode analyzes
actual source fetched from the Org B repository — and it obtains that source
**only** by following the identity trust chain, exactly like every other
cross-domain action in this demo.

The repo (`demo-admin/payments-service`) is owned by **Org B**. Org A's agent
therefore cannot read it directly: reading is itself a cross-domain privileged
action and must be delegated, asserted, and policy-checked. A direct read
would be the ungoverned access this demo exists to argue against.

## Design

Today OpenCode holds one broad assertion (`triage:create`) minted at step 10,
long after the scan at step 6. Scanning needs Org B authority *earlier* and
*narrower*, so it gets its own assertion:

    5   task-scoped VC badge (existing)
    5b  mint READ assertion at Keycloak A — scope=gitea:read, resource=[repo]
    5c  Org A egress PDP on that assertion (reuses /api/egress-check)
    5d  redeem at Keycloak B  → Org B access token carrying gitea:read only
    5e  GET file contents through Envoy B + gitea-gateway (policy-checked)
    6   OpenCode analyzes the fetched source → real finding (CWE-89)
    …   the finding flows into badge intent, ticket, and plan
    10  remediation assertion (existing, unchanged)

Two narrowly-scoped assertions (read, then remediate) instead of one broad
one — this strengthens the least-privilege story rather than complicating it,
and invents no new mechanism: 5b–5e are a second, minimal instance of the
pattern the demo already runs for remediation.

## Tasks

- [ ] Seed a SQL-injection fixture into `payments-service` (`gitea/init.sh`,
      same API pattern as the auto-init README): string-concatenated SQL in a
      small, inert sample, header-commented `INTENTIONALLY VULNERABLE — DEMO
      FIXTURE`. **No vulnerable dependency and no manifest** — nothing for SCA
      tooling to flag, nothing to build, nothing to pull.
- [ ] Org B realm: register `gitea:read` optional scope (`kc-b-init`), and add
      an `opencode-agent` client to `org-b-realm.json` granted **only**
      `gitea:read`, so Org A's agent is a known cross-domain party in Org B
      with read and nothing else.
- [ ] `gitea-gateway`: `GET /api/gitea/contents/{owner}/{repo}/{path}` —
      requires Envoy policy metadata, rechecks scope, then uses admin creds to
      read the file. Read-only; no write path touched.
- [ ] Envoy B resource listener: route + OPA rule for the read — requires
      `gitea:read`, method GET, repository bound into the assertion's
      `resource` claim, delegation depth 1. Plus rego tests.
- [ ] `opencode-agent`: steps 5b–5e (mint read assertion → egress check →
      KC-B redemption → fetch source), then rewrite `scan` to send the fetched
      source to opencode-server and parse a structured finding
      (cwe, file, line, description, severity).
- [ ] Feed the real finding forward: badge intent, ticket, and plan prompt use
      the detected weakness instead of the `CVE-2024-12345` literal.
- [ ] Webapp: diagram rows + explainers for the four new steps.
- [ ] README: scan is no longer mocked — update the real-vs-mocked table, the
      sequence flow, and the services/scopes tables.
- [ ] Live verification, including the **denial path** (below).

## Notes / decisions

- **Source goes to OpenCode in the prompt, not via the filesystem.**
  opencode-server runs `external_directory: deny` (the `7ac84e6` hang fix) and
  has its own workspace, so passing the fetched content in the session message
  avoids both a shared mount and any permission change. OpenCode is still
  genuinely reading and analyzing the repo's real source.
- **CWE, not CVE.** A fixture we authored has no CVE; `CVE-2024-12345` is
  fabricated. Report CWE-89 (SQL injection) — what a real code-analysis pass
  actually yields, and strictly more honest.
- **The scan gains a real failure mode.** It now depends on a successful
  cross-domain read, so a policy denial halts the run before any remediation.
  That is correct behaviour and worth demonstrating explicitly — arguably the
  most compelling thing this change adds, since it shows the trust chain
  refusing a read, not just permitting one.
- Depends on M10 (PR #23) and M11 (PR #25); both merged, branch rebased onto
  `main` at 190c998.
- **The read assertion goes through M11's badge check too.** Minting it at
  Keycloak A now requires the VC badge as `actor_token`, verified against
  vc-issuer's JWKS and bound to Sarah — so step 5b must send the badge just as
  step 10 does. That is the desired behaviour, not an obstacle: the read
  assertion is minted under the same attestation as the remediation one.

## Review

_(to fill in after live verification)_

---

# Milestone 13: real AGNTCY VC badges — retire vc-issuer

Goal: issue the agent badge as a genuine W3C Verifiable Credential, signed with
the org's Vault trust-authority key and **published to identity-node**, instead
of minting a bespoke JWT in a local stand-in service.

## Why

`vc-issuer` was justified as a "stand-in — identity-node has no badge API".
**That premise is false.** identity-node 0.0.23 exposes the VC API today —
`GET /v1alpha1/vc/{id}/.well-known/vcs.json` already answers `{"vcs":[]}` for
`AGNTCY-opencode-agent`, empty only because nothing publishes to it.

Three defects follow from the stand-in, all fixed by using the real API:

- its signing key is generated **per process boot** (`rsa.generate_private_key`
  at import), so badges die on restart and `kid` churns — `BadgeAttestation`
  re-fetches JWKS on unknown `kid` purely to cope with this
- `POST /vc/issue` **authenticates nobody**; it signed a badge for
  `mallory@org-a.example`, a user that does not exist
- it never imports `agntcy_identity_client`, so the badge sits outside the
  AGNTCY trust model entirely — anchored to no registered authority

And the artifact is not what we call it: the payload is
`iss/sub/caps/delegating_user/intent/act_chain` with `typ=vc+jwt`, but has no
`@context`, `type`, or `credentialSubject`. The UI calls it "a W3C Verifiable
Credential". It is not one.

## The upstream contract (from agntcy/identity protos)

    VcService:
      POST /v1alpha1/vc/publish   PublishRequest{vc: EnvelopedCredential, proof?: Proof}
      POST /v1alpha1/vc/verify    VerifyRequest{vc} -> VerificationResult{status, document}
      POST /v1alpha1/vc/search    SearchRequest{id, schema, content}
      POST /v1alpha1/vc/revoke
      GET  /v1alpha1/vc/{id}/.well-known/vcs.json

    VerifiableCredential = context[], type[], issuer, content, id,
                           issuance_date, expiration_date, credential_schema[],
                           credential_status[], proof
    EnvelopedCredential  = {envelope_type, value}
      CREDENTIAL_ENVELOPE_TYPE_JOSE = 2
    CredentialContent    = {content_type, content}
      CREDENTIAL_CONTENT_TYPE_AGENT_BADGE = 1   (content follows the OASF agent schema)
    BadgeClaims          = {id, badge}

Note the verbs: publish/verify/revoke/search — **there is no `/vc/issue`**. The
node registers credentials the issuer has already signed. Signing belongs to
the issuer, with the issuer's key: for us, Vault. That is exactly the flow the
`proof` field anticipates — "provided when the Issuer is provided by an
external IdP. Example: a signed JWT" — the same Vault-signed proof JWT that
`agntcy_identity_client.build_proof_jwt` already produces for CIMD.

## Tasks

- [ ] Spike first: can a Vault-signed JOSE credential be published to 0.0.23
      and pass `/vc/verify`? Everything below is plumbing; this is the risk.
- [ ] `agntcy_identity_client/vc.py`: build the W3C VC, envelope it as JOSE
      signed via Vault, publish, verify
- [ ] `opencode-agent`: `resolve-badge` uses it; badge claims carry the
      policy-scoped intent exactly as today
- [ ] `keycloak-idjag-spi`: verify the badge against identity-node's issuer
      JWKS rather than vc-issuer's — a real trust anchor, stable `kid`
- [ ] Delete `vc-issuer` (service, image, env, README rows) as `idjag-issuer` went
- [ ] Correct the "W3C Verifiable Credential" claim — true once this lands
- [ ] Live verification incl. the negative paths M11 established

## Notes

- Keep the badge's semantic fields (caps, delegating_user, intent, act_chain)
  as the credential `content`; the change is the envelope, signer, and
  registry — not what the badge asserts.
- If 0.0.23 rejects the shape, pin a newer node image before writing plumbing.

---

# Milestone 14: AgentBadge VCs for Triage and Sub-Agent (Org B)

Goal: every registered agent identity resolves to a credential describing what
it is permitted to do. Today only `AGNTCY-opencode-agent` does —
`/v1alpha1/vc/{id}/.well-known/vcs.json` returns 2 VCs for it and **0** for
`AGNTCY-triage-agent` and `AGNTCY-sub-agent`.

## The naming problem this exposes

"Badge" currently means two unrelated artifacts:

| Artifact | Type | Holder |
|---|---|---|
| VC badge | `typ=JOSE`, W3C `AgentBadge`, published to identity-node | OpenCode only |
| "sub-badge" | `typ=oauth-id-jag+jwt` — an OAuth assertion, not a credential | Triage mints, Sub-Agent redeems |

So "Triage mints a narrowed sub-badge" involves nothing VC-shaped. Worth
renaming in docs/UI regardless of what we build: assertion vs credential.

## Scope

- Triage publishes an AgentBadge under **org-b's** Vault key after
  `subbadge-scope-check`, attesting the policy-approved narrowing
  (`act_chain: [opencode-agent, triage-agent]`)
- Sub-Agent publishes one attesting `gitea:write gitea:pr` bound to the repo
  (`act_chain: [..., sub-agent]`)
- Both reuse `agntcy_identity_client/vc.py` unchanged — it is already
  org-agnostic via `VaultConfig.from_env()` (ORG_COMMON_NAME=org-b)

## The decision to make: authoritative, or resolvable-but-advisory?

**A. Advisory** — publish only, nothing checks it. Cheap, no new failure
modes, demonstrates resolvability. But it is decoration, which is exactly the
criticism that justified M11.

**B. Authoritative at the PDP** — Envoy B fetches the VC and requires the
requested operation ⊆ VC caps. A real enforcement point, but puts
identity-node in the request path of every resource call and duplicates what
the ID-JAG already proves.

**C. Checked at handoff (recommended)** — each receiving agent verifies the
*sender's* published credential before acting on what it was handed: Triage
resolves OpenCode's VC when the ticket arrives, Sub-Agent resolves Triage's
when spawned. Requires `act_chain` and caps to be consistent with the
assertion presented. Extends the in-agent verification pattern already
established (`verify-idjag`, `verify-subbadge`) without a per-request PDP
dependency.

Precedence must be explicit either way: **the assertion authorizes the
request; the credential must not contradict it; a contradiction is refused.**
Two attestations of overlapping facts are only safe with a stated tie-break.

## Tasks

- [ ] Triage: publish AgentBadge after `subbadge-scope-check` (org-b key)
- [ ] Sub-Agent: publish AgentBadge after its CIMD registration
- [ ] (if C) `verify-badge` steps at each handoff, binding credential to the
      assertion's `act_chain` and to the sender's CIMD id
- [ ] Fold in the outstanding **badge↔CIMD binding** item — the VC subject is
      the agent's CIMD id, so this milestone is where that binding becomes real
- [ ] Rename assertion vs credential in docs/UI so "badge" stops meaning both
- [ ] Webapp rows + explainers; README; live verification incl. negative paths

## Open risk

Publishing on every run accumulates credentials — `AGNTCY-opencode-agent`
already holds 2 after two runs. Decide whether to revoke/supersede
(`POST /v1alpha1/vc/revoke` exists) or accept growth in a demo.

## M14 addendum: credential lifecycle (decided 2026-08-07)

**Decided: publish once per identity.** One identity resolves to one live
credential. Per-task narrowing stays in the ID-JAG assertion, which is what
the policy layer actually enforces — the badge's per-task `intent` is checked
by nothing today (M11 verifies `delegating_user` only), so making the
credential durable loses no enforcement. Implemented via
`vc.find_live_badge()`: reuse the existing valid credential for this grant,
issue only if absent.

**Registry vs history — deliberate split:**

| | Holds | Semantics |
|---|---|---|
| Identity Node (VC registry) | the *current* credential per identity | mutable: supersede/revoke |
| AGNTCY Directory (OASF, CIDs) | every turn and credential event | append-only, tamper-evident |

Revoking in the registry must not erase history, and it doesn't — the two are
separate services. "How did this agent evolve" is answered from the Directory,
"what may it do now" from the registry. Conflating them would force a choice
between those two questions.

### TODO: supersede-on-issue (revoke the superseded credential)

Blocked on an issuance-time defect found 2026-08-07:

- `POST /v1alpha1/vc/revoke` fails with *"unable to find the revocation status
  in credentialStatus"*. Our credentials are issued **without** a
  `credentialStatus`, so **every credential issued so far is permanently
  irrevocable**. `CredentialStatus{id, type, created_at, purpose}` exists in
  the proto; we simply never emit one.
- Fix at issuance first (`build_badge_credential` must emit
  `credentialStatus`), then supersede: publish the new credential, revoke the
  prior one, and push a Directory record of the transition.
- Credentials issued before that change can never be revoked — only expiry
  removes them from consideration, and see below.

### TODO: the node does not enforce temporal validity

Verified 2026-08-07 by publishing a credential whose `expirationDate` was an
hour in the past:

- the node **accepted** the publish
- `.well-known` grew 5 → 6 — **expired credentials are not filtered**
- **`/vc/verify` returned `status: true`** for it

So `/vc/verify` attests the signature, not that the credential is live. Any
relying party treating it as "is this badge good?" would accept an expired
badge. Our Keycloak SPI checks `expirationDate` itself, which is therefore
load-bearing rather than defence-in-depth — and `vc._still_valid()` does the
same on the client side. Worth raising upstream.

### TODO: Directory records for credential events

Push an OASF record on issue/supersede/revoke so the credential timeline is
reconstructible from the Directory alone, independent of the registry's
current state.

## Badge↔CIMD binding — resolved (2026-08-07)

The backlog carried "badge↔CIMD binding" as an open item. Testing against
identity-node 0.0.23 shows **most of it is already enforced by the node**, so
the item is narrower than it looked. Three distinct things were conflated:

| Property | Status |
|---|---|
| A credential's subject must be a **registered identity** | **enforced upstream** |
| A credential's **issuer must be the issuer that registered the subject** | **enforced upstream** |
| The **presenter is the subject** (proof of possession) | **not achievable** |

Evidence:

- Publishing a credential about `AGNTCY-totally-made-up-agent` →
  `400 could not resolve the ID`. Badges cannot be minted about identities
  that do not exist.
- org-a signing a credential about `AGNTCY-triage-agent` (an org-b identity) →
  `400 Unable to verify the integrity of the data provided`. Cross-org
  issuance is refused; all credentials listed for that subject are
  `issuer=agntcy:org-b`.

So nothing needs building for A or B — worth stating in the README rather than
implementing, since it's a property the demo gets from the Identity Node.

**C is the real residual and it is blocked by CIMD's model.** Resolving any
agent returns its *org's* key — `AGNTCY-triage-agent` and `AGNTCY-sub-agent`
share modulus fingerprint `29f9581d9a48` — so no agent holds a private key it
could use to prove it is the subject of a credential it presents. Process-to-
identity binding comes from Keycloak client credentials, at the OAuth layer,
not from the identity layer.

Consequence for M14's handoff checks: they can honestly assert *"org-X
published this credential about this identifier, and it does not contradict
the assertion presented"* — not *"the process I am talking to is that
identifier"*. Both steps say so in their own result payload.

Closing this item; per-agent keypairs would be an upstream change, and are
worth raising alongside the credential-lifecycle findings in discussion #27.
