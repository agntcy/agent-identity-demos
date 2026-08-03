# Milestone 10: Sub-Agent identity lifecycle + Triage discovery (Org B)

Goal: finish the Org B side of the delegation chain. Sub-Agent is currently
the only agent in the demo with no identity of its own — it blindly redeems
whatever sub-badge it is handed. Give it the same lifecycle OpenCode (M8) and
Triage (M9) have, and close the one stage Triage is still missing.

Lifecycle shape every agent should share:
verify inbound credential → register own identity → policy-scoped credential
→ work → (delegate narrower | record the turn)

## Tasks

- [x] Sub-Agent `s1 verify-subbadge`: verify the sub-badge in-agent against
      **Keycloak B's** JWKS *before* redeeming it — signature, `iss`/`aud`,
      `typ=oauth-id-jag+jwt`, `client_id`==sub-agent, `act.act_chain` is the
      parent chain of the chain it was spawned with, `scope` ⊆ the scopes it
      is allowed to hold, `resource` covers the repo it was asked to touch,
      `intent` matches. Fail closed — no redemption on any mismatch.
- [x] Sub-Agent `s2 cimd-generate-id` / `s2b cimd-resolve-id`: register its
      OWN identity (`AGNTCY-sub-agent`) at identity-node under the **org-b**
      trust authority (Vault-signed proof JWT), then resolve it back
- [x] Sub-Agent `s6 dir-push`: push its own OASF turn record → CID (the leaf
      of the chain gets an audit entry too)
- [x] Sub-Agent packaging: proto + shared_lib build contexts, grpc deps,
      compose wiring (Vault, identity-node, Directory); drop the dead
      `IDJAG_ISSUER_URL` — nothing mints there any more
- [x] Triage `t6b dir-search`: discover sub-agent in the Directory by name
      before spawning it — the one lifecycle stage Triage lacks vs OpenCode
- [x] Webapp diagram + explainer text for the five new steps
- [x] README: M10 paragraph, real-vs-mocked table, services table, sequence
      flow, reviewer verification section
- [x] Live verification (full stack, real run)
- [x] Fix the Vault/identity-node key-mismatch trap found during verification
      (`identity-node-init` now fails at bootstrap with the remedy instead of
      surfacing as `ERROR_REASON_INVALID_PROOF` mid-run) + troubleshooting docs

## Notes / decisions

- **No new PDP endpoint for Sub-Agent.** It is the leaf — it delegates to
  nobody, so there is no narrowing for policy to approve. Its "policy-scoped
  credential" stage is the sub-badge it was handed plus Envoy B's existing
  resource-access enforcement on every call it makes.
- **Don't assert an exact `sub` on the sub-badge.** Keycloak B mints it from
  the inbound Sarah-federated access token, so `sub` is a KC-B user id, not
  `sarah@org-a.example`. Require it present, don't pin its value.
- The badge's `act_chain` is `[opencode-agent, triage-agent]` while the
  spawn body's is `[opencode-agent, triage-agent, sub-agent]` — verification
  compares badge chain against `body.act_chain[:-1]`.

## Review

Verified live on 2026-08-02 (full stack, 21 services):

- End-to-end `POST :8100/api/run` → **ok=true, 35 steps** (was 30 — five new:
  Triage `dir-search`, Sub-Agent `verify-subbadge`, `cimd-generate-id`,
  `cimd-resolve-id`, `dir-push`). Run completes in ~2.2s with a mocked plan.
- **All three agents now hold CIMD identities**, resolvable at identity-node:
  `AGNTCY-opencode-agent` (kid org-a-issuer-v1), `AGNTCY-triage-agent` and
  `AGNTCY-sub-agent` (both kid org-b-issuer-v1)
- `verify-subbadge` on the happy path: iss=KC-B, `client_id=sub-agent`,
  scope `openid gitea:write gitea:pr` (**no triage:create**), resource
  `[demo-admin/payments-service]`, act_chain `[opencode-agent, triage-agent]`
- **Negative test — fails closed**: a forged sub-badge (tampered signature,
  and carrying an escalated `triage:create`) is refused at s1; the run returns
  a single errored step, so no CIMD registration, no redemption at Keycloak B,
  and no resource call ever happens.
- Triage `dir-search` found the delegate by name (5 matches, `record_name=sub-agent`)
- Sub-Agent's own Directory turn record: real CID `baeareietrwdh23eek…`
- `denied-pr-attempt` still correctly `denied` (policy_denied)
- PR created: `/demo-admin/payments-service/pulls/7`, act_chain
  `opencode-agent → triage-agent → sub-agent`
- Images build clean (protoc codegen + `dir_proto`/`shared_lib` contexts);
  `docker compose config` OK

Not covered: the `ALLOWED_SCOPES` subset check is exercised positively (a
correctly-narrowed badge passes) but not negatively — forging a *validly
signed* over-scoped badge would need Keycloak B's realm key, so that path
is only reachable via a genuine upstream narrowing bug.

## Bugs found during verification (not M10 code)

1. **Vault dev-mode key loss silently breaks CIMD.** `identity-vault` is
   in-memory, so every restart destroys its transit keys, but identity-node's
   postgres survives. `register_issuer` saw "already exists" and skipped
   re-registration, leaving identity-node verifying proof JWTs against a dead
   public key → `ERROR_REASON_INVALID_PROOF` deep inside a run with nothing
   naming the cause. This cost most of a verification session.

   **Fixed** — `assert_key_matches_registration()` in `identity-node-init.py`
   compares Vault's current modulus against the issuer's published JWKS and
   exits non-zero at bootstrap with the exact remedy. Verified both ways:
   healthy stack still registers/skips normally; after
   `docker compose restart identity-vault` (which reproduces the real key
   loss) init fails loudly, and following its printed remedy restores a green
   `ok=true, 35 steps` run. Documented in the troubleshooting section.
2. **Stale images silently reintroduce fixed bugs.** Three separate symptoms
   (10-minute runs, expired Sarah token, Triage's missing actor-token header)
   all traced to containers running images built before `7ac84e6`/M9 rather
   than to code under test — most sharply, `envoy-org-b` running with
   `forward: false` on the actor-token provider where the repo says `true`.
   **Documented** as a troubleshooting entry with the rebuild commands,
   including the `--force-recreate` needed for realm-JSON changes to re-import.

## Follow-up milestones

- M11: real work in Org B (LLM plan; gitea-gateway accepting caller-supplied
  patch content so the Sub-Agent pushes OpenCode's actual fix)
- M12: real CVE scan (the last mocked step in the chain); badge↔CIMD binding
