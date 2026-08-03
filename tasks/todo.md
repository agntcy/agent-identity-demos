# Milestone 11: issuer-side badge attestation (Keycloak A)

Goal: stop Keycloak A minting an ID-JAG on the strength of a delegation badge
nobody checked.

## The gap

`keycloak-idjag-spi` verified `subject_token` cryptographically, then took
`scope`, `intent`, `resource`, and `act_chain` verbatim from form params. It
never referenced `actor_token` at all — `grep actor_token` over the SPI
returned nothing. The VC badge was verified only by OpenCode, calling
vc-issuer on its own badge, and then OpenCode told Keycloak what authority to
mint. **The only party checking the attestation was the party it was supposed
to constrain**, and the badge's scoping was advisory rather than enforced.

The demo also claimed otherwise. The step explainer read: *"a capability
attestation anchored in vc-issuer's signing key, not a self-asserted claim"* —
which, at the point of issuance, it was.

Scope here is deliberately the smallest increment that is actually true:
verify the badge, and bind it to the subject. Capability containment and
act-chain construction are explicitly out (see Known limitations in README).

## Tasks

- [x] `BadgeAttestation.java`: fetch vc-issuer's JWKS, verify the `vc+jwt`
      signature, check `typ`/`exp`, require
      `delegating_user == subject_token.sub`
- [x] Wire into `IdJagTokenExchangeProvider` after `subject_token` verification
- [x] `idjag.badge.jwks.url` client attribute — opt-in, so realms that have
      not enabled it keep prior behaviour
- [x] Send `actor_token` on the **mint** request, not only on step 9
- [x] Correct the docs that overclaimed: README's `actor_token` note, the
      agent's module docstring, and the step explainers
- [x] Live verification, including negative paths

## Notes / decisions

- **Signature verification and the subject binding are one change, not two.**
  Comparing `delegating_user` against an unverified badge would be defeated by
  forging one, so implementing the binding without the signature check would
  add a control that does not hold.
- **The badge was being presented at the wrong step.** It travelled with step
  9's standard exchange — which Keycloak documents as ignoring `actor_token` —
  and was absent from step 10, where authority is actually minted. Discovered
  when the happy path first failed with "actor_token is required". Fixed by
  sending it with the mint: the attestation belongs with the request that
  creates authority.
- **This is an architectural fix, not a patched exploit.** The minted `sub`
  already came from the verified `subject_token`, so a mismatched badge could
  not corrupt the output before — it was simply ignored. The value is that the
  badge becomes a required, verified input instead of a decorative parameter.
- **JWKS is re-fetched on unknown `kid`.** vc-issuer generates a fresh keypair
  and kid on every boot, so pinning would break across a restart.

## Review

Verified live on 2026-08-03 (full stack, rebuilt keycloak-a + opencode-agent):

- Happy path: `POST :8100/api/run` → **ok=true, 35 steps**, no failures
- **No `actor_token`** → `403 actor_token (VC delegation badge) is required by
  this client but was not supplied`
- **Forged badge** (self-signed, claims Sarah) → `403 vc-issuer's JWKS has no
  key for kid 'forged'`
- **Genuine vc-issuer badge for a different principal** paired with Sarah's
  verified token → `403 actor_token attests delegation by
  'mallory@org-a.example', which is not the subject_token's subject
  'sarah@org-a.example'`

The third case is the one that matters: a cryptographically valid badge,
refused solely because it attests the wrong principal.

Incidental finding worth recording: `vc-issuer`'s `/vc/issue` authenticates
nobody — it signed a badge for `mallory@org-a.example`, a user that does not
exist in the org-a realm. Its signature attests "vc-issuer emitted this", not
"this delegation happened". Captured under Known limitations.

## Follow-up milestones

- M12: policy-gated code scan — OpenCode reads Org B's repo through the trust
  chain and analyses real source (branch `feat/policy-gated-code-scan`,
  partially built: fixture, gateway read route, rego + 21/21 tests)
- Capability containment at issuance (`scope`/`resource`/`intent` ⊆ badge),
  issuer-constructed `act_chain`, and the symmetric check at Keycloak B's
  sub-badge mint
- `vc-issuer` authenticating the delegating user on `/vc/issue` rather than
  accepting it as input
