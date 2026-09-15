# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import poc


class TwoVcVpTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.challenge = "test-challenge"
        self.domain = "https://verifier.example/test"
        self.secondary = poc.SecondaryVcIssuer()
        self.identity = poc.IdentityService()
        self.policy = poc.TrustPolicy(
            trusted_org_issuer=self.secondary.issuer,
            trusted_badge_issuer=self.identity.issuer,
            trusted_organization=self.identity.organization_uri,
            trusted_identity_service=self.identity.issuer,
            trusted_resolver="agntcy://approved-local-resolver",
        )
        self.verifier = poc.Verifier(self.secondary, self.identity, self.policy)
        self.organization_vc = self.secondary.issue_organization_vc(self.identity.organization_uri, self.now)
        self.badge = self.identity.issue_agent_badge(self.now)
        self.vp = self.identity.create_vp(
            self.badge, self.organization_vc, self.challenge, self.domain, self.now
        )

    def test_two_vcs_and_vp_are_accepted(self):
        result = self.verifier.verify_bundle(self.vp, self.challenge, self.domain, self.now)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["agent"], "Security Autonomous Agent")
        self.assertEqual(result["organization_id"], "acme-security-org-001")
        self.assertTrue(all(check["passed"] for check in result["checks"]))

    def test_wrong_challenge_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "VP challenge"):
            self.verifier.verify_bundle(self.vp, "wrong-challenge", self.domain, self.now)

    def test_operated_by_binding_is_rejected(self):
        badge_header, badge_claims, _, _ = poc.decode_jwt(self.badge)
        badge_claims = copy.deepcopy(badge_claims)
        badge_claims["credentialSubject"]["operatedBy"] = "urn:org:untrusted"
        tampered_badge = poc.sign_jwt(badge_claims, self.identity.issuer_key, "JWT")
        tampered_vp = self.identity.create_vp(
            tampered_badge, self.organization_vc, self.challenge, self.domain, self.now
        )
        with self.assertRaisesRegex(ValueError, "operatedBy binding"):
            self.verifier.verify_bundle(tampered_vp, self.challenge, self.domain, self.now)

    def test_cimd_digest_is_rejected_when_cimd_changes(self):
        original = self.identity.cimd_document
        self.identity.cimd_document = {**original, "client_id": "different-agent"}
        with self.assertRaisesRegex(ValueError, "CIMD bytes match relatedResource digest"):
            self.verifier.verify_bundle(self.vp, self.challenge, self.domain, self.now)


if __name__ == "__main__":
    unittest.main()
