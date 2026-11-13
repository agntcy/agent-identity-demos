"""The fixture must fail closed independently of the live identity result."""
import time
import unittest
import jwt
import dnb_demo as demo


class AttestationPolicyTests(unittest.TestCase):
    def test_scenarios_keep_business_decision_separate(self):
        now = int(time.time())
        expected = {"valid": "accepted", "revoked": "revoked", "expired": "expired", "stale": "stale", "unavailable": "unavailable", "wrong_org": "wrong_organization", "tampered": "invalid_signature"}
        for scenario, outcome in expected.items():
            with self.subTest(scenario=scenario):
                token, status = demo.fixture(scenario, now)
                result = demo.evaluate(token, status, demo.ORGANIZATION, now)
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(result["accepted"], scenario == "valid")

    def test_freshness_boundary_excludes_old_success(self):
        now = int(time.time())
        token, status = demo.fixture("valid", now)
        self.assertTrue(demo.evaluate(token, status, demo.ORGANIZATION, now + demo.MAX_AGE - 1)["accepted"])
        self.assertEqual(demo.evaluate(token, status, demo.ORGANIZATION, now + demo.MAX_AGE)["outcome"], "stale")
        status["source_available"] = False
        self.assertEqual(demo.evaluate(token, status, demo.ORGANIZATION, now)["outcome"], "unavailable")

    def test_wrong_issuer_rejected_even_with_valid_signature(self):
        now = int(time.time())
        token, status = demo.fixture("valid", now)
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["iss"] = "https://unapproved.example.invalid"
        altered = jwt.encode(claims, demo.KEY, algorithm="RS256")
        self.assertFalse(demo.evaluate(altered, status, demo.ORGANIZATION, now)["accepted"])
