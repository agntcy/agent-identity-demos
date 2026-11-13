import json
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import directory
from agntcy_identity_client import trust_bundle
from agntcy_identity_client import vc
from agntcy_identity_client.vault import b64url


def _token(payload: dict, private_key: rsa.RSAPrivateKey, kid: str, typ: str) -> str:
    header = {"alg": "RS256", "kid": kid, "typ": typ}
    encoded_header = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(signature)}"


def _jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


class TrustBundleTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.holder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.org_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.holder = "AGNTCY-security-autonomous-agent"
        self.organization = "urn:agntcy:organization:org-a"

    def test_badge_operator_is_derived_from_canonical_oasf_record(self):
        record = directory.build_agent_record(
            "security-autonomous-agent", "http://identity-node:4000", identity_id=self.holder
        )
        credential = vc.build_badge_credential(
            VaultConfig("http://vault", "token", "org-a-issuer", "org-a"),
            subject_id=self.holder,
            caps=["scan"],
            delegating_user="service-account-security-autonomous-agent",
            intent="scan-remediate:repo",
            act_chain=["security-autonomous-agent"],
            agent_definition=record,
        )
        self.assertEqual(
            credential["credentialSubject"]["operatedBy"], self.organization
        )

    def test_holder_signed_vp_and_secondary_vc_verify_with_distinct_keys(self):
        organization_claims = {
            "issuer": "agntcy:secondary-vc-issuer",
            "type": ["VerifiableCredential", "OrganizationCredential"],
            "expirationDate": "2999-01-01T00:00:00Z",
            "credentialSubject": {"id": self.organization, "organizationId": "org-a-1"},
        }
        organization_vc = _token(
            organization_claims, self.org_key, "secondary-vc-issuer-v1", "JWT"
        )
        vp_claims = {
            "iss": self.holder,
            "aud": "urn:verifier",
            "nonce": "challenge",
            "exp": self.now + 300,
            "vp": {
                "holder": self.holder,
                "type": ["VerifiablePresentation"],
                "verifiableCredential": ["agent-badge", organization_vc],
            },
        }
        presentation = _token(
            vp_claims, self.holder_key, "org-a-issuer-v1", "VerifiablePresentation+jwt"
        )

        verified_vp = trust_bundle.verify_compact(
            presentation,
            _jwk(self.holder_key, "org-a-issuer-v1"),
            expected_typ="VerifiablePresentation+jwt",
            expected_issuer=self.holder,
            expected_audience="urn:verifier",
            now=self.now,
        )
        verified_org = trust_bundle.verify_compact(
            organization_vc,
            _jwk(self.org_key, "secondary-vc-issuer-v1"),
            expected_typ="JWT",
            expected_issuer="agntcy:secondary-vc-issuer",
            now=self.now,
        )
        self.assertEqual(verified_vp["nonce"], "challenge")
        self.assertEqual(verified_org["credentialSubject"]["id"], self.organization)
        self.assertNotEqual(
            _jwk(self.holder_key, "org-a-issuer-v1")["n"],
            _jwk(self.org_key, "secondary-vc-issuer-v1")["n"],
        )


if __name__ == "__main__":
    unittest.main()
