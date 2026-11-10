# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agntcy_identity_client import VaultConfig, native_claims
from agntcy_identity_client.vault import b64url


class NativeClaimTests(unittest.IsolatedAsyncioTestCase):
    def test_payload_matches_directory_wire_vector(self):
        # Shared v2 vector in agntcy/dir at 9ad81444, testdata/request.json.
        vector = "eyJyZWNvcmRfY2lkIjoicmVjb3JkLW9uZSIsInJvbGUiOiJDTEFJTV9ST0xFX0lERU5USVRZIiwic3ViamVjdCI6ImFnbnRjeTovL0FnZW50LU9uZSIsInNpZ25lZF9hdCI6IjIwMjYtMTAtMDZUMDA6MDA6MDBaIiwiZXhwaXJlc19hdCI6IiJ9"
        self.assertEqual(
            native_claims.canonical_payload("record-one", "agntcy://Agent-One", "2026-10-06T00:00:00Z"),
            base64.urlsafe_b64decode(vector),
        )

    async def test_claim_signature_binds_the_exact_record(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cfg = VaultConfig("http://vault", "test-token", "org-a-issuer", "org-a")
        record = {"name": "agent", "annotations": {"agntcy.dir/identity": "agntcy://Agent-One"}}
        captured = []

        async def sign(_client, _cfg, signing_input):
            return b64url(key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()))

        with (patch.object(native_claims.directory, "push_record", return_value="record-one"),
              patch.object(native_claims, "vault_sign_rs256", side_effect=sign),
              patch.object(native_claims, "push_claim", side_effect=lambda address, claim: captured.append(claim)),
              patch.object(native_claims, "identity_status", side_effect=[
                  {"verified": False, "status": "pending"},
                  {"verified": True, "status": "verified", "cid": "record-one"},
              ]),
              patch.object(native_claims, "identity_cids", return_value=["record-one"])):
            result = await native_claims.publish_and_verify(None, cfg, "directory:8888", record, "Agent-One")

        self.assertTrue(result["verified_search"])
        claim = captured[0]
        header, empty, signature = claim["signature"].split(".")
        self.assertEqual(empty, "")
        self.assertEqual(json.loads(base64.urlsafe_b64decode(header + "==")), {"alg": "RS256"})
        signature_bytes = base64.urlsafe_b64decode(signature + "==")

        def signing_input(cid):
            return (header + "." + b64url(native_claims.canonical_payload(cid, claim["subject"], claim["signedAt"]))).encode()

        key.public_key().verify(signature_bytes, signing_input("record-one"), padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature_bytes, signing_input("another-record"), padding.PKCS1v15(), hashes.SHA256())

    async def test_mismatched_subject_never_reaches_directory(self):
        with patch.object(native_claims.directory, "push_record") as push:
            with self.assertRaisesRegex(ValueError, "subject"):
                await native_claims.publish_and_verify(None, None, "directory:8888", {
                    "annotations": {"agntcy.dir/identity": "agntcy://Someone-Else"},
                }, "Agent-One")
            push.assert_not_called()

    async def test_rejected_badge_never_publishes_a_claim(self):
        from agntcy_identity_client import vc

        with (patch.dict("os.environ", {"DIRECTORY_NATIVE_CLAIMS": "true"}),
              patch.object(native_claims, "publish_and_verify", new_callable=AsyncMock) as publish):
            with self.assertRaisesRegex(ValueError, "rejected"):
                await vc._with_native_claim(None, None, "Agent-One", {}, {"verified": False})
            publish.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
