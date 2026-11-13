# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import directory
from agntcy_identity_client import vc


class CatalogBadgeTests(unittest.TestCase):
    def test_directory_record_is_the_badge_description(self):
        record = directory.build_agent_record(
            "security-autonomous-agent", "http://identity-node:4000"
        )
        credential = vc.build_badge_credential(
            VaultConfig("http://vault", "token", "org-a-issuer", "org-a"),
            subject_id="AGNTCY-security-autonomous-agent",
            caps=["scan"],
            delegating_user="service-account-security-autonomous-agent",
            intent="scan-remediate:demo-admin/payments-service",
            act_chain=["security-autonomous-agent"],
            agent_definition=record,
        )

        subject = credential["credentialSubject"]
        self.assertEqual(subject["badge"], record)
        self.assertEqual(
            subject["relatedResource"][0]["digest"], directory.oasf_digest(record)
        )
        self.assertEqual(
            subject["directoryRecord"]["identity_id"],
            record["annotations"]["identity_id"],
        )

    def test_badge_subject_must_match_catalog_identity(self):
        record = directory.build_agent_record(
            "security-autonomous-agent", "http://identity-node:4000"
        )
        with self.assertRaisesRegex(ValueError, "identity_id"):
            vc.build_badge_credential(
                VaultConfig("http://vault", "token", "org-a-issuer", "org-a"),
                subject_id="AGNTCY-other-agent",
                caps=[],
                delegating_user="user",
                intent="scan",
                act_chain=[],
                agent_definition=record,
            )


if __name__ == "__main__":
    unittest.main()
