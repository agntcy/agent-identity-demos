# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Shared AGNTCY identity client — Vault-backed CIMD attestation + Directory.

Extracted from webapp/app.py so every Org A service (webapp, opencode-agent
orchestrator, future agents) uses one implementation of:

  - Vault Transit signing + DER→JWK public key extraction  (vault.py)
  - Self-issued proof JWTs and identity-node CIMD calls    (cimd.py)
  - AGNTCY Directory push/search over gRPC                 (directory.py)

Conventions (must match identity-node-init.py's bootstrap registration):
  - kid  = "{key_name}-v1"        (Vault Transit key version 1)
  - iss  = "agntcy:{common_name}" (registered trust-authority common name)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class VaultConfig:
    """Org trust-authority signing configuration (key lives in Vault Transit)."""

    vault_addr: str
    vault_token: str
    key_name: str
    common_name: str

    @property
    def kid(self) -> str:
        return f"{self.key_name}-v1"

    @property
    def issuer(self) -> str:
        return f"agntcy:{self.common_name}"

    @classmethod
    def from_env(cls) -> "VaultConfig":
        return cls(
            vault_addr=os.environ.get("VAULT_ADDR", "http://identity-vault:8200").rstrip("/"),
            vault_token=os.environ.get("VAULT_TOKEN", ""),
            key_name=os.environ.get("VAULT_KEY_NAME", "org-a-issuer"),
            common_name=os.environ.get("ORG_A_COMMON_NAME", "org-a"),
        )


from .vault import b64url, get_issuer_jwk, vault_sign_rs256, build_proof_jwt  # noqa: E402
from .cimd import generate_id, resolve_id  # noqa: E402

__all__ = [
    "VaultConfig",
    "b64url",
    "get_issuer_jwk",
    "vault_sign_rs256",
    "build_proof_jwt",
    "generate_id",
    "resolve_id",
]
