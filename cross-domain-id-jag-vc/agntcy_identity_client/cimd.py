# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""CIMD calls against the AGNTCY Identity Node (real REST API).

Every call signs a fresh Vault-backed proof JWT (see vault.py) — that is how
identity-node authenticates the org trust authority. Extracted from
webapp/app.py; returns raw API data, callers do their own step formatting.
"""

from __future__ import annotations

import httpx

from . import VaultConfig
from .vault import build_proof_jwt


class CimdError(Exception):
    """Non-2xx identity-node response (other than idempotent already-registered)."""

    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(f"HTTP {status_code}: {body[:300]}")


async def generate_id(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cfg: VaultConfig,
    sub: str,
) -> dict:
    """Generate a CIMD id for `sub` under the org's trust authority.

    Returns {"id": ..., "controller": ..., "already_registered": bool}.
    Idempotent: ERROR_REASON_ID_ALREADY_REGISTERED maps to the well-known
    AGNTCY-<sub> id instead of raising.
    """
    url = f"{identity_node_url.rstrip('/')}/v1alpha1/id/generate"
    proof_jwt = await build_proof_jwt(client, cfg, sub)
    r = await client.post(url, json={
        "issuer": {"organization": cfg.common_name, "commonName": cfg.common_name},
        "proof": {"type": "JWT", "proofValue": proof_jwt},
    })
    if r.status_code == 200:
        rm = r.json().get("resolverMetadata", {})
        return {
            "id": rm.get("id", ""),
            "controller": rm.get("controller", ""),
            "already_registered": False,
        }
    if r.status_code == 400 and "ID_ALREADY_REGISTERED" in r.text:
        return {"id": f"AGNTCY-{sub}", "controller": "", "already_registered": True}
    raise CimdError(r.status_code, r.text)


async def resolve_id(
    client: httpx.AsyncClient,
    identity_node_url: str,
    cimd_id: str,
) -> dict:
    """Resolve a CIMD id back to its ResolverMetadata (raw dict)."""
    url = f"{identity_node_url.rstrip('/')}/v1alpha1/id/resolve"
    r = await client.post(url, json={"id": cimd_id})
    if r.status_code != 200:
        raise CimdError(r.status_code, r.text)
    return r.json().get("resolverMetadata", {})
