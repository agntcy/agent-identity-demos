# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Independent secondary issuer for enterprise Organization VCs."""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agntcy_identity_client import VaultConfig
from agntcy_identity_client import trust_bundle
from agntcy_identity_client.vault import get_issuer_jwk

VAULT_CFG = VaultConfig.from_env()
DEFAULT_ORGANIZATION_URI = os.environ.get(
    "DEFAULT_ORGANIZATION_URI", "urn:agntcy:organization:org-a"
)

ORGANIZATIONS = {
    DEFAULT_ORGANIZATION_URI: {
        "organizationId": os.environ.get("DEFAULT_ORGANIZATION_ID", "org-a-enterprise-001"),
        "legalName": os.environ.get("DEFAULT_LEGAL_NAME", "Org A Security Engineering"),
    }
}

app = FastAPI(title="Secondary Enterprise VC Issuer", version="1.0.0")


class OrganizationCredentialRequest(BaseModel):
    organization_uri: str = DEFAULT_ORGANIZATION_URI


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "issuer": VAULT_CFG.issuer}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        return {"keys": [await get_issuer_jwk(client, VAULT_CFG)]}


@app.post("/api/vc/organization")
async def issue_organization_credential(body: OrganizationCredentialRequest) -> dict:
    organization = ORGANIZATIONS.get(body.organization_uri)
    if organization is None:
        raise HTTPException(status_code=404, detail="organization is not verified by this issuer")
    async with httpx.AsyncClient(timeout=10) as client:
        token, document = await trust_bundle.issue_organization_vc(
            client,
            VAULT_CFG,
            organization_uri=body.organization_uri,
            organization_id=organization["organizationId"],
            legal_name=organization["legalName"],
        )
    return {
        "credential": token,
        "document": document,
        "issuer": VAULT_CFG.issuer,
        "jwks_uri": "/.well-known/jwks.json",
    }
