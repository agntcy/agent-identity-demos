# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Vault Transit signing primitives for CIMD proof JWTs.

The org's RSA private key never leaves Vault — every proof JWT is signed via
Vault's /transit/sign API. The public key is read back from Vault as PEM and
parsed to a JWK by hand (no crypto library needed since Vault does the
signing). Extracted from webapp/app.py.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import httpx

from . import VaultConfig

# JWK cache keyed by (vault_addr, key_name) — the transit public key is
# stable for the life of the demo stack.
_jwk_cache: dict[tuple[str, str], dict] = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _der_rsa_public_numbers(der: bytes) -> tuple[bytes, bytes]:
    """Extract (n, e) from a DER-encoded SubjectPublicKeyInfo."""

    def read_len(data: bytes, off: int) -> tuple[int, int]:
        first = data[off]
        if first & 0x80 == 0:
            return first, off + 1
        n = first & 0x7F
        return int.from_bytes(data[off + 1:off + 1 + n], "big"), off + 1 + n

    def read_tlv(data: bytes, off: int) -> tuple[int, bytes, int]:
        length, val_off = read_len(data, off + 1)
        return data[off], data[val_off:val_off + length], val_off + length

    _, outer_seq, _ = read_tlv(der, 0)
    _, _alg_id, off2 = read_tlv(outer_seq, 0)
    _, bitstring, _ = read_tlv(outer_seq, off2)
    inner = bitstring[1:]  # drop "unused bits" byte
    _, rsa_pub_seq, _ = read_tlv(inner, 0)
    _, n_bytes, off3 = read_tlv(rsa_pub_seq, 0)
    _, e_bytes, _ = read_tlv(rsa_pub_seq, off3)

    def strip_leading_zero(b: bytes) -> bytes:
        return b[1:] if len(b) > 1 and b[0] == 0 else b

    return strip_leading_zero(n_bytes), strip_leading_zero(e_bytes)


async def get_issuer_jwk(client: httpx.AsyncClient, cfg: VaultConfig) -> dict:
    """Fetch (and cache) the org's public key from Vault Transit, as a JWK."""
    cache_key = (cfg.vault_addr, cfg.key_name)
    if cache_key in _jwk_cache:
        return _jwk_cache[cache_key]

    r = await client.get(
        f"{cfg.vault_addr}/v1/transit/keys/{cfg.key_name}",
        headers={"X-Vault-Token": cfg.vault_token},
    )
    r.raise_for_status()
    keys = r.json()["data"]["keys"]
    latest_version = max(keys, key=int)
    pem = keys[latest_version]["public_key"]

    lines = [ln for ln in pem.strip().splitlines() if "BEGIN" not in ln and "END" not in ln]
    der = base64.b64decode("".join(lines))
    n_bytes, e_bytes = _der_rsa_public_numbers(der)

    jwk = {
        "kty": "RSA",
        "n": b64url(n_bytes),
        "e": b64url(e_bytes),
        "alg": "RS256",
        "use": "sig",
        "kid": cfg.kid,
    }
    _jwk_cache[cache_key] = jwk
    return jwk


async def vault_sign_rs256(client: httpx.AsyncClient, cfg: VaultConfig, signing_input: str) -> str:
    """Sign `signing_input` (RS256/PKCS1v15/SHA-256) via Vault Transit."""
    input_b64 = base64.b64encode(signing_input.encode()).decode()
    r = await client.post(
        f"{cfg.vault_addr}/v1/transit/sign/{cfg.key_name}",
        json={"input": input_b64, "hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15"},
        headers={"X-Vault-Token": cfg.vault_token},
    )
    r.raise_for_status()
    vault_sig = r.json()["data"]["signature"]  # "vault:v1:<base64-std>"
    sig_bytes = base64.b64decode(vault_sig.split(":", 2)[2])
    return b64url(sig_bytes)


async def build_proof_jwt(client: httpx.AsyncClient, cfg: VaultConfig, sub: str) -> str:
    """Self-issued proof JWT: iss=agntcy:<org>, sub=<agent>, signed via Vault.

    identity-node requires a matching `kid` on both the sub_jwk and the JWS
    header — omitting either produces an opaque failure.
    """
    jwk = await get_issuer_jwk(client, cfg)
    header = {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}
    now = int(time.time())
    payload = {
        "iss": cfg.issuer,
        "sub": sub,
        "aud": [sub],
        "exp": now + 3600,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "sub_jwk": jwk,
    }
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = await vault_sign_rs256(client, cfg, signing_input)
    return f"{signing_input}.{signature}"
