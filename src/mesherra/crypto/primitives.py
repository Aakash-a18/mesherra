"""Crypto Primitives.

Implements ARCHITECTURE.md section 13.9.

Shared utility module. No invention; off-the-shelf libraries only
(`cryptography` package).

Provides:
- Signing and signature verification (Ed25519 or equivalent modern scheme)
- Key management (per-principal keys, per-session ephemeral keys)
- Content addressing (SHA-256 hashing)
- Short-lived scoped credentials for guest principals (cold-start primitive
  for MeshyCal invitees; lifecycle deferred to Phase 1.5 per section 14)

Status: scaffolding only.
"""

from __future__ import annotations


class Signer:
    """Sign payloads with a principal's private key."""

    def __init__(self, key_path: str) -> None:
        raise NotImplementedError

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError


class Verifier:
    """Verify signatures against a public key."""

    def __init__(self, public_key: bytes) -> None:
        raise NotImplementedError

    def verify(self, payload: bytes, signature: bytes) -> bool:
        raise NotImplementedError


def content_hash(payload: bytes) -> bytes:
    """SHA-256 content addressing for canonical payloads."""
    raise NotImplementedError


def mint_guest_credential(scope: dict, expires_in_seconds: int) -> bytes:
    """Mint a short-lived scoped credential for a guest principal.

    Lifecycle (minting policy, expiry rules, conversion to standing) deferred
    to Phase 1.5 per ARCHITECTURE.md section 14.
    """
    raise NotImplementedError
