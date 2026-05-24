"""Mesherra crypto primitives.

Per ARCHITECTURE.md section 13.9 and demos/phase_1/SPEC.md section 4.

Off-the-shelf primitives only; no invention:
- Canonical JSON encoding: ``jcs`` library (RFC 8785).
- Hashing: ``hashlib.sha256`` (stdlib).
- Signing: Ed25519 via the ``cryptography`` library.

The module exposes four building blocks used by the provenance layer:

* :func:`canonical_json` — deterministic JSON-to-bytes encoder. The single
  authoritative way to turn a Python dict into the bytes that get hashed or
  signed. Never call ``json.dumps`` for signed/hashed content — Python's
  default serializer is not canonical and produces different bytes across
  processes.
* :func:`content_hash` — SHA-256 hex digest of canonical bytes. The
  ``payload_hash`` field of a ``Residue`` entry is this function applied to
  the canonical bytes of the payload.
* :class:`Signer` / :class:`Verifier` — Ed25519 sign and verify. Signatures
  are emitted and consumed as **base64 strings** (the wire form the
  ``Residue.signature`` field stores), not raw bytes; callers do not have to
  manage byte/string conversion.

Return-type convention (chosen to match what the Residue model actually
stores, so callers don't have to convert at every step):

* :func:`content_hash` returns ``str`` (lowercase hex). The Residue stores
  hex (regex ``^[0-9a-f]{64}$``).
* :meth:`Signer.sign` returns ``str`` (base64). The Residue stores base64.
* :meth:`Verifier.verify` accepts the base64 ``str`` directly.
* :func:`canonical_json` returns ``bytes`` (UTF-8) — the format SHA-256 and
  Ed25519 expect.
"""

from __future__ import annotations

import base64
from hashlib import sha256
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# -- Canonicalization & hashing ------------------------------------------


def canonical_json(obj: Any) -> bytes:
    """Encode ``obj`` to canonical JSON bytes per RFC 8785 (JCS).

    Output is order-independent for dict keys: the same logical object
    encoded twice (even with different key insertion order) produces
    byte-equal output. This is the property the entire provenance layer
    relies on — without it, two ledgers would compute different
    ``payload_hash`` values for the same payload.

    Used wherever bytes must be deterministic across processes:
    ``payload_hash`` computation, ``previous_hash`` chain links, and the
    signing input for a Residue (with the ``signature`` field omitted).
    """
    return jcs.canonicalize(obj)


def content_hash(payload: bytes) -> str:
    """SHA-256 hex digest of ``payload``.

    Returns a 64-character lowercase hex string — the wire form stored in
    Residue.payload_hash and Residue.previous_hash. Callers should pass
    canonical bytes (typically from :func:`canonical_json`); SHA-256 itself
    has no opinion about content, so any caller bug that hashes non-canonical
    bytes will surface as a payload-hash mismatch between ledgers.
    """
    return sha256(payload).hexdigest()


# -- Ed25519 signing & verification --------------------------------------


class Signer:
    """Ed25519 signer holding a single principal's private key.

    Construct via one of the classmethods rather than the raw initializer
    when you need to load a key from disk or generate a new one:

    * :meth:`generate` — fresh keypair (tests, demos).
    * :meth:`from_pem` — load from PEM-encoded private key bytes.
    * :meth:`from_raw_bytes` — load from a raw 32-byte Ed25519 seed.

    Signatures are emitted as **base64 strings** so they drop directly into
    the ``Residue.signature`` field without conversion.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> Signer:
        """Generate a fresh Ed25519 keypair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> Signer:
        """Load a private key from PEM-encoded bytes.

        Supports both PKCS8 unencrypted and encrypted (with ``password``).
        Raises ValueError if the loaded key is not Ed25519.
        """
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(
                f"PEM contains a {type(key).__name__}, not Ed25519PrivateKey"
            )
        return cls(key)

    @classmethod
    def from_raw_bytes(cls, raw: bytes) -> Signer:
        """Load from a 32-byte Ed25519 private key seed."""
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def sign(self, payload: bytes) -> str:
        """Sign ``payload``; return the base64-encoded signature string.

        Ed25519 is deterministic: signing the same payload with the same
        private key always produces the same signature. Tests can rely on
        this for known-answer assertions.
        """
        sig_bytes = self._private_key.sign(payload)
        return base64.b64encode(sig_bytes).decode("ascii")

    def export_pem(self) -> bytes:
        """Export the private key as unencrypted PKCS8 PEM bytes.

        Phase 1 stores keys at rest in local-secrets/ (gitignored). Encryption
        at rest is a Phase 2+ concern; for the localhost demo the keys never
        leave the machine.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def verifier(self) -> Verifier:
        """Return the matching :class:`Verifier` for the public half."""
        return Verifier(self._private_key.public_key())

    def public_key_b64(self) -> str:
        """Return the raw 32-byte Ed25519 public key as base64.

        This is the form an agent publishes in its config so counterparties
        can construct a :class:`Verifier` via :meth:`Verifier.from_b64`.
        """
        return base64.b64encode(self._raw_public_bytes()).decode("ascii")

    def _raw_public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


class Verifier:
    """Ed25519 verifier holding a single principal's public key.

    Construct via :meth:`from_b64` (when the public key was published as a
    base64 string in agent config), :meth:`from_raw_bytes` (raw 32 bytes),
    or :meth:`from_pem` (PEM-encoded public key).
    """

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_b64(cls, b64: str) -> Verifier:
        """Load from a base64-encoded raw 32-byte Ed25519 public key."""
        raw = base64.b64decode(b64)
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @classmethod
    def from_raw_bytes(cls, raw: bytes) -> Verifier:
        """Load from a raw 32-byte Ed25519 public key."""
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @classmethod
    def from_pem(cls, pem: bytes) -> Verifier:
        """Load from PEM-encoded public key bytes.

        Raises ValueError if the loaded key is not Ed25519.
        """
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(
                f"PEM contains a {type(key).__name__}, not Ed25519PublicKey"
            )
        return cls(key)

    def verify(self, payload: bytes, signature_b64: str) -> bool:
        """Verify ``signature_b64`` over ``payload``.

        Returns True if the signature is valid for this public key, False
        otherwise. Malformed base64 or wrong-length signatures also return
        False (they are unverifiable, by definition). This collapses
        InvalidSignature, malformed base64, and wrong key length into one
        boolean so callers can write ``if verifier.verify(...)`` without a
        try/except around every call site.
        """
        try:
            sig_bytes = base64.b64decode(signature_b64, validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        try:
            self._public_key.verify(sig_bytes, payload)
        except InvalidSignature:
            return False
        return True

    def public_key_b64(self) -> str:
        """Return the raw 32-byte Ed25519 public key as base64."""
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def export_pem(self) -> bytes:
        """Export the public key as SubjectPublicKeyInfo PEM bytes."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


# -- Guest credential (deferred to Phase 1.5) ----------------------------


def mint_guest_credential(scope: dict, expires_in_seconds: int) -> bytes:
    """Mint a short-lived scoped credential for a guest principal.

    Lifecycle (minting policy, expiry rules, conversion to standing) deferred
    to Phase 1.5 per ARCHITECTURE.md section 14.
    """
    raise NotImplementedError(
        "mint_guest_credential is implemented in Phase 1.5 "
        "(guest principal lifecycle)."
    )
