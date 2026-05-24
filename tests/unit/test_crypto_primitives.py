"""Unit tests for mesherra.crypto.primitives.

Covers SPEC §4 (canonicalization commitment) and SPEC §5 assertion 3
(every signature verifies). Step 3 (the ledger) and step 4 (the A2A wire)
both call into this module; if these tests are not green, nothing downstream
can pass.

No real principal identifiers, calendar data, or keys appear in fixtures —
all keys are generated per test (Ed25519PrivateKey.generate); identifiers
use the synthetic ``@phase1.local`` domain.
"""

from __future__ import annotations

import base64
import json
from hashlib import sha256

import pytest

from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
    mint_guest_credential,
)

# -- canonical_json -------------------------------------------------------


class TestCanonicalJson:
    """SPEC §4: JCS canonicalization is the single authority for signed bytes."""

    def test_returns_bytes(self) -> None:
        out = canonical_json({"a": 1})
        assert isinstance(out, bytes)

    def test_key_order_independent(self) -> None:
        """The same logical object encoded two ways must produce equal bytes.

        This is the property the entire trust layer hangs on: if two
        ledgers compute different bytes for the same payload, the
        payload_hash diverges and the end-state assertion fails.
        """
        a = canonical_json({"a": 1, "b": 2, "c": 3})
        b = canonical_json({"c": 3, "a": 1, "b": 2})
        assert a == b

    def test_nested_key_order_independent(self) -> None:
        a = canonical_json({"outer": {"x": 1, "y": 2}, "list": [{"k": 1, "j": 2}]})
        b = canonical_json({"list": [{"j": 2, "k": 1}], "outer": {"y": 2, "x": 1}})
        assert a == b

    def test_list_order_preserved(self) -> None:
        """Lists are ordered; reordering elements must change the bytes.

        Phase 1 proposal candidates carry an ordered preference list, so
        list-order sensitivity is required behavior, not a bug.
        """
        a = canonical_json({"candidates": ["t1", "t2", "t3"]})
        b = canonical_json({"candidates": ["t3", "t2", "t1"]})
        assert a != b

    def test_unicode_handling(self) -> None:
        """JCS requires UTF-8 and preserves unicode characters exactly."""
        payload = {"name": "café résumé"}
        out = canonical_json(payload)
        decoded = json.loads(out.decode("utf-8"))
        assert decoded == payload

    def test_spec_preflight(self) -> None:
        """Run the SPEC §9 pre-flight assertion via the wrapper."""
        p1 = {"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30}
        p2 = {"duration_minutes": 30, "candidates": ["2026-05-26T14:00:00Z"]}
        c1 = canonical_json(p1)
        c2 = canonical_json(p2)
        assert c1 == c2
        assert sha256(c1).hexdigest() == sha256(c2).hexdigest()


# -- content_hash ---------------------------------------------------------


class TestContentHash:
    """SPEC §3 payload_hash field: 64 lowercase hex characters."""

    def test_returns_64_char_lowercase_hex(self) -> None:
        h = content_hash(b"anything")
        assert isinstance(h, str)
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

    def test_known_answer_empty(self) -> None:
        """SHA-256 of the empty string is a fixed known value."""
        assert content_hash(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_known_answer_abc(self) -> None:
        """SHA-256 of 'abc' is a fixed known value (NIST FIPS 180-4 example)."""
        assert content_hash(b"abc") == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_deterministic(self) -> None:
        assert content_hash(b"deterministic") == content_hash(b"deterministic")

    def test_collision_resistant_for_single_bit_flip(self) -> None:
        """Changing one byte must change the digest completely."""
        a = content_hash(b"hello")
        b = content_hash(b"jello")
        assert a != b

    def test_pairs_with_canonical_json(self) -> None:
        """The combined call payload_hash(canonical_json(...)) is the
        load-bearing pattern for the Residue.payload_hash field."""
        h1 = content_hash(canonical_json({"a": 1, "b": 2}))
        h2 = content_hash(canonical_json({"b": 2, "a": 1}))
        assert h1 == h2


# -- Signer / Verifier round-trip ----------------------------------------


class TestSignVerifyRoundTrip:
    """SPEC §5 assertion 3: every signature verifies against actor's key."""

    def test_sign_returns_base64_string(self) -> None:
        signer = Signer.generate()
        sig = signer.sign(b"payload")
        assert isinstance(sig, str)
        # base64 of 64 raw signature bytes is 88 ascii chars
        assert len(sig) == 88
        decoded = base64.b64decode(sig, validate=True)
        assert len(decoded) == 64

    def test_round_trip_succeeds(self) -> None:
        signer = Signer.generate()
        sig = signer.sign(b"payload")
        assert signer.verifier().verify(b"payload", sig) is True

    def test_ed25519_signature_is_deterministic(self) -> None:
        """Ed25519 is RFC-deterministic: same key + same payload → same signature.

        This guarantees an entire residue chain can be reconstructed
        byte-for-byte from the same inputs — important for the cold re-verify
        in SPEC §5 assertion 14.
        """
        signer = Signer.generate()
        s1 = signer.sign(b"payload")
        s2 = signer.sign(b"payload")
        assert s1 == s2

    def test_tampered_payload_fails(self) -> None:
        signer = Signer.generate()
        sig = signer.sign(b"original payload")
        assert signer.verifier().verify(b"tampered payload", sig) is False

    def test_wrong_key_fails(self) -> None:
        """A signature from key A must not verify under key B's public key."""
        signer_a = Signer.generate()
        signer_b = Signer.generate()
        sig = signer_a.sign(b"payload")
        assert signer_b.verifier().verify(b"payload", sig) is False

    def test_signs_canonical_bytes_of_payload(self) -> None:
        """End-to-end pattern used by the SDK: canonical_json → sign → verify."""
        signer = Signer.generate()
        verifier = signer.verifier()
        payload_dict = {"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30}
        canonical = canonical_json(payload_dict)
        sig = signer.sign(canonical)
        assert verifier.verify(canonical, sig) is True

    def test_malformed_base64_signature_returns_false(self) -> None:
        """Verify must not raise on garbage input — it must return False."""
        signer = Signer.generate()
        assert signer.verifier().verify(b"payload", "!!!not-base64!!!") is False

    def test_wrong_length_signature_returns_false(self) -> None:
        """A correctly-base64 but wrong-length signature returns False, not raises."""
        signer = Signer.generate()
        short = base64.b64encode(b"\x00" * 10).decode("ascii")
        assert signer.verifier().verify(b"payload", short) is False


# -- Key loading & export -----------------------------------------------


class TestKeyLoading:
    """Phase 1 stores keys as PEM in local-secrets/ (gitignored)."""

    def test_generate_produces_working_signer(self) -> None:
        signer = Signer.generate()
        assert signer.verifier().verify(b"x", signer.sign(b"x")) is True

    def test_signer_pem_round_trip(self) -> None:
        original = Signer.generate()
        pem = original.export_pem()
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        reloaded = Signer.from_pem(pem)
        # Same private key → same deterministic signature on same input.
        assert original.sign(b"x") == reloaded.sign(b"x")

    def test_signer_from_raw_bytes(self) -> None:
        """A 32-byte seed deterministically produces the same keypair."""
        seed = b"\x42" * 32
        s1 = Signer.from_raw_bytes(seed)
        s2 = Signer.from_raw_bytes(seed)
        assert s1.sign(b"x") == s2.sign(b"x")

    def test_signer_from_pem_rejects_non_ed25519(self) -> None:
        """PEM containing a non-Ed25519 key must raise ValueError."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            generate_private_key,
        )

        rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="not Ed25519PrivateKey"):
            Signer.from_pem(rsa_pem)

    def test_verifier_b64_round_trip(self) -> None:
        """Publishing the public key as base64 and reloading it preserves
        the verifier's behavior — this is the agent-config flow."""
        signer = Signer.generate()
        pub_b64 = signer.public_key_b64()
        reloaded = Verifier.from_b64(pub_b64)
        sig = signer.sign(b"x")
        assert reloaded.verify(b"x", sig) is True

    def test_verifier_pem_round_trip(self) -> None:
        signer = Signer.generate()
        verifier = signer.verifier()
        pem = verifier.export_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        reloaded = Verifier.from_pem(pem)
        sig = signer.sign(b"x")
        assert reloaded.verify(b"x", sig) is True

    def test_verifier_from_pem_rejects_non_ed25519(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            generate_private_key,
        )

        rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(ValueError, match="not Ed25519PublicKey"):
            Verifier.from_pem(rsa_pem)

    def test_signer_public_key_b64_matches_verifier(self) -> None:
        """A Signer's public_key_b64 and its derived Verifier's public_key_b64
        must agree — both reach into the same key object."""
        signer = Signer.generate()
        assert signer.public_key_b64() == signer.verifier().public_key_b64()


# -- Phase 1.5 deferred surface -----------------------------------------


class TestDeferredSurface:
    """Confirm the Phase 1.5 surface is present-but-unimplemented, so
    accidental usage fails loudly rather than silently doing nothing."""

    def test_mint_guest_credential_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="Phase 1.5"):
            mint_guest_credential({"scope": "x"}, 60)
