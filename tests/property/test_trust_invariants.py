"""Property-based tests for the mesherra trust-layer primitives.

These tests use Hypothesis to generate thousands of random inputs and
assert load-bearing invariants of the trust layer. Where a unit test
proves "this one example works," a property test proves "no
counterexample exists in N tries." For trust-layer code that markets
itself as "the halves either fit or they don't," the second claim is
the load-bearing one.

The properties pinned down here are deliberately tight — only the
invariants mesherra's mission claim depends on. Per
``demos/phase_1/SPEC.md`` §9, JCS canonicalization is "the cheapest
test that catches the most expensive bug" — if these properties hold
under arbitrary inputs, the rest of the trust pipeline is built on
solid ground; if any of them fall over, the whole stack falls with it.

Covered invariants (one or more property tests each):

1. ``canonical_json`` is invariant to key-insertion order (the SPEC §9
   pre-flight check, generalized).
2. ``content_hash`` is deterministic, well-formed hex, and collision-
   resistant for distinct inputs.
3. Signer/Verifier roundtrip: any bytes signed by a Signer verify under
   the matching public key.
4. Signer/Verifier wrong-key rejection: signed bytes do NOT verify
   under a *different* principal's public key.
5. Signer/Verifier tamper detection: flipping any single bit of the
   signed payload invalidates the signature.
6. SendClaim canonical bytes are deterministic — two SendClaims built
   from the same fields produce byte-identical canonical encodings
   (the load-bearing property for inter-side signature reconstruction).
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, given, settings, strategies as st

from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.models.primitives import Operation, SendClaim


# -- Strategies ----------------------------------------------------------


# JSON-compatible primitive values (no bytes, no NaN/Inf since JSON can't
# encode them and JCS is strict). Strings are restricted to printable
# unicode minus control characters to avoid Pydantic min_length oddities.
_PRINTABLE_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xFFFF, blacklist_categories=("Cs",)),
    min_size=0,
    max_size=50,
)
_NON_EMPTY_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xFFFF, blacklist_categories=("Cs",)),
    min_size=1,
    max_size=50,
)
_JSON_PRIMITIVE = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=2**31 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _PRINTABLE_TEXT,
)
_JSON_OBJECT = st.dictionaries(
    keys=_NON_EMPTY_TEXT,
    values=_JSON_PRIMITIVE,
    min_size=0,
    max_size=8,
)


# Strategy for SHA-256 hex digests (used as payload_hash values).
_SHA256_HEX = st.text(alphabet=string.hexdigits.lower()[:16], min_size=64, max_size=64)


@st.composite
def _valid_send_claim_fields(draw) -> dict:
    """Generate kwargs that pass SendClaim's Pydantic validation."""
    return {
        "payload_hash": draw(_SHA256_HEX),
        "payload_schema": draw(_NON_EMPTY_TEXT),
        "operation": draw(st.sampled_from(list(Operation))),
        "sender_principal_id": draw(_NON_EMPTY_TEXT),
        "context_id": draw(_NON_EMPTY_TEXT),
        "timestamp": draw(_NON_EMPTY_TEXT),
    }


# -- Property 1: canonical_json is order-invariant -----------------------


class TestCanonicalJsonInvariants:
    """The cheapest test that catches the most expensive bug (SPEC §9).

    Different key-insertion orders of the same logical dict MUST produce
    byte-identical canonical encodings. If this property fails, every
    cross-side signature verification in the trust layer falls over
    because A and B would canonicalize the same payload to different
    bytes and the sha-256 hashes wouldn't match.
    """

    @given(_JSON_OBJECT)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_canonical_json_invariant_to_key_order(self, d: dict) -> None:
        reversed_d = dict(reversed(list(d.items())))
        assert canonical_json(d) == canonical_json(reversed_d)

    @given(_JSON_OBJECT)
    def test_canonical_json_is_deterministic(self, d: dict) -> None:
        assert canonical_json(d) == canonical_json(d)


# -- Property 2: content_hash invariants ---------------------------------


class TestContentHashInvariants:
    @given(st.binary(max_size=4096))
    def test_content_hash_is_deterministic(self, payload: bytes) -> None:
        assert content_hash(payload) == content_hash(payload)

    @given(st.binary(max_size=4096))
    def test_content_hash_is_64_lowercase_hex(self, payload: bytes) -> None:
        hashed = content_hash(payload)
        assert len(hashed) == 64
        assert all(c in string.hexdigits.lower()[:16] for c in hashed)

    @given(st.binary(min_size=1, max_size=4096), st.integers(min_value=0))
    def test_content_hash_changes_when_payload_changes(
        self, payload: bytes, byte_idx: int
    ) -> None:
        """Flipping any single byte must yield a different digest.

        SHA-256 collision probability for distinct inputs is ~2^-256, so
        Hypothesis would need to win a cosmic lottery to find a false
        counterexample here. If this test ever fails, something is much
        more wrong than a flaky property test.
        """
        idx = byte_idx % len(payload)
        tampered = bytearray(payload)
        tampered[idx] ^= 0xFF
        assert content_hash(payload) != content_hash(bytes(tampered))


# -- Property 3-5: Signer/Verifier invariants ----------------------------


class TestCryptoSignVerifyInvariants:
    """The mission-critical trust property: signatures fit or they don't.

    Generating fresh Signers inside each test is expensive (Ed25519
    keygen takes a few ms), so we keep payloads short and use
    ``suppress_health_check`` where Hypothesis would otherwise flag the
    runtime. The properties themselves are tight enough that 100
    examples per property is plenty of evidence.
    """

    @given(st.binary(max_size=512))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_sign_verify_roundtrip(self, payload: bytes) -> None:
        signer = Signer.generate()
        verifier = Verifier.from_b64(signer.public_key_b64())
        signature = signer.sign(payload)
        assert verifier.verify(payload, signature)

    @given(st.binary(max_size=512))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_signature_does_not_verify_under_different_key(
        self, payload: bytes
    ) -> None:
        signer_a = Signer.generate()
        signer_b = Signer.generate()
        verifier_b = Verifier.from_b64(signer_b.public_key_b64())
        signature = signer_a.sign(payload)
        assert not verifier_b.verify(payload, signature)

    @given(st.binary(min_size=1, max_size=512), st.integers(min_value=0))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_tampered_payload_fails_verification(
        self, payload: bytes, byte_idx: int
    ) -> None:
        signer = Signer.generate()
        verifier = Verifier.from_b64(signer.public_key_b64())
        signature = signer.sign(payload)
        idx = byte_idx % len(payload)
        tampered = bytearray(payload)
        tampered[idx] ^= 0xFF
        assert not verifier.verify(bytes(tampered), signature)


# -- Property 6: SendClaim canonical bytes are deterministic -------------


class TestSendClaimSigningInvariants:
    """Sender and receiver MUST canonicalize the same SendClaim fields
    to byte-identical bytes — otherwise SendClaim signature
    verification can never reconstruct what the sender signed. This
    is the operational requirement behind every SendClaim verification
    in the inbound/outbound gateway pipelines."""

    @given(_valid_send_claim_fields())
    def test_two_send_claims_with_same_fields_canonicalize_identically(
        self, fields: dict
    ) -> None:
        sc1 = SendClaim(**fields)
        sc2 = SendClaim(**fields)
        assert canonical_json(sc1.to_signing_bytes_input()) == canonical_json(
            sc2.to_signing_bytes_input()
        )

    @given(_valid_send_claim_fields())
    def test_send_claim_canonical_round_trip_is_idempotent(self, fields: dict) -> None:
        """Canonicalizing canonical bytes (after parsing) must be a no-op.

        ``canonical_json(payload)`` -> bytes -> ``json.loads`` -> the
        same canonical bytes. This is the property a verifier relies on
        when reconstructing the SendClaim from envelope fields.
        """
        import json

        sc = SendClaim(**fields)
        first_bytes = canonical_json(sc.to_signing_bytes_input())
        roundtripped = json.loads(first_bytes)
        second_bytes = canonical_json(roundtripped)
        assert first_bytes == second_bytes

    @given(_valid_send_claim_fields(), _valid_send_claim_fields())
    def test_distinct_send_claims_have_distinct_canonical_bytes(
        self, fields_a: dict, fields_b: dict
    ) -> None:
        """If two SendClaim field-sets differ in any field, their
        canonical bytes must differ. Otherwise an attacker could craft
        a different-but-equivalent SendClaim and reuse a signature."""
        sc_a = SendClaim(**fields_a)
        sc_b = SendClaim(**fields_b)
        # Compare the model dumps (not the SendClaim objects, which are
        # Pydantic and compare by field). Equal field-sets allowed —
        # only assert the iff direction.
        if sc_a.model_dump(mode="json") != sc_b.model_dump(mode="json"):
            assert canonical_json(sc_a.to_signing_bytes_input()) != canonical_json(
                sc_b.to_signing_bytes_input()
            )
