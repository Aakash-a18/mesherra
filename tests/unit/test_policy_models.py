"""Unit tests for the policy primitive models and signing helpers.

Covers SPEC §2 (PolicyDoc schema), §2.1 (signing canonicalization), §2.2
indirectly (Rule field-path validation is the input contract the engine
relies on later).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mesherra.crypto.primitives import Signer, canonical_json
from mesherra.policy import (
    Direction,
    Match,
    PolicyDoc,
    Rule,
    SignedPolicyDoc,
    sign_policy_doc,
    verify_policy_doc,
)


class TestRuleFieldPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "candidates",
            "duration_minutes",
            "constraint_hints.tz",
            "a.b.c.d",
            "ledgerOwner",  # camelCase ok after first segment
        ],
    )
    def test_accepts_valid_field_paths(self, path: str) -> None:
        rule = Rule(
            match=Match(schema="x"),
            outbound_block=[path],
        )
        assert rule.outbound_block == [path]

    @pytest.mark.parametrize(
        "path",
        [
            "Candidates",          # leading uppercase
            "1candidates",         # leading digit
            ".tz",                 # leading dot
            "tz.",                 # trailing dot
            "a..b",                # double dot
            "",                    # empty
            "candidates[0]",       # array index — not supported in v1
            "constraint hints.tz", # space
        ],
    )
    def test_rejects_invalid_field_paths(self, path: str) -> None:
        with pytest.raises(ValueError):
            Rule(match=Match(schema="x"), outbound_block=[path])

    def test_max_array_size_validates_paths_and_nonneg(self) -> None:
        # Valid: positive size, valid path.
        rule = Rule(match=Match(schema="x"), max_array_size={"candidates": 5})
        assert rule.max_array_size == {"candidates": 5}

        # Invalid: negative size.
        with pytest.raises(ValueError):
            Rule(match=Match(schema="x"), max_array_size={"candidates": -1})

        # Invalid: bad path.
        with pytest.raises(ValueError):
            Rule(match=Match(schema="x"), max_array_size={"Bad.path": 1})


class TestMatchDefaults:
    def test_direction_defaults_to_both(self) -> None:
        m = Match(schema="meshycal.scheduling/proposal-v1")
        assert m.direction is Direction.BOTH

    def test_explicit_direction(self) -> None:
        m = Match(schema="x", direction=Direction.OUTBOUND)
        assert m.direction is Direction.OUTBOUND


class TestPolicyDocConstruction:
    def _doc(self, **overrides: object) -> PolicyDoc:
        base = dict(
            principal_id="user-a@phase3.local",
            version=1,
            issued_at="2026-05-24T12:00:00Z",
            rules=[
                Rule(
                    match=Match(
                        schema="meshycal.scheduling/proposal-v1",
                        direction=Direction.OUTBOUND,
                    ),
                    outbound_allow=["candidates", "duration_minutes"],
                    outbound_block=["calendar_titles", "attendee_emails"],
                    max_array_size={"candidates": 5},
                )
            ],
        )
        base.update(overrides)
        return PolicyDoc(**base)  # type: ignore[arg-type]

    def test_minimum_doc_has_no_rules(self) -> None:
        doc = PolicyDoc(
            principal_id="x",
            version=1,
            issued_at="2026-05-24T12:00:00Z",
        )
        assert doc.rules == []

    def test_version_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            PolicyDoc(
                principal_id="x",
                version=0,
                issued_at="2026-05-24T12:00:00Z",
            )

    def test_principal_id_required_nonempty(self) -> None:
        with pytest.raises(ValueError):
            PolicyDoc(
                principal_id="",
                version=1,
                issued_at="2026-05-24T12:00:00Z",
            )

    def test_doc_is_frozen(self) -> None:
        doc = self._doc()
        with pytest.raises((TypeError, ValueError)):
            doc.version = 2  # type: ignore[misc]

    def test_to_signing_payload_excludes_no_special_fields(self) -> None:
        # Policy doc has no signature field embedded — signing payload is the
        # full model_dump. Verifies the contract is "everything is signed."
        doc = self._doc()
        payload = doc.to_signing_payload()
        assert set(payload.keys()) == {
            "principal_id", "version", "issued_at", "rules"
        }


class TestSignAndVerify:
    def _doc(self, principal_id: str = "user-a@phase3.local") -> PolicyDoc:
        return PolicyDoc(
            principal_id=principal_id,
            version=1,
            issued_at="2026-05-24T12:00:00Z",
            rules=[
                Rule(
                    match=Match(schema="meshycal.scheduling/proposal-v1"),
                    outbound_block=["calendar_titles"],
                )
            ],
        )

    def test_sign_then_verify_succeeds(self) -> None:
        signer = Signer.generate()
        signed = sign_policy_doc(doc=self._doc(), signer=signer)
        assert isinstance(signed, SignedPolicyDoc)
        assert verify_policy_doc(
            signed=signed,
            public_key_b64=signer.public_key_b64(),
        )

    def test_verify_rejects_wrong_key(self) -> None:
        signer_a = Signer.generate()
        signer_b = Signer.generate()
        signed = sign_policy_doc(doc=self._doc(), signer=signer_a)
        # B's key cannot verify A's signature.
        assert not verify_policy_doc(
            signed=signed,
            public_key_b64=signer_b.public_key_b64(),
        )

    def test_verify_rejects_tampered_doc(self) -> None:
        signer = Signer.generate()
        signed = sign_policy_doc(doc=self._doc(), signer=signer)
        # Construct a tampered copy with a different version.
        tampered_doc = self._doc().model_copy(update={"version": 2})
        tampered = SignedPolicyDoc(
            doc=tampered_doc,
            signature_b64=signed.signature_b64,
        )
        assert not verify_policy_doc(
            signed=tampered,
            public_key_b64=signer.public_key_b64(),
        )

    def test_signing_is_deterministic_under_jcs(self) -> None:
        # Two signers from the same seed produce the same signature on the
        # same doc (Ed25519 is deterministic and JCS is canonical).
        seed = b"\x01" * 32
        signer_1 = Signer.from_raw_bytes(seed)
        signer_2 = Signer.from_raw_bytes(seed)
        doc = self._doc()
        s1 = sign_policy_doc(doc=doc, signer=signer_1)
        s2 = sign_policy_doc(doc=doc, signer=signer_2)
        assert s1.signature_b64 == s2.signature_b64

    def test_canonical_bytes_match_schema(self) -> None:
        # The bytes we sign over should JCS-encode the same keys the JSON
        # schema declares as required.
        doc = self._doc()
        payload = canonical_json(doc.to_signing_payload())
        decoded = json.loads(payload)
        assert set(decoded.keys()) >= {
            "principal_id", "version", "issued_at", "rules"
        }


class TestJsonSchemaMirror:
    """The JSON schema file at src/mesherra/policy/schemas/policy_doc_v1.json
    is the cross-language mirror of the Pydantic model. Field-set equivalence
    is the load-bearing contract (consumers in other languages will validate
    against the JSON schema, not the Pydantic model)."""

    def test_schema_file_present_and_parses(self) -> None:
        schema_path = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "mesherra" / "policy" / "schemas" / "policy_doc_v1.json"
        )
        assert schema_path.is_file(), f"schema mirror missing at {schema_path}"
        schema = json.loads(schema_path.read_text())
        assert schema["$id"] == "mesherra.policy/doc-v1"
        assert set(schema["required"]) == {
            "principal_id", "version", "issued_at", "rules"
        }
