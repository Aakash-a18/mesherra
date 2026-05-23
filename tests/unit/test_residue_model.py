"""Unit tests for the Residue Pydantic model.

Covers Phase 1 step 1 (Models) per demos/phase_1/SPEC.md section 3.

What's verified here:
- Well-formed entries construct successfully.
- All field-level validators reject malformed values.
- ``to_signing_payload()`` omits exactly the signature field.
- The JSON encoding round-trips through JCS deterministically.
- The committed JSON Schema mirror agrees with the Pydantic-generated schema.

These tests are pure unit tests: no I/O beyond reading the mirror file, no
network, no crypto signing (that lands in Phase 1 step 2).
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from jcs import canonicalize
from pydantic import ValidationError

from mesherra.models.primitives import ActionType, Operation, Residue

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "mesherra"
    / "provenance"
    / "entry_v1.json"
)

ZERO_HASH = "0" * 64


@pytest.fixture
def base_entry_data() -> dict[str, Any]:
    """A well-formed dict for constructing a Residue."""
    return dict(
        ledger_owner="user-a@phase1.local",
        task_id="task-7f3a",
        context_id="ctx-1b2c",
        sequence=0,
        previous_hash="",
        timestamp="2026-05-23T15:30:00Z",
        actor="user-a@phase1.local",
        counterpart="user-b@phase1.local",
        action_type=ActionType.EMIT,
        operation=Operation.PROPOSAL,
        payload_hash=ZERO_HASH,
        payload_schema="meshycal.scheduling/proposal-v1",
        signature="placeholder-base64",
    )


@pytest.fixture
def entry(base_entry_data: dict[str, Any]) -> Residue:
    return Residue(**base_entry_data)


class TestConstruction:
    def test_well_formed_entry_constructs(self, entry: Residue) -> None:
        assert entry.version == 1
        assert entry.action_type is ActionType.EMIT
        assert entry.operation is Operation.PROPOSAL
        assert entry.sequence == 0
        assert entry.previous_hash == ""

    def test_first_entry_uses_empty_previous_hash(self, base_entry_data: dict[str, Any]) -> None:
        # sequence=0 with empty previous_hash is valid (start of a chain)
        e = Residue(**{**base_entry_data, "sequence": 0, "previous_hash": ""})
        assert e.previous_hash == ""

    def test_non_first_entry_with_real_previous_hash(self, base_entry_data: dict[str, Any]) -> None:
        e = Residue(**{**base_entry_data, "sequence": 1, "previous_hash": "a" * 64})
        assert e.previous_hash == "a" * 64

    def test_residue_is_frozen(self, entry: Residue) -> None:
        with pytest.raises(ValidationError):
            entry.sequence = 99  # type: ignore[misc]


class TestValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("payload_hash", "abc"),               # too short
            ("payload_hash", "Z" * 64),            # non-hex chars
            ("payload_hash", "A" * 64),            # uppercase rejected (we mandate lower)
            ("previous_hash", "notanhex"),         # wrong length and chars
            ("previous_hash", "abc"),              # wrong length
            ("sequence", -1),                      # negative
            ("version", 2),                        # only v1 allowed
            ("action_type", "not-an-action"),      # unknown enum value
            ("operation", "not-an-op"),            # unknown enum value
            ("ledger_owner", ""),                  # empty
            ("task_id", ""),                       # empty
            ("context_id", ""),                    # empty
            ("timestamp", ""),                     # empty
            ("actor", ""),                         # empty
            ("counterpart", ""),                   # empty
            ("payload_schema", ""),                # empty
            ("signature", ""),                     # empty
        ],
    )
    def test_rejects_malformed_field(
        self,
        base_entry_data: dict[str, Any],
        field: str,
        bad_value: Any,
    ) -> None:
        with pytest.raises(ValidationError):
            Residue(**{**base_entry_data, field: bad_value})

    def test_rejects_extra_fields(self, base_entry_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            Residue(**{**base_entry_data, "unknown_field": "anything"})


class TestSigningPayload:
    def test_omits_signature(self, entry: Residue) -> None:
        payload = entry.to_signing_payload()
        assert "signature" not in payload

    def test_preserves_all_other_fields(self, entry: Residue) -> None:
        payload = entry.to_signing_payload()
        expected = {
            "version", "ledger_owner", "task_id", "context_id", "sequence",
            "previous_hash", "timestamp", "actor", "counterpart",
            "action_type", "operation", "payload_hash", "payload_schema",
        }
        assert set(payload.keys()) == expected

    def test_enum_values_serialize_as_strings(self, entry: Residue) -> None:
        payload = entry.to_signing_payload()
        assert payload["action_type"] == "emit"
        assert payload["operation"] == "proposal"
        assert payload["version"] == 1


class TestCanonicalization:
    def test_jcs_is_order_independent(self, entry: Residue) -> None:
        payload = entry.to_signing_payload()
        canon_1 = canonicalize(payload)
        canon_2 = canonicalize(dict(reversed(list(payload.items()))))
        assert canon_1 == canon_2

    def test_jcs_hash_is_stable(self, entry: Residue) -> None:
        payload = entry.to_signing_payload()
        h1 = sha256(canonicalize(payload)).hexdigest()
        h2 = sha256(canonicalize(dict(reversed(list(payload.items()))))).hexdigest()
        assert h1 == h2

    def test_logically_equal_entries_hash_identically(
        self,
        base_entry_data: dict[str, Any],
    ) -> None:
        # Two entries built from logically-identical data but assembled in
        # different field orders (Python dict iteration order). The signing
        # payload of each must hash to the same value.
        e1 = Residue(**base_entry_data)
        reversed_data = dict(reversed(list(base_entry_data.items())))
        e2 = Residue(**reversed_data)
        h1 = sha256(canonicalize(e1.to_signing_payload())).hexdigest()
        h2 = sha256(canonicalize(e2.to_signing_payload())).hexdigest()
        assert h1 == h2


class TestSchemaMirror:
    """The committed JSON Schema mirror at entry_v1.json must agree with the
    Pydantic-generated schema. If you change one without updating the other,
    these tests fail."""

    def test_mirror_file_exists(self) -> None:
        assert SCHEMA_PATH.is_file(), f"Schema mirror missing: {SCHEMA_PATH}"

    def test_property_sets_match(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Residue.model_json_schema()
        assert set(mirror["properties"].keys()) == set(pydantic_schema["properties"].keys())

    def test_mirror_required_is_superset_of_pydantic_required(self) -> None:
        """The wire-format mirror may require fields that Pydantic treats as
        optional (because they have defaults). Pydantic must not require any
        field the mirror does not."""
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Residue.model_json_schema()
        assert set(pydantic_schema["required"]) <= set(mirror["required"])

    def test_mirror_only_required_fields_have_pydantic_defaults(self) -> None:
        """Every field the mirror requires but Pydantic does not must have a
        default value or const in Pydantic. This catches drift where a field
        becomes required in the mirror but optional in Pydantic without a
        default."""
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Residue.model_json_schema()
        mirror_required = set(mirror["required"])
        pydantic_required = set(pydantic_schema["required"])
        for field in mirror_required - pydantic_required:
            prop = pydantic_schema["properties"][field]
            assert "default" in prop or "const" in prop, (
                f"Mirror requires '{field}' but Pydantic has no default — schemas drifted"
            )
