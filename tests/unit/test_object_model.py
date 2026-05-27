"""Unit tests for the Object Pydantic model.

Covers Phase 4 Slice 1 step 1 (Models) per demos/phase_4/SPEC.md section 2.

What's verified here:
- Well-formed Objects construct successfully.
- All field-level validators reject malformed values.
- ``content_hash`` is computed deterministically from ``state`` via JCS + SHA-256.
- Passing a content_hash that does not match the state raises ValidationError.
- The Object is frozen at the model level.
- The JSON Schema mirror agrees with the Pydantic-generated schema.

Pure unit tests: no I/O beyond reading the mirror file, no network, no crypto signing.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.crypto.primitives import canonical_json as canonicalize
from mesherra.crypto.primitives import content_hash as compute_hash
from mesherra.models.primitives import LayerKind, Mutability, Object

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "mesherra"
    / "object"
    / "object_v1.json"
)


@pytest.fixture
def base_state() -> dict[str, Any]:
    """A well-formed Object ``state`` payload — synthetic only (CLAUDE.md rule 8)."""
    return {
        "candidates": ["2026-06-01T09:00:00Z", "2026-06-01T14:00:00Z"],
        "duration_minutes": 30,
        "timezone": "UTC",
    }


@pytest.fixture
def base_object_data(base_state: dict[str, Any]) -> dict[str, Any]:
    """A well-formed dict for constructing an Object.

    Omits ``content_hash`` so the model computes it. Tests that explicitly
    set content_hash do so themselves.
    """
    return dict(
        object_id="obj-7f3a",
        owner="user-a@phase4.local",
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.STATIC,
        schema_ref="meshycal.scheduling/calendar-v1",
        state=base_state,
        object_version=1,
        created_at="2026-05-26T20:00:00Z",
        updated_at="2026-05-26T20:00:00Z",
    )


@pytest.fixture
def obj(base_object_data: dict[str, Any]) -> Object:
    return Object(**base_object_data)


class TestConstruction:
    def test_well_formed_object_constructs(self, obj: Object) -> None:
        assert obj.version == 1
        assert obj.object_id == "obj-7f3a"
        assert obj.owner == "user-a@phase4.local"
        assert obj.home_layer is LayerKind.PERSONAL
        assert obj.mutability is Mutability.STATIC
        assert obj.object_version == 1

    def test_content_hash_auto_computed_when_omitted(
        self, base_object_data: dict[str, Any], base_state: dict[str, Any]
    ) -> None:
        obj = Object(**base_object_data)
        expected = compute_hash(canonicalize(base_state))
        assert obj.content_hash == expected

    def test_explicit_correct_content_hash_accepted(
        self, base_object_data: dict[str, Any], base_state: dict[str, Any]
    ) -> None:
        correct = compute_hash(canonicalize(base_state))
        obj = Object(**{**base_object_data, "content_hash": correct})
        assert obj.content_hash == correct

    def test_object_is_frozen(self, obj: Object) -> None:
        with pytest.raises(ValidationError):
            obj.object_version = 99  # type: ignore[misc]

    def test_minimal_state_supported(self, base_object_data: dict[str, Any]) -> None:
        # Empty state dict is technically valid (an Object with no state yet).
        # SPEC §2 requires state to be an object, not non-empty.
        obj = Object(**{**base_object_data, "state": {}})
        assert obj.state == {}


class TestValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("object_id", ""),                          # empty
            ("owner", ""),                              # empty
            ("schema_ref", ""),                         # empty
            ("created_at", ""),                         # empty
            ("updated_at", ""),                         # empty
            ("object_version", 0),                      # SPEC: minimum 1
            ("object_version", -1),                     # negative
            ("home_layer", "not-a-layer"),              # unknown enum value
            ("mutability", "not-a-mutability"),         # unknown enum value
            ("version", 2),                             # only v1 allowed
        ],
    )
    def test_rejects_malformed_field(
        self,
        base_object_data: dict[str, Any],
        field: str,
        bad_value: Any,
    ) -> None:
        with pytest.raises(ValidationError):
            Object(**{**base_object_data, field: bad_value})

    def test_rejects_extra_fields(self, base_object_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            Object(**{**base_object_data, "unknown_field": "anything"})

    def test_content_hash_mismatch_raises(
        self, base_object_data: dict[str, Any]
    ) -> None:
        wrong_hash = "0" * 64
        with pytest.raises(ValidationError):
            Object(**{**base_object_data, "content_hash": wrong_hash})

    def test_content_hash_malformed_raises(
        self, base_object_data: dict[str, Any]
    ) -> None:
        # Not 64 hex chars
        with pytest.raises(ValidationError):
            Object(**{**base_object_data, "content_hash": "deadbeef"})

    def test_content_hash_uppercase_rejected(
        self, base_object_data: dict[str, Any]
    ) -> None:
        # SPEC §2 / §6 consistent with Residue: lowercase hex only
        with pytest.raises(ValidationError):
            Object(**{**base_object_data, "content_hash": "A" * 64})


class TestContentHash:
    def test_same_state_same_hash(self, base_object_data: dict[str, Any]) -> None:
        o1 = Object(**base_object_data)
        o2 = Object(**base_object_data)
        assert o1.content_hash == o2.content_hash

    def test_different_state_different_hash(
        self, base_object_data: dict[str, Any]
    ) -> None:
        o1 = Object(**base_object_data)
        mutated = {**base_object_data, "state": {**base_object_data["state"], "duration_minutes": 60}}
        o2 = Object(**mutated)
        assert o1.content_hash != o2.content_hash

    def test_state_key_order_independent(
        self, base_object_data: dict[str, Any]
    ) -> None:
        # Two states built from logically-identical data but in different
        # Python dict insertion order must hash identically (JCS sorts keys).
        forward = base_object_data["state"]
        reversed_state = dict(reversed(list(forward.items())))
        o1 = Object(**base_object_data)
        o2 = Object(**{**base_object_data, "state": reversed_state})
        assert o1.content_hash == o2.content_hash

    def test_content_hash_excludes_object_metadata(
        self, base_object_data: dict[str, Any]
    ) -> None:
        # Per SPEC §6: content_hash is over state alone, not over the whole
        # Object. Changing only metadata (e.g., updated_at) must NOT change
        # content_hash.
        o1 = Object(**base_object_data)
        later = {**base_object_data, "updated_at": "2027-01-01T00:00:00Z"}
        o2 = Object(**later)
        assert o1.content_hash == o2.content_hash

    def test_content_hash_is_lowercase_hex_sha256(
        self, base_object_data: dict[str, Any]
    ) -> None:
        obj = Object(**base_object_data)
        assert len(obj.content_hash) == 64
        assert all(c in "0123456789abcdef" for c in obj.content_hash)


class TestSchemaMirror:
    """The committed JSON Schema mirror at object_v1.json must agree with the
    Pydantic-generated schema. Drift between the two is a corruption signal."""

    def test_mirror_file_exists(self) -> None:
        assert SCHEMA_PATH.is_file(), f"Schema mirror missing: {SCHEMA_PATH}"

    def test_mirror_has_correct_schema_id(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        assert mirror["$id"] == "mesherra.object/object-v1"

    def test_property_sets_match(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Object.model_json_schema()
        assert set(mirror["properties"].keys()) == set(pydantic_schema["properties"].keys())

    def test_mirror_required_is_superset_of_pydantic_required(self) -> None:
        """The wire-format mirror may require fields that Pydantic treats as
        optional (because they have defaults). Pydantic must not require any
        field the mirror does not."""
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Object.model_json_schema()
        assert set(pydantic_schema["required"]) <= set(mirror["required"])

    def test_mirror_only_required_fields_have_pydantic_defaults(self) -> None:
        """Every field the mirror requires but Pydantic does not must have a
        default value or const in Pydantic."""
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = Object.model_json_schema()
        mirror_required = set(mirror["required"])
        pydantic_required = set(pydantic_schema["required"])
        for field in mirror_required - pydantic_required:
            prop = pydantic_schema["properties"][field]
            assert "default" in prop or "const" in prop, (
                f"Mirror requires '{field}' but Pydantic has no default — schemas drifted"
            )

    def test_jcs_canonicalization_roundtrips(
        self, base_object_data: dict[str, Any]
    ) -> None:
        # Sanity: the same state hashed via the same JCS+SHA256 pipeline as the
        # content_hash field, computed externally, agrees with what the model
        # stored. Catches an accidental swap to a non-canonical encoder.
        obj = Object(**base_object_data)
        expected = sha256(canonicalize(base_object_data["state"])).hexdigest()
        assert obj.content_hash == expected
