"""Unit tests for the ObjectUpdate wire payload (Slice 2 step 2).

Covers ``demos/phase_4/SLICE_2_SPEC.md`` §2. ObjectUpdate is the wire shape
the owner pushes to a subscribed receiver under a live reference promotion.

What's verified here:

- Well-formed payloads construct successfully, with auto-computed
  ``snapshot_content_hash`` matching JCS(snapshot_state).
- Field-level validators reject malformed values.
- Cross-field invariant: ``snapshot_content_hash`` equals
  SHA-256(JCS(snapshot_state)) — model rejects mismatch at construction.
  This is the model-level half of the §7.3 "defense-in-depth recomputation
  on receive" check; the handler does the same check on receive (the
  belt-and-braces matters because the *payload* could be reconstructed by
  an attacker who got both the state and a stale hash from somewhere).
- Schema-ID constant, frozen + extra="forbid", same discipline as the
  Slice 1 wire models in ``test_object_wire.py``.

Schema-ID + Pydantic shape match the JSON shape in SLICE_2_SPEC §2.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.crypto.primitives import canonical_json, content_hash
from mesherra.object.wire import (
    OBJECT_UPDATE_SCHEMA,
    ObjectUpdate,
)


# -- Schema-ID constant -------------------------------------------------


class TestSchemaID:
    def test_object_update_schema_id(self) -> None:
        assert OBJECT_UPDATE_SCHEMA == "mesherra.object/object-update-v1"


# -- ObjectUpdate -------------------------------------------------------


@pytest.fixture
def snapshot_state() -> dict[str, Any]:
    return {"candidates": ["2026-06-01T09:00:00Z"], "duration_minutes": 30}


@pytest.fixture
def base_data(snapshot_state: dict[str, Any]) -> dict[str, Any]:
    return dict(
        promotion_id="prm-live-1",
        object_version=2,
        snapshot_state=snapshot_state,
        snapshot_content_hash=content_hash(canonical_json(snapshot_state)),
    )


class TestObjectUpdateConstruction:
    def test_construct(self, base_data: dict[str, Any]) -> None:
        u = ObjectUpdate(**base_data)
        assert u.version == 1
        assert u.promotion_id == "prm-live-1"
        assert u.object_version == 2
        assert u.snapshot_state == base_data["snapshot_state"]

    def test_snapshot_content_hash_auto_computed_when_omitted(
        self, snapshot_state: dict[str, Any]
    ) -> None:
        # Same model-fills-in convenience as Object/Promotion: callers may
        # omit the hash and the model derives it. Receivers always send
        # the hash filled, but owner-side construction often supplies just
        # the state — letting the model compute closes the "did the caller
        # use the right canonicaliser" footgun at the model boundary.
        u = ObjectUpdate(
            promotion_id="prm-live-1",
            object_version=2,
            snapshot_state=snapshot_state,
        )
        assert u.snapshot_content_hash == content_hash(canonical_json(snapshot_state))

    def test_explicit_correct_hash_accepted(
        self, base_data: dict[str, Any], snapshot_state: dict[str, Any]
    ) -> None:
        correct = content_hash(canonical_json(snapshot_state))
        u = ObjectUpdate(**{**base_data, "snapshot_content_hash": correct})
        assert u.snapshot_content_hash == correct


class TestObjectUpdateValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("promotion_id", ""),
            ("snapshot_content_hash", "tooshort"),
            ("snapshot_content_hash", "Z" * 64),  # non-hex
        ],
    )
    def test_rejects_malformed_field(
        self, base_data: dict[str, Any], field: str, bad_value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, field: bad_value})

    def test_object_version_zero_rejected(self, base_data: dict[str, Any]) -> None:
        # Object.object_version >= 1; the wire shape must match.
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "object_version": 0})

    def test_object_version_negative_rejected(self, base_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "object_version": -3})

    def test_extra_field_rejected(self, base_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "leaky": "value"})

    def test_frozen(self, base_data: dict[str, Any]) -> None:
        u = ObjectUpdate(**base_data)
        with pytest.raises(ValidationError):
            u.object_version = 99  # type: ignore[misc]

    def test_version_constant(self, base_data: dict[str, Any]) -> None:
        # A wire-version bump would be a new schema; v1 code rejects v2.
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "version": 2})  # type: ignore[arg-type]


class TestObjectUpdateHashInvariant:
    """SLICE_2_SPEC §2 cross-field invariant: snapshot_content_hash =
    SHA-256(JCS(snapshot_state)). The model verifies on construction; the
    handler verifies again on receive."""

    def test_supplied_mismatch_rejected(
        self, base_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "snapshot_content_hash": "0" * 64})

    def test_uppercase_hash_rejected(
        self, base_data: dict[str, Any], snapshot_state: dict[str, Any]
    ) -> None:
        # Hash field is lowercase-hex by the pattern; an uppercase hex that
        # would otherwise match the bytes must still be rejected.
        correct_upper = content_hash(canonical_json(snapshot_state)).upper()
        with pytest.raises(ValidationError):
            ObjectUpdate(**{**base_data, "snapshot_content_hash": correct_upper})

    def test_two_updates_same_state_same_hash(
        self, snapshot_state: dict[str, Any]
    ) -> None:
        # The same scoped state at the same object_version always produces
        # the same content_hash — receivers may dedup at the wire level on
        # this property. (Also: cold-replayability — the residue payload_hash
        # is a function of the state alone, so the two ledgers will agree.)
        u1 = ObjectUpdate(
            promotion_id="prm-live-1", object_version=2, snapshot_state=snapshot_state
        )
        u2 = ObjectUpdate(
            promotion_id="prm-live-1", object_version=2, snapshot_state=snapshot_state
        )
        assert u1.snapshot_content_hash == u2.snapshot_content_hash
        assert u1.model_dump_json() == u2.model_dump_json()

    def test_different_state_different_hash(
        self, snapshot_state: dict[str, Any]
    ) -> None:
        u1 = ObjectUpdate(
            promotion_id="prm-live-1", object_version=2, snapshot_state=snapshot_state
        )
        mutated = {**snapshot_state, "duration_minutes": 60}
        u2 = ObjectUpdate(
            promotion_id="prm-live-1", object_version=3, snapshot_state=mutated
        )
        assert u1.snapshot_content_hash != u2.snapshot_content_hash
