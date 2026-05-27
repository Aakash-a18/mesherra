"""Unit tests for the Promotion Pydantic model.

Covers Phase 4 Slice 1 step 3 (Models) per demos/phase_4/SPEC.md section 4.

Promotion is the LOCAL event recorded by the owner when authorizing a
counterpart to perceive an Object. It produces:

1. A PromotionHandle (the wire artifact — tested separately)
2. Paired Residue entries on both ledgers (gateway integration — Slice 1 step 7)
3. A row in the owner's ObjectStore.promotions table (store — Slice 1 step 4)

This file tests #1's underlying Promotion model only: field shapes,
cross-field validators, snapshot_content_hash invariants. Wire-format
concerns live in test_promotion_handle_model.py.

Slice 1 ships ``mode == REFERENCE`` and ``mutability == STATIC`` only;
COPY (Slice 3) and LIVE (Slice 2) are deferred.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.crypto.primitives import canonical_json
from mesherra.crypto.primitives import content_hash as compute_hash
from mesherra.models.primitives import (
    Mutability,
    Promotion,
    PromotionMode,
)


@pytest.fixture
def snapshot_state() -> dict[str, Any]:
    return {
        "candidates": ["2026-06-01T09:00:00Z", "2026-06-01T14:00:00Z"],
        "duration_minutes": 30,
    }


@pytest.fixture
def base_promotion_data(snapshot_state: dict[str, Any]) -> dict[str, Any]:
    return dict(
        promotion_id="prm-1a2b",
        object_id="obj-7f3a",
        owner="alice@phase4.local",
        receiver="bob@phase4.local",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates", "duration_minutes"]},
        expiry="2026-06-02T00:00:00Z",
        snapshot_state=snapshot_state,
        fetch_endpoint="https://alice.example/mesherra/objects/fetch/prm-1a2b",
        created_at="2026-05-26T20:00:00Z",
    )


@pytest.fixture
def promotion(base_promotion_data: dict[str, Any]) -> Promotion:
    return Promotion(**base_promotion_data)


class TestConstruction:
    def test_static_reference_promotion_constructs(self, promotion: Promotion) -> None:
        assert promotion.mode is PromotionMode.REFERENCE
        assert promotion.mutability is Mutability.STATIC
        assert promotion.fetch_endpoint is not None
        assert promotion.snapshot_state is not None

    def test_snapshot_content_hash_auto_computed(
        self,
        base_promotion_data: dict[str, Any],
        snapshot_state: dict[str, Any],
    ) -> None:
        p = Promotion(**base_promotion_data)
        expected = compute_hash(canonical_json(snapshot_state))
        assert p.snapshot_content_hash == expected

    def test_explicit_correct_snapshot_content_hash_accepted(
        self,
        base_promotion_data: dict[str, Any],
        snapshot_state: dict[str, Any],
    ) -> None:
        correct = compute_hash(canonical_json(snapshot_state))
        p = Promotion(**{**base_promotion_data, "snapshot_content_hash": correct})
        assert p.snapshot_content_hash == correct

    def test_promotion_is_frozen(self, promotion: Promotion) -> None:
        with pytest.raises(ValidationError):
            promotion.receiver = "eve@phase4.local"  # type: ignore[misc]


class TestValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("promotion_id", ""),
            ("object_id", ""),
            ("owner", ""),
            ("receiver", ""),
            ("created_at", ""),
            ("expiry", ""),
            ("fetch_endpoint", ""),  # reference mode requires non-empty
            ("mode", "not-a-mode"),
            ("mutability", "not-a-mutability"),
        ],
    )
    def test_rejects_malformed_field(
        self,
        base_promotion_data: dict[str, Any],
        field: str,
        bad_value: Any,
    ) -> None:
        with pytest.raises(ValidationError):
            Promotion(**{**base_promotion_data, field: bad_value})

    def test_rejects_extra_fields(self, base_promotion_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            Promotion(**{**base_promotion_data, "unknown": "anything"})

    def test_owner_cannot_promote_to_self(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            Promotion(
                **{**base_promotion_data, "receiver": base_promotion_data["owner"]}
            )

    def test_expiry_must_be_after_created_at(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            Promotion(
                **{
                    **base_promotion_data,
                    "created_at": "2026-06-02T00:00:00Z",
                    "expiry": "2026-05-26T20:00:00Z",  # before created_at
                }
            )

    def test_expiry_equal_to_created_at_rejected(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        # SPEC §5: expiry > issued_at (analogous for created_at)
        ts = "2026-06-01T12:00:00Z"
        with pytest.raises(ValidationError):
            Promotion(**{**base_promotion_data, "created_at": ts, "expiry": ts})

    def test_snapshot_content_hash_mismatch_rejected(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            Promotion(**{**base_promotion_data, "snapshot_content_hash": "0" * 64})

    def test_snapshot_content_hash_uppercase_rejected(
        self, base_promotion_data: dict[str, Any], snapshot_state: dict[str, Any]
    ) -> None:
        correct_upper = compute_hash(canonical_json(snapshot_state)).upper()
        with pytest.raises(ValidationError):
            Promotion(**{**base_promotion_data, "snapshot_content_hash": correct_upper})


class TestModeMutabilityCrossFields:
    def test_reference_mode_requires_fetch_endpoint(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            Promotion(
                **{
                    **base_promotion_data,
                    "mode": PromotionMode.REFERENCE,
                    "fetch_endpoint": None,
                }
            )

    def test_static_mutability_requires_snapshot_state(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        # SPEC §4: snapshot_state populated for static; None for live (Slice 2).
        with pytest.raises(ValidationError):
            Promotion(
                **{
                    **base_promotion_data,
                    "mutability": Mutability.STATIC,
                    "snapshot_state": None,
                }
            )

    def test_copy_mode_forbids_fetch_endpoint(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        # Slice 1 doesn't ship copy end-to-end, but the model must already
        # reject mode==copy with a fetch_endpoint to keep Slice 3 honest.
        with pytest.raises(ValidationError):
            Promotion(
                **{
                    **base_promotion_data,
                    "mode": PromotionMode.COPY,
                    # fetch_endpoint still present from fixture → violation
                }
            )

    def test_copy_mode_without_fetch_endpoint_constructs(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        # Slice 3 preview: copy mode + no fetch_endpoint is the legitimate
        # Slice 3 shape. Slice 1 storage will refuse to act on it, but the
        # model accepts it.
        p = Promotion(
            **{
                **base_promotion_data,
                "mode": PromotionMode.COPY,
                "fetch_endpoint": None,
            }
        )
        assert p.mode is PromotionMode.COPY
        assert p.fetch_endpoint is None


class TestSnapshotInvariant:
    def test_snapshot_content_hash_matches_snapshot_state(
        self, promotion: Promotion, snapshot_state: dict[str, Any]
    ) -> None:
        # The cryptographic anchor: the handle the receiver gets contains
        # snapshot_content_hash, and every fetch response must hash to this.
        # If the Promotion's local copy disagrees, the entire scheme breaks.
        assert promotion.snapshot_content_hash == compute_hash(
            canonical_json(snapshot_state)
        )

    def test_different_snapshot_state_yields_different_hash(
        self, base_promotion_data: dict[str, Any]
    ) -> None:
        p1 = Promotion(**base_promotion_data)
        mutated = {
            **base_promotion_data,
            "snapshot_state": {**base_promotion_data["snapshot_state"], "duration_minutes": 60},
        }
        p2 = Promotion(**mutated)
        assert p1.snapshot_content_hash != p2.snapshot_content_hash
