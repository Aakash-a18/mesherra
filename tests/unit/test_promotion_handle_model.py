"""Unit tests for the PromotionHandle Pydantic model.

Covers Phase 4 Slice 1 step 3 (Models) per demos/phase_4/SPEC.md section 5.

PromotionHandle is the WIRE artifact — the only thing that crosses the
boundary at promotion time in reference mode. It is signed by the owner;
the receiver verifies the signature against the owner's public key resolved
through the Identity Directory. The full Object state never crosses; only
the handle does.

Tested here:
- Field shapes and required-set
- Cross-field invariants (mode + fetch_endpoint / scoped_payload pairing)
- expiry > issued_at
- owner != receiver
- to_signing_payload() omits owner_signature (the same convention as Residue)
- JSON Schema mirror agreement
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.models.primitives import (
    Mutability,
    PromotionHandle,
    PromotionMode,
)

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "mesherra"
    / "object"
    / "promotion_handle_v1.json"
)


@pytest.fixture
def base_handle_data() -> dict[str, Any]:
    return dict(
        promotion_id="prm-1a2b",
        object_id="obj-7f3a",
        owner="alice@phase4.local",
        receiver="bob@phase4.local",
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates", "duration_minutes"]},
        snapshot_content_hash="a" * 64,
        fetch_endpoint="https://alice.example/mesherra/objects/fetch/prm-1a2b",
        expiry="2026-06-02T00:00:00Z",
        issued_at="2026-05-26T20:00:00Z",
        owner_signature="placeholder-base64",
    )


@pytest.fixture
def handle(base_handle_data: dict[str, Any]) -> PromotionHandle:
    return PromotionHandle(**base_handle_data)


class TestConstruction:
    def test_well_formed_reference_handle_constructs(
        self, handle: PromotionHandle
    ) -> None:
        assert handle.version == 1
        assert handle.mode is PromotionMode.REFERENCE
        assert handle.fetch_endpoint is not None
        assert handle.scoped_payload is None

    def test_well_formed_copy_handle_constructs(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        # Slice 3 preview — the model must accept the copy shape now so the
        # shape is locked even though the fetch path doesn't ship yet.
        copy_data = {
            **base_handle_data,
            "mode": PromotionMode.COPY,
            "fetch_endpoint": None,
            "scoped_payload": "base64-bytes-here",
        }
        h = PromotionHandle(**copy_data)
        assert h.mode is PromotionMode.COPY
        assert h.fetch_endpoint is None
        assert h.scoped_payload == "base64-bytes-here"

    def test_handle_is_frozen(self, handle: PromotionHandle) -> None:
        with pytest.raises(ValidationError):
            handle.receiver = "eve@phase4.local"  # type: ignore[misc]


class TestValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("promotion_id", ""),
            ("object_id", ""),
            ("owner", ""),
            ("receiver", ""),
            ("schema_ref", ""),
            ("expiry", ""),
            ("issued_at", ""),
            ("owner_signature", ""),
            ("snapshot_content_hash", "deadbeef"),
            ("snapshot_content_hash", "A" * 64),  # uppercase rejected
            ("version", 2),
            ("mode", "not-a-mode"),
            ("mutability", "not-a-mutability"),
        ],
    )
    def test_rejects_malformed_field(
        self,
        base_handle_data: dict[str, Any],
        field: str,
        bad_value: Any,
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(**{**base_handle_data, field: bad_value})

    def test_rejects_extra_fields(self, base_handle_data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(**{**base_handle_data, "unknown": "anything"})

    def test_owner_cannot_promote_to_self(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{**base_handle_data, "receiver": base_handle_data["owner"]}
            )

    def test_expiry_must_be_after_issued_at(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{
                    **base_handle_data,
                    "issued_at": "2026-06-02T00:00:00Z",
                    "expiry": "2026-05-26T20:00:00Z",
                }
            )

    def test_expiry_equal_to_issued_at_rejected(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        ts = "2026-06-01T12:00:00Z"
        with pytest.raises(ValidationError):
            PromotionHandle(**{**base_handle_data, "issued_at": ts, "expiry": ts})


class TestModeCrossFields:
    def test_reference_mode_requires_fetch_endpoint(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{
                    **base_handle_data,
                    "mode": PromotionMode.REFERENCE,
                    "fetch_endpoint": None,
                }
            )

    def test_reference_mode_forbids_scoped_payload(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{
                    **base_handle_data,
                    "mode": PromotionMode.REFERENCE,
                    "scoped_payload": "should-not-be-here",
                }
            )

    def test_copy_mode_requires_scoped_payload(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{
                    **base_handle_data,
                    "mode": PromotionMode.COPY,
                    "fetch_endpoint": None,
                    "scoped_payload": None,
                }
            )

    def test_copy_mode_forbids_fetch_endpoint(
        self, base_handle_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            PromotionHandle(
                **{
                    **base_handle_data,
                    "mode": PromotionMode.COPY,
                    "scoped_payload": "base64-bytes",
                    # fetch_endpoint still present from fixture
                }
            )


class TestSigningPayload:
    def test_omits_owner_signature(self, handle: PromotionHandle) -> None:
        payload = handle.to_signing_payload()
        assert "owner_signature" not in payload

    def test_preserves_all_other_fields(self, handle: PromotionHandle) -> None:
        payload = handle.to_signing_payload()
        expected = {
            "version", "promotion_id", "object_id", "owner", "receiver",
            "schema_ref", "mode", "mutability", "scope",
            "snapshot_content_hash", "fetch_endpoint", "scoped_payload",
            "expiry", "issued_at",
        }
        assert set(payload.keys()) == expected

    def test_enum_values_serialize_as_strings(self, handle: PromotionHandle) -> None:
        payload = handle.to_signing_payload()
        assert payload["mode"] == "reference"
        assert payload["mutability"] == "static"
        assert payload["version"] == 1


class TestSchemaMirror:
    def test_mirror_file_exists(self) -> None:
        assert SCHEMA_PATH.is_file(), f"Schema mirror missing: {SCHEMA_PATH}"

    def test_mirror_has_correct_schema_id(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        assert mirror["$id"] == "mesherra.object/promotion-handle-v1"

    def test_property_sets_match(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = PromotionHandle.model_json_schema()
        assert set(mirror["properties"].keys()) == set(pydantic_schema["properties"].keys())

    def test_mirror_required_is_superset_of_pydantic_required(self) -> None:
        mirror = json.loads(SCHEMA_PATH.read_text())
        pydantic_schema = PromotionHandle.model_json_schema()
        assert set(pydantic_schema["required"]) <= set(mirror["required"])
