"""Unit tests for Phase 4 Object wire-payload Pydantic models.

These models describe the bytes that flow on the A2A wire during the
Slice 1 Object Promotion lifecycle (SPEC §8.2):

- ``FetchRequest``        — schema ``mesherra.object/fetch-v1``
- ``FetchResponse``       — schema ``mesherra.object/fetch-response-v1``
- ``FetchDenied``         — schema ``mesherra.object/fetch-denied-v1``
- ``PromotionAck``        — schema ``mesherra.object/promotion-ack-v1``

The PromotionHandle itself (the PROMOTE payload) is already covered by
test_promotion_handle_model.py — these tests cover the *other* four
payload shapes in the Slice 1 wire protocol.

What's verified here:
- Well-formed payloads construct successfully.
- Field-level validators reject malformed values.
- Models are frozen and ``extra="forbid"`` (defensive against silent drift).
- The denial reason field accepts the documented values.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_REQUEST_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    PROMOTION_ACK_SCHEMA,
    FetchDenied,
    FetchRequest,
    FetchResponse,
    PromotionAck,
)


# -- Schema-ID constants ------------------------------------------------


class TestSchemaIDs:
    """Slice 1 wire-format identifiers. Hardcoded checks so a typo in the
    constant is caught here rather than discovered on the wire."""

    def test_fetch_request_schema_id(self) -> None:
        assert FETCH_REQUEST_SCHEMA == "mesherra.object/fetch-v1"

    def test_fetch_response_schema_id(self) -> None:
        assert FETCH_RESPONSE_SCHEMA == "mesherra.object/fetch-response-v1"

    def test_fetch_denied_schema_id(self) -> None:
        assert FETCH_DENIED_SCHEMA == "mesherra.object/fetch-denied-v1"

    def test_promotion_ack_schema_id(self) -> None:
        assert PROMOTION_ACK_SCHEMA == "mesherra.object/promotion-ack-v1"


# -- FetchRequest -------------------------------------------------------


class TestFetchRequest:
    def test_construct_minimal(self) -> None:
        req = FetchRequest(promotion_id="prom-1", fetch_sequence=1)
        assert req.version == 1
        assert req.promotion_id == "prom-1"
        assert req.fetch_sequence == 1

    def test_promotion_id_required(self) -> None:
        with pytest.raises(ValidationError):
            FetchRequest(fetch_sequence=1)  # type: ignore[call-arg]

    def test_promotion_id_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            FetchRequest(promotion_id="", fetch_sequence=1)

    def test_fetch_sequence_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            FetchRequest(promotion_id="prom-1", fetch_sequence=0)
        with pytest.raises(ValidationError):
            FetchRequest(promotion_id="prom-1", fetch_sequence=-1)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FetchRequest(  # type: ignore[call-arg]
                promotion_id="prom-1", fetch_sequence=1, extra="nope"
            )

    def test_frozen(self) -> None:
        req = FetchRequest(promotion_id="prom-1", fetch_sequence=1)
        with pytest.raises(ValidationError):
            req.fetch_sequence = 2  # type: ignore[misc]

    def test_version_constant(self) -> None:
        # Caller passing version=2 must be rejected; the Literal makes it
        # impossible to construct a v2 instance through v1 code.
        with pytest.raises(ValidationError):
            FetchRequest(  # type: ignore[arg-type]
                version=2, promotion_id="prom-1", fetch_sequence=1
            )


# -- FetchResponse ------------------------------------------------------


class TestFetchResponse:
    BASE: dict[str, Any] = dict(
        promotion_id="prom-1",
        snapshot_state={"a": 1, "b": "two"},
        snapshot_content_hash="a" * 64,
    )

    def test_construct(self) -> None:
        resp = FetchResponse(**self.BASE)
        assert resp.version == 1
        assert resp.snapshot_state == {"a": 1, "b": "two"}

    def test_promotion_id_required(self) -> None:
        d = {**self.BASE}
        del d["promotion_id"]
        with pytest.raises(ValidationError):
            FetchResponse(**d)

    def test_snapshot_content_hash_must_be_64_hex(self) -> None:
        with pytest.raises(ValidationError):
            FetchResponse(**{**self.BASE, "snapshot_content_hash": "tooshort"})
        with pytest.raises(ValidationError):
            FetchResponse(
                **{**self.BASE, "snapshot_content_hash": "Z" * 64}
            )

    def test_snapshot_state_can_be_empty_dict(self) -> None:
        resp = FetchResponse(**{**self.BASE, "snapshot_state": {}})
        assert resp.snapshot_state == {}

    def test_fetch_sequence_field_rejected(self) -> None:
        # Per SPEC §9 #8: response payload must be byte-equal across
        # fetches of the same static-reference snapshot. Including a
        # per-fetch counter would break that, so the field is forbidden.
        with pytest.raises(ValidationError):
            FetchResponse(**{**self.BASE, "fetch_sequence": 1})

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FetchResponse(**{**self.BASE, "leak": "value"})

    def test_frozen(self) -> None:
        resp = FetchResponse(**self.BASE)
        with pytest.raises(ValidationError):
            resp.snapshot_state = {"hacked": True}  # type: ignore[misc]

    def test_two_responses_with_same_snapshot_serialize_byte_equal(self) -> None:
        # The SPEC §9 #8 invariant at the model level: same snapshot ⇒
        # same canonical bytes.
        r1 = FetchResponse(
            promotion_id="prom-1",
            snapshot_state={"x": [1, 2, 3]},
            snapshot_content_hash="b" * 64,
        )
        r2 = FetchResponse(
            promotion_id="prom-1",
            snapshot_state={"x": [1, 2, 3]},
            snapshot_content_hash="b" * 64,
        )
        assert r1.model_dump_json() == r2.model_dump_json()


# -- FetchDenied --------------------------------------------------------


class TestFetchDenied:
    BASE: dict[str, Any] = dict(
        promotion_id="prom-1",
        fetch_sequence=1,
        reason="expired",
    )

    def test_construct(self) -> None:
        d = FetchDenied(**self.BASE)
        assert d.reason == "expired"

    @pytest.mark.parametrize(
        "reason",
        [
            "expired",
            "revoked",
            "receiver_mismatch",
            "unknown_promotion",
            "scope_violation",
        ],
    )
    def test_documented_denial_reasons_accepted(self, reason: str) -> None:
        d = FetchDenied(**{**self.BASE, "reason": reason})
        assert d.reason == reason

    def test_unknown_reason_rejected(self) -> None:
        # Slice 1 pins the documented reason set; arbitrary strings must
        # not silently flow as denial reasons (the caller relies on the
        # set being stable for residue downstream).
        with pytest.raises(ValidationError):
            FetchDenied(**{**self.BASE, "reason": "i_dont_like_you"})

    def test_promotion_id_required(self) -> None:
        d = {**self.BASE}
        del d["promotion_id"]
        with pytest.raises(ValidationError):
            FetchDenied(**d)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FetchDenied(**{**self.BASE, "extra": "nope"})


# -- PromotionAck -------------------------------------------------------


class TestPromotionAck:
    def test_construct(self) -> None:
        ack = PromotionAck(promotion_id="prom-1")
        assert ack.version == 1
        assert ack.promotion_id == "prom-1"
        assert ack.received is True

    def test_received_defaults_true(self) -> None:
        # The ack exists solely to confirm receipt — there is no "not received"
        # variant; if the gateway raised, the request would have failed before
        # the ack was built.
        ack = PromotionAck(promotion_id="prom-1")
        assert ack.received is True

    def test_promotion_id_required(self) -> None:
        with pytest.raises(ValidationError):
            PromotionAck()  # type: ignore[call-arg]

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PromotionAck(promotion_id="prom-1", leak="value")  # type: ignore[call-arg]

    def test_frozen(self) -> None:
        ack = PromotionAck(promotion_id="prom-1")
        with pytest.raises(ValidationError):
            ack.received = False  # type: ignore[misc]
