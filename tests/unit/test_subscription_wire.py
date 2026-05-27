"""Unit tests for the Slice 2 subscribe / unsubscribe / object-update-ack
wire payloads.

Covers ``demos/phase_4/SLICE_2_SPEC.md`` §3 (Operation enum extension wire
schema table) and the denial-payload shapes referenced from §§7.2 and 7.3.

Eight new wire models (the request side of ObjectUpdate already shipped
in step 2):

| Schema URI                                  | Pydantic model    | Purpose                  |
|---------------------------------------------|-------------------|--------------------------|
| mesherra.object/subscribe-v1                | SubscribeRequest  | receiver → owner request |
| mesherra.object/subscribe-ack-v1            | SubscribeAck      | owner → receiver ack     |
| mesherra.object/subscribe-denied-v1         | SubscribeDenied   | owner → receiver denial  |
| mesherra.object/unsubscribe-v1              | UnsubscribeReq.   | receiver → owner request |
| mesherra.object/unsubscribe-ack-v1          | UnsubscribeAck    | owner → receiver ack     |
| mesherra.object/unsubscribe-denied-v1       | UnsubscribeDenied | owner → receiver denial  |
| mesherra.object/object-update-ack-v1        | ObjectUpdateAck   | receiver → owner ack     |
| mesherra.object/object-update-denied-v1     | ObjectUpdateDen.  | receiver → owner denial  |

Denial reasons are pinned by Literal types (same discipline as Slice 1's
``DenialReason``) so the receiver, the residue ledger, and any future
analytics consumer all rely on a known small set.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.object.wire import (
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_DENIED_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_DENIED_SCHEMA,
    SUBSCRIBE_REQUEST_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_DENIED_SCHEMA,
    UNSUBSCRIBE_REQUEST_SCHEMA,
    ObjectUpdateAck,
    ObjectUpdateDenialReason,
    ObjectUpdateDenied,
    SubscribeAck,
    SubscribeDenialReason,
    SubscribeDenied,
    SubscribeRequest,
    UnsubscribeAck,
    UnsubscribeDenialReason,
    UnsubscribeDenied,
    UnsubscribeRequest,
)


# -- Schema-ID constants -----------------------------------------------


class TestSchemaIDs:
    """Pin every schema URI as a constant: a typo here is caught here
    rather than on the wire (same discipline as the Slice 1 wire tests)."""

    def test_subscribe_request(self) -> None:
        assert SUBSCRIBE_REQUEST_SCHEMA == "mesherra.object/subscribe-v1"

    def test_subscribe_ack(self) -> None:
        assert SUBSCRIBE_ACK_SCHEMA == "mesherra.object/subscribe-ack-v1"

    def test_subscribe_denied(self) -> None:
        assert SUBSCRIBE_DENIED_SCHEMA == "mesherra.object/subscribe-denied-v1"

    def test_unsubscribe_request(self) -> None:
        assert UNSUBSCRIBE_REQUEST_SCHEMA == "mesherra.object/unsubscribe-v1"

    def test_unsubscribe_ack(self) -> None:
        assert UNSUBSCRIBE_ACK_SCHEMA == "mesherra.object/unsubscribe-ack-v1"

    def test_unsubscribe_denied(self) -> None:
        assert UNSUBSCRIBE_DENIED_SCHEMA == "mesherra.object/unsubscribe-denied-v1"

    def test_object_update_ack(self) -> None:
        assert OBJECT_UPDATE_ACK_SCHEMA == "mesherra.object/object-update-ack-v1"

    def test_object_update_denied(self) -> None:
        assert OBJECT_UPDATE_DENIED_SCHEMA == "mesherra.object/object-update-denied-v1"


# -- SubscribeRequest ---------------------------------------------------


class TestSubscribeRequest:
    def test_construct(self) -> None:
        req = SubscribeRequest(promotion_id="prm-live-1")
        assert req.version == 1
        assert req.promotion_id == "prm-live-1"

    def test_promotion_id_required(self) -> None:
        with pytest.raises(ValidationError):
            SubscribeRequest()  # type: ignore[call-arg]

    def test_promotion_id_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            SubscribeRequest(promotion_id="")

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SubscribeRequest(promotion_id="prm-live-1", leak="value")  # type: ignore[call-arg]

    def test_frozen(self) -> None:
        req = SubscribeRequest(promotion_id="prm-live-1")
        with pytest.raises(ValidationError):
            req.promotion_id = "other"  # type: ignore[misc]


# -- SubscribeAck -------------------------------------------------------


class TestSubscribeAck:
    def test_construct(self) -> None:
        ack = SubscribeAck(promotion_id="prm-live-1")
        assert ack.version == 1
        assert ack.subscribed is True

    def test_subscribed_defaults_true(self) -> None:
        # The ack confirms the row is in 'active'. No "not subscribed"
        # variant: SubscribeDenied carries denial; SubscribeAck is positive.
        ack = SubscribeAck(promotion_id="prm-live-1")
        assert ack.subscribed is True

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SubscribeAck(promotion_id="prm-live-1", leak="value")  # type: ignore[call-arg]


# -- SubscribeDenied ----------------------------------------------------


class TestSubscribeDenied:
    BASE: dict[str, Any] = dict(promotion_id="prm-live-1", reason="expired")

    def test_construct(self) -> None:
        d = SubscribeDenied(**self.BASE)
        assert d.reason == "expired"

    @pytest.mark.parametrize(
        "reason",
        [
            "unknown_promotion",
            "receiver_mismatch",
            "not_live_promotion",
            "expired",
        ],
    )
    def test_documented_reasons_accepted(self, reason: str) -> None:
        d = SubscribeDenied(promotion_id="prm-live-1", reason=reason)
        assert d.reason == reason

    def test_unknown_reason_rejected(self) -> None:
        # Same discipline as the Slice 1 DenialReason: an unrecognized
        # value must not silently flow as a denial reason (downstream
        # consumers rely on the set being stable).
        with pytest.raises(ValidationError):
            SubscribeDenied(promotion_id="prm-live-1", reason="i_dont_like_you")

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SubscribeDenied(**{**self.BASE, "leak": "value"})

    def test_subscribe_denial_reason_type_exposed(self) -> None:
        # The Literal type is exported so callers can build a denial with
        # type-checked reason values (cf. Slice 1's DenialReason export).
        reason: SubscribeDenialReason = "expired"  # type: ignore[assignment]
        d = SubscribeDenied(promotion_id="prm-live-1", reason=reason)
        assert d.reason == "expired"


# -- UnsubscribeRequest -------------------------------------------------


class TestUnsubscribeRequest:
    def test_construct(self) -> None:
        req = UnsubscribeRequest(promotion_id="prm-live-1")
        assert req.promotion_id == "prm-live-1"

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UnsubscribeRequest(promotion_id="prm-live-1", extra=1)  # type: ignore[call-arg]


# -- UnsubscribeAck -----------------------------------------------------


class TestUnsubscribeAck:
    def test_construct(self) -> None:
        ack = UnsubscribeAck(promotion_id="prm-live-1")
        assert ack.unsubscribed is True

    def test_unsubscribed_defaults_true(self) -> None:
        # Per Slice 1 ack convention: only positive ack flows here; denial
        # uses UnsubscribeDenied.
        ack = UnsubscribeAck(promotion_id="prm-live-1")
        assert ack.unsubscribed is True


# -- UnsubscribeDenied --------------------------------------------------


class TestUnsubscribeDenied:
    BASE: dict[str, Any] = dict(promotion_id="prm-live-1", reason="not_active")

    @pytest.mark.parametrize("reason", ["not_active", "expired"])
    def test_documented_reasons_accepted(self, reason: str) -> None:
        # Per §7.2 UNSUBSCRIBE matrix: 'not_active' (no row) and 'expired'
        # (row exists but past expiry — ack would be misleading).
        d = UnsubscribeDenied(promotion_id="prm-live-1", reason=reason)
        assert d.reason == reason

    def test_unknown_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UnsubscribeDenied(promotion_id="prm-live-1", reason="whatever")

    def test_unsubscribe_denial_reason_type_exposed(self) -> None:
        reason: UnsubscribeDenialReason = "expired"  # type: ignore[assignment]
        d = UnsubscribeDenied(promotion_id="prm-live-1", reason=reason)
        assert d.reason == "expired"


# -- ObjectUpdateAck ----------------------------------------------------


class TestObjectUpdateAck:
    def test_construct(self) -> None:
        ack = ObjectUpdateAck(promotion_id="prm-live-1", object_version=2)
        assert ack.received is True
        assert ack.object_version == 2

    def test_object_version_required(self) -> None:
        # The ack echoes the version the receiver processed so the owner
        # can correlate "v3 was acked, bump last_pushed_object_version to 3"
        # without having to pair to the in-flight request manually.
        with pytest.raises(ValidationError):
            ObjectUpdateAck(promotion_id="prm-live-1")  # type: ignore[call-arg]

    def test_object_version_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdateAck(promotion_id="prm-live-1", object_version=0)


# -- ObjectUpdateDenied -------------------------------------------------


class TestObjectUpdateDenied:
    @pytest.mark.parametrize("reason", ["expired", "version_regression"])
    def test_documented_reasons_accepted(self, reason: str) -> None:
        # Per §7.3 soft-failure cases: handle past expiry, or object_version
        # not strictly greater than last_pushed. Both produce a denial — the
        # owner can decide whether to abandon or retry the subscription.
        d = ObjectUpdateDenied(
            promotion_id="prm-live-1", object_version=3, reason=reason
        )
        assert d.reason == reason

    def test_unknown_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ObjectUpdateDenied(
                promotion_id="prm-live-1",
                object_version=3,
                reason="i_disagree",
            )

    def test_object_update_denial_reason_type_exposed(self) -> None:
        reason: ObjectUpdateDenialReason = "version_regression"  # type: ignore[assignment]
        d = ObjectUpdateDenied(
            promotion_id="prm-live-1", object_version=3, reason=reason
        )
        assert d.reason == "version_regression"
