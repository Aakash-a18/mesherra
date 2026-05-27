"""Unit tests for the ActiveSubscription Pydantic model + SubscriptionStatus
enum and its transition rule.

Covers Phase 4 Slice 2 step 1 per ``demos/phase_4/SLICE_2_SPEC.md`` sections
4–5 and 7.2 (state transition matrices).

ActiveSubscription is the *state* row that lives in the per-principal
ObjectStore's ``active_subscriptions`` table. One row per (promotion_id, role)
— role distinguishes owner-side from receiver-side because both can coexist
in a single principal's ObjectStore (mirrors how ``promotions`` and
``received_handles`` cohabit in Slice 1).

This file tests the model + the enum + the pure-function transition rule.
Persistence (record / get / update / list) is tested in
``test_object_store_subscriptions.py`` (Slice 2 step 5). Handler-side
dispatch through SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE arrives in
``test_object_inbound_handler_live.py`` (Slice 2 step 6).

Same discipline as Slice 1's ``test_promotion_model.py``: frozen + extra=forbid,
explicit field validators, no real user data.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.models.primitives import (
    ActiveSubscription,
    InvalidSubscriptionTransition,
    SubscriptionRole,
    SubscriptionStatus,
)


@pytest.fixture
def base_subscription_data() -> dict[str, Any]:
    return dict(
        promotion_id="prm-1a2b",
        counterpart="bob@phase4.local",
        role=SubscriptionRole.OWNER,
        last_pushed_object_version=None,
        status=SubscriptionStatus.ACTIVE,
        subscribed_at="2026-05-27T20:00:00Z",
        last_status_change_at="2026-05-27T20:00:00Z",
    )


@pytest.fixture
def subscription(base_subscription_data: dict[str, Any]) -> ActiveSubscription:
    return ActiveSubscription(**base_subscription_data)


# -- Enum values ----------------------------------------------------------


class TestSubscriptionRole:
    """The role enum must expose exactly the two documented members; spec §5
    pins them as the CHECK constraint of the SQLite column."""

    def test_owner_value(self) -> None:
        assert SubscriptionRole.OWNER.value == "owner"

    def test_receiver_value(self) -> None:
        assert SubscriptionRole.RECEIVER.value == "receiver"

    def test_exactly_two_members(self) -> None:
        assert {r.value for r in SubscriptionRole} == {"owner", "receiver"}


class TestSubscriptionStatus:
    """Four legitimate states per SLICE_2_SPEC §4: active / disconnected /
    expired / closed_by_receiver. The SQLite CHECK constraint mirrors this
    set; the enum is the source of truth at the Python boundary."""

    def test_active_value(self) -> None:
        assert SubscriptionStatus.ACTIVE.value == "active"

    def test_disconnected_value(self) -> None:
        assert SubscriptionStatus.DISCONNECTED.value == "disconnected"

    def test_expired_value(self) -> None:
        assert SubscriptionStatus.EXPIRED.value == "expired"

    def test_closed_by_receiver_value(self) -> None:
        assert SubscriptionStatus.CLOSED_BY_RECEIVER.value == "closed_by_receiver"

    def test_exactly_four_members(self) -> None:
        assert {s.value for s in SubscriptionStatus} == {
            "active",
            "disconnected",
            "expired",
            "closed_by_receiver",
        }


# -- Construction ---------------------------------------------------------


class TestConstruction:
    def test_constructs_minimal(self, subscription: ActiveSubscription) -> None:
        assert subscription.promotion_id == "prm-1a2b"
        assert subscription.role is SubscriptionRole.OWNER
        assert subscription.status is SubscriptionStatus.ACTIVE
        assert subscription.last_pushed_object_version is None

    def test_constructs_with_receiver_role(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        sub = ActiveSubscription(
            **{**base_subscription_data, "role": SubscriptionRole.RECEIVER}
        )
        assert sub.role is SubscriptionRole.RECEIVER

    def test_role_accepts_string_alias(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        # str-Enum accepts the raw value at the boundary; integration code
        # often hands these in as plain strings from SQLite rows.
        sub = ActiveSubscription(**{**base_subscription_data, "role": "receiver"})
        assert sub.role is SubscriptionRole.RECEIVER

    def test_status_accepts_string_alias(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        sub = ActiveSubscription(
            **{**base_subscription_data, "status": "disconnected"}
        )
        assert sub.status is SubscriptionStatus.DISCONNECTED

    def test_last_pushed_object_version_can_be_int(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        sub = ActiveSubscription(
            **{**base_subscription_data, "last_pushed_object_version": 3}
        )
        assert sub.last_pushed_object_version == 3

    def test_frozen(self, subscription: ActiveSubscription) -> None:
        with pytest.raises(ValidationError):
            subscription.status = SubscriptionStatus.EXPIRED  # type: ignore[misc]


# -- Field-level validation -----------------------------------------------


class TestValidation:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("promotion_id", ""),
            ("counterpart", ""),
            ("subscribed_at", ""),
            ("last_status_change_at", ""),
            ("role", "not-a-role"),
            ("status", "not-a-status"),
        ],
    )
    def test_rejects_malformed_field(
        self,
        base_subscription_data: dict[str, Any],
        field: str,
        bad_value: Any,
    ) -> None:
        with pytest.raises(ValidationError):
            ActiveSubscription(**{**base_subscription_data, field: bad_value})

    def test_rejects_extra_fields(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            ActiveSubscription(**{**base_subscription_data, "unknown": "anything"})

    def test_last_pushed_object_version_zero_rejected(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        # Object.object_version is >= 1 (see Object model); 0 is never a
        # legitimate "pushed" version. None means "no push yet" — that's the
        # distinct legitimate value.
        with pytest.raises(ValidationError):
            ActiveSubscription(
                **{**base_subscription_data, "last_pushed_object_version": 0}
            )

    def test_last_pushed_object_version_negative_rejected(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            ActiveSubscription(
                **{**base_subscription_data, "last_pushed_object_version": -1}
            )

    def test_last_status_change_before_subscribed_rejected(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        # The status-change timestamp records a transition; the FIRST transition
        # is the subscription's creation itself. A later transition cannot have
        # happened before the creation. Same shape as Promotion's
        # expiry-after-created_at cross-field rule.
        with pytest.raises(ValidationError):
            ActiveSubscription(
                **{
                    **base_subscription_data,
                    "subscribed_at": "2026-05-27T20:00:00Z",
                    "last_status_change_at": "2026-05-27T19:59:59Z",
                }
            )

    def test_last_status_change_equal_to_subscribed_accepted(
        self, base_subscription_data: dict[str, Any]
    ) -> None:
        # The initial-creation case: both timestamps equal because the create
        # IS the first status change.
        ts = "2026-05-27T20:00:00Z"
        sub = ActiveSubscription(
            **{**base_subscription_data, "subscribed_at": ts, "last_status_change_at": ts}
        )
        assert sub.subscribed_at == sub.last_status_change_at


# -- Transition rule (pure function on the enum) --------------------------


class TestSubscriptionStatusTransition:
    """SLICE_2_SPEC §7.2 pins the legal state graph. The rule is a pure
    function on the enum so the store and the handlers can delegate to a
    single source of truth.

    Legal graph:

        (initial) -> active
        active         -> active | disconnected | expired | closed_by_receiver
        disconnected   -> active | disconnected | expired | closed_by_receiver
        closed_by_receiver -> active | closed_by_receiver
        expired        -> expired

    Illegal transitions raise InvalidSubscriptionTransition.
    """

    @pytest.mark.parametrize(
        "from_status,to_status",
        [
            (SubscriptionStatus.ACTIVE, SubscriptionStatus.ACTIVE),
            (SubscriptionStatus.ACTIVE, SubscriptionStatus.DISCONNECTED),
            (SubscriptionStatus.ACTIVE, SubscriptionStatus.EXPIRED),
            (SubscriptionStatus.ACTIVE, SubscriptionStatus.CLOSED_BY_RECEIVER),
            (SubscriptionStatus.DISCONNECTED, SubscriptionStatus.ACTIVE),
            (SubscriptionStatus.DISCONNECTED, SubscriptionStatus.DISCONNECTED),
            (SubscriptionStatus.DISCONNECTED, SubscriptionStatus.EXPIRED),
            (SubscriptionStatus.DISCONNECTED, SubscriptionStatus.CLOSED_BY_RECEIVER),
            (SubscriptionStatus.CLOSED_BY_RECEIVER, SubscriptionStatus.ACTIVE),
            (SubscriptionStatus.CLOSED_BY_RECEIVER, SubscriptionStatus.CLOSED_BY_RECEIVER),
            (SubscriptionStatus.EXPIRED, SubscriptionStatus.EXPIRED),
        ],
    )
    def test_legal_transitions_pass(
        self,
        from_status: SubscriptionStatus,
        to_status: SubscriptionStatus,
    ) -> None:
        # Returns silently; no exception.
        SubscriptionStatus.validate_transition(from_status, to_status)

    @pytest.mark.parametrize(
        "from_status,to_status",
        [
            # expired is terminal — cannot revive in any direction.
            (SubscriptionStatus.EXPIRED, SubscriptionStatus.ACTIVE),
            (SubscriptionStatus.EXPIRED, SubscriptionStatus.DISCONNECTED),
            (SubscriptionStatus.EXPIRED, SubscriptionStatus.CLOSED_BY_RECEIVER),
            # closed_by_receiver: only legal forward edge is back to active
            # (the re-subscribe-after-unsubscribe case per §7.2). Going to
            # disconnected or expired is illegal; you can't be "disconnected"
            # from something you explicitly closed, and only the wall-clock
            # at promotion.expiry can move a row to expired.
            (SubscriptionStatus.CLOSED_BY_RECEIVER, SubscriptionStatus.DISCONNECTED),
            (SubscriptionStatus.CLOSED_BY_RECEIVER, SubscriptionStatus.EXPIRED),
        ],
    )
    def test_illegal_transitions_raise(
        self,
        from_status: SubscriptionStatus,
        to_status: SubscriptionStatus,
    ) -> None:
        with pytest.raises(InvalidSubscriptionTransition):
            SubscriptionStatus.validate_transition(from_status, to_status)

    def test_invalid_transition_message_names_both_states(self) -> None:
        with pytest.raises(InvalidSubscriptionTransition) as excinfo:
            SubscriptionStatus.validate_transition(
                SubscriptionStatus.EXPIRED, SubscriptionStatus.ACTIVE
            )
        msg = str(excinfo.value)
        assert "expired" in msg
        assert "active" in msg
