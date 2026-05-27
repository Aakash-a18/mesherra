"""Unit tests for the Slice 2 additions to ObjectInboundHandler.

Covers ``demos/phase_4/SLICE_2_SPEC.md`` §§7.2 and 7.3 — the three new
inbound handler methods:

- ``handle_subscribe`` — owner-side: receiver requests subscription.
- ``handle_unsubscribe`` — owner-side: receiver requests teardown.
- ``handle_object_update`` — receiver-side: owner pushes a new snapshot.

Cross-method discipline (mirrors the Slice 1 handler tests in
``test_object_inbound_handler.py``):

* The handler is trust-layer routine. Consumer never sees these ops.
* Soft failures (denial reasons in §7.2 SUBSCRIBE/UNSUBSCRIBE matrices,
  §7.3 ObjectUpdate soft list) return a denial HandlerOutput.
* Hard failures (forwarded path, content_hash mismatch, malformed
  payload, unknown receiver-side handle) raise — gateway propagates and
  the airlock writes a failure residue.

Unit tests only — no real network. Step 7 wires this into the gateway
and step 13 lifts the assertions to the cross-process roundtrip.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    LayerKind,
    Mutability,
    Object,
    Operation,
    Promotion,
    PromotionHandle,
    PromotionMode,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.handler import (
    HandlerOutput,
    InvalidObjectUpdatePayload,
    ObjectInboundHandler,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_DENIED_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_DENIED_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_DENIED_SCHEMA,
    ObjectUpdate,
    ObjectUpdateAck,
    ObjectUpdateDenied,
    SubscribeAck,
    SubscribeDenied,
    SubscribeRequest,
    UnsubscribeAck,
    UnsubscribeDenied,
    UnsubscribeRequest,
)

OWNER = "alice@phase4.local"
RECEIVER = "bob@phase4.local"
EVE = "eve@phase4.local"


# -- Fixtures ----------------------------------------------------------


@pytest.fixture
def owner_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def receiver_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def directory(
    owner_signer: Signer, receiver_signer: Signer
) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {
            OWNER: owner_signer.public_key_b64(),
            RECEIVER: receiver_signer.public_key_b64(),
            EVE: Signer.generate().public_key_b64(),
        }
    )


@pytest.fixture
def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture
def expiry_future_iso() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


@pytest.fixture
def expiry_past_iso() -> str:
    return (datetime.now(UTC) - timedelta(seconds=10)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


@pytest.fixture
def later_iso() -> str:
    """A timestamp strictly later than any `datetime.now(UTC)` captured
    by the handler under test. Used by transition tests that need to
    drive status changes that the model's ``last_status_change_at >=
    subscribed_at`` validator must accept."""
    return (datetime.now(UTC) + timedelta(seconds=30)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


@pytest.fixture
def base_state() -> dict[str, Any]:
    return {"candidates": ["2026-06-01T09:00:00Z"], "duration_minutes": 30}


def _build_live_object(state: dict[str, Any], *, now: str, version: int = 1) -> Object:
    return Object(
        object_id="obj-live-1",
        owner=OWNER,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.LIVE,
        schema_ref="meshycal.scheduling/calendar-v1",
        state=state,
        object_version=version,
        created_at=now,
        updated_at=now,
    )


def _build_live_promotion(
    *,
    now: str,
    expiry: str,
    receiver: str = RECEIVER,
) -> Promotion:
    return Promotion(
        promotion_id="prm-live-1",
        object_id="obj-live-1",
        owner=OWNER,
        receiver=receiver,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.LIVE,
        scope={"fields": ["candidates", "duration_minutes"]},
        expiry=expiry,
        snapshot_state=None,
        fetch_endpoint="https://alice.example/mesherra/fetch/prm-live-1",
        created_at=now,
    )


def _build_static_promotion(*, now: str, expiry: str) -> Promotion:
    return Promotion(
        promotion_id="prm-static-1",
        object_id="obj-static-1",
        owner=OWNER,
        receiver=RECEIVER,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates"]},
        expiry=expiry,
        snapshot_state={"candidates": ["2026-06-01T09:00:00Z"]},
        fetch_endpoint="https://alice.example/mesherra/fetch/prm-static-1",
        created_at=now,
    )


def _build_signed_handle(
    *,
    signer: Signer,
    promotion: Promotion,
    issued_at: str,
    snapshot_content_hash: str,
) -> PromotionHandle:
    unsigned = PromotionHandle(
        promotion_id=promotion.promotion_id,
        object_id=promotion.object_id,
        owner=promotion.owner,
        receiver=promotion.receiver,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=promotion.mode,
        mutability=promotion.mutability,
        scope=promotion.scope,
        snapshot_content_hash=snapshot_content_hash,
        fetch_endpoint=promotion.fetch_endpoint,
        scoped_payload=None,
        expiry=promotion.expiry,
        issued_at=issued_at,
        owner_signature="placeholder",
    )
    sig = signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


# ----------------------------------------------------------------------
# handle_subscribe (owner-side)
# ----------------------------------------------------------------------


class TestHandleSubscribe:
    """Alice (owner) receives a SUBSCRIBE from Bob (receiver)."""

    @pytest.fixture
    def owner_store(self, tmp_path: Path) -> ObjectStore:
        s = ObjectStore(db_path=tmp_path / "alice.sqlite", owner_principal_id=OWNER)
        yield s
        s.close()

    @pytest.fixture
    def owner_handler(
        self,
        owner_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> ObjectInboundHandler:
        return ObjectInboundHandler(
            principal_id=OWNER, object_store=owner_store, directory=directory
        )

    @pytest.fixture
    def seeded_owner_store(
        self,
        owner_store: ObjectStore,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> ObjectStore:
        owner_store.put(_build_live_object(base_state, now=now_iso))
        owner_store.record_promotion(
            _build_live_promotion(now=now_iso, expiry=expiry_future_iso)
        )
        return owner_store

    @pytest.mark.asyncio
    async def test_happy_path_creates_active_row(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
    ) -> None:
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        assert out.operation is Operation.SUBSCRIBE
        assert out.payload_schema == SUBSCRIBE_ACK_SCHEMA
        ack = SubscribeAck.model_validate(out.payload)
        assert ack.subscribed is True
        # Owner-side row exists, active, no pushes yet.
        sub = seeded_owner_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.ACTIVE
        assert sub.last_pushed_object_version is None
        assert sub.counterpart == RECEIVER

    @pytest.mark.asyncio
    async def test_unknown_promotion_denied(
        self, owner_handler: ObjectInboundHandler
    ) -> None:
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-nope").model_dump(),
            sender_principal_id=RECEIVER,
        )
        assert out.payload_schema == SUBSCRIBE_DENIED_SCHEMA
        denied = SubscribeDenied.model_validate(out.payload)
        assert denied.reason == "unknown_promotion"

    @pytest.mark.asyncio
    async def test_receiver_mismatch_denied(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
    ) -> None:
        # SLICE_2_SPEC §9 #12 — Eve cannot subscribe with Bob's handle.
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=EVE,
        )
        denied = SubscribeDenied.model_validate(out.payload)
        assert denied.reason == "receiver_mismatch"
        # No row created — Eve's subscribe attempt leaves no state behind.
        from mesherra.object.store import SubscriptionNotFound
        with pytest.raises(SubscriptionNotFound):
            seeded_owner_store.get_subscription(
                promotion_id="prm-live-1", role=SubscriptionRole.OWNER
            )

    @pytest.mark.asyncio
    async def test_static_promotion_denied(
        self,
        owner_handler: ObjectInboundHandler,
        owner_store: ObjectStore,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # SUBSCRIBE is only for LIVE promotions.
        owner_store.put(
            _build_live_object(base_state, now=now_iso).model_copy(
                update={"object_id": "obj-static-1", "mutability": Mutability.STATIC}
            )
        )
        owner_store.record_promotion(
            _build_static_promotion(now=now_iso, expiry=expiry_future_iso)
        )
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-static-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        denied = SubscribeDenied.model_validate(out.payload)
        assert denied.reason == "not_live_promotion"

    @pytest.mark.asyncio
    async def test_expired_promotion_denied(
        self,
        owner_handler: ObjectInboundHandler,
        owner_store: ObjectStore,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_past_iso: str,
    ) -> None:
        # The promotion's own model rejects expiry <= created_at, so we
        # set created_at safely in the past too.
        past_created = (datetime.now(UTC) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        owner_store.put(_build_live_object(base_state, now=now_iso))
        owner_store.record_promotion(
            _build_live_promotion(now=past_created, expiry=expiry_past_iso)
        )
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        denied = SubscribeDenied.model_validate(out.payload)
        assert denied.reason == "expired"

    @pytest.mark.asyncio
    async def test_idempotent_resubscribe_while_active(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
    ) -> None:
        # §7.2 row "active": re-subscribe is a no-op, still returns SubscribeAck.
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        out2 = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        ack = SubscribeAck.model_validate(out2.payload)
        assert ack.subscribed is True
        sub = seeded_owner_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_resubscribe_from_disconnected_recovers(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
        later_iso: str,
    ) -> None:
        # §7.2 row "disconnected" → "active" recovery.
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        seeded_owner_store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.DISCONNECTED,
            changed_at=later_iso,
        )
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        sub = seeded_owner_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_resubscribe_from_closed_resets_pushed_version(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
        later_iso: str,
    ) -> None:
        # §7.2 row "closed_by_receiver" → "active" with last_pushed=NULL reset.
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        seeded_owner_store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=5,
        )
        seeded_owner_store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.CLOSED_BY_RECEIVER,
            changed_at=later_iso,
        )
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        sub = seeded_owner_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.ACTIVE
        assert sub.last_pushed_object_version is None  # reset per §7.2

    @pytest.mark.asyncio
    async def test_resubscribe_from_expired_denied(
        self,
        owner_handler: ObjectInboundHandler,
        seeded_owner_store: ObjectStore,
        later_iso: str,
    ) -> None:
        # §7.2 row "expired" → SubscribeDenied(expired). The handler must
        # branch on pre-state BEFORE calling validate_transition so this
        # returns a denial wire response (not an internal-error raise).
        await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        seeded_owner_store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.EXPIRED,
            changed_at=later_iso,
        )
        out = await owner_handler.handle_subscribe(
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        denied = SubscribeDenied.model_validate(out.payload)
        assert denied.reason == "expired"


# ----------------------------------------------------------------------
# handle_unsubscribe (owner-side)
# ----------------------------------------------------------------------


class TestHandleUnsubscribe:
    @pytest.fixture
    def owner_store(self, tmp_path: Path) -> ObjectStore:
        s = ObjectStore(db_path=tmp_path / "alice.sqlite", owner_principal_id=OWNER)
        yield s
        s.close()

    @pytest.fixture
    def owner_handler(
        self,
        owner_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> ObjectInboundHandler:
        return ObjectInboundHandler(
            principal_id=OWNER, object_store=owner_store, directory=directory
        )

    @pytest.fixture
    def store_with_active_sub(
        self,
        owner_store: ObjectStore,
        owner_handler: ObjectInboundHandler,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> ObjectStore:
        owner_store.put(_build_live_object(base_state, now=now_iso))
        owner_store.record_promotion(
            _build_live_promotion(now=now_iso, expiry=expiry_future_iso)
        )
        owner_store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at=now_iso,
        )
        return owner_store

    @pytest.mark.asyncio
    async def test_happy_path_closes_subscription(
        self,
        owner_handler: ObjectInboundHandler,
        store_with_active_sub: ObjectStore,
    ) -> None:
        out = await owner_handler.handle_unsubscribe(
            payload=UnsubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        assert out.operation is Operation.UNSUBSCRIBE
        assert out.payload_schema == UNSUBSCRIBE_ACK_SCHEMA
        ack = UnsubscribeAck.model_validate(out.payload)
        assert ack.unsubscribed is True
        sub = store_with_active_sub.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.CLOSED_BY_RECEIVER

    @pytest.mark.asyncio
    async def test_no_row_denied_not_active(
        self,
        owner_handler: ObjectInboundHandler,
    ) -> None:
        out = await owner_handler.handle_unsubscribe(
            payload=UnsubscribeRequest(promotion_id="prm-never").model_dump(),
            sender_principal_id=RECEIVER,
        )
        assert out.payload_schema == UNSUBSCRIBE_DENIED_SCHEMA
        denied = UnsubscribeDenied.model_validate(out.payload)
        assert denied.reason == "not_active"

    @pytest.mark.asyncio
    async def test_idempotent_when_already_closed(
        self,
        owner_handler: ObjectInboundHandler,
        store_with_active_sub: ObjectStore,
    ) -> None:
        await owner_handler.handle_unsubscribe(
            payload=UnsubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        out2 = await owner_handler.handle_unsubscribe(
            payload=UnsubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        # §7.2 row "closed_by_receiver" → UnsubscribeAck idempotent.
        ack = UnsubscribeAck.model_validate(out2.payload)
        assert ack.unsubscribed is True

    @pytest.mark.asyncio
    async def test_expired_row_denied_expired(
        self,
        owner_handler: ObjectInboundHandler,
        store_with_active_sub: ObjectStore,
        now_iso: str,
    ) -> None:
        store_with_active_sub.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.EXPIRED,
            changed_at=now_iso,
        )
        out = await owner_handler.handle_unsubscribe(
            payload=UnsubscribeRequest(promotion_id="prm-live-1").model_dump(),
            sender_principal_id=RECEIVER,
        )
        denied = UnsubscribeDenied.model_validate(out.payload)
        assert denied.reason == "expired"


# ----------------------------------------------------------------------
# handle_object_update (receiver-side)
# ----------------------------------------------------------------------


class TestHandleObjectUpdate:
    """Bob (receiver) gets an OBJECT_UPDATE pushed by Alice (owner)."""

    @pytest.fixture
    def receiver_store(self, tmp_path: Path) -> ObjectStore:
        s = ObjectStore(db_path=tmp_path / "bob.sqlite", owner_principal_id=RECEIVER)
        yield s
        s.close()

    @pytest.fixture
    def receiver_handler(
        self,
        receiver_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> ObjectInboundHandler:
        return ObjectInboundHandler(
            principal_id=RECEIVER, object_store=receiver_store, directory=directory
        )

    def _setup_subscribed_receiver(
        self,
        store: ObjectStore,
        owner_signer: Signer,
        *,
        now_iso: str,
        expiry: str,
        state_for_hash: dict[str, Any],
    ) -> PromotionHandle:
        # Receiver stores: (a) PromotionHandle in received_handles, (b)
        # active_subscriptions row with role='receiver'.
        scoped = {k: v for k, v in state_for_hash.items()
                  if k in {"candidates", "duration_minutes"}}
        snapshot_hash = content_hash(canonical_json(scoped))
        handle = _build_signed_handle(
            signer=owner_signer,
            promotion=_build_live_promotion(now=now_iso, expiry=expiry),
            issued_at=now_iso,
            snapshot_content_hash=snapshot_hash,
        )
        store.record_received_handle(handle)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=OWNER,
            role=SubscriptionRole.RECEIVER,
            subscribed_at=now_iso,
        )
        return handle

    @pytest.mark.asyncio
    async def test_happy_path_acks_and_fires_callback(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        handle = self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=now_iso,
            expiry=expiry_future_iso,
            state_for_hash=base_state,
        )
        new_state = {"candidates": ["A", "B"], "duration_minutes": 45}
        new_hash = content_hash(canonical_json(new_state))
        callback_calls: list[tuple[str, dict[str, Any], int]] = []

        async def cb(h: PromotionHandle, state: dict[str, Any], version: int) -> None:
            callback_calls.append((h.promotion_id, state, version))

        receiver_handler.register_object_update_callback(cb)
        out = await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=2,
                snapshot_state=new_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )

        assert out.operation is Operation.OBJECT_UPDATE
        assert out.payload_schema == OBJECT_UPDATE_ACK_SCHEMA
        ack = ObjectUpdateAck.model_validate(out.payload)
        assert ack.object_version == 2
        assert ack.received is True
        # Receiver row's last_pushed bumped.
        sub = receiver_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.last_pushed_object_version == 2
        # Callback fired with the verified data.
        assert callback_calls == [("prm-live-1", new_state, 2)]

    @pytest.mark.asyncio
    async def test_unknown_handle_raises(
        self,
        receiver_handler: ObjectInboundHandler,
        base_state: dict[str, Any],
    ) -> None:
        # No handle stored at all — the owner shouldn't be pushing to us.
        # This is a hard failure (not a soft denial): no subscription
        # relationship exists. Gateway propagates the raise as a failure
        # residue.
        new_hash = content_hash(canonical_json(base_state))
        with pytest.raises(InvalidObjectUpdatePayload):
            await receiver_handler.handle_object_update(
                payload=ObjectUpdate(
                    promotion_id="prm-never",
                    object_version=1,
                    snapshot_state=base_state,
                    snapshot_content_hash=new_hash,
                ).model_dump(),
                sender_principal_id=OWNER,
            )

    @pytest.mark.asyncio
    async def test_sender_not_owner_raises(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # Eve tries to push an update for a handle Bob got from Alice —
        # forwarded-path attack. Hard failure per §7.3 (Slice 2 forbids
        # forwarded push paths, same as Slice 1 PROMOTE).
        self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=now_iso,
            expiry=expiry_future_iso,
            state_for_hash=base_state,
        )
        new_hash = content_hash(canonical_json(base_state))
        with pytest.raises(InvalidObjectUpdatePayload):
            await receiver_handler.handle_object_update(
                payload=ObjectUpdate(
                    promotion_id="prm-live-1",
                    object_version=2,
                    snapshot_state=base_state,
                    snapshot_content_hash=new_hash,
                ).model_dump(),
                sender_principal_id=EVE,
            )

    @pytest.mark.asyncio
    async def test_expired_handle_denied(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
    ) -> None:
        past_created = (datetime.now(UTC) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        past_expiry = (datetime.now(UTC) - timedelta(seconds=10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=past_created,
            expiry=past_expiry,
            state_for_hash=base_state,
        )
        new_hash = content_hash(canonical_json(base_state))
        out = await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=2,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        assert out.payload_schema == OBJECT_UPDATE_DENIED_SCHEMA
        denied = ObjectUpdateDenied.model_validate(out.payload)
        assert denied.reason == "expired"

    @pytest.mark.asyncio
    async def test_version_regression_denied(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=now_iso,
            expiry=expiry_future_iso,
            state_for_hash=base_state,
        )
        new_hash = content_hash(canonical_json(base_state))
        # First push at v3 succeeds.
        await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=3,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        # Second push at v2 (regression) — denied.
        out = await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=2,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        denied = ObjectUpdateDenied.model_validate(out.payload)
        assert denied.reason == "version_regression"
        # last_pushed stays at 3.
        sub = receiver_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.last_pushed_object_version == 3

    @pytest.mark.asyncio
    async def test_content_hash_mismatch_raises(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # Hard failure per §7.3: signature / hash mismatch raises rather
        # than denying. NOTE: the ObjectUpdate Pydantic model itself
        # rejects mismatch at construction (test_object_update_wire.py),
        # so we have to bypass model_validate to construct a malicious
        # payload. The handler recomputes from the raw payload dict.
        self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=now_iso,
            expiry=expiry_future_iso,
            state_for_hash=base_state,
        )
        malformed_payload = {
            "version": 1,
            "promotion_id": "prm-live-1",
            "object_version": 2,
            "snapshot_state": base_state,
            "snapshot_content_hash": "0" * 64,  # wrong
        }
        with pytest.raises(InvalidObjectUpdatePayload):
            await receiver_handler.handle_object_update(
                payload=malformed_payload, sender_principal_id=OWNER
            )

    @pytest.mark.asyncio
    async def test_no_subscription_row_denied(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # Receiver has the handle (PROMOTE landed) but never subscribed.
        # Owner pushing anyway is a state mismatch — soft denial so the
        # owner can transition to disconnected and back off gracefully.
        scoped = {k: v for k, v in base_state.items()
                  if k in {"candidates", "duration_minutes"}}
        snapshot_hash = content_hash(canonical_json(scoped))
        handle = _build_signed_handle(
            signer=owner_signer,
            promotion=_build_live_promotion(now=now_iso, expiry=expiry_future_iso),
            issued_at=now_iso,
            snapshot_content_hash=snapshot_hash,
        )
        receiver_store.record_received_handle(handle)
        # Note: NO record_subscription call.
        new_hash = content_hash(canonical_json(base_state))
        out = await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=2,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        denied = ObjectUpdateDenied.model_validate(out.payload)
        assert denied.reason == "expired"

    @pytest.mark.asyncio
    async def test_gap_detection_accepts_forward_jump(
        self,
        receiver_handler: ObjectInboundHandler,
        receiver_store: ObjectStore,
        owner_signer: Signer,
        base_state: dict[str, Any],
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # §8: gap-tolerant. v=5 arriving after v=2 is a forward jump
        # (the receiver missed v=3 and v=4 to a transient drop). Push is
        # processed; last_pushed advances to 5.
        self._setup_subscribed_receiver(
            receiver_store,
            owner_signer,
            now_iso=now_iso,
            expiry=expiry_future_iso,
            state_for_hash=base_state,
        )
        new_hash = content_hash(canonical_json(base_state))
        await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=2,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        await receiver_handler.handle_object_update(
            payload=ObjectUpdate(
                promotion_id="prm-live-1",
                object_version=5,
                snapshot_state=base_state,
                snapshot_content_hash=new_hash,
            ).model_dump(),
            sender_principal_id=OWNER,
        )
        sub = receiver_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.last_pushed_object_version == 5
