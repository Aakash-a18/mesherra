"""Integration tests for the Slice 2 InboundGateway dispatch wiring.

Covers Phase 4 Slice 2 step 7 per ``demos/phase_4/SLICE_2_SPEC.md`` §3
(Operation enum extension dispatch note) and the §7.2 / §7.3 handler
contracts.

Three new trust operations — SUBSCRIBE, UNSUBSCRIBE, OBJECT_UPDATE —
must route through the InboundGateway to the ObjectInboundHandler
*before* the consumer. The consumer never sees them; they are part of
Mesherra's wire protocol, not domain logic. Same shape and discipline
as Slice 1's PROMOTE / FETCH dispatch (covered in
``test_gateway_phase4_dispatch.py``).

What's verified here:

- SUBSCRIBE envelope → ``handle_subscribe`` → SubscribeAck response;
  consumer NEVER called.
- UNSUBSCRIBE envelope → ``handle_unsubscribe`` → UnsubscribeAck.
- OBJECT_UPDATE envelope → ``handle_object_update`` → ObjectUpdateAck.
- The three new ops do not collide with the existing Slice 1
  PROMOTE/FETCH dispatch.
- TrustLayerHandlerNotWired raised when a Slice 2 op arrives but the
  ObjectInboundHandler was not wired (catches misconfiguration the
  same way it does for Slice 1).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import MesherraEnvelope
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.inbound import (
    InboundGateway,
    IncomingMessage,
    OutgoingResponse,
    TrustLayerHandlerNotWired,
)
from mesherra.gateways.replay import ReplayProtector
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    LayerKind,
    Mutability,
    Object,
    Operation,
    Promotion,
    PromotionHandle,
    PromotionMode,
    SendClaim,
    SubscriptionRole,
)
from mesherra.object.handler import ObjectInboundHandler
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_REQUEST_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_REQUEST_SCHEMA,
    ObjectUpdate,
    ObjectUpdateAck,
    SubscribeAck,
    SubscribeRequest,
    UnsubscribeAck,
    UnsubscribeRequest,
)
from mesherra.provenance.ledger import ProvenanceLedger

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"


# -- Helpers -------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign_envelope(
    *,
    signer: Signer,
    sender: str,
    payload: dict[str, Any],
    payload_schema: str,
    operation: Operation,
    context_id: str = "ctx-phase4-live",
    task_id: str = "task-default",
) -> MesherraEnvelope:
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=payload_schema,
        operation=operation,
        sender_principal_id=sender,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    sig = signer.sign(canonical_json(claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=sender,
        payload=payload,
        payload_schema=payload_schema,
        operation=operation,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=sig,
    )


def _seed_live_promotion(store: ObjectStore) -> Promotion:
    now = _now_iso()
    obj = Object(
        object_id="obj-live-1",
        owner=ALICE,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.LIVE,
        schema_ref="meshycal.scheduling/calendar-v1",
        state={"candidates": ["A"], "duration_minutes": 30},
        object_version=1,
        created_at=now,
        updated_at=now,
    )
    store.put(obj)
    promotion = Promotion(
        promotion_id="prm-live-1",
        object_id=obj.object_id,
        owner=ALICE,
        receiver=BOB,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.LIVE,
        scope={"fields": ["candidates", "duration_minutes"]},
        expiry=_future_iso(),
        snapshot_state=None,
        fetch_endpoint="http://owner.example/a2a",
        created_at=now,
    )
    store.record_promotion(promotion)
    return promotion


def _sign_live_handle(*, signer: Signer) -> PromotionHandle:
    snapshot = {"candidates": ["A"], "duration_minutes": 30}
    snapshot_hash = content_hash(canonical_json(snapshot))
    unsigned = PromotionHandle(
        promotion_id="prm-live-1",
        object_id="obj-live-1",
        owner=ALICE,
        receiver=BOB,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.LIVE,
        scope={"fields": ["candidates", "duration_minutes"]},
        snapshot_content_hash=snapshot_hash,
        fetch_endpoint="http://owner.example/a2a",
        scoped_payload=None,
        expiry=_future_iso(),
        issued_at=_now_iso(),
        owner_signature="placeholder",
    )
    sig = signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


# -- Fixtures -----------------------------------------------------


@pytest.fixture
def alice_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def bob_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def directory(alice_signer: Signer, bob_signer: Signer) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {ALICE: alice_signer.public_key_b64(), BOB: bob_signer.public_key_b64()}
    )


@pytest.fixture
def alice_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(db_path=tmp_path / "alice-objects.sqlite", owner_principal_id=ALICE)
    yield s
    s.close()


@pytest.fixture
def bob_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(db_path=tmp_path / "bob-objects.sqlite", owner_principal_id=BOB)
    yield s
    s.close()


@pytest.fixture
def alice_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(db_path=tmp_path / "alice-ledger.sqlite", ledger_owner=ALICE)
    yield l
    l.close()


@pytest.fixture
def bob_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(db_path=tmp_path / "bob-ledger.sqlite", ledger_owner=BOB)
    yield l
    l.close()


def _build_inbound(
    *,
    principal: str,
    signer: Signer,
    ledger: ProvenanceLedger,
    directory: StaticDirectoryClient,
    object_handler: ObjectInboundHandler | None,
) -> tuple[InboundGateway, list[Operation]]:
    """Build an InboundGateway and a list-of-consumer-calls tracker.

    The list is shared with the consumer closure so tests can assert
    that the consumer was NEVER called for trust-layer ops.
    """
    consumer_calls: list[Operation] = []

    async def consumer(msg: IncomingMessage) -> OutgoingResponse | None:
        consumer_calls.append(msg.operation)
        return None

    gateway = InboundGateway(
        principal_id=principal,
        signer=signer,
        ledger=ledger,
        directory=directory,
        replay_protector=ReplayProtector(clock_skew_seconds=3600),
        object_handler=object_handler,
    )
    gateway.register_consumer(consumer)
    return gateway, consumer_calls


# -- SUBSCRIBE dispatch -----------------------------------------


class TestSubscribeDispatch:
    @pytest.mark.asyncio
    async def test_routes_to_handler_consumer_never_called(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        alice_ledger: ProvenanceLedger,
        alice_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        _seed_live_promotion(alice_store)
        handler = ObjectInboundHandler(
            principal_id=ALICE, object_store=alice_store, directory=directory
        )
        gateway, consumer_calls = _build_inbound(
            principal=ALICE,
            signer=alice_signer,
            ledger=alice_ledger,
            directory=directory,
            object_handler=handler,
        )

        req = SubscribeRequest(promotion_id="prm-live-1")
        envelope = _sign_envelope(
            signer=bob_signer,
            sender=BOB,
            payload=req.model_dump(),
            payload_schema=SUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.SUBSCRIBE,
        )
        response = await gateway.handle_inbound(envelope)
        assert response is not None
        assert response.operation is Operation.SUBSCRIBE
        assert response.payload_schema == SUBSCRIBE_ACK_SCHEMA
        ack = SubscribeAck.model_validate(response.payload)
        assert ack.subscribed is True
        # The consumer must not have seen this op.
        assert consumer_calls == []
        # The owner-side row was persisted by the handler.
        sub = alice_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.counterpart == BOB

    @pytest.mark.asyncio
    async def test_subscribe_without_handler_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        alice_ledger: ProvenanceLedger,
        directory: StaticDirectoryClient,
    ) -> None:
        gateway, _ = _build_inbound(
            principal=ALICE,
            signer=alice_signer,
            ledger=alice_ledger,
            directory=directory,
            object_handler=None,  # not wired
        )
        envelope = _sign_envelope(
            signer=bob_signer,
            sender=BOB,
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            payload_schema=SUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.SUBSCRIBE,
        )
        with pytest.raises(TrustLayerHandlerNotWired):
            await gateway.handle_inbound(envelope)


# -- UNSUBSCRIBE dispatch ---------------------------------------


class TestUnsubscribeDispatch:
    @pytest.mark.asyncio
    async def test_routes_to_handler(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        alice_ledger: ProvenanceLedger,
        alice_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        _seed_live_promotion(alice_store)
        handler = ObjectInboundHandler(
            principal_id=ALICE, object_store=alice_store, directory=directory
        )
        gateway, consumer_calls = _build_inbound(
            principal=ALICE,
            signer=alice_signer,
            ledger=alice_ledger,
            directory=directory,
            object_handler=handler,
        )

        # Subscribe first so there's a row to unsubscribe.
        sub_env = _sign_envelope(
            signer=bob_signer,
            sender=BOB,
            payload=SubscribeRequest(promotion_id="prm-live-1").model_dump(),
            payload_schema=SUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.SUBSCRIBE,
            context_id="ctx-sub",
        )
        await gateway.handle_inbound(sub_env)

        # Now unsubscribe.
        unsub_env = _sign_envelope(
            signer=bob_signer,
            sender=BOB,
            payload=UnsubscribeRequest(promotion_id="prm-live-1").model_dump(),
            payload_schema=UNSUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.UNSUBSCRIBE,
            context_id="ctx-unsub",
        )
        response = await gateway.handle_inbound(unsub_env)
        assert response is not None
        assert response.operation is Operation.UNSUBSCRIBE
        assert response.payload_schema == UNSUBSCRIBE_ACK_SCHEMA
        ack = UnsubscribeAck.model_validate(response.payload)
        assert ack.unsubscribed is True
        assert consumer_calls == []


# -- OBJECT_UPDATE dispatch ------------------------------------


class TestObjectUpdateDispatch:
    @pytest.mark.asyncio
    async def test_routes_to_handler(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        # Bob is the receiver; the OBJECT_UPDATE arrives at his gateway.
        # Seed his received_handles and active_subscriptions.
        handle = _sign_live_handle(signer=alice_signer)
        bob_store.record_received_handle(handle)
        bob_store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=ALICE,
            role=SubscriptionRole.RECEIVER,
            subscribed_at=_now_iso(),
        )

        handler = ObjectInboundHandler(
            principal_id=BOB, object_store=bob_store, directory=directory
        )
        gateway, consumer_calls = _build_inbound(
            principal=BOB,
            signer=bob_signer,
            ledger=bob_ledger,
            directory=directory,
            object_handler=handler,
        )

        new_state = {"candidates": ["A", "B"], "duration_minutes": 45}
        update = ObjectUpdate(
            promotion_id="prm-live-1",
            object_version=2,
            snapshot_state=new_state,
        )
        envelope = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload=update.model_dump(),
            payload_schema=OBJECT_UPDATE_SCHEMA,
            operation=Operation.OBJECT_UPDATE,
        )
        response = await gateway.handle_inbound(envelope)
        assert response is not None
        assert response.operation is Operation.OBJECT_UPDATE
        assert response.payload_schema == OBJECT_UPDATE_ACK_SCHEMA
        ack = ObjectUpdateAck.model_validate(response.payload)
        assert ack.object_version == 2
        assert consumer_calls == []
        sub = bob_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.last_pushed_object_version == 2

    @pytest.mark.asyncio
    async def test_object_update_without_handler_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        directory: StaticDirectoryClient,
    ) -> None:
        gateway, _ = _build_inbound(
            principal=BOB,
            signer=bob_signer,
            ledger=bob_ledger,
            directory=directory,
            object_handler=None,
        )
        update = ObjectUpdate(
            promotion_id="prm-live-1",
            object_version=2,
            snapshot_state={"candidates": ["A"]},
        )
        envelope = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload=update.model_dump(),
            payload_schema=OBJECT_UPDATE_SCHEMA,
            operation=Operation.OBJECT_UPDATE,
        )
        with pytest.raises(TrustLayerHandlerNotWired):
            await gateway.handle_inbound(envelope)
