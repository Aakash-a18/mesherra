"""Integration tests for InboundGateway → ObjectInboundHandler dispatch.

These tests prove that Phase 4 trust-layer operations (PROMOTE, FETCH)
flow through the InboundGateway to the ObjectInboundHandler instead of
the consumer handler. The consumer must NEVER see PROMOTE/FETCH (those
are Mesherra-internal protocol, not domain logic), and the trust-layer
ops still produce paired Residue entries identical in shape to Phase 1
operations.

Companion negative cases:
- Phase 4 op without an object_handler wired raises a clear error
  (catches the misconfiguration immediately).
- Response-only operations (FETCH_RESPONSE, FETCH_DENIED) arriving as
  an unsolicited inbound message are rejected — these only ever exist
  as the response to our own send, never as an incoming primary
  message.
- Existing Phase 1 operations still reach the consumer unchanged.
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
    UnsolicitedTrustOperation,
    TrustLayerHandlerNotWired,
)
from mesherra.gateways.replay import ReplayProtector
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    ActionType,
    LayerKind,
    Mutability,
    Object,
    Operation,
    Promotion,
    PromotionHandle,
    PromotionMode,
    SendClaim,
)
from mesherra.object.handler import ObjectInboundHandler
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_REQUEST_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    PROMOTION_ACK_SCHEMA,
    FetchRequest,
)
from mesherra.provenance.ledger import ProvenanceLedger


ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"
EVE = "eve@phase4.local"


# -- Helpers --------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _wire_now_iso() -> str:
    """Seconds-precision form used by the existing gateway timestamps."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign_envelope(
    *,
    signer: Signer,
    sender: str,
    payload: dict[str, Any],
    payload_schema: str,
    operation: Operation,
    context_id: str = "ctx-phase4-dispatch",
    task_id: str = "",
    timestamp: str | None = None,
    nonce: str | None = None,
) -> MesherraEnvelope:
    timestamp = timestamp or _wire_now_iso()
    nonce = nonce or str(uuid.uuid4())
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


def _sign_handle(
    *,
    signer: Signer,
    promotion_id: str = "prom-disp-1",
    object_id: str = "obj-disp-1",
    owner: str = ALICE,
    receiver: str = BOB,
    snapshot_state: dict[str, Any] | None = None,
    expiry: str | None = None,
) -> PromotionHandle:
    snapshot_state = snapshot_state or {"candidates": ["A", "B"]}
    snapshot_hash = content_hash(canonical_json(snapshot_state))
    unsigned = PromotionHandle(
        promotion_id=promotion_id,
        object_id=object_id,
        owner=owner,
        receiver=receiver,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": list(snapshot_state.keys())},
        snapshot_content_hash=snapshot_hash,
        fetch_endpoint="http://owner.example/a2a",
        scoped_payload=None,
        expiry=expiry or _future_iso(),
        issued_at=_now_iso(),
        owner_signature="placeholder",
    )
    sig = signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


def _seed_alice_promotion(
    store: ObjectStore,
    *,
    promotion_id: str = "prom-disp-1",
    receiver: str = BOB,
    expiry: str | None = None,
) -> Promotion:
    now = _now_iso()
    obj = Object(
        object_id="obj-disp-1",
        owner=ALICE,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.STATIC,
        schema_ref="meshycal.scheduling/calendar-v1",
        state={"candidates": ["A", "B"], "not_in_scope_field": "hidden"},
        object_version=1,
        created_at=now,
        updated_at=now,
    )
    store.put(obj)
    promotion = Promotion(
        promotion_id=promotion_id,
        object_id=obj.object_id,
        owner=ALICE,
        receiver=receiver,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates"]},
        expiry=expiry or _future_iso(),
        snapshot_state={"candidates": ["A", "B"]},
        fetch_endpoint="http://owner.example/a2a",
        created_at=now,
    )
    store.record_promotion(promotion)
    return promotion


# -- Fixtures -------------------------------------------------------


@pytest.fixture
def alice_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def bob_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def directory(
    alice_signer: Signer, bob_signer: Signer
) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {
            ALICE: alice_signer.public_key_b64(),
            BOB: bob_signer.public_key_b64(),
        }
    )


@pytest.fixture
def bob_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(db_path=tmp_path / "bob-objects.sqlite", owner_principal_id=BOB)
    yield s
    s.close()


@pytest.fixture
def alice_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(
        db_path=tmp_path / "alice-objects.sqlite", owner_principal_id=ALICE
    )
    yield s
    s.close()


@pytest.fixture
def bob_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(db_path=tmp_path / "bob-ledger.sqlite", ledger_owner=BOB)
    yield l
    l.close()


@pytest.fixture
def alice_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(
        db_path=tmp_path / "alice-ledger.sqlite", ledger_owner=ALICE
    )
    yield l
    l.close()


def _build_bob_inbound(
    *,
    bob_signer: Signer,
    bob_ledger: ProvenanceLedger,
    directory: StaticDirectoryClient,
    object_handler: ObjectInboundHandler | None,
) -> InboundGateway:
    g = InboundGateway(
        principal_id=BOB,
        signer=bob_signer,
        ledger=bob_ledger,
        directory=directory,
        replay_protector=ReplayProtector(clock_skew_seconds=3600),
        object_handler=object_handler,
    )

    async def consumer(_msg: IncomingMessage) -> OutgoingResponse | None:
        # Consumer is wired but should NOT be called for trust-layer ops.
        # If it ever is, we surface that by raising — the test asserts no
        # consumer call by counting calls.
        raise AssertionError(
            f"Consumer was called for op {_msg.operation!r}; trust-layer "
            "operations must NOT reach the consumer."
        )

    g.register_consumer(consumer)
    return g


def _build_alice_inbound(
    *,
    alice_signer: Signer,
    alice_ledger: ProvenanceLedger,
    directory: StaticDirectoryClient,
    object_handler: ObjectInboundHandler | None,
) -> InboundGateway:
    g = InboundGateway(
        principal_id=ALICE,
        signer=alice_signer,
        ledger=alice_ledger,
        directory=directory,
        replay_protector=ReplayProtector(clock_skew_seconds=3600),
        object_handler=object_handler,
    )

    async def consumer(_msg: IncomingMessage) -> OutgoingResponse | None:
        raise AssertionError(
            f"Consumer was called for op {_msg.operation!r}; trust-layer "
            "operations must NOT reach the consumer."
        )

    g.register_consumer(consumer)
    return g


# -- PROMOTE dispatch -------------------------------------------------


class TestPromoteDispatch:
    async def test_promote_persists_handle_consumer_not_called(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        handler = ObjectInboundHandler(
            principal_id=BOB, object_store=bob_store, directory=directory
        )
        gateway = _build_bob_inbound(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            directory=directory,
            object_handler=handler,
        )
        signed = _sign_handle(signer=alice_signer)
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload=signed.model_dump(),
            payload_schema="mesherra.object/promotion-handle-v1",
            operation=Operation.PROMOTE,
            task_id="task-promote-1",
        )
        resp_env = await gateway.handle_inbound(env)
        assert resp_env is not None
        assert resp_env.operation is Operation.PROMOTE
        assert resp_env.payload_schema == PROMOTION_ACK_SCHEMA
        # Handle landed in bob's store
        stored = bob_store.get_received_handle(signed.promotion_id)
        assert stored == signed

    async def test_promote_writes_paired_residues(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        handler = ObjectInboundHandler(
            principal_id=BOB, object_store=bob_store, directory=directory
        )
        gateway = _build_bob_inbound(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            directory=directory,
            object_handler=handler,
        )
        signed = _sign_handle(signer=alice_signer)
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload=signed.model_dump(),
            payload_schema="mesherra.object/promotion-handle-v1",
            operation=Operation.PROMOTE,
            task_id="task-promote-2",
        )
        await gateway.handle_inbound(env)
        entries = bob_ledger.get_by_task("task-promote-2")
        # Expect: RECEIVE promote (incoming) + EMIT promote (ack response)
        ops_by_action = [(e.action_type, e.operation) for e in entries]
        assert (ActionType.RECEIVE, Operation.PROMOTE) in ops_by_action
        assert (ActionType.EMIT, Operation.PROMOTE) in ops_by_action


# -- FETCH dispatch ---------------------------------------------------


class TestFetchDispatch:
    async def test_fetch_returns_response(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        alice_ledger: ProvenanceLedger,
        alice_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        _seed_alice_promotion(alice_store)
        handler = ObjectInboundHandler(
            principal_id=ALICE, object_store=alice_store, directory=directory
        )
        gateway = _build_alice_inbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            object_handler=handler,
        )
        req = FetchRequest(promotion_id="prom-disp-1", fetch_sequence=1)
        env = _sign_envelope(
            signer=bob_signer,
            sender=BOB,
            payload=req.model_dump(),
            payload_schema=FETCH_REQUEST_SCHEMA,
            operation=Operation.FETCH,
            task_id="task-fetch-1",
        )
        resp_env = await gateway.handle_inbound(env)
        assert resp_env is not None
        assert resp_env.operation is Operation.FETCH_RESPONSE
        assert resp_env.payload_schema == FETCH_RESPONSE_SCHEMA

    async def test_fetch_from_wrong_receiver_returns_denied(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        alice_ledger: ProvenanceLedger,
        alice_store: ObjectStore,
    ) -> None:
        # Eve attempts the fetch; she's not the promotion's receiver.
        eve_signer = Signer.generate()
        directory = StaticDirectoryClient(
            {
                ALICE: alice_signer.public_key_b64(),
                BOB: bob_signer.public_key_b64(),
                EVE: eve_signer.public_key_b64(),
            }
        )
        _seed_alice_promotion(alice_store)
        handler = ObjectInboundHandler(
            principal_id=ALICE, object_store=alice_store, directory=directory
        )
        gateway = _build_alice_inbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            object_handler=handler,
        )
        req = FetchRequest(promotion_id="prom-disp-1", fetch_sequence=1)
        env = _sign_envelope(
            signer=eve_signer,
            sender=EVE,
            payload=req.model_dump(),
            payload_schema=FETCH_REQUEST_SCHEMA,
            operation=Operation.FETCH,
            task_id="task-fetch-eve",
        )
        resp_env = await gateway.handle_inbound(env)
        assert resp_env is not None
        assert resp_env.operation is Operation.FETCH_DENIED
        assert resp_env.payload_schema == FETCH_DENIED_SCHEMA


# -- Negative paths ---------------------------------------------------


class TestNegativeDispatch:
    async def test_phase1_operation_still_dispatches_to_consumer(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        directory: StaticDirectoryClient,
    ) -> None:
        consumer_calls: list[Operation] = []

        gateway = InboundGateway(
            principal_id=BOB,
            signer=bob_signer,
            ledger=bob_ledger,
            directory=directory,
            replay_protector=ReplayProtector(clock_skew_seconds=3600),
            # No object_handler — Phase 1 path doesn't need it.
        )

        async def consumer(msg: IncomingMessage) -> OutgoingResponse | None:
            consumer_calls.append(msg.operation)
            return OutgoingResponse(
                payload={"counter": True}, operation=Operation.COUNTER
            )

        gateway.register_consumer(consumer)
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload={"candidates": ["X"]},
            payload_schema="meshycal.scheduling/proposal-v1",
            operation=Operation.PROPOSAL,
            task_id="task-phase1-1",
        )
        await gateway.handle_inbound(env)
        assert consumer_calls == [Operation.PROPOSAL]

    async def test_phase4_op_without_handler_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        directory: StaticDirectoryClient,
    ) -> None:
        # Misconfiguration: PROMOTE arrives but no object_handler wired.
        gateway = InboundGateway(
            principal_id=BOB,
            signer=bob_signer,
            ledger=bob_ledger,
            directory=directory,
            replay_protector=ReplayProtector(clock_skew_seconds=3600),
        )

        async def consumer(_msg: IncomingMessage) -> OutgoingResponse | None:
            raise AssertionError("Should not be called")

        gateway.register_consumer(consumer)
        signed = _sign_handle(signer=alice_signer)
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload=signed.model_dump(),
            payload_schema="mesherra.object/promotion-handle-v1",
            operation=Operation.PROMOTE,
            task_id="task-promote-noh",
        )
        with pytest.raises(TrustLayerHandlerNotWired):
            await gateway.handle_inbound(env)

    async def test_unsolicited_fetch_response_rejected(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        # FETCH_RESPONSE only exists as a response to our own FETCH.
        # Arriving as a primary message is a wire-protocol violation.
        handler = ObjectInboundHandler(
            principal_id=BOB, object_store=bob_store, directory=directory
        )
        gateway = _build_bob_inbound(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            directory=directory,
            object_handler=handler,
        )
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload={
                "version": 1,
                "promotion_id": "x",
                "fetch_sequence": 1,
                "snapshot_state": {},
                "snapshot_content_hash": "0" * 64,
            },
            payload_schema=FETCH_RESPONSE_SCHEMA,
            operation=Operation.FETCH_RESPONSE,
            task_id="task-unsolicited-fr",
        )
        with pytest.raises(UnsolicitedTrustOperation):
            await gateway.handle_inbound(env)

    async def test_unsolicited_fetch_denied_rejected(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        handler = ObjectInboundHandler(
            principal_id=BOB, object_store=bob_store, directory=directory
        )
        gateway = _build_bob_inbound(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            directory=directory,
            object_handler=handler,
        )
        env = _sign_envelope(
            signer=alice_signer,
            sender=ALICE,
            payload={
                "version": 1,
                "promotion_id": "x",
                "fetch_sequence": 1,
                "reason": "expired",
            },
            payload_schema=FETCH_DENIED_SCHEMA,
            operation=Operation.FETCH_DENIED,
            task_id="task-unsolicited-fd",
        )
        with pytest.raises(UnsolicitedTrustOperation):
            await gateway.handle_inbound(env)
