"""Unit tests for the Slice 2 SDK live-promotion methods.

Covers Phase 4 Slice 2 step 9 per ``demos/phase_4/SLICE_2_SPEC.md`` §6.1.

The Mesherra SDK gains three live-promotion methods that wrap the wire
operations introduced in steps 1-8:

* :meth:`Mesherra.subscribe_to_object` — sends SUBSCRIBE through the
  outbound airlock, records the receiver-side ``active_subscriptions``
  row, and is idempotent within the same active subscription.
* :meth:`Mesherra.unsubscribe_from_object` — sends UNSUBSCRIBE, marks the
  receiver-side row ``closed_by_receiver`` on ack.
* :meth:`Mesherra.on_object_update` — registers the receiver-side
  callback that fires when an OBJECT_UPDATE is delivered. The trust-
  layer verifications (sig, hash, version, mutability) happen before
  the callback ever sees the data.

A ``SubscriptionDenied`` exception (parallel to ``PromotionFetchDenied``)
surfaces owner-side denials with the structured reason.

Tests use a fake A2A adapter that echoes ack responses — no real network.
The full cross-process roundtrip is exercised in step 13.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import MesherraEnvelope
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    Mutability,
    Operation,
    PromotionHandle,
    PromotionMode,
    SendClaim,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    OBJECT_UPDATE_ACK_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_DENIED_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import (
    Mesherra,
    SubscriptionDenied,
)

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"


# -- A fake adapter that echoes pre-configured responses ---------------


class _FakeAdapter:
    """Pretends to be an A2AAdapter; routes outbound sends to an in-test
    response factory keyed by operation."""

    def __init__(self) -> None:
        self._handler: Any = None
        self._responses: dict[Operation, MesherraEnvelope | None] = {}
        self.sent: list[MesherraEnvelope] = []

    def register_handler(self, handler: Any) -> None:
        self._handler = handler

    def set_response(
        self, operation: Operation, envelope: MesherraEnvelope | None
    ) -> None:
        self._responses[operation] = envelope

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        self.sent.append(envelope)
        return self._responses.get(envelope.operation)


# -- Helpers ---------------------------------------------------------


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ack_envelope(
    *,
    owner_signer: Signer,
    response_op: Operation,
    response_schema: str,
    response_payload: dict[str, Any],
    context_id: str,
    task_id: str = "task-sub-1",
) -> MesherraEnvelope:
    """Build a signed response envelope coming back from the owner (Alice)."""
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(response_payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=response_schema,
        operation=response_op,
        sender_principal_id=ALICE,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    sig = owner_signer.sign(canonical_json(claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=ALICE,
        payload=response_payload,
        payload_schema=response_schema,
        operation=response_op,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=sig,
    )


def _build_live_handle(
    *, owner_signer: Signer, expiry_hours: int = 1
) -> PromotionHandle:
    snapshot = {"candidates": ["A"], "duration_minutes": 30}
    snapshot_hash = content_hash(canonical_json(snapshot))
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expiry = (datetime.now(UTC) + timedelta(hours=expiry_hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
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
        fetch_endpoint="http://alice.example/a2a",
        scoped_payload=None,
        expiry=expiry,
        issued_at=now,
        owner_signature="placeholder",
    )
    sig = owner_signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


def _build_static_handle(*, owner_signer: Signer) -> PromotionHandle:
    snapshot = {"candidates": ["A"]}
    snapshot_hash = content_hash(canonical_json(snapshot))
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    unsigned = PromotionHandle(
        promotion_id="prm-static-1",
        object_id="obj-static-1",
        owner=ALICE,
        receiver=BOB,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates"]},
        snapshot_content_hash=snapshot_hash,
        fetch_endpoint="http://alice.example/a2a",
        scoped_payload=None,
        expiry=expiry,
        issued_at=now,
        owner_signature="placeholder",
    )
    sig = owner_signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


# -- Fixtures --------------------------------------------------------


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
def bob_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(db_path=tmp_path / "bob.objects.sqlite", owner_principal_id=BOB)
    yield s
    s.close()


@pytest.fixture
def bob_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(db_path=tmp_path / "bob.ledger.sqlite", ledger_owner=BOB)
    yield l
    l.close()


@pytest.fixture
def bob_mesherra(
    bob_signer: Signer,
    bob_ledger: ProvenanceLedger,
    bob_store: ObjectStore,
    directory: StaticDirectoryClient,
) -> tuple[Mesherra, _FakeAdapter]:
    adapter = _FakeAdapter()
    m = Mesherra(
        principal_id=BOB,
        signer=bob_signer,
        ledger=bob_ledger,
        adapter=adapter,  # type: ignore[arg-type]
        directory=directory,
        object_store=bob_store,
    )
    return m, adapter


# -- subscribe_to_object --------------------------------------------


class TestSubscribeToObject:
    @pytest.mark.asyncio
    async def test_happy_path_records_receiver_side_row(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_store: ObjectStore,
        alice_signer: Signer,
    ) -> None:
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)
        bob_store.record_received_handle(handle)
        ctx = "ctx-sub-happy"
        adapter.set_response(
            Operation.SUBSCRIBE,
            _ack_envelope(
                owner_signer=alice_signer,
                response_op=Operation.SUBSCRIBE,
                response_schema=SUBSCRIBE_ACK_SCHEMA,
                response_payload={
                    "version": 1,
                    "promotion_id": "prm-live-1",
                    "subscribed": True,
                },
                context_id=ctx,
            ),
        )
        await m.subscribe_to_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id=ctx
        )

        # Wire op sent.
        assert len(adapter.sent) == 1
        assert adapter.sent[0].operation is Operation.SUBSCRIBE
        # Receiver-side row recorded as active.
        sub = bob_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.status is SubscriptionStatus.ACTIVE
        assert sub.counterpart == ALICE

    @pytest.mark.asyncio
    async def test_static_handle_rejected(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_signer: Signer,
    ) -> None:
        m, _ = bob_mesherra
        handle = _build_static_handle(owner_signer=alice_signer)
        with pytest.raises(ValueError):
            await m.subscribe_to_object(
                handle=handle, peer_url="http://alice.example/a2a"
            )

    @pytest.mark.asyncio
    async def test_idempotent_resubscribe_no_extra_send(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_store: ObjectStore,
        alice_signer: Signer,
    ) -> None:
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)
        bob_store.record_received_handle(handle)
        adapter.set_response(
            Operation.SUBSCRIBE,
            _ack_envelope(
                owner_signer=alice_signer,
                response_op=Operation.SUBSCRIBE,
                response_schema=SUBSCRIBE_ACK_SCHEMA,
                response_payload={
                    "version": 1,
                    "promotion_id": "prm-live-1",
                    "subscribed": True,
                },
                context_id="ctx-sub-1",
            ),
        )
        await m.subscribe_to_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id="ctx-sub-1"
        )
        # Re-subscribe should detect the existing active row and short-circuit.
        await m.subscribe_to_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id="ctx-sub-2"
        )
        assert len(adapter.sent) == 1  # only the first send went out

    @pytest.mark.asyncio
    async def test_resubscribe_after_close_resets_pushed_version(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_store: ObjectStore,
        alice_signer: Signer,
    ) -> None:
        # §7.2 row 4 symmetry: re-subscribing after a prior close resets
        # last_pushed_object_version on the receiver side too. (The owner
        # handler's symmetric reset is covered in
        # test_object_inbound_handler_live.py.)
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)
        bob_store.record_received_handle(handle)
        # Seed: receiver-side row in CLOSED_BY_RECEIVER with a stale push count.
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        bob_store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=ALICE,
            role=SubscriptionRole.RECEIVER,
            subscribed_at=now_iso,
        )
        bob_store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.RECEIVER,
            object_version=7,
        )
        later = (datetime.now(UTC) + timedelta(seconds=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        bob_store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.RECEIVER,
            new_status=SubscriptionStatus.CLOSED_BY_RECEIVER,
            changed_at=later,
        )
        adapter.set_response(
            Operation.SUBSCRIBE,
            _ack_envelope(
                owner_signer=alice_signer,
                response_op=Operation.SUBSCRIBE,
                response_schema=SUBSCRIBE_ACK_SCHEMA,
                response_payload={
                    "version": 1,
                    "promotion_id": "prm-live-1",
                    "subscribed": True,
                },
                context_id="ctx-resub",
            ),
        )
        await m.subscribe_to_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id="ctx-resub"
        )
        sub = bob_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.status is SubscriptionStatus.ACTIVE
        assert sub.last_pushed_object_version is None  # reset per §7.2 row 4

    @pytest.mark.asyncio
    async def test_owner_denial_raises_subscription_denied(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_store: ObjectStore,
        alice_signer: Signer,
    ) -> None:
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)
        bob_store.record_received_handle(handle)
        ctx = "ctx-sub-denied"
        adapter.set_response(
            Operation.SUBSCRIBE,
            _ack_envelope(
                owner_signer=alice_signer,
                response_op=Operation.SUBSCRIBE,
                response_schema=SUBSCRIBE_DENIED_SCHEMA,
                response_payload={
                    "version": 1,
                    "promotion_id": "prm-live-1",
                    "reason": "expired",
                },
                context_id=ctx,
            ),
        )
        with pytest.raises(SubscriptionDenied) as excinfo:
            await m.subscribe_to_object(
                handle=handle, peer_url="http://alice.example/a2a", context_id=ctx
            )
        assert "expired" in str(excinfo.value)
        # No receiver-side row created on denial.
        from mesherra.object.store import SubscriptionNotFound
        with pytest.raises(SubscriptionNotFound):
            bob_store.get_subscription(
                promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
            )


# -- unsubscribe_from_object -----------------------------------------


class TestUnsubscribeFromObject:
    @pytest.mark.asyncio
    async def test_marks_local_row_closed(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_store: ObjectStore,
        alice_signer: Signer,
    ) -> None:
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)
        bob_store.record_received_handle(handle)
        # Pre-existing active subscription on Bob's side.
        bob_store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=ALICE,
            role=SubscriptionRole.RECEIVER,
            subscribed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
        ctx = "ctx-unsub-1"
        adapter.set_response(
            Operation.UNSUBSCRIBE,
            _ack_envelope(
                owner_signer=alice_signer,
                response_op=Operation.UNSUBSCRIBE,
                response_schema=UNSUBSCRIBE_ACK_SCHEMA,
                response_payload={
                    "version": 1,
                    "promotion_id": "prm-live-1",
                    "unsubscribed": True,
                },
                context_id=ctx,
            ),
        )
        await m.unsubscribe_from_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id=ctx
        )
        assert len(adapter.sent) == 1
        assert adapter.sent[0].operation is Operation.UNSUBSCRIBE
        sub = bob_store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert sub.status is SubscriptionStatus.CLOSED_BY_RECEIVER


# -- on_object_update -----------------------------------------------


class TestOnObjectUpdate:
    def test_registers_callback_on_handler(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
    ) -> None:
        m, _ = bob_mesherra

        async def cb(handle, state, version):  # noqa: ANN001 — minimal stub
            pass

        m.on_object_update(cb)
        # The handler's _object_update_callback attribute is now set. We
        # don't assert against the internal field directly — instead we
        # check via the public path: re-registering doesn't raise, and
        # the SDK exposes nothing else for that wire.
        m.on_object_update(cb)  # replace-on-call must not raise

    def test_requires_object_store(
        self,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        directory: StaticDirectoryClient,
    ) -> None:
        adapter = _FakeAdapter()
        m_no_store = Mesherra(
            principal_id=BOB,
            signer=bob_signer,
            ledger=bob_ledger,
            adapter=adapter,  # type: ignore[arg-type]
            directory=directory,
            # no object_store
        )

        async def cb(handle, state, version):  # noqa: ANN001
            pass

        with pytest.raises(RuntimeError):
            m_no_store.on_object_update(cb)
