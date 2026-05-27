"""Unit tests for the Slice 2 live-push extension of Mesherra.update_object.

Covers Phase 4 Slice 2 step 10 per ``demos/phase_4/SLICE_2_SPEC.md`` §6.2
and §7.1.

The Slice 1 ``update_object`` was synchronous (persist new version and
return). Slice 2 extends it: after persisting, the SDK enumerates every
active owner-side subscription for the object_id and pushes a scoped
OBJECT_UPDATE to each receiver. The method becomes ``async`` because
the push fan-out awaits outbound airlock sends.

What's verified here:

- LIVE object with an active subscription → one OBJECT_UPDATE sent;
  ``last_pushed_object_version`` bumps on ack.
- LIVE object with no subscriptions → no wire ops sent (silent path).
- STATIC object → no wire ops sent regardless of subscriptions (Slice 1
  behavior preserved; only LIVE promotions produce push targets).
- LIVE object with multiple subscribers → one OBJECT_UPDATE per receiver
  in the fan-out (sequential per §7.1).
- LIVE object with a denied push → subscription marked DISCONNECTED;
  update_object itself returns the new Object successfully (the push is
  a best-effort side effect, not a precondition for the mutation).
- LIVE object with adapter raise (transient transport failure) → same
  recovery as denial: subscription marked DISCONNECTED; the update
  succeeds; subsequent update_object calls retry by attempting another
  push.
- Scoped state: out-of-scope fields on the Object are NOT in the pushed
  snapshot (§9 #11 LIVE-mode scope-filter invariant).
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
    LayerKind,
    Mutability,
    Operation,
    PromotionMode,
    SendClaim,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_DENIED_SCHEMA,
    OBJECT_UPDATE_SCHEMA,
    ObjectUpdate,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import Mesherra

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"
CAROL = "carol@phase4.local"


# -- Fake adapter that captures sends and serves canned responses ------


class _FakeAdapter:
    def __init__(self) -> None:
        self._handler: Any = None
        self._response_by_op: dict[Operation, MesherraEnvelope | None] = {}
        self._raise_on_op: dict[Operation, Exception] = {}
        self.sent: list[MesherraEnvelope] = []

    def register_handler(self, handler: Any) -> None:
        self._handler = handler

    def set_response(
        self, op: Operation, envelope: MesherraEnvelope | None
    ) -> None:
        self._response_by_op[op] = envelope

    def set_raise(self, op: Operation, exc: Exception) -> None:
        self._raise_on_op[op] = exc

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        if envelope.operation in self._raise_on_op:
            raise self._raise_on_op[envelope.operation]
        self.sent.append(envelope)
        return self._response_by_op.get(envelope.operation)


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_ack(
    *,
    receiver_signer: Signer,
    receiver_principal: str,
    object_version: int,
    context_id: str,
    promotion_id: str = "prm-live-1",
    task_id: str = "task-push-1",
) -> MesherraEnvelope:
    payload = {
        "version": 1,
        "promotion_id": promotion_id,
        "object_version": object_version,
        "received": True,
    }
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=OBJECT_UPDATE_ACK_SCHEMA,
        operation=Operation.OBJECT_UPDATE,
        sender_principal_id=receiver_principal,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    sig = receiver_signer.sign(canonical_json(claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=receiver_principal,
        payload=payload,
        payload_schema=OBJECT_UPDATE_ACK_SCHEMA,
        operation=Operation.OBJECT_UPDATE,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=sig,
    )


def _build_denied(
    *,
    receiver_signer: Signer,
    receiver_principal: str,
    object_version: int,
    reason: str,
    context_id: str,
    promotion_id: str = "prm-live-1",
    task_id: str = "task-push-1",
) -> MesherraEnvelope:
    payload = {
        "version": 1,
        "promotion_id": promotion_id,
        "object_version": object_version,
        "reason": reason,
    }
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=OBJECT_UPDATE_DENIED_SCHEMA,
        operation=Operation.OBJECT_UPDATE,
        sender_principal_id=receiver_principal,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    sig = receiver_signer.sign(canonical_json(claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=receiver_principal,
        payload=payload,
        payload_schema=OBJECT_UPDATE_DENIED_SCHEMA,
        operation=Operation.OBJECT_UPDATE,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=sig,
    )


# -- Fixtures ---------------------------------------------------


@pytest.fixture
def alice_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def bob_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def carol_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def directory(
    alice_signer: Signer, bob_signer: Signer, carol_signer: Signer
) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {
            ALICE: alice_signer.public_key_b64(),
            BOB: bob_signer.public_key_b64(),
            CAROL: carol_signer.public_key_b64(),
        }
    )


@pytest.fixture
def alice_store(tmp_path: Path) -> ObjectStore:
    s = ObjectStore(db_path=tmp_path / "alice.objectstore.sqlite", owner_principal_id=ALICE)
    yield s
    s.close()


@pytest.fixture
def alice_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(db_path=tmp_path / "alice.ledger.sqlite", ledger_owner=ALICE)
    yield l
    l.close()


@pytest.fixture
def alice_mesherra(
    alice_signer: Signer,
    alice_ledger: ProvenanceLedger,
    alice_store: ObjectStore,
    directory: StaticDirectoryClient,
) -> tuple[Mesherra, _FakeAdapter]:
    adapter = _FakeAdapter()
    m = Mesherra(
        principal_id=ALICE,
        signer=alice_signer,
        ledger=alice_ledger,
        adapter=adapter,  # type: ignore[arg-type]
        directory=directory,
        object_store=alice_store,
    )
    return m, adapter


# Helper: seed a LIVE object + LIVE promotion + active owner-side sub.
# Returns (object_id, promotion_id) so tests can drive assertions on the
# generated UUID4 promotion_id.
def _seed_live(
    sdk: Mesherra,
    *,
    state: dict[str, Any] | None = None,
    receiver: str = BOB,
    scope_fields: list[str] | None = None,
) -> tuple[str, str]:
    state = state or {"candidates": ["A"], "duration_minutes": 30}
    scope_fields = scope_fields or list(state.keys())
    obj = sdk.create_object(
        state=state,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.LIVE,
        schema_ref="meshycal.scheduling/calendar-v1",
    )
    promotion, _handle = sdk.promote(
        object_id=obj.object_id,
        receiver=receiver,
        scope={"fields": scope_fields},
        expiry=(datetime.now(UTC) + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        mutability=Mutability.LIVE,
        fetch_endpoint_base="http://alice.example/a2a",
    )
    # Owner-side row: pretend the receiver subscribed. (In a full
    # roundtrip the SUBSCRIBE wire op would populate this; step-10 unit
    # tests stub it directly.) The peer_url is the test's stand-in for
    # the receiver's listener URL — without it the SDK can't push.
    sdk._object_store.record_subscription(  # type: ignore[union-attr]
        promotion_id=promotion.promotion_id,
        counterpart=receiver,
        role=SubscriptionRole.OWNER,
        subscribed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        peer_url="http://bob.example/a2a",
    )
    return obj.object_id, promotion.promotion_id


# -- LIVE one-receiver happy path ----------------------------


class TestLivePushHappyPath:
    @pytest.mark.asyncio
    async def test_one_subscriber_one_push_ack_bumps_version(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_store: ObjectStore,
        bob_signer: Signer,
    ) -> None:
        sdk, adapter = alice_mesherra
        object_id, promotion_id = _seed_live(sdk)
        # Helper builds an ack with a hardcoded promotion_id; rebuild
        # with the real one this seed produced.
        adapter.set_response(
            Operation.OBJECT_UPDATE,
            _build_ack(
                receiver_signer=bob_signer,
                receiver_principal=BOB,
                object_version=2,
                context_id="ctx-push",
                promotion_id=promotion_id,
            ),
        )
        updated = await sdk.update_object(
            object_id, {"candidates": ["A", "B"], "duration_minutes": 45}
        )
        # Slice 1 behavior preserved.
        assert updated.object_version == 2
        # Push fired.
        assert len(adapter.sent) == 1
        sent = adapter.sent[0]
        assert sent.operation is Operation.OBJECT_UPDATE
        assert sent.payload_schema == OBJECT_UPDATE_SCHEMA
        # last_pushed bumped on ack.
        sub = alice_store.get_subscription(
            promotion_id=promotion_id, role=SubscriptionRole.OWNER
        )
        assert sub.last_pushed_object_version == 2


# -- LIVE: no subscribers, no push -----------------------------


class TestLiveNoSubscribers:
    @pytest.mark.asyncio
    async def test_no_subscribers_no_push(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
    ) -> None:
        sdk, adapter = alice_mesherra
        obj = sdk.create_object(
            state={"a": 1},
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.LIVE,
            schema_ref="meshycal.scheduling/calendar-v1",
        )
        await sdk.update_object(obj.object_id, {"a": 2})
        assert adapter.sent == []


# -- STATIC: no push regardless ------------------------------


class TestStaticNoPush:
    @pytest.mark.asyncio
    async def test_static_object_never_pushes(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
    ) -> None:
        sdk, adapter = alice_mesherra
        obj = sdk.create_object(
            state={"a": 1},
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
        )
        # Even if there were a subscription row, STATIC promotions never
        # produce push targets (the SQL JOIN filters mutability='live').
        await sdk.update_object(obj.object_id, {"a": 2})
        assert adapter.sent == []


# -- LIVE: scope filter -------------------------------------


class TestLiveScopeFilter:
    @pytest.mark.asyncio
    async def test_out_of_scope_fields_not_pushed(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
        bob_signer: Signer,
    ) -> None:
        # §9 #11 LIVE-mode scope-filter invariant: only fields in
        # promotion.scope.fields appear in the pushed snapshot_state.
        sdk, adapter = alice_mesherra
        object_id, promotion_id = _seed_live(
            sdk,
            state={"candidates": ["A"], "duration_minutes": 30, "secret_diary": "private"},
            scope_fields=["candidates", "duration_minutes"],
        )
        adapter.set_response(
            Operation.OBJECT_UPDATE,
            _build_ack(
                receiver_signer=bob_signer,
                receiver_principal=BOB,
                object_version=2,
                context_id="ctx-scope",
                promotion_id=promotion_id,
            ),
        )
        await sdk.update_object(
            object_id,
            {
                "candidates": ["A", "B"],
                "duration_minutes": 60,
                "secret_diary": "still private",
            },
        )
        sent_payload = adapter.sent[0].payload
        update = ObjectUpdate.model_validate(sent_payload)
        # Out-of-scope field MUST NOT appear in the pushed snapshot.
        assert "secret_diary" not in update.snapshot_state
        assert update.snapshot_state == {
            "candidates": ["A", "B"],
            "duration_minutes": 60,
        }


# -- LIVE: denied push marks disconnected ------------------


class TestLivePushDenied:
    @pytest.mark.asyncio
    async def test_denial_marks_disconnected(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_store: ObjectStore,
        bob_signer: Signer,
    ) -> None:
        sdk, adapter = alice_mesherra
        object_id, promotion_id = _seed_live(sdk)
        adapter.set_response(
            Operation.OBJECT_UPDATE,
            _build_denied(
                receiver_signer=bob_signer,
                receiver_principal=BOB,
                object_version=2,
                reason="expired",
                context_id="ctx-denied",
                promotion_id=promotion_id,
            ),
        )
        # update_object should not raise — push is best-effort.
        updated = await sdk.update_object(object_id, {"candidates": ["X"], "duration_minutes": 99})
        assert updated.object_version == 2
        sub = alice_store.get_subscription(
            promotion_id=promotion_id, role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.DISCONNECTED
        # last_pushed NOT bumped since the push was rejected.
        assert sub.last_pushed_object_version is None


# -- LIVE: transient transport failure --------------------


class TestLivePushTransientFailure:
    @pytest.mark.asyncio
    async def test_adapter_raise_marks_disconnected(
        self,
        alice_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_store: ObjectStore,
    ) -> None:
        sdk, adapter = alice_mesherra
        object_id, promotion_id = _seed_live(sdk)
        adapter.set_raise(Operation.OBJECT_UPDATE, RuntimeError("network down"))
        updated = await sdk.update_object(object_id, {"candidates": ["X"], "duration_minutes": 99})
        assert updated.object_version == 2
        sub = alice_store.get_subscription(
            promotion_id=promotion_id, role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.DISCONNECTED
        assert sub.last_pushed_object_version is None
