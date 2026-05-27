"""Unit tests for Mesherra.fetch_object — the receiver-side method that
turns a held PromotionHandle into the scoped snapshot data.

These tests use a FakeAdapter to inject pre-built response envelopes
without standing up a real listener. They cover:

- Happy path: FETCH_RESPONSE returns snapshot, content_hash matches
  handle, snapshot_state returned to caller
- Content-hash mismatch: owner returned bytes whose hash diverges from
  the handle's commitment → FetchContentHashMismatch
- Owner refused: FETCH_DENIED returned → PromotionFetchDenied with reason
- Unexpected response operation: anything other than FETCH_RESPONSE/
  FETCH_DENIED → raises (defensive)
- Outbound side fills the right operation + payload_schema on the wire

The full two-side wire flow is covered by the Slice 1 integration test
(task #6); here we cover SDK-level dispatch semantics.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import MesherraEnvelope
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.outbound import GatewayError
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    Mutability,
    Operation,
    PromotionHandle,
    PromotionMode,
    SendClaim,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_REQUEST_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    FetchDenied,
    FetchResponse,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import (
    FetchContentHashMismatch,
    Mesherra,
    PromotionFetchDenied,
)


ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"


# -- Fake adapter --------------------------------------------------------


class _FakeAdapter:
    """Stand-in for A2AAdapter with a programmable response.

    Mimics the parts of the adapter the Outbound/Inbound gateways use.
    Does NOT inherit from A2AAdapter (no need; the SDK constructor takes
    A2AAdapter typed but duck-typing works at runtime). Captures sent
    envelopes for assertion.
    """

    def __init__(self, response_envelope: MesherraEnvelope | None) -> None:
        self._handler: Any = None
        self.response = response_envelope
        self.sent: list[tuple[str, MesherraEnvelope]] = []

    def register_handler(self, handler: Any) -> None:
        self._handler = handler

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        self.sent.append((peer_url, envelope))
        return self.response


# -- Helpers -------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_handle(
    *,
    owner_signer: Signer,
    snapshot_state: dict[str, Any],
) -> PromotionHandle:
    snapshot_hash = content_hash(canonical_json(snapshot_state))
    unsigned = PromotionHandle(
        promotion_id="prom-fetch-test-1",
        object_id="obj-alice-1",
        owner=ALICE,
        receiver=BOB,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": list(snapshot_state.keys())},
        snapshot_content_hash=snapshot_hash,
        fetch_endpoint="http://alice.example/a2a",
        scoped_payload=None,
        expiry=_future_iso(),
        issued_at=_now_iso(),
        owner_signature="placeholder",
    )
    sig = owner_signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


def _build_response_envelope(
    *,
    owner_signer: Signer,
    response_payload: dict[str, Any],
    response_op: Operation,
    response_schema: str,
    context_id: str,
    task_id: str = "task-fetch-1",
) -> MesherraEnvelope:
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


# -- Fixtures ------------------------------------------------------------


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
def bob_ledger(tmp_path: Path) -> ProvenanceLedger:
    return ProvenanceLedger(
        db_path=tmp_path / "bob.ledger.sqlite", ledger_owner=BOB
    )


@pytest.fixture
def bob_store(tmp_path: Path) -> ObjectStore:
    return ObjectStore(
        db_path=tmp_path / "bob.objects.sqlite", owner_principal_id=BOB
    )


def _make_bob_sdk(
    *,
    bob_signer: Signer,
    bob_ledger: ProvenanceLedger,
    bob_store: ObjectStore | None,
    directory: StaticDirectoryClient,
    fake_adapter: _FakeAdapter,
) -> Mesherra:
    # type: ignore[arg-type] — duck-typing the adapter for the fake
    return Mesherra(
        principal_id=BOB,
        signer=bob_signer,
        ledger=bob_ledger,
        adapter=fake_adapter,  # type: ignore[arg-type]
        directory=directory,
        object_store=bob_store,
    )


# -- Tests --------------------------------------------------------------


class TestFetchObjectHappyPath:
    async def test_returns_snapshot_state(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        snapshot = {"candidates": ["A", "B"]}
        handle = _build_handle(
            owner_signer=alice_signer, snapshot_state=snapshot
        )
        snapshot_hash = content_hash(canonical_json(snapshot))
        resp = FetchResponse(
            promotion_id=handle.promotion_id,
            snapshot_state=snapshot,
            snapshot_content_hash=snapshot_hash,
        )
        # Use a context_id that the SDK passes through; pre-fab response.
        context_id = "ctx-fetch-happy"
        resp_env = _build_response_envelope(
            owner_signer=alice_signer,
            response_payload=resp.model_dump(),
            response_op=Operation.FETCH_RESPONSE,
            response_schema=FETCH_RESPONSE_SCHEMA,
            context_id=context_id,
        )
        adapter = _FakeAdapter(response_envelope=resp_env)
        sdk = _make_bob_sdk(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            bob_store=bob_store,
            directory=directory,
            fake_adapter=adapter,
        )

        try:
            result = await sdk.fetch_object(
                handle=handle,
                peer_url="http://alice.example/a2a",
                fetch_sequence=1,
                context_id=context_id,
            )
            assert result == snapshot
        finally:
            bob_ledger.close()
            bob_store.close()

    async def test_outbound_uses_fetch_operation_and_schema(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        snapshot = {"x": 1}
        handle = _build_handle(
            owner_signer=alice_signer, snapshot_state=snapshot
        )
        snapshot_hash = content_hash(canonical_json(snapshot))
        resp = FetchResponse(
            promotion_id=handle.promotion_id,
            snapshot_state=snapshot,
            snapshot_content_hash=snapshot_hash,
        )
        context_id = "ctx-op-check"
        resp_env = _build_response_envelope(
            owner_signer=alice_signer,
            response_payload=resp.model_dump(),
            response_op=Operation.FETCH_RESPONSE,
            response_schema=FETCH_RESPONSE_SCHEMA,
            context_id=context_id,
        )
        adapter = _FakeAdapter(response_envelope=resp_env)
        sdk = _make_bob_sdk(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            bob_store=bob_store,
            directory=directory,
            fake_adapter=adapter,
        )
        try:
            await sdk.fetch_object(
                handle=handle,
                peer_url="http://alice.example/a2a",
                fetch_sequence=3,
                context_id=context_id,
            )
            assert len(adapter.sent) == 1
            peer_url, sent_env = adapter.sent[0]
            assert peer_url == "http://alice.example/a2a"
            assert sent_env.operation is Operation.FETCH
            assert sent_env.payload_schema == FETCH_REQUEST_SCHEMA
            assert sent_env.payload["promotion_id"] == handle.promotion_id
            assert sent_env.payload["fetch_sequence"] == 3
        finally:
            bob_ledger.close()
            bob_store.close()


class TestFetchObjectNegative:
    async def test_content_hash_mismatch_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        # Handle commits to one snapshot; owner returns different bytes
        # whose hash matches itself but NOT the handle's commitment.
        committed = {"x": 1}
        handle = _build_handle(
            owner_signer=alice_signer, snapshot_state=committed
        )
        # Cheating owner returns different snapshot with consistent
        # internal hash. The receiver must catch the divergence.
        cheated = {"x": 2}
        cheated_hash = content_hash(canonical_json(cheated))
        resp = FetchResponse(
            promotion_id=handle.promotion_id,
            snapshot_state=cheated,
            snapshot_content_hash=cheated_hash,
        )
        context_id = "ctx-mismatch"
        resp_env = _build_response_envelope(
            owner_signer=alice_signer,
            response_payload=resp.model_dump(),
            response_op=Operation.FETCH_RESPONSE,
            response_schema=FETCH_RESPONSE_SCHEMA,
            context_id=context_id,
        )
        adapter = _FakeAdapter(response_envelope=resp_env)
        sdk = _make_bob_sdk(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            bob_store=bob_store,
            directory=directory,
            fake_adapter=adapter,
        )
        try:
            with pytest.raises(FetchContentHashMismatch):
                await sdk.fetch_object(
                    handle=handle,
                    peer_url="http://alice.example/a2a",
                    fetch_sequence=1,
                    context_id=context_id,
                )
        finally:
            bob_ledger.close()
            bob_store.close()

    async def test_fetch_denied_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        handle = _build_handle(
            owner_signer=alice_signer, snapshot_state={"x": 1}
        )
        denied = FetchDenied(
            promotion_id=handle.promotion_id,
            fetch_sequence=1,
            reason="expired",
        )
        context_id = "ctx-denied"
        resp_env = _build_response_envelope(
            owner_signer=alice_signer,
            response_payload=denied.model_dump(),
            response_op=Operation.FETCH_DENIED,
            response_schema=FETCH_DENIED_SCHEMA,
            context_id=context_id,
        )
        adapter = _FakeAdapter(response_envelope=resp_env)
        sdk = _make_bob_sdk(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            bob_store=bob_store,
            directory=directory,
            fake_adapter=adapter,
        )
        try:
            with pytest.raises(PromotionFetchDenied) as excinfo:
                await sdk.fetch_object(
                    handle=handle,
                    peer_url="http://alice.example/a2a",
                    fetch_sequence=1,
                    context_id=context_id,
                )
            assert "expired" in str(excinfo.value)
        finally:
            bob_ledger.close()
            bob_store.close()

    async def test_unexpected_response_op_raises(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        bob_ledger: ProvenanceLedger,
        bob_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> None:
        # Owner replies with an op that's neither FETCH_RESPONSE nor
        # FETCH_DENIED — defensive: don't trust unexpected operations.
        handle = _build_handle(
            owner_signer=alice_signer, snapshot_state={"x": 1}
        )
        context_id = "ctx-bad-op"
        # Build a response with operation=PROMOTE (clearly wrong for fetch)
        resp_env = _build_response_envelope(
            owner_signer=alice_signer,
            response_payload={"version": 1, "promotion_id": handle.promotion_id, "received": True},
            response_op=Operation.PROMOTE,
            response_schema="mesherra.object/promotion-ack-v1",
            context_id=context_id,
        )
        adapter = _FakeAdapter(response_envelope=resp_env)
        sdk = _make_bob_sdk(
            bob_signer=bob_signer,
            bob_ledger=bob_ledger,
            bob_store=bob_store,
            directory=directory,
            fake_adapter=adapter,
        )
        try:
            with pytest.raises(GatewayError):
                await sdk.fetch_object(
                    handle=handle,
                    peer_url="http://alice.example/a2a",
                    fetch_sequence=1,
                    context_id=context_id,
                )
        finally:
            bob_ledger.close()
            bob_store.close()
