"""Unit tests for the Slice 2 LIVE branch of Mesherra.fetch_object.

Covers Phase 4 Slice 2 step 11 per ``demos/phase_4/SLICE_2_SPEC.md`` §6.2.

Slice 1 ``fetch_object`` was STATIC-only: it returned the frozen
``snapshot_state`` captured at promotion-creation time and raised
``FetchContentHashMismatch`` if the response hash diverged from
``handle.snapshot_content_hash``.

Slice 2 extends fetch_object's semantics:

* For STATIC handles: behavior unchanged. Hash check still fires.
* For LIVE handles: returns the CURRENT scoped state, not a frozen
  snapshot. The hash returned in the FETCH_RESPONSE is the hash of the
  current scoped state — NOT necessarily equal to
  ``handle.snapshot_content_hash`` (which only commits to the
  promotion-creation snapshot for the receiver's *initial* commitment
  per §6.2). The SDK does NOT raise ``FetchContentHashMismatch`` for
  LIVE.

The handler also needs the corresponding owner-side change: for LIVE
promotions, ``handle_fetch`` computes the scoped state from the
Object's current state rather than returning the (None) stored
snapshot.

Tested here:

- Bob fetches a LIVE handle after Alice mutates the Object → he gets
  the post-mutation scoped state (current, not frozen).
- LIVE fetch does NOT raise even though the response hash differs
  from handle.snapshot_content_hash.
- STATIC fetch behavior unchanged (covered in tests/unit/test_sdk_fetch_object.py;
  smoke check here that hash check still fires for STATIC).
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
    FETCH_RESPONSE_SCHEMA,
    FetchResponse,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import (
    FetchContentHashMismatch,
    Mesherra,
)

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"


class _FakeAdapter:
    def __init__(self) -> None:
        self._handler: Any = None
        self.next_response: MesherraEnvelope | None = None
        self.sent: list[MesherraEnvelope] = []

    def register_handler(self, handler: Any) -> None:
        self._handler = handler

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        self.sent.append(envelope)
        return self.next_response


def _build_live_handle(*, owner_signer: Signer) -> PromotionHandle:
    """Build a LIVE handle as if Alice had just promoted to Bob over
    initial state. The handle's snapshot_content_hash commits to the
    initial scoped state — Slice 2's "initial commitment"."""
    initial_state = {"candidates": ["A"], "duration_minutes": 30}
    snapshot_hash = content_hash(canonical_json(initial_state))
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    unsigned = PromotionHandle(
        promotion_id="prm-live-fetch-1",
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


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_fetch_response(
    *,
    owner_signer: Signer,
    promotion_id: str,
    snapshot_state: dict[str, Any],
    context_id: str,
    task_id: str = "task-fetch-1",
) -> MesherraEnvelope:
    """An owner-signed FETCH_RESPONSE envelope echoing the requested snapshot."""
    snapshot_hash = content_hash(canonical_json(snapshot_state))
    resp = FetchResponse(
        promotion_id=promotion_id,
        snapshot_state=snapshot_state,
        snapshot_content_hash=snapshot_hash,
    )
    payload = resp.model_dump()
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=FETCH_RESPONSE_SCHEMA,
        operation=Operation.FETCH_RESPONSE,
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
        payload=payload,
        payload_schema=FETCH_RESPONSE_SCHEMA,
        operation=Operation.FETCH_RESPONSE,
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
def directory(alice_signer: Signer, bob_signer: Signer) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {ALICE: alice_signer.public_key_b64(), BOB: bob_signer.public_key_b64()}
    )


@pytest.fixture
def bob_mesherra(
    bob_signer: Signer,
    directory: StaticDirectoryClient,
    tmp_path: Path,
) -> tuple[Mesherra, _FakeAdapter]:
    adapter = _FakeAdapter()
    ledger = ProvenanceLedger(
        db_path=tmp_path / "bob.ledger.sqlite", ledger_owner=BOB
    )
    store = ObjectStore(
        db_path=tmp_path / "bob.objects.sqlite", owner_principal_id=BOB
    )
    m = Mesherra(
        principal_id=BOB,
        signer=bob_signer,
        ledger=ledger,
        adapter=adapter,  # type: ignore[arg-type]
        directory=directory,
        object_store=store,
    )
    yield m, adapter
    ledger.close()
    store.close()


# -- LIVE fetch returns CURRENT state ---------------------------


class TestLiveFetchSemantics:
    @pytest.mark.asyncio
    async def test_live_fetch_returns_current_state_no_hash_mismatch_raise(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_signer: Signer,
    ) -> None:
        m, adapter = bob_mesherra
        handle = _build_live_handle(owner_signer=alice_signer)

        # Owner has mutated since promotion; the current scoped state
        # differs from the handle's committed initial state.
        current_state = {"candidates": ["A", "B", "C"], "duration_minutes": 60}
        adapter.next_response = _build_fetch_response(
            owner_signer=alice_signer,
            promotion_id="prm-live-fetch-1",
            snapshot_state=current_state,
            context_id="ctx-live-fetch",
        )

        # MUST NOT raise FetchContentHashMismatch — LIVE explicitly
        # allows the response hash to differ from handle.snapshot_content_hash.
        result = await m.fetch_object(
            handle=handle, peer_url="http://alice.example/a2a", context_id="ctx-live-fetch"
        )
        assert result == current_state


# -- STATIC behavior preserved ---------------------------------


class TestStaticFetchSemanticsPreserved:
    @pytest.mark.asyncio
    async def test_static_fetch_still_raises_on_mismatch(
        self,
        bob_mesherra: tuple[Mesherra, _FakeAdapter],
        alice_signer: Signer,
    ) -> None:
        # Sanity: STATIC handles' hash check still fires even though
        # LIVE bypass code now exists in the same method.
        m, adapter = bob_mesherra
        # Build a STATIC handle (Slice 1 shape).
        snapshot_initial = {"candidates": ["A"]}
        snapshot_hash = content_hash(canonical_json(snapshot_initial))
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        unsigned = PromotionHandle(
            promotion_id="prm-static-fetch-1",
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
        sig = alice_signer.sign(canonical_json(unsigned.to_signing_payload()))
        handle = unsigned.model_copy(update={"owner_signature": sig})

        # Owner returns a DIFFERENT snapshot than the handle committed to.
        adapter.next_response = _build_fetch_response(
            owner_signer=alice_signer,
            promotion_id="prm-static-fetch-1",
            snapshot_state={"candidates": ["DIFFERENT"]},
            context_id="ctx-static-fetch",
        )
        with pytest.raises(FetchContentHashMismatch):
            await m.fetch_object(
                handle=handle,
                peer_url="http://alice.example/a2a",
                context_id="ctx-static-fetch",
            )


# -- Owner-side: handle_fetch computes current state for LIVE -----


class TestHandlerFetchLive:
    """Direct test that ObjectInboundHandler.handle_fetch returns the
    Object's current scoped state for LIVE promotions, not a stale or
    empty snapshot."""

    @pytest.mark.asyncio
    async def test_handler_returns_current_live_state(
        self,
        alice_signer: Signer,
        tmp_path: Path,
        directory: StaticDirectoryClient,
    ) -> None:
        store = ObjectStore(
            db_path=tmp_path / "alice-live.sqlite", owner_principal_id=ALICE
        )
        try:
            now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            obj = Object(
                object_id="obj-live-1",
                owner=ALICE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.LIVE,
                schema_ref="meshycal.scheduling/calendar-v1",
                state={"candidates": ["A"], "duration_minutes": 30, "secret": "nope"},
                object_version=1,
                created_at=now,
                updated_at=now,
            )
            store.put(obj)
            promotion = Promotion(
                promotion_id="prm-live-fetch-2",
                object_id="obj-live-1",
                owner=ALICE,
                receiver=BOB,
                mode=PromotionMode.REFERENCE,
                mutability=Mutability.LIVE,
                scope={"fields": ["candidates", "duration_minutes"]},
                expiry=(datetime.now(UTC) + timedelta(hours=1)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                snapshot_state=None,
                fetch_endpoint="http://alice.example/a2a",
                created_at=now,
            )
            store.record_promotion(promotion)
            # Mutate before the fetch arrives.
            updated = Object(
                object_id="obj-live-1",
                owner=ALICE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.LIVE,
                schema_ref="meshycal.scheduling/calendar-v1",
                state={"candidates": ["A", "B"], "duration_minutes": 45, "secret": "nope"},
                object_version=2,
                created_at=now,
                updated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            )
            store.put(updated)

            handler = ObjectInboundHandler(
                principal_id=ALICE, object_store=store, directory=directory
            )
            from mesherra.object.wire import FetchRequest
            out = await handler.handle_fetch(
                payload=FetchRequest(
                    promotion_id="prm-live-fetch-2", fetch_sequence=1
                ).model_dump(),
                sender_principal_id=BOB,
            )
            resp = FetchResponse.model_validate(out.payload)
            # Current scoped state — out-of-scope 'secret' is filtered;
            # the post-mutation values are returned.
            assert resp.snapshot_state == {
                "candidates": ["A", "B"],
                "duration_minutes": 45,
            }
            # Response hash is hash of the current scoped state.
            assert resp.snapshot_content_hash == content_hash(
                canonical_json(resp.snapshot_state)
            )
        finally:
            store.close()
