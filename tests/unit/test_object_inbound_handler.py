"""Unit tests for ObjectInboundHandler.

The handler is the trust-layer routine the InboundGateway dispatches to
for Phase 4 operations (PROMOTE, FETCH). It is NOT a consumer handler —
it is part of Mesherra's airlock pipeline. Its responsibilities (Slice 1):

PROMOTE:
- Verify handle.owner_signature against handle.owner's public key (from Directory)
- Slice 1 constraint: sender_principal_id == handle.owner (no forwarding)
- Persist via ObjectStore.record_received_handle
- Return PromotionAck

FETCH (SPEC §8.2 step 4):
- Look up promotion by promotion_id in our ObjectStore
- Unknown promotion → FetchDenied(unknown_promotion)
- sender_principal_id != promotion.receiver → FetchDenied(receiver_mismatch)  [SPEC §9 #16 stolen-handle]
- now > promotion.expiry → FetchDenied(expired)
- Otherwise → FetchResponse(snapshot_state, snapshot_content_hash)
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
)
from mesherra.object.handler import (
    HandlerOutput,
    InvalidPromotionHandleSignature,
    ObjectInboundHandler,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    PROMOTION_ACK_SCHEMA,
    FetchDenied,
    FetchRequest,
    FetchResponse,
    PromotionAck,
)


# -- Fixtures -----------------------------------------------------------


@pytest.fixture
def owner_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def receiver_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def eve_signer() -> Signer:
    return Signer.generate()


@pytest.fixture
def directory(
    owner_signer: Signer,
    receiver_signer: Signer,
    eve_signer: Signer,
) -> StaticDirectoryClient:
    return StaticDirectoryClient(
        {
            "alice@phase4.local": owner_signer.public_key_b64(),
            "bob@phase4.local": receiver_signer.public_key_b64(),
            "eve@phase4.local": eve_signer.public_key_b64(),
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
    # Far enough in the past that the handler's now-check is unambiguous,
    # but the PromotionHandle's own ``expiry > issued_at`` validator must
    # still hold for the model to construct — we set issued_at further
    # in the past in the helper.
    return (datetime.now(UTC) - timedelta(minutes=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _build_promotion(
    *,
    owner: str,
    receiver: str,
    state: dict[str, Any],
    scope_fields: list[str],
    issued_at: str,
    expiry: str,
    object_id: str = "obj-default-1",
    promotion_id: str = "prom-default-1",
) -> Promotion:
    scope = {"fields": scope_fields}
    snapshot_state = {k: v for k, v in state.items() if k in scope_fields}
    return Promotion(
        promotion_id=promotion_id,
        object_id=object_id,
        owner=owner,
        receiver=receiver,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope=scope,
        expiry=expiry,
        snapshot_state=snapshot_state,
        fetch_endpoint="http://owner.example/a2a",
        created_at=issued_at,
    )


def _build_signed_handle(
    *,
    signer: Signer,
    promotion: Promotion,
    schema_ref: str,
    issued_at: str,
) -> PromotionHandle:
    unsigned = PromotionHandle(
        promotion_id=promotion.promotion_id,
        object_id=promotion.object_id,
        owner=promotion.owner,
        receiver=promotion.receiver,
        schema_ref=schema_ref,
        mode=promotion.mode,
        mutability=promotion.mutability,
        scope=promotion.scope,
        snapshot_content_hash=promotion.snapshot_content_hash,
        fetch_endpoint=promotion.fetch_endpoint,
        scoped_payload=None,
        expiry=promotion.expiry,
        issued_at=issued_at,
        owner_signature="placeholder",
    )
    sig = signer.sign(canonical_json(unsigned.to_signing_payload()))
    return unsigned.model_copy(update={"owner_signature": sig})


# -- PROMOTE handler --------------------------------------------------


class TestHandlePromote:
    """Bob receives a PromotionHandle from Alice. Handler persists +
    returns ack."""

    @pytest.fixture
    def receiver_store(self, tmp_path: Path) -> ObjectStore:
        # Bob's store
        store = ObjectStore(
            db_path=tmp_path / "bob.sqlite",
            owner_principal_id="bob@phase4.local",
        )
        yield store
        store.close()

    @pytest.fixture
    def handler(
        self,
        receiver_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> ObjectInboundHandler:
        return ObjectInboundHandler(
            principal_id="bob@phase4.local",
            object_store=receiver_store,
            directory=directory,
        )

    @pytest.fixture
    def signed_handle(
        self,
        owner_signer: Signer,
        expiry_future_iso: str,
        now_iso: str,
    ) -> PromotionHandle:
        promotion = _build_promotion(
            owner="alice@phase4.local",
            receiver="bob@phase4.local",
            state={"candidates": ["A", "B"], "secret": "nope"},
            scope_fields=["candidates"],
            issued_at=now_iso,
            expiry=expiry_future_iso,
        )
        return _build_signed_handle(
            signer=owner_signer,
            promotion=promotion,
            schema_ref="meshycal.scheduling/calendar-v1",
            issued_at=now_iso,
        )

    @pytest.mark.asyncio
    async def test_persists_handle(
        self,
        handler: ObjectInboundHandler,
        signed_handle: PromotionHandle,
        receiver_store: ObjectStore,
    ) -> None:
        await handler.handle_promote(
            payload=signed_handle.model_dump(),
            sender_principal_id="alice@phase4.local",
        )
        stored = receiver_store.get_received_handle(signed_handle.promotion_id)
        assert stored == signed_handle

    @pytest.mark.asyncio
    async def test_returns_ack(
        self,
        handler: ObjectInboundHandler,
        signed_handle: PromotionHandle,
    ) -> None:
        out = await handler.handle_promote(
            payload=signed_handle.model_dump(),
            sender_principal_id="alice@phase4.local",
        )
        assert out.operation is Operation.PROMOTE
        assert out.payload_schema == PROMOTION_ACK_SCHEMA
        ack = PromotionAck.model_validate(out.payload)
        assert ack.promotion_id == signed_handle.promotion_id
        assert ack.received is True

    @pytest.mark.asyncio
    async def test_rejects_invalid_owner_signature(
        self,
        handler: ObjectInboundHandler,
        signed_handle: PromotionHandle,
    ) -> None:
        # Tamper: replace signature with junk
        tampered = signed_handle.model_copy(
            update={"owner_signature": "AAAA"}
        )
        with pytest.raises(InvalidPromotionHandleSignature):
            await handler.handle_promote(
                payload=tampered.model_dump(),
                sender_principal_id="alice@phase4.local",
            )

    @pytest.mark.asyncio
    async def test_rejects_when_sender_is_not_handle_owner(
        self,
        handler: ObjectInboundHandler,
        signed_handle: PromotionHandle,
    ) -> None:
        # Slice 1: only the owner can issue a PROMOTE. A forwarded handle
        # from eve (where eve is not the handle owner) is rejected.
        # Future slices may allow forwarding; this test pins the Slice 1
        # constraint so any relaxation is an explicit change.
        with pytest.raises(InvalidPromotionHandleSignature):
            await handler.handle_promote(
                payload=signed_handle.model_dump(),
                sender_principal_id="eve@phase4.local",
            )

    @pytest.mark.asyncio
    async def test_rejects_handle_for_different_receiver(
        self,
        handler: ObjectInboundHandler,
        owner_signer: Signer,
        now_iso: str,
        expiry_future_iso: str,
    ) -> None:
        # A handle addressed to eve has no business in bob's store
        # (defense-in-depth on the §9 #16 stolen-handle assertion).
        promotion = _build_promotion(
            owner="alice@phase4.local",
            receiver="eve@phase4.local",  # not bob
            state={"x": 1},
            scope_fields=["x"],
            issued_at=now_iso,
            expiry=expiry_future_iso,
        )
        eve_handle = _build_signed_handle(
            signer=owner_signer,
            promotion=promotion,
            schema_ref="meshycal.scheduling/calendar-v1",
            issued_at=now_iso,
        )
        with pytest.raises(Exception):  # ObjectStore raises OwnershipChangeRejected
            await handler.handle_promote(
                payload=eve_handle.model_dump(),
                sender_principal_id="alice@phase4.local",
            )


# -- FETCH handler ----------------------------------------------------


class TestHandleFetch:
    """Alice (owner) receives a FETCH from Bob (receiver). Handler
    looks up promotion, applies invariants, returns response or denial."""

    @pytest.fixture
    def owner_store(self, tmp_path: Path) -> ObjectStore:
        store = ObjectStore(
            db_path=tmp_path / "alice.sqlite",
            owner_principal_id="alice@phase4.local",
        )
        yield store
        store.close()

    @pytest.fixture
    def handler(
        self,
        owner_store: ObjectStore,
        directory: StaticDirectoryClient,
    ) -> ObjectInboundHandler:
        return ObjectInboundHandler(
            principal_id="alice@phase4.local",
            object_store=owner_store,
            directory=directory,
        )

    @pytest.fixture
    def seeded_promotion(
        self,
        owner_store: ObjectStore,
        now_iso: str,
        expiry_future_iso: str,
    ) -> Promotion:
        # Seed alice's store with an Object + Promotion to bob
        obj = Object(
            object_id="obj-alice-1",
            owner="alice@phase4.local",
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state={
                "candidates": ["2026-06-01T10:00Z"],
                "not_in_scope_field": "owner-only",
            },
            object_version=1,
            created_at=now_iso,
            updated_at=now_iso,
        )
        owner_store.put(obj)
        promotion = _build_promotion(
            owner="alice@phase4.local",
            receiver="bob@phase4.local",
            state=obj.state,
            scope_fields=["candidates"],
            issued_at=now_iso,
            expiry=expiry_future_iso,
            object_id="obj-alice-1",
            promotion_id="prom-alice-bob-1",
        )
        owner_store.record_promotion(promotion)
        return promotion

    @pytest.mark.asyncio
    async def test_returns_fetch_response_for_authorized_receiver(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        req = FetchRequest(
            promotion_id=seeded_promotion.promotion_id, fetch_sequence=1
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="bob@phase4.local",
        )
        assert out.operation is Operation.FETCH_RESPONSE
        assert out.payload_schema == FETCH_RESPONSE_SCHEMA
        resp = FetchResponse.model_validate(out.payload)
        assert resp.promotion_id == seeded_promotion.promotion_id
        assert resp.snapshot_state == seeded_promotion.snapshot_state

    @pytest.mark.asyncio
    async def test_response_omits_out_of_scope_fields(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        # SPEC §9 #15: the scope filter must actually filter. The Object
        # has 'not_in_scope_field', the promotion's scope is 'candidates'
        # only. The response must NOT contain 'not_in_scope_field'.
        req = FetchRequest(
            promotion_id=seeded_promotion.promotion_id, fetch_sequence=1
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="bob@phase4.local",
        )
        resp = FetchResponse.model_validate(out.payload)
        assert "not_in_scope_field" not in resp.snapshot_state
        assert "candidates" in resp.snapshot_state

    @pytest.mark.asyncio
    async def test_response_content_hash_matches_snapshot(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        req = FetchRequest(
            promotion_id=seeded_promotion.promotion_id, fetch_sequence=1
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="bob@phase4.local",
        )
        resp = FetchResponse.model_validate(out.payload)
        expected = content_hash(canonical_json(resp.snapshot_state))
        assert resp.snapshot_content_hash == expected
        # Also matches the promotion's pre-stored hash:
        assert resp.snapshot_content_hash == seeded_promotion.snapshot_content_hash

    @pytest.mark.asyncio
    async def test_denied_for_unknown_promotion(
        self, handler: ObjectInboundHandler
    ) -> None:
        req = FetchRequest(promotion_id="nope-not-here", fetch_sequence=1)
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="bob@phase4.local",
        )
        assert out.operation is Operation.FETCH_DENIED
        assert out.payload_schema == FETCH_DENIED_SCHEMA
        denied = FetchDenied.model_validate(out.payload)
        assert denied.reason == "unknown_promotion"

    @pytest.mark.asyncio
    async def test_denied_for_wrong_receiver(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        # SPEC §9 #16 stolen-handle invariant. Eve presents bob's
        # promotion_id; handler must refuse because the FETCH's sender is
        # not the promotion's receiver.
        req = FetchRequest(
            promotion_id=seeded_promotion.promotion_id, fetch_sequence=1
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="eve@phase4.local",
        )
        assert out.operation is Operation.FETCH_DENIED
        denied = FetchDenied.model_validate(out.payload)
        assert denied.reason == "receiver_mismatch"

    @pytest.mark.asyncio
    async def test_denied_for_expired_promotion(
        self,
        handler: ObjectInboundHandler,
        owner_store: ObjectStore,
        now_iso: str,
    ) -> None:
        # Build a promotion with expiry just barely in the future of
        # issued_at (to pass model validation), but in the past of "now".
        issued = (datetime.now(UTC) - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        expiry = (datetime.now(UTC) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        obj = Object(
            object_id="obj-alice-expired",
            owner="alice@phase4.local",
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state={"x": 1},
            object_version=1,
            created_at=issued,
            updated_at=issued,
        )
        owner_store.put(obj)
        promotion = Promotion(
            promotion_id="prom-expired-1",
            object_id=obj.object_id,
            owner="alice@phase4.local",
            receiver="bob@phase4.local",
            mode=PromotionMode.REFERENCE,
            mutability=Mutability.STATIC,
            scope={"fields": ["x"]},
            expiry=expiry,
            snapshot_state={"x": 1},
            fetch_endpoint="http://owner.example/a2a",
            created_at=issued,
        )
        owner_store.record_promotion(promotion)

        req = FetchRequest(
            promotion_id=promotion.promotion_id, fetch_sequence=1
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="bob@phase4.local",
        )
        assert out.operation is Operation.FETCH_DENIED
        denied = FetchDenied.model_validate(out.payload)
        assert denied.reason == "expired"

    @pytest.mark.asyncio
    async def test_response_is_byte_equal_across_fetches(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        # SPEC §9 #8: two fetches against the same static-reference
        # promotion must produce byte-equal response payloads (so the
        # downstream residue payload_hashes are also equal). The
        # FetchResponse omits fetch_sequence specifically to preserve
        # this property.
        bytes_seen: set[bytes] = set()
        for seq in [1, 2, 7]:
            req = FetchRequest(
                promotion_id=seeded_promotion.promotion_id,
                fetch_sequence=seq,
            )
            out = await handler.handle_fetch(
                payload=req.model_dump(),
                sender_principal_id="bob@phase4.local",
            )
            resp = FetchResponse.model_validate(out.payload)
            bytes_seen.add(resp.model_dump_json().encode())
        # All three responses produced identical bytes
        assert len(bytes_seen) == 1

    @pytest.mark.asyncio
    async def test_denial_echoes_fetch_sequence(
        self,
        handler: ObjectInboundHandler,
        seeded_promotion: Promotion,
    ) -> None:
        req = FetchRequest(
            promotion_id=seeded_promotion.promotion_id, fetch_sequence=42
        )
        out = await handler.handle_fetch(
            payload=req.model_dump(),
            sender_principal_id="eve@phase4.local",
        )
        denied = FetchDenied.model_validate(out.payload)
        assert denied.fetch_sequence == 42


# -- HandlerOutput shape ---------------------------------------------


class TestHandlerOutput:
    def test_handler_output_is_immutable(self) -> None:
        out = HandlerOutput(
            operation=Operation.PROMOTE,
            payload={"p": "v"},
            payload_schema=PROMOTION_ACK_SCHEMA,
        )
        with pytest.raises(Exception):
            out.payload_schema = "other"  # type: ignore[misc]
