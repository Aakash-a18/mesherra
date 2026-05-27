"""Phase 4 outbound trust-op policy bypass — symmetric with the inbound
bypass in InboundGateway.

The InboundGateway short-circuits PROMOTE/FETCH past the policy engine
because they're protocol-level (the user can't policy-block a peer from
sending them a handle). OutboundGateway needs the same bypass for the
egress direction: otherwise a consumer with a real PolicyStore (default-
deny on unmatched schemas) would have *every* Mesherra.promote() and
Mesherra.fetch_object() call fail with PolicyBlocked, because the trust-
layer wire schemas (mesherra.object/*) have no matching policy rules.

These tests:

1. Construct an OutboundGateway with a PolicyStore that default-denies
   any unmatched schema (an empty rule-set is the easiest way to get
   that state).
2. Verify PROMOTE / FETCH / FETCH_RESPONSE / FETCH_DENIED outbound calls
   complete without PolicyBlocked.
3. Verify a Phase 1 op (PROPOSAL) on an unknown schema still raises
   PolicyBlocked (regression-prevention for the Phase 3 behavior).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import MesherraEnvelope
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.outbound import OutboundGateway, PolicyBlocked
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import Operation, SendClaim
from mesherra.object.wire import (
    FETCH_REQUEST_SCHEMA,
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_REQUEST_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_REQUEST_SCHEMA,
)
from mesherra.policy import (
    PolicyDoc,
    PolicyEngine,
    PolicyStore,
    sign_policy_doc,
)
from mesherra.provenance.ledger import ProvenanceLedger


ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"

PROMOTION_HANDLE_SCHEMA = "mesherra.object/promotion-handle-v1"


class _FakeAdapter:
    """A2AAdapter shape that echoes back a configurable response envelope."""

    def __init__(self, response_envelope: MesherraEnvelope | None) -> None:
        self._handler: Any = None
        self.response = response_envelope
        self.sent: list[MesherraEnvelope] = []

    def register_handler(self, handler: Any) -> None:
        self._handler = handler

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        self.sent.append(envelope)
        return self.response


def _wire_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ack_response(
    *,
    bob_signer: Signer,
    context_id: str,
    response_op: Operation,
    response_schema: str,
    response_payload: dict[str, Any],
    task_id: str = "task-bypass-1",
) -> MesherraEnvelope:
    """Build a signed response envelope from Bob (the peer)."""
    timestamp = _wire_now_iso()
    nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(response_payload))
    claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=response_schema,
        operation=response_op,
        sender_principal_id=BOB,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    sig = bob_signer.sign(canonical_json(claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=BOB,
        payload=response_payload,
        payload_schema=response_schema,
        operation=response_op,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=sig,
    )


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
def alice_ledger(tmp_path: Path) -> ProvenanceLedger:
    l = ProvenanceLedger(
        db_path=tmp_path / "alice.ledger.sqlite", ledger_owner=ALICE
    )
    yield l
    l.close()


@pytest.fixture
def default_deny_policy_store(
    alice_signer: Signer, tmp_path: Path
) -> PolicyStore:
    """A PolicyStore with an empty rule-set so the engine default-denies
    every (schema, direction) pair. The strictest possible state — proves
    the trust-op bypass works under the most restrictive policy."""
    store = PolicyStore(
        db_path=tmp_path / "alice.policy.sqlite",
        principal_id=ALICE,
        public_key_b64=alice_signer.public_key_b64(),
    )
    doc = PolicyDoc(
        principal_id=ALICE,
        version=1,
        issued_at=_wire_now_iso(),
        rules=[],
    )
    signed = sign_policy_doc(doc=doc, signer=alice_signer)
    store.save_signed(signed)
    return store


def _build_outbound(
    *,
    alice_signer: Signer,
    alice_ledger: ProvenanceLedger,
    directory: StaticDirectoryClient,
    policy_store: PolicyStore,
    adapter: _FakeAdapter,
) -> OutboundGateway:
    return OutboundGateway(
        principal_id=ALICE,
        signer=alice_signer,
        ledger=alice_ledger,
        adapter=adapter,  # type: ignore[arg-type]
        directory=directory,
        policy_store=policy_store,
        policy_engine=PolicyEngine(),
    )


class TestTrustOpsBypassOutboundPolicy:
    async def test_promote_with_default_deny_policy_does_not_block(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        context_id = "ctx-promote-bypass"
        ack_payload = {
            "version": 1,
            "promotion_id": "prom-1",
            "received": True,
        }
        response_env = _ack_response(
            bob_signer=bob_signer,
            context_id=context_id,
            response_op=Operation.PROMOTE,
            response_schema="mesherra.object/promotion-ack-v1",
            response_payload=ack_payload,
        )
        adapter = _FakeAdapter(response_envelope=response_env)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        # The handle payload contents don't matter for this test; what
        # matters is that the outbound gateway does NOT raise PolicyBlocked.
        result = await outbound.send(
            peer_url="http://bob.example/a2a",
            peer_principal_id=BOB,
            payload={"version": 1, "promotion_id": "prom-1"},
            payload_schema=PROMOTION_HANDLE_SCHEMA,
            operation=Operation.PROMOTE,
            context_id=context_id,
        )
        assert result.response_operation is Operation.PROMOTE

    async def test_fetch_with_default_deny_policy_does_not_block(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        context_id = "ctx-fetch-bypass"
        snapshot = {"x": 1}
        snapshot_hash = content_hash(canonical_json(snapshot))
        response_env = _ack_response(
            bob_signer=bob_signer,
            context_id=context_id,
            response_op=Operation.FETCH_RESPONSE,
            response_schema="mesherra.object/fetch-response-v1",
            response_payload={
                "version": 1,
                "promotion_id": "prom-1",
                "fetch_sequence": 1,
                "snapshot_state": snapshot,
                "snapshot_content_hash": snapshot_hash,
            },
        )
        adapter = _FakeAdapter(response_envelope=response_env)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        result = await outbound.send(
            peer_url="http://bob.example/a2a",
            peer_principal_id=BOB,
            payload={"version": 1, "promotion_id": "prom-1", "fetch_sequence": 1},
            payload_schema=FETCH_REQUEST_SCHEMA,
            operation=Operation.FETCH,
            context_id=context_id,
        )
        assert result.response_operation is Operation.FETCH_RESPONSE

    async def test_subscribe_with_default_deny_policy_does_not_block(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        context_id = "ctx-subscribe-bypass"
        ack_payload = {
            "version": 1,
            "promotion_id": "prm-live-1",
            "subscribed": True,
        }
        response_env = _ack_response(
            bob_signer=bob_signer,
            context_id=context_id,
            response_op=Operation.SUBSCRIBE,
            response_schema=SUBSCRIBE_ACK_SCHEMA,
            response_payload=ack_payload,
        )
        adapter = _FakeAdapter(response_envelope=response_env)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        result = await outbound.send(
            peer_url="http://bob.example/a2a",
            peer_principal_id=BOB,
            payload={"version": 1, "promotion_id": "prm-live-1"},
            payload_schema=SUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.SUBSCRIBE,
            context_id=context_id,
        )
        assert result.response_operation is Operation.SUBSCRIBE

    async def test_unsubscribe_with_default_deny_policy_does_not_block(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        context_id = "ctx-unsubscribe-bypass"
        ack_payload = {
            "version": 1,
            "promotion_id": "prm-live-1",
            "unsubscribed": True,
        }
        response_env = _ack_response(
            bob_signer=bob_signer,
            context_id=context_id,
            response_op=Operation.UNSUBSCRIBE,
            response_schema=UNSUBSCRIBE_ACK_SCHEMA,
            response_payload=ack_payload,
        )
        adapter = _FakeAdapter(response_envelope=response_env)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        result = await outbound.send(
            peer_url="http://bob.example/a2a",
            peer_principal_id=BOB,
            payload={"version": 1, "promotion_id": "prm-live-1"},
            payload_schema=UNSUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.UNSUBSCRIBE,
            context_id=context_id,
        )
        assert result.response_operation is Operation.UNSUBSCRIBE

    async def test_object_update_with_default_deny_policy_does_not_block(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        context_id = "ctx-object-update-bypass"
        snapshot = {"x": 1}
        snapshot_hash = content_hash(canonical_json(snapshot))
        ack_payload = {
            "version": 1,
            "promotion_id": "prm-live-1",
            "object_version": 2,
            "received": True,
        }
        response_env = _ack_response(
            bob_signer=bob_signer,
            context_id=context_id,
            response_op=Operation.OBJECT_UPDATE,
            response_schema=OBJECT_UPDATE_ACK_SCHEMA,
            response_payload=ack_payload,
        )
        adapter = _FakeAdapter(response_envelope=response_env)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        result = await outbound.send(
            peer_url="http://bob.example/a2a",
            peer_principal_id=BOB,
            payload={
                "version": 1,
                "promotion_id": "prm-live-1",
                "object_version": 2,
                "snapshot_state": snapshot,
                "snapshot_content_hash": snapshot_hash,
            },
            payload_schema=OBJECT_UPDATE_SCHEMA,
            operation=Operation.OBJECT_UPDATE,
            context_id=context_id,
        )
        assert result.response_operation is Operation.OBJECT_UPDATE

    async def test_phase1_op_unknown_schema_still_blocks(
        self,
        alice_signer: Signer,
        bob_signer: Signer,
        directory: StaticDirectoryClient,
        alice_ledger: ProvenanceLedger,
        default_deny_policy_store: PolicyStore,
    ) -> None:
        # Regression check: the bypass MUST be narrow — Phase 1 ops on
        # an unknown schema must still trip the default-deny gate.
        # Otherwise the bypass would silently disable all outbound policy.
        adapter = _FakeAdapter(response_envelope=None)
        outbound = _build_outbound(
            alice_signer=alice_signer,
            alice_ledger=alice_ledger,
            directory=directory,
            policy_store=default_deny_policy_store,
            adapter=adapter,
        )
        with pytest.raises(PolicyBlocked):
            await outbound.send(
                peer_url="http://bob.example/a2a",
                peer_principal_id=BOB,
                payload={"foo": "bar"},
                payload_schema="unknown/v1",
                operation=Operation.PROPOSAL,
            )
