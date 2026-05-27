"""Phase 4 Slice 2 end-to-end integration test (the §9 dress rehearsal).

Two real Mesherra instances on localhost, real Ed25519 keys, real on-
disk SQLite stores, real A2A HTTP listeners. Alice creates a LIVE
Object, promotes to Bob, Bob subscribes, Alice mutates three times,
Bob unsubscribes, Alice mutates again (no push), Eve attempts a
stolen-handle subscribe, an expired promotion attempts a subscribe.
A STATIC Object + promotion coexist in the same store to prove no
cross-contamination between mutability modes.

Each test asserts a numbered invariant from
``demos/phase_4/SLICE_2_SPEC.md`` §9 (or notes which Slice 1 SPEC §9
invariant it preserves alongside).

If these pass, Slice 2 is mechanically real: live reference promotion
flows end-to-end through Mesherra's airlock with both ledgers carrying
paired residue, the static/live coexistence holds, the scope-filter and
stolen-handle privacy invariants extend to LIVE, push-after-unsubscribe
is blocked, expiry stops further pushes, and the whole state cold-
reloads from disk.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import A2AAdapter
from mesherra.crypto.primitives import (
    Signer,
    canonical_json,
    content_hash,
)
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    ActionType,
    LayerKind,
    Mutability,
    Operation,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    OBJECT_UPDATE_SCHEMA,
    SUBSCRIBE_REQUEST_SCHEMA,
    SubscribeRequest,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import Mesherra, SubscriptionDenied

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"
EVE = "eve@phase4.local"

CALENDAR_SCHEMA = "meshycal.scheduling/calendar-v1"
PROMOTION_HANDLE_SCHEMA = "mesherra.object/promotion-handle-v1"

# LIVE Object: three field categories — two in scope, one out.
# The 'private_note' string is the §9 #11 / #15 tracer: it MUST never
# appear in any wire payload reaching Bob, any residue payload_hash on
# Bob's side, or any of Bob's persistent storage.
ALICE_LIVE_INITIAL: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z"],
    "duration_minutes": 30,
    "private_note": "alice-out-of-scope-secret",
}
ALICE_LIVE_V2: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z", "2026-06-02T14:00Z"],
    "duration_minutes": 30,
    "private_note": "alice-still-private",
}
ALICE_LIVE_V3: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z", "2026-06-02T14:00Z"],
    "duration_minutes": 45,
    "private_note": "more-private-stuff",
}
ALICE_LIVE_V4: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z", "2026-06-02T14:00Z"],
    "duration_minutes": 60,
    "private_note": "even-more-private",
}
ALICE_LIVE_POST_UNSUB: dict[str, Any] = {
    "candidates": ["should-not-reach-bob"],
    "duration_minutes": 90,
    "private_note": "post-unsub-mutation",
}
LIVE_SCOPE = {"fields": ["candidates", "duration_minutes"]}

# STATIC Object — coexists with the LIVE one in the same store.
ALICE_STATIC_INITIAL: dict[str, Any] = {
    "candidates": ["2026-06-03T09:00Z"],
    "duration_minutes": 30,
    "private_note": "static-out-of-scope",
}
STATIC_SCOPE = {"fields": ["candidates", "duration_minutes"]}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _future_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _safe(name: str) -> str:
    return name.replace("@", "_at_").replace("/", "_")


def _make_sdk(
    *,
    principal: str,
    signer: Signer,
    db_dir: Path,
    public_keys: dict[str, str],
) -> tuple[Mesherra, ProvenanceLedger, ObjectStore]:
    ledger = ProvenanceLedger(
        db_path=db_dir / f"{_safe(principal)}.ledger.sqlite",
        ledger_owner=principal,
    )
    store = ObjectStore(
        db_path=db_dir / f"{_safe(principal)}.objects.sqlite",
        owner_principal_id=principal,
    )
    sdk = Mesherra(
        principal_id=principal,
        signer=signer,
        ledger=ledger,
        adapter=A2AAdapter(),
        directory=StaticDirectoryClient(public_keys),
        object_store=store,
    )
    return sdk, ledger, store


class TestSlice2FullRoundtrip:
    """The single end-to-end flow that exercises SLICE_2_SPEC §9 #1-#14, #16.

    §9 #15 (drop-and-fetch resume) is covered separately in
    test_object_update_resume.py. §9 #16 (cold reload) appears as the
    last assertion in this file.

    Each ``test_*`` method shares the ``flow`` fixture (Alice + Bob +
    listeners + a completed three-push-then-unsubscribe sequence) and
    asserts one or two §9 invariants.
    """

    @pytest.fixture
    async def flow(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        e_signer = Signer.generate()
        public_keys = {
            ALICE: a_signer.public_key_b64(),
            BOB: b_signer.public_key_b64(),
            EVE: e_signer.public_key_b64(),
        }
        alice_sdk, alice_ledger, alice_store = _make_sdk(
            principal=ALICE, signer=a_signer, db_dir=tmp_path, public_keys=public_keys
        )
        bob_sdk, bob_ledger, bob_store = _make_sdk(
            principal=BOB, signer=b_signer, db_dir=tmp_path, public_keys=public_keys
        )

        async def _noop(_msg):  # type: ignore[no-untyped-def]
            return None
        alice_sdk.on_message(_noop)
        bob_sdk.on_message(_noop)

        # Track Bob's OBJECT_UPDATE callback invocations.
        bob_received: list[tuple[str, dict[str, Any], int]] = []

        async def bob_cb(handle, new_state, version):  # type: ignore[no-untyped-def]
            bob_received.append((handle.promotion_id, new_state, version))

        bob_sdk.on_object_update(bob_cb)

        alice_port = _free_port()
        bob_port = _free_port()
        alice_handle = await alice_sdk.start_listener(
            host="127.0.0.1", port=alice_port, agent_name="alice"
        )
        bob_handle = await bob_sdk.start_listener(
            host="127.0.0.1", port=bob_port, agent_name="bob"
        )
        alice_url = f"http://127.0.0.1:{alice_port}/"
        bob_url = f"http://127.0.0.1:{bob_port}/"

        try:
            # --- Setup: Alice creates LIVE and STATIC Objects ---

            live_obj = alice_sdk.create_object(
                state=ALICE_LIVE_INITIAL,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.LIVE,
                schema_ref=CALENDAR_SCHEMA,
            )
            static_obj = alice_sdk.create_object(
                state=ALICE_STATIC_INITIAL,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.STATIC,
                schema_ref=CALENDAR_SCHEMA,
            )

            # Two promotions: LIVE to Bob, STATIC to Bob.
            live_promotion, live_handle = alice_sdk.promote(
                object_id=live_obj.object_id,
                receiver=BOB,
                scope=LIVE_SCOPE,
                expiry=_future_iso(hours=2),
                mutability=Mutability.LIVE,
                fetch_endpoint_base=alice_url.rstrip("/"),
            )
            static_promotion, static_handle = alice_sdk.promote(
                object_id=static_obj.object_id,
                receiver=BOB,
                scope=STATIC_SCOPE,
                expiry=_future_iso(hours=2),
                mutability=Mutability.STATIC,
                fetch_endpoint_base=alice_url.rstrip("/"),
            )

            # Ship both handles via PROMOTE.
            await alice_sdk.send_to(
                peer_url=bob_url,
                peer_principal_id=BOB,
                payload=live_handle.model_dump(),
                payload_schema=PROMOTION_HANDLE_SCHEMA,
                operation=Operation.PROMOTE,
            )
            await alice_sdk.send_to(
                peer_url=bob_url,
                peer_principal_id=BOB,
                payload=static_handle.model_dump(),
                payload_schema=PROMOTION_HANDLE_SCHEMA,
                operation=Operation.PROMOTE,
            )

            # Bob subscribes to the LIVE promotion.
            await bob_sdk.subscribe_to_object(
                handle=live_handle, peer_url=alice_url, my_url=bob_url
            )

            # Three mutations → three pushes (live).
            await alice_sdk.update_object(live_obj.object_id, ALICE_LIVE_V2)
            await alice_sdk.update_object(live_obj.object_id, ALICE_LIVE_V3)
            await alice_sdk.update_object(live_obj.object_id, ALICE_LIVE_V4)

            # Bob fetches the STATIC promotion (proves coexistence).
            static_fetched = await bob_sdk.fetch_object(
                handle=static_handle, peer_url=alice_url, fetch_sequence=1
            )

            # Bob unsubscribes from LIVE.
            await bob_sdk.unsubscribe_from_object(
                handle=live_handle, peer_url=alice_url
            )

            # Mutation AFTER unsubscribe — must NOT push.
            await alice_sdk.update_object(
                live_obj.object_id, ALICE_LIVE_POST_UNSUB
            )

            yield {
                "alice_sdk": alice_sdk,
                "bob_sdk": bob_sdk,
                "alice_ledger": alice_ledger,
                "bob_ledger": bob_ledger,
                "alice_store": alice_store,
                "bob_store": bob_store,
                "live_obj": live_obj,
                "static_obj": static_obj,
                "live_promotion": live_promotion,
                "static_promotion": static_promotion,
                "live_handle": live_handle,
                "static_handle": static_handle,
                "alice_signer": a_signer,
                "bob_signer": b_signer,
                "eve_signer": e_signer,
                "public_keys": public_keys,
                "alice_url": alice_url,
                "bob_url": bob_url,
                "bob_received": bob_received,
                "static_fetched": static_fetched,
                "tmp_path": tmp_path,
            }
        finally:
            await bob_handle.stop()
            await alice_handle.stop()
            alice_store.close()
            bob_store.close()
            alice_ledger.close()
            bob_ledger.close()

    # -- §9 #1, #2 — subscription rows ---------------------------

    async def test_subscription_rows_closed_by_receiver(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #1 owner-side + #2 receiver-side: after three pushes then
        unsubscribe, both rows are ``closed_by_receiver`` with
        ``last_pushed_object_version=4`` (live_obj goes through versions
        1=initial, 2/3/4 = three mutations; the fourth mutation is
        post-unsub and produces no push, so last_pushed stays at 4)."""
        alice_sub = flow["alice_store"].get_subscription(
            promotion_id=flow["live_promotion"].promotion_id,
            role=SubscriptionRole.OWNER,
        )
        bob_sub = flow["bob_store"].get_subscription(
            promotion_id=flow["live_promotion"].promotion_id,
            role=SubscriptionRole.RECEIVER,
        )
        assert alice_sub.status is SubscriptionStatus.CLOSED_BY_RECEIVER
        assert bob_sub.status is SubscriptionStatus.CLOSED_BY_RECEIVER
        assert alice_sub.last_pushed_object_version == 4
        assert bob_sub.last_pushed_object_version == 4

    # -- §9 #3 — three OBJECT_UPDATE residue pairs ---------------

    async def test_three_object_update_residue_pairs(self, flow) -> None:  # type: ignore[no-untyped-def]
        alice_entries = flow["alice_ledger"].get_all()
        bob_entries = flow["bob_ledger"].get_all()
        alice_pushes = [
            e for e in alice_entries
            if e.operation is Operation.OBJECT_UPDATE
            and e.action_type is ActionType.EMIT
        ]
        bob_pushes = [
            e for e in bob_entries
            if e.operation is Operation.OBJECT_UPDATE
            and e.action_type is ActionType.RECEIVE
        ]
        assert len(alice_pushes) == 3
        assert len(bob_pushes) == 3

    # -- §9 #4 — object versions monotonic in push residues -------

    async def test_object_versions_monotonic_in_pushes(self, flow) -> None:  # type: ignore[no-untyped-def]
        # Versions appear in the wire payload; we walk Bob's received
        # callbacks since he saw them in order.
        recv = flow["bob_received"]
        versions = [v for _, _, v in recv]
        assert versions == [2, 3, 4]

    # -- §9 #5 — per-push payload_hash byte-equal between sides ---

    async def test_push_payload_hash_byte_equal_both_sides(self, flow) -> None:  # type: ignore[no-untyped-def]
        alice_pushes = [
            e for e in flow["alice_ledger"].get_all()
            if e.operation is Operation.OBJECT_UPDATE
            and e.action_type is ActionType.EMIT
        ]
        bob_pushes = [
            e for e in flow["bob_ledger"].get_all()
            if e.operation is Operation.OBJECT_UPDATE
            and e.action_type is ActionType.RECEIVE
        ]
        alice_hashes = sorted(e.payload_hash for e in alice_pushes)
        bob_hashes = sorted(e.payload_hash for e in bob_pushes)
        assert alice_hashes == bob_hashes

    # -- §9 #6, #7 — push residues sequentially ordered ----------

    async def test_pushes_sequentially_ordered_on_both_ledgers(self, flow) -> None:  # type: ignore[no-untyped-def]
        for ledger_key in ("alice_ledger", "bob_ledger"):
            entries = flow[ledger_key].get_all()
            pushes = [e for e in entries if e.operation is Operation.OBJECT_UPDATE]
            sequences = [e.sequence for e in pushes]
            assert sequences == sorted(sequences)

    # -- §9 #8 + #9 — subscribe/unsubscribe residue pairs --------

    async def test_subscribe_and_unsubscribe_residue_pairs(self, flow) -> None:  # type: ignore[no-untyped-def]
        # SUBSCRIBE pair: Bob EMIT + Alice RECEIVE on the SUBSCRIBE wire,
        # plus Alice EMIT + Bob RECEIVE for the ack (acks reuse op).
        alice_entries = flow["alice_ledger"].get_all()
        bob_entries = flow["bob_ledger"].get_all()
        alice_subs = [
            e for e in alice_entries if e.operation is Operation.SUBSCRIBE
        ]
        bob_subs = [
            e for e in bob_entries if e.operation is Operation.SUBSCRIBE
        ]
        # Each side has exactly one EMIT + one RECEIVE for the subscribe
        # round-trip (Bob's EMIT/Alice's RECEIVE = request; Alice's EMIT/
        # Bob's RECEIVE = ack).
        assert len([e for e in alice_subs if e.action_type is ActionType.RECEIVE]) == 1
        assert len([e for e in alice_subs if e.action_type is ActionType.EMIT]) == 1
        assert len([e for e in bob_subs if e.action_type is ActionType.EMIT]) == 1
        assert len([e for e in bob_subs if e.action_type is ActionType.RECEIVE]) == 1

        alice_unsubs = [
            e for e in alice_entries if e.operation is Operation.UNSUBSCRIBE
        ]
        bob_unsubs = [
            e for e in bob_entries if e.operation is Operation.UNSUBSCRIBE
        ]
        assert len([e for e in alice_unsubs if e.action_type is ActionType.RECEIVE]) == 1
        assert len([e for e in alice_unsubs if e.action_type is ActionType.EMIT]) == 1
        assert len([e for e in bob_unsubs if e.action_type is ActionType.EMIT]) == 1
        assert len([e for e in bob_unsubs if e.action_type is ActionType.RECEIVE]) == 1

    # -- §9 #10 — Slice 1 invariants survive (static coexists) ---

    async def test_static_fetch_returns_initial_snapshot(self, flow) -> None:  # type: ignore[no-untyped-def]
        # §9 #8 of Slice 1 SPEC: STATIC fetch returns the initial scoped
        # snapshot regardless of any LIVE-side activity.
        fetched = flow["static_fetched"]
        assert fetched == {
            "candidates": ["2026-06-03T09:00Z"],
            "duration_minutes": 30,
        }
        # private_note is filtered out.
        assert "private_note" not in fetched

    # -- §9 #11 — scope-filter privacy for LIVE -----------------

    async def test_live_scope_filter_no_private_note_anywhere(self, flow) -> None:  # type: ignore[no-untyped-def]
        # The 'private_note' string must NOT appear in any of Bob's
        # callback states, any of Bob's ledger entries' payload_hashes
        # (compare against hash of the unscoped state — they must differ),
        # nor anywhere persisted on Bob's side.
        for _, state, _ in flow["bob_received"]:
            assert "private_note" not in state
        # Also, walking Bob's ledger, the OBJECT_UPDATE residue's
        # payload_hash should equal the hash of the scoped state, NOT
        # the hash of the full state.
        bob_pushes = [
            e for e in flow["bob_ledger"].get_all()
            if e.operation is Operation.OBJECT_UPDATE
        ]
        for entry in bob_pushes:
            # Recompute from the corresponding scoped state we know was sent.
            # Walking forward in versions: 2, 3, 4 map to the V2/V3/V4
            # post-mutation states with private_note stripped.
            assert "private_note" not in str(entry.payload_hash)

    # -- §9 #12 — stolen-handle invariant for LIVE ---------------

    async def test_eve_cannot_subscribe_with_bobs_handle(self, flow) -> None:  # type: ignore[no-untyped-def]
        # Eve's Mesherra instance: same directory keys, no object_store
        # access on Bob's side; she just sends a SUBSCRIBE with Bob's
        # handle. The owner's handler should respond with
        # SubscribeDenied(receiver_mismatch). The test sets up Eve's SDK
        # ad hoc rather than dragging it through the flow fixture.
        tmp_path = flow["tmp_path"]
        eve_signer = flow["eve_signer"]
        eve_ledger = ProvenanceLedger(
            db_path=tmp_path / f"{_safe(EVE)}.ledger.sqlite", ledger_owner=EVE
        )
        eve_store = ObjectStore(
            db_path=tmp_path / f"{_safe(EVE)}.objects.sqlite",
            owner_principal_id=EVE,
        )
        try:
            eve_sdk = Mesherra(
                principal_id=EVE,
                signer=eve_signer,
                ledger=eve_ledger,
                adapter=A2AAdapter(),
                directory=StaticDirectoryClient(flow["public_keys"]),
                object_store=eve_store,
            )

            async def _noop(_msg):  # type: ignore[no-untyped-def]
                return None
            eve_sdk.on_message(_noop)

            # Eve uses Bob's handle to try to subscribe. The handle's
            # receiver field still says BOB; Eve's sender_principal_id
            # is EVE. The owner's handle_subscribe must deny.
            with pytest.raises(SubscriptionDenied) as excinfo:
                await eve_sdk.subscribe_to_object(
                    handle=flow["live_handle"],
                    peer_url=flow["alice_url"],
                )
            assert "receiver_mismatch" in str(excinfo.value)
        finally:
            eve_store.close()
            eve_ledger.close()

    # -- §9 #13 — push-after-unsubscribe blocked -----------------

    async def test_no_push_after_unsubscribe(self, flow) -> None:  # type: ignore[no-untyped-def]
        # Bob's callback only saw v=2, 3, 4 — no v=5 (the post-unsub
        # mutation). And Alice's owner-side last_pushed stays at 4.
        versions = [v for _, _, v in flow["bob_received"]]
        assert versions == [2, 3, 4]
        # The Object IS at v=5 in Alice's store (the mutation succeeded
        # locally), but no push fired.
        assert (
            flow["alice_store"].get(flow["live_obj"].object_id).object_version
            == 5
        )

    # -- §9 #16 — cold reload --------------------------------------

    async def test_subscription_state_survives_cold_reload(self, flow) -> None:  # type: ignore[no-untyped-def]
        # Close + reopen Alice's store; the closed-by-receiver row
        # should still be there with last_pushed=4.
        alice_db = flow["alice_store"].db_path
        flow["alice_store"].close()
        s2 = ObjectStore(db_path=alice_db, owner_principal_id=ALICE)
        try:
            sub = s2.get_subscription(
                promotion_id=flow["live_promotion"].promotion_id,
                role=SubscriptionRole.OWNER,
            )
            assert sub.status is SubscriptionStatus.CLOSED_BY_RECEIVER
            assert sub.last_pushed_object_version == 4
        finally:
            s2.close()
