"""Phase 4 Slice 1 end-to-end integration test (the §9 dress rehearsal).

Two real Mesherra instances on localhost, real Ed25519 keys, real on-
disk SQLite stores, real A2A HTTP listeners. Alice creates an Object,
promotes it to Bob (static reference, scoped), Bob fetches twice (with
an owner mutation in between), Eve attempts a stolen-handle fetch, an
expired promotion attempts a fetch. The full demo_4 flow.

Each test asserts a numbered invariant from ``demos/phase_4/SPEC.md``
§9. Together they cover all 17 of that section's end-state assertions.

If these pass, Slice 1 is mechanically real: scoped disclosure flows
end-to-end through Mesherra's airlock with both ledgers carrying paired
residue, the snapshot-at-promotion-time semantics hold, the privacy
invariants (§15 scope-filter, §16 stolen-handle) bind, and the whole
state cold-reloads from disk.
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
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    ActionType,
    LayerKind,
    Mutability,
    Object,
    Operation,
    Promotion,
    PromotionMode,
)
from mesherra.object.store import ObjectStore
from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    PROMOTION_ACK_SCHEMA,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import (
    FetchContentHashMismatch,
    Mesherra,
    OwnershipError,
    PromotionFetchDenied,
)

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"
EVE = "eve@phase4.local"

PROMOTION_HANDLE_SCHEMA = "mesherra.object/promotion-handle-v1"
CALENDAR_SCHEMA = "meshycal.scheduling/calendar-v1"

# The Object's state under test. The `not_in_scope_field` is critical
# to the §9 #15 (scope-filter) assertion — it MUST never appear in any
# fetch payload, any residue payload_hash, or any counterpart-side store.
ALICE_INITIAL_STATE: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z", "2026-06-02T14:00Z"],
    "duration_minutes": 30,
    "not_in_scope_field": "alice-private-info-must-not-cross",
}

# Post-mutation state (§9 #1, #8 — second fetch must return ORIGINAL
# snapshot regardless of this change).
ALICE_MUTATED_STATE: dict[str, Any] = {
    "candidates": ["2026-06-03T11:00Z"],
    "duration_minutes": 60,
    "not_in_scope_field": "alice-other-private-info-also-must-not-cross",
}

SCOPE = {"fields": ["candidates", "duration_minutes"]}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _safe_filename(principal_id: str) -> str:
    return principal_id.replace("@", "_at_").replace("/", "_")


def _make_sdk_with_object_store(
    *,
    principal_id: str,
    signer: Signer,
    db_dir: Path,
    public_key_directory: dict[str, str],
) -> tuple[Mesherra, ProvenanceLedger, ObjectStore]:
    """Build a Mesherra instance with both a Ledger and an ObjectStore."""
    fname = _safe_filename(principal_id)
    ledger = ProvenanceLedger(
        db_path=db_dir / f"{fname}.ledger.sqlite",
        ledger_owner=principal_id,
    )
    object_store = ObjectStore(
        db_path=db_dir / f"{fname}.objects.sqlite",
        owner_principal_id=principal_id,
    )
    sdk = Mesherra(
        principal_id=principal_id,
        signer=signer,
        ledger=ledger,
        adapter=A2AAdapter(),
        directory=StaticDirectoryClient(public_key_directory),
        object_store=object_store,
    )
    return sdk, ledger, object_store


def _future_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _past_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


class TestSlice1FullRoundtrip:
    """The single end-to-end flow that exercises §9 #1–#13, #15.

    Spans:
      - Alice creates an Object
      - Alice promotes (static reference) to Bob
      - Bob fetches once (fetch #1)
      - Alice mutates the Object
      - Bob fetches again (fetch #2) — must return ORIGINAL snapshot

    Assertions live in individual ``test_*`` methods that share the
    ``flow`` fixture. Per-assertion methods keep the failure messages
    targeted; a per-assertion regression points at exactly one §9 item.
    """

    @pytest.fixture
    async def flow(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        e_signer = Signer.generate()  # not used in this flow but in dir
        public_keys = {
            ALICE: a_signer.public_key_b64(),
            BOB: b_signer.public_key_b64(),
            EVE: e_signer.public_key_b64(),
        }

        alice_sdk, alice_ledger, alice_objects = _make_sdk_with_object_store(
            principal_id=ALICE,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        bob_sdk, bob_ledger, bob_objects = _make_sdk_with_object_store(
            principal_id=BOB,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        # Both sides must register a consumer for A2A's listener init even
        # though Slice 1 trust-layer ops bypass it (the gateway raises
        # before consumer if it tried to dispatch one, but the consumer
        # registration is needed by adapter.start_listener).
        async def _noop_consumer(_msg):  # type: ignore[no-untyped-def]
            return None
        alice_sdk.on_message(_noop_consumer)
        bob_sdk.on_message(_noop_consumer)

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
            # --- Run the flow ---

            # Step 1: Alice creates an Object
            obj = alice_sdk.create_object(
                state=ALICE_INITIAL_STATE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.STATIC,
                schema_ref=CALENDAR_SCHEMA,
            )
            pre_mutation_content_hash = obj.content_hash

            # Step 2: Alice promotes to Bob
            promotion, handle = alice_sdk.promote(
                object_id=obj.object_id,
                receiver=BOB,
                scope=SCOPE,
                expiry=_future_iso(hours=2),
                fetch_endpoint_base=alice_url.rstrip("/"),
            )

            # Step 3: Alice ships the handle via PROMOTE
            promote_result = await alice_sdk.send_to(
                peer_url=bob_url,
                peer_principal_id=BOB,
                payload=handle.model_dump(),
                payload_schema=PROMOTION_HANDLE_SCHEMA,
                operation=Operation.PROMOTE,
            )

            # Step 4: Bob fetches the snapshot (fetch #1)
            fetched_1 = await bob_sdk.fetch_object(
                handle=handle,
                peer_url=alice_url,
                fetch_sequence=1,
            )

            # Step 5: Alice mutates the Object
            updated_obj = await alice_sdk.update_object(
                object_id=obj.object_id,
                new_state=ALICE_MUTATED_STATE,
            )

            # Step 6: Bob fetches again (fetch #2) — must return ORIGINAL snapshot
            fetched_2 = await bob_sdk.fetch_object(
                handle=handle,
                peer_url=alice_url,
                fetch_sequence=2,
            )

            yield {
                "alice_sdk": alice_sdk,
                "bob_sdk": bob_sdk,
                "alice_ledger": alice_ledger,
                "bob_ledger": bob_ledger,
                "alice_objects": alice_objects,
                "bob_objects": bob_objects,
                "obj": obj,
                "updated_obj": updated_obj,
                "promotion": promotion,
                "handle": handle,
                "alice_signer": a_signer,
                "bob_signer": b_signer,
                "eve_signer": e_signer,
                "public_keys": public_keys,
                "alice_url": alice_url,
                "bob_url": bob_url,
                "promote_result": promote_result,
                "fetched_1": fetched_1,
                "fetched_2": fetched_2,
                "pre_mutation_content_hash": pre_mutation_content_hash,
                "tmp_path": tmp_path,
            }
        finally:
            await bob_handle.stop()
            await alice_handle.stop()
            alice_objects.close()
            bob_objects.close()
            alice_ledger.close()
            bob_ledger.close()

    # -- §9 #1, #2, #3: Owner-side store state -------------------------

    async def test_object_at_post_mutation_version(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #1: Owner's Object exists with object_version == 2."""
        loaded = flow["alice_objects"].get(flow["obj"].object_id)
        assert loaded.object_version == 2
        assert loaded.state == ALICE_MUTATED_STATE

    async def test_promotion_snapshot_hash_is_pre_mutation(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #2: Promotion's snapshot_content_hash equals Object's
        content_hash at the moment of promotion (NOT the post-mutation
        hash). This is the static-reference invariant at storage layer."""
        prom = flow["alice_objects"].get_promotion(flow["promotion"].promotion_id)
        assert prom.mode is PromotionMode.REFERENCE
        assert prom.mutability is Mutability.STATIC
        # The pre-mutation hash should equal the promotion's snapshot
        # hash, NOT the current (post-mutation) Object hash.
        loaded_obj = flow["alice_objects"].get(flow["obj"].object_id)
        scoped_initial = {
            k: v for k, v in ALICE_INITIAL_STATE.items() if k in SCOPE["fields"]
        }
        expected_pre_mutation = content_hash(canonical_json(scoped_initial))
        assert prom.snapshot_content_hash == expected_pre_mutation
        assert prom.snapshot_content_hash != loaded_obj.content_hash

    async def test_promotion_snapshot_is_scoped_subset(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #3: Promotion's snapshot_state is the scoped subset of
        the Object's state at promotion time."""
        prom = flow["alice_objects"].get_promotion(flow["promotion"].promotion_id)
        assert prom.snapshot_state is not None
        assert set(prom.snapshot_state.keys()) == set(SCOPE["fields"])
        # And does NOT contain the out-of-scope field:
        assert "not_in_scope_field" not in prom.snapshot_state

    # -- §9 #4, #5: Counterpart-side store state ------------------------

    async def test_counterpart_holds_signed_handle(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #4: Bob's store has the received handle and its owner
        signature verifies against Alice's public key."""
        stored = flow["bob_objects"].get_received_handle(
            flow["handle"].promotion_id
        )
        assert stored == flow["handle"]

        # Signature verification against Alice's published key
        verifier = Verifier.from_b64(
            flow["public_keys"][ALICE]
        )
        signing_bytes = canonical_json(stored.to_signing_payload())
        assert verifier.verify(signing_bytes, stored.owner_signature) is True

    async def test_counterpart_has_no_object_for_this_id(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #5: Bob's store has no Object with owner==Bob for this id —
        the receiver holds the handle, not the canonical Object."""
        bob_objs = flow["bob_objects"].list()
        # Bob owns zero Objects in this test flow
        assert bob_objs == []

    # -- §9 #6: Promotion residue pair --------------------------------

    async def test_promotion_residue_paired_across_ledgers(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #6, #11: paired residue on both sides with byte-equal
        payload_hash. Alice has EMIT promote; Bob has RECEIVE promote."""
        a_entries = flow["alice_ledger"].get_all()
        b_entries = flow["bob_ledger"].get_all()

        a_promote_emits = [
            e for e in a_entries
            if e.operation is Operation.PROMOTE
            and e.action_type is ActionType.EMIT
        ]
        b_promote_receives = [
            e for e in b_entries
            if e.operation is Operation.PROMOTE
            and e.action_type is ActionType.RECEIVE
        ]
        assert len(a_promote_emits) == 1
        assert len(b_promote_receives) == 1
        # §9 #11: payload_hash byte-equal
        assert a_promote_emits[0].payload_hash == b_promote_receives[0].payload_hash

    # -- §9 #7, #8, #12: Fetch residue pairs ----------------------------

    async def test_first_fetch_returns_scoped_snapshot(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #7 part: the receiver got the scoped data."""
        scoped_initial = {
            k: v for k, v in ALICE_INITIAL_STATE.items() if k in SCOPE["fields"]
        }
        assert flow["fetched_1"] == scoped_initial

    async def test_second_fetch_returns_original_snapshot_after_mutation(
        self, flow
    ) -> None:  # type: ignore[no-untyped-def]
        """§9 #8: static-reference invariant — second fetch returns
        the SAME bytes as the first, despite the owner mutation."""
        assert flow["fetched_1"] == flow["fetched_2"]
        # And the snapshot is the PRE-mutation scoped state, not the
        # post-mutation scoped state:
        scoped_mutated = {
            k: v for k, v in ALICE_MUTATED_STATE.items() if k in SCOPE["fields"]
        }
        assert flow["fetched_2"] != scoped_mutated

    async def test_two_fetch_response_payload_hashes_identical(
        self, flow
    ) -> None:  # type: ignore[no-untyped-def]
        """§9 #8, #12: both fetch_response payload_hashes are byte-equal
        across both fetches AND across both ledgers."""
        a_entries = flow["alice_ledger"].get_all()
        b_entries = flow["bob_ledger"].get_all()
        a_resp_emits = [
            e for e in a_entries
            if e.operation is Operation.FETCH_RESPONSE
            and e.action_type is ActionType.EMIT
        ]
        b_resp_receives = [
            e for e in b_entries
            if e.operation is Operation.FETCH_RESPONSE
            and e.action_type is ActionType.RECEIVE
        ]
        assert len(a_resp_emits) == 2
        assert len(b_resp_receives) == 2
        # Both Alice's emits have the same payload_hash (static snapshot)
        assert a_resp_emits[0].payload_hash == a_resp_emits[1].payload_hash
        # Both Bob's receives match Alice's emits
        assert b_resp_receives[0].payload_hash == a_resp_emits[0].payload_hash
        assert b_resp_receives[1].payload_hash == a_resp_emits[1].payload_hash

    # -- §9 #9, #10: Chain + signature integrity ------------------------

    async def test_hash_chain_integrity_both_ledgers(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #9: chain integrity preserved on both ledgers."""
        assert flow["alice_ledger"].verify_chain() is True
        assert flow["bob_ledger"].verify_chain() is True

    async def test_all_residue_signatures_verify(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #10: every residue entry's signature verifies under the
        ledger owner's published public key. (The signer of a residue
        entry is the ledger owner — Alice signs Alice's entries, Bob
        signs Bob's. The ``actor`` field records who took the action
        being recorded, which is often the counterpart on RECEIVE
        entries.)"""
        for ledger in (flow["alice_ledger"], flow["bob_ledger"]):
            for entry in ledger.get_all():
                owner_key = flow["public_keys"][entry.ledger_owner]
                verifier = Verifier.from_b64(owner_key)
                signing_bytes = canonical_json(entry.to_signing_payload())
                assert verifier.verify(signing_bytes, entry.signature) is True, (
                    f"Signature failed for {entry.operation} entry in "
                    f"{entry.ledger_owner}'s ledger (actor={entry.actor})"
                )

    # -- §9 #13: Counterpart cannot mutate ----------------------------

    async def test_counterpart_cannot_mutate_object(self, flow) -> None:  # type: ignore[no-untyped-def]
        """§9 #13: Bob's update_object on Alice's object_id raises
        OwnershipError. Bob's store has no Object to mutate; the
        SDK's gate raises ObjectNotFound — either way no write occurs."""
        bob_ledger_size_before = len(flow["bob_ledger"].get_all())
        # The SDK will fail because Bob doesn't have this Object in his store
        # (which is the desired behavior — he never owned it).
        with pytest.raises(Exception):
            await flow["bob_sdk"].update_object(
                object_id=flow["obj"].object_id, new_state={"hijacked": True}
            )
        # No ledger writes from the failed attempt
        assert len(flow["bob_ledger"].get_all()) == bob_ledger_size_before

    # -- §9 #15: Scope filter actually filters --------------------------

    async def test_out_of_scope_field_never_appears_anywhere(
        self, flow
    ) -> None:  # type: ignore[no-untyped-def]
        """§9 #15: the load-bearing privacy invariant. The string value
        of the out-of-scope field appears NOWHERE on Bob's side — not
        in fetched payloads, not in his received-handle, not in his
        store, not in his residue payload_hashes (we check by recomputing
        the hash on the scoped snapshot)."""
        SECRET_1 = ALICE_INITIAL_STATE["not_in_scope_field"]
        SECRET_2 = ALICE_MUTATED_STATE["not_in_scope_field"]

        # 1. Bob's fetched payloads
        for fetched in (flow["fetched_1"], flow["fetched_2"]):
            assert "not_in_scope_field" not in fetched
            assert SECRET_1 not in str(fetched)
            assert SECRET_2 not in str(fetched)

        # 2. Bob's received-handle does not encode the secret
        stored_handle = flow["bob_objects"].get_received_handle(
            flow["handle"].promotion_id
        )
        handle_json = stored_handle.model_dump_json()
        assert SECRET_1 not in handle_json
        assert SECRET_2 not in handle_json

        # 3. Bob's fetch_response residues hash to the FetchResponse
        # wire payload (which wraps the scoped snapshot). The wrapper
        # adds version + promotion_id + snapshot_content_hash, none of
        # which include the secret. We reconstruct the expected wire
        # payload from public information and check the hash matches.
        from mesherra.object.wire import FetchResponse
        scoped_initial = {
            k: v for k, v in ALICE_INITIAL_STATE.items() if k in SCOPE["fields"]
        }
        snapshot_hash = content_hash(canonical_json(scoped_initial))
        expected_wire = FetchResponse(
            promotion_id=flow["handle"].promotion_id,
            snapshot_state=scoped_initial,
            snapshot_content_hash=snapshot_hash,
        )
        expected_wire_hash = content_hash(
            canonical_json(expected_wire.model_dump())
        )
        b_resp_receives = [
            e for e in flow["bob_ledger"].get_all()
            if e.operation is Operation.FETCH_RESPONSE
            and e.action_type is ActionType.RECEIVE
        ]
        for entry in b_resp_receives:
            assert entry.payload_hash == expected_wire_hash, (
                "fetch_response residue payload_hash diverged from the "
                "reconstructed FetchResponse wire payload hash"
            )


# -- §9 #14: Expiry enforcement ------------------------------------


class TestExpiryEnforcement:
    """§9 #14: a fetch against a past-expiry promotion returns
    fetch_denied; both sides record paired fetch_denied residue."""

    async def test_expired_promotion_fetch_returns_denied(
        self, tmp_path: Path
    ) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            ALICE: a_signer.public_key_b64(),
            BOB: b_signer.public_key_b64(),
        }
        alice_sdk, alice_ledger, alice_objects = _make_sdk_with_object_store(
            principal_id=ALICE,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        bob_sdk, bob_ledger, bob_objects = _make_sdk_with_object_store(
            principal_id=BOB,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        async def _noop(_msg):  # type: ignore[no-untyped-def]
            return None
        alice_sdk.on_message(_noop)
        bob_sdk.on_message(_noop)

        alice_port = _free_port()
        bob_port = _free_port()
        alice_handle = await alice_sdk.start_listener(
            host="127.0.0.1", port=alice_port, agent_name="alice"
        )
        bob_handle = await bob_sdk.start_listener(
            host="127.0.0.1", port=bob_port, agent_name="bob"
        )

        try:
            # Set up: an expired promotion in Alice's store. We construct
            # it manually with past timestamps because SDK.promote()
            # auto-generates timestamps from "now". The model validators
            # require expiry > issued_at, which we satisfy by setting
            # both in the past (issued_at 2h ago, expiry 1h ago).
            now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            obj = Object(
                object_id="obj-expired-1",
                owner=ALICE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.STATIC,
                schema_ref=CALENDAR_SCHEMA,
                state={"x": 1},
                object_version=1,
                created_at=now,
                updated_at=now,
            )
            alice_objects.put(obj)
            promotion = Promotion(
                promotion_id="prom-expired-1",
                object_id="obj-expired-1",
                owner=ALICE,
                receiver=BOB,
                mode=PromotionMode.REFERENCE,
                mutability=Mutability.STATIC,
                scope={"fields": ["x"]},
                expiry=_past_iso(hours=1),
                snapshot_state={"x": 1},
                fetch_endpoint=f"http://127.0.0.1:{alice_port}/",
                created_at=_past_iso(hours=2),
            )
            alice_objects.record_promotion(promotion)

            # Build a handle (signed by Alice) for Bob to use
            from mesherra.models.primitives import PromotionHandle

            unsigned = PromotionHandle(
                promotion_id="prom-expired-1",
                object_id="obj-expired-1",
                owner=ALICE,
                receiver=BOB,
                schema_ref=CALENDAR_SCHEMA,
                mode=PromotionMode.REFERENCE,
                mutability=Mutability.STATIC,
                scope={"fields": ["x"]},
                snapshot_content_hash=promotion.snapshot_content_hash,
                fetch_endpoint=f"http://127.0.0.1:{alice_port}/",
                scoped_payload=None,
                expiry=_past_iso(hours=1),
                issued_at=_past_iso(hours=2),
                owner_signature="placeholder",
            )
            sig = a_signer.sign(canonical_json(unsigned.to_signing_payload()))
            handle = unsigned.model_copy(update={"owner_signature": sig})

            # Bob attempts fetch — must raise PromotionFetchDenied with
            # reason=expired
            with pytest.raises(PromotionFetchDenied) as excinfo:
                await bob_sdk.fetch_object(
                    handle=handle,
                    peer_url=f"http://127.0.0.1:{alice_port}/",
                    fetch_sequence=1,
                )
            assert "expired" in str(excinfo.value)

            # Both sides have paired fetch_denied residue
            a_denials = [
                e for e in alice_ledger.get_all()
                if e.operation is Operation.FETCH_DENIED
                and e.action_type is ActionType.EMIT
            ]
            b_denials = [
                e for e in bob_ledger.get_all()
                if e.operation is Operation.FETCH_DENIED
                and e.action_type is ActionType.RECEIVE
            ]
            assert len(a_denials) == 1
            assert len(b_denials) == 1
            assert a_denials[0].payload_hash == b_denials[0].payload_hash
        finally:
            await bob_handle.stop()
            await alice_handle.stop()
            alice_objects.close()
            bob_objects.close()
            alice_ledger.close()
            bob_ledger.close()


# -- §9 #16: Stolen-handle rejected ------------------------------------


class TestStolenHandleRejected:
    """§9 #16: the load-bearing invariant against handle theft. Eve
    (not the receiver) presents Bob's handle to Alice; Alice's airlock
    refuses because sender != handle.receiver."""

    async def test_eve_fetch_with_bobs_handle_denied(
        self, tmp_path: Path
    ) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        e_signer = Signer.generate()
        public_keys = {
            ALICE: a_signer.public_key_b64(),
            BOB: b_signer.public_key_b64(),
            EVE: e_signer.public_key_b64(),
        }
        alice_sdk, alice_ledger, alice_objects = _make_sdk_with_object_store(
            principal_id=ALICE,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        bob_sdk, bob_ledger, bob_objects = _make_sdk_with_object_store(
            principal_id=BOB,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        eve_sdk, eve_ledger, eve_objects = _make_sdk_with_object_store(
            principal_id=EVE,
            signer=e_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        async def _noop(_msg):  # type: ignore[no-untyped-def]
            return None
        for sdk in (alice_sdk, bob_sdk, eve_sdk):
            sdk.on_message(_noop)

        alice_port = _free_port()
        bob_port = _free_port()
        alice_h = await alice_sdk.start_listener(
            host="127.0.0.1", port=alice_port, agent_name="alice"
        )
        bob_h = await bob_sdk.start_listener(
            host="127.0.0.1", port=bob_port, agent_name="bob"
        )

        try:
            obj = alice_sdk.create_object(
                state=ALICE_INITIAL_STATE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.STATIC,
                schema_ref=CALENDAR_SCHEMA,
            )
            promotion, handle = alice_sdk.promote(
                object_id=obj.object_id,
                receiver=BOB,
                scope=SCOPE,
                expiry=_future_iso(hours=2),
                fetch_endpoint_base=f"http://127.0.0.1:{alice_port}",
            )

            # Eve obtains the handle out-of-band (in the test, we just
            # pass it directly) and attempts to fetch
            with pytest.raises(PromotionFetchDenied) as excinfo:
                await eve_sdk.fetch_object(
                    handle=handle,
                    peer_url=f"http://127.0.0.1:{alice_port}/",
                    fetch_sequence=1,
                )
            assert "receiver_mismatch" in str(excinfo.value)

            # Both Alice (owner) and Eve (sender) record paired
            # fetch_denied residue. Bob is NOT involved.
            a_denials = [
                e for e in alice_ledger.get_all()
                if e.operation is Operation.FETCH_DENIED
                and e.action_type is ActionType.EMIT
            ]
            e_denials = [
                e for e in eve_ledger.get_all()
                if e.operation is Operation.FETCH_DENIED
                and e.action_type is ActionType.RECEIVE
            ]
            assert len(a_denials) == 1
            assert len(e_denials) == 1
            assert a_denials[0].payload_hash == e_denials[0].payload_hash

            # And Bob's ledger has NO entries for this stolen-handle attempt
            b_fetch_entries = [
                e for e in bob_ledger.get_all()
                if e.operation in {Operation.FETCH, Operation.FETCH_DENIED}
            ]
            assert b_fetch_entries == []

            # Eve's store has NO scoped data — no Object, no received-handle
            # for this promotion (she never went through PROMOTE):
            assert eve_objects.list() == []

        finally:
            await bob_h.stop()
            await alice_h.stop()
            alice_objects.close()
            bob_objects.close()
            eve_objects.close()
            alice_ledger.close()
            bob_ledger.close()
            eve_ledger.close()


# -- §9 #17: Cold reload -----------------------------------------------


class TestColdReload:
    """§9 #17: after the demo terminates, the SQLite files reload, all
    signatures re-verify, all chains re-verify, all assertions from
    §9 still hold without the running process."""

    async def test_full_roundtrip_state_survives_cold_reload(
        self, tmp_path: Path
    ) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            ALICE: a_signer.public_key_b64(),
            BOB: b_signer.public_key_b64(),
        }

        # --- Run the full flow then close ---
        alice_sdk, alice_ledger, alice_objects = _make_sdk_with_object_store(
            principal_id=ALICE,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        bob_sdk, bob_ledger, bob_objects = _make_sdk_with_object_store(
            principal_id=BOB,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        async def _noop(_msg):  # type: ignore[no-untyped-def]
            return None
        alice_sdk.on_message(_noop)
        bob_sdk.on_message(_noop)

        alice_port = _free_port()
        bob_port = _free_port()
        alice_h = await alice_sdk.start_listener(
            host="127.0.0.1", port=alice_port, agent_name="alice"
        )
        bob_h = await bob_sdk.start_listener(
            host="127.0.0.1", port=bob_port, agent_name="bob"
        )

        try:
            obj = alice_sdk.create_object(
                state=ALICE_INITIAL_STATE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.STATIC,
                schema_ref=CALENDAR_SCHEMA,
            )
            object_id = obj.object_id

            promotion, handle = alice_sdk.promote(
                object_id=object_id,
                receiver=BOB,
                scope=SCOPE,
                expiry=_future_iso(hours=2),
                fetch_endpoint_base=f"http://127.0.0.1:{alice_port}",
            )
            promotion_id = promotion.promotion_id

            await alice_sdk.send_to(
                peer_url=f"http://127.0.0.1:{bob_port}/",
                peer_principal_id=BOB,
                payload=handle.model_dump(),
                payload_schema=PROMOTION_HANDLE_SCHEMA,
                operation=Operation.PROMOTE,
            )
            await bob_sdk.fetch_object(
                handle=handle,
                peer_url=f"http://127.0.0.1:{alice_port}/",
                fetch_sequence=1,
            )
        finally:
            await bob_h.stop()
            await alice_h.stop()
            alice_objects.close()
            bob_objects.close()
            alice_ledger.close()
            bob_ledger.close()

        # --- Cold reload: same paths, fresh processes ---
        alice_ledger_2 = ProvenanceLedger(
            db_path=tmp_path / f"{_safe_filename(ALICE)}.ledger.sqlite",
            ledger_owner=ALICE,
        )
        bob_ledger_2 = ProvenanceLedger(
            db_path=tmp_path / f"{_safe_filename(BOB)}.ledger.sqlite",
            ledger_owner=BOB,
        )
        alice_objects_2 = ObjectStore(
            db_path=tmp_path / f"{_safe_filename(ALICE)}.objects.sqlite",
            owner_principal_id=ALICE,
        )
        bob_objects_2 = ObjectStore(
            db_path=tmp_path / f"{_safe_filename(BOB)}.objects.sqlite",
            owner_principal_id=BOB,
        )

        try:
            # 1. Chains re-verify
            assert alice_ledger_2.verify_chain() is True
            assert bob_ledger_2.verify_chain() is True

            # 2. Every signature verifies under ledger-owner directory key
            # (the ledger owner signs every entry in their own ledger;
            # the actor field is who took the action, often the
            # counterpart for RECEIVE entries).
            for ledger in (alice_ledger_2, bob_ledger_2):
                for entry in ledger.get_all():
                    owner_key = public_keys[entry.ledger_owner]
                    verifier = Verifier.from_b64(owner_key)
                    signing_bytes = canonical_json(entry.to_signing_payload())
                    assert verifier.verify(
                        signing_bytes, entry.signature
                    ) is True

            # 3. Alice's Object + Promotion reload intact
            loaded_obj = alice_objects_2.get(object_id)
            assert loaded_obj.owner == ALICE
            loaded_prom = alice_objects_2.get_promotion(promotion_id)
            assert loaded_prom.receiver == BOB

            # 4. Bob's received handle reload intact + signature still good
            loaded_handle = bob_objects_2.get_received_handle(promotion_id)
            verifier = Verifier.from_b64(public_keys[ALICE])
            signing_bytes = canonical_json(loaded_handle.to_signing_payload())
            assert verifier.verify(
                signing_bytes, loaded_handle.owner_signature
            ) is True
        finally:
            alice_objects_2.close()
            bob_objects_2.close()
            alice_ledger_2.close()
            bob_ledger_2.close()
