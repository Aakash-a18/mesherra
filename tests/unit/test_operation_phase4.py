"""Tests for the Phase 4 additions to the Operation enum.

Covers SPEC §8.3 (Slice 1 ops) and SLICE_2_SPEC §3 (Slice 2 ops):

Slice 1 (§8.3):

- ``promote`` — owner issues a PromotionHandle to a receiver
- ``fetch`` — receiver requests scoped data from the owner
- ``fetch_response`` — owner returns scoped data
- ``fetch_denied`` — owner rejects (expired, revoked, stolen-handle)

Slice 2 (SLICE_2_SPEC §3):

- ``subscribe`` — receiver requests subscription to a live promotion
- ``unsubscribe`` — receiver requests teardown of an active subscription
- ``object_update`` — owner pushes a new scoped snapshot to a receiver

Wire-compatibility check: the SQLite ``operation`` column is plain TEXT
with no CHECK constraint, so adding values is additive. Existing rows
with the Phase 1 four operations (and the Slice 1 four) remain valid;
new rows can carry the Slice 2 values. The UNIQUE(task_id, action_type,
operation) backstop (ARCH §11.1) continues to function unchanged for the
new operations too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mesherra.crypto.primitives import Signer
from mesherra.models.primitives import ActionType, Operation, Residue
from mesherra.provenance.ledger import DuplicateEntry, ProvenanceLedger


class TestEnumValues:
    def test_phase1_values_unchanged(self) -> None:
        # Wire-compat: old rows must still parse.
        assert Operation("proposal") is Operation.PROPOSAL
        assert Operation("counter") is Operation.COUNTER
        assert Operation("acceptance") is Operation.ACCEPTANCE
        assert Operation("rejection") is Operation.REJECTION

    def test_phase4_values_present(self) -> None:
        assert Operation("promote") is Operation.PROMOTE
        assert Operation("fetch") is Operation.FETCH
        assert Operation("fetch_response") is Operation.FETCH_RESPONSE
        assert Operation("fetch_denied") is Operation.FETCH_DENIED

    def test_slice2_values_present(self) -> None:
        # SLICE_2_SPEC §3: three new operations carrying the live-reference
        # promotion lifecycle on the wire. Additive vs Slice 1.
        assert Operation("subscribe") is Operation.SUBSCRIBE
        assert Operation("unsubscribe") is Operation.UNSUBSCRIBE
        assert Operation("object_update") is Operation.OBJECT_UPDATE

    def test_full_enum_membership(self) -> None:
        # Pin the complete set so an accidental removal or reordering is
        # caught here rather than discovered in a downstream gateway
        # dispatch table (where the symptom would be "this op is rejected"
        # rather than "this op was deleted").
        assert {o.value for o in Operation} == {
            # Phase 1
            "proposal", "counter", "acceptance", "rejection",
            # Phase 4 Slice 1
            "promote", "fetch", "fetch_response", "fetch_denied",
            # Phase 4 Slice 2
            "subscribe", "unsubscribe", "object_update",
        }

    @pytest.mark.parametrize(
        "op,expected",
        [
            (Operation.PROMOTE, "promote"),
            (Operation.FETCH, "fetch"),
            (Operation.FETCH_RESPONSE, "fetch_response"),
            (Operation.FETCH_DENIED, "fetch_denied"),
            (Operation.SUBSCRIBE, "subscribe"),
            (Operation.UNSUBSCRIBE, "unsubscribe"),
            (Operation.OBJECT_UPDATE, "object_update"),
        ],
    )
    def test_phase4_values_serialize_as_lowercase_underscore(
        self, op: Operation, expected: str
    ) -> None:
        assert op.value == expected
        # str(StrEnum) returns the value in Python 3.11+; explicit casts of
        # the enum to str via .value or by string formatting must produce
        # the canonical wire form.
        assert f"{op.value}" == expected


class TestResidueAcceptsPhase4Operations:
    """Residue.operation accepts each Phase 4 value without modification."""

    BASE = dict(
        ledger_owner="alice@phase4.local",
        task_id="task-promote-1",
        context_id="ctx-1",
        sequence=0,
        previous_hash="",
        timestamp="2026-05-26T20:00:00Z",
        actor="alice@phase4.local",
        counterpart="bob@phase4.local",
        action_type=ActionType.EMIT,
        payload_hash="a" * 64,
        payload_schema="mesherra.object/promotion-handle-v1",
        signature="placeholder-base64",
    )

    @pytest.mark.parametrize(
        "op",
        [
            # Slice 1
            Operation.PROMOTE,
            Operation.FETCH,
            Operation.FETCH_RESPONSE,
            Operation.FETCH_DENIED,
            # Slice 2
            Operation.SUBSCRIBE,
            Operation.UNSUBSCRIBE,
            Operation.OBJECT_UPDATE,
        ],
    )
    def test_residue_constructs_with_phase4_op(self, op: Operation) -> None:
        r = Residue(**self.BASE, operation=op)
        assert r.operation is op


class TestLedgerStoresPhase4Operations:
    """The append-only ledger persists Phase 4 operations and the
    UNIQUE(task_id, action_type, operation) backstop fires for them."""

    def _signed_residue(
        self,
        signer: Signer,
        *,
        owner: str,
        task_id: str,
        sequence: int,
        previous_hash: str,
        action_type: ActionType,
        operation: Operation,
        counterpart: str = "bob@phase4.local",
    ) -> Residue:
        # Build an unsigned dict, canonical-sign it, attach signature.
        unsigned = dict(
            ledger_owner=owner,
            task_id=task_id,
            context_id="ctx-phase4",
            sequence=sequence,
            previous_hash=previous_hash,
            timestamp="2026-05-26T20:00:00Z",
            actor=owner if action_type is ActionType.EMIT else counterpart,
            counterpart=counterpart,
            action_type=action_type,
            operation=operation,
            payload_hash="a" * 64,
            payload_schema="mesherra.object/promotion-handle-v1",
            signature="placeholder",  # rewritten after signing
        )
        provisional = Residue(**unsigned)
        from mesherra.crypto.primitives import canonical_json
        sig = signer.sign(canonical_json(provisional.to_signing_payload()))
        return Residue(**{**unsigned, "signature": sig})

    def test_phase4_operations_round_trip_through_ledger(
        self, tmp_path: Path
    ) -> None:
        owner = "alice@phase4.local"
        signer = Signer.generate()
        db = tmp_path / "phase4-ops.sqlite"
        ledger = ProvenanceLedger(db_path=db, ledger_owner=owner)
        try:
            previous_hash = ""
            sequence_ops = [
                # Slice 1
                Operation.PROMOTE,
                Operation.FETCH,
                Operation.FETCH_RESPONSE,
                Operation.FETCH_DENIED,
                # Slice 2
                Operation.SUBSCRIBE,
                Operation.UNSUBSCRIBE,
                Operation.OBJECT_UPDATE,
            ]
            for i, op in enumerate(sequence_ops):
                residue = self._signed_residue(
                    signer,
                    owner=owner,
                    task_id=f"task-phase4-{op.value}",
                    sequence=i,
                    previous_hash=previous_hash,
                    action_type=ActionType.EMIT,
                    operation=op,
                )
                previous_hash = ledger.append(residue)
            entries = ledger.get_all()
            ops = [e.operation for e in entries]
            assert ops == sequence_ops
            assert ledger.verify_chain() is True
        finally:
            ledger.close()

    def test_unique_backstop_fires_for_phase4_promote(
        self, tmp_path: Path
    ) -> None:
        # The ARCH §11.1 UNIQUE(task_id, action_type, operation) backstop
        # must still raise DuplicateEntry for the new operations.
        owner = "alice@phase4.local"
        signer = Signer.generate()
        db = tmp_path / "phase4-dup.sqlite"
        ledger = ProvenanceLedger(db_path=db, ledger_owner=owner)
        try:
            r1 = self._signed_residue(
                signer,
                owner=owner,
                task_id="task-same",
                sequence=0,
                previous_hash="",
                action_type=ActionType.EMIT,
                operation=Operation.PROMOTE,
            )
            ledger.append(r1)

            # A second residue with the same (task_id, action_type,
            # operation) tuple — even if sequence/hash chain are nominally
            # correct (we recompute them) — must trip the unique backstop.
            # Build a second residue with new sequence but identical
            # (task_id, action_type, operation).
            r2 = self._signed_residue(
                signer,
                owner=owner,
                task_id="task-same",
                sequence=1,
                previous_hash=ledger.head_hash,
                action_type=ActionType.EMIT,
                operation=Operation.PROMOTE,
            )
            with pytest.raises(DuplicateEntry):
                ledger.append(r2)
        finally:
            ledger.close()
