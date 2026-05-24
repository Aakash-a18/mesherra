"""Unit tests for mesherra.provenance.ledger.

Covers SPEC §5 structural assertions 1-4 (sequence, hash chain, ordering) at
the ledger level. Cross-ledger paired assertions (5-13) and signature
verification (assertion 3) are exercised at the integration level by the
demo orchestrator; the ledger's job is only the local chain.

Tests cover the cold-reload path explicitly (SPEC §5 assertion 14): the
ledger file is closed, reopened from disk, and the chain re-verified.

Synthetic data only: principal ids use the ``@phase1.local`` domain,
keypairs are generated per test, timestamps are fixed strings.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.models.primitives import ActionType, Operation, Residue
from mesherra.provenance.ledger import (
    BrokenChain,
    DuplicateEntry,
    LedgerOwnerMismatch,
    ProvenanceLedger,
    SequenceGap,
)

OWNER_A = "user-a@phase1.local"
OWNER_B = "user-b@phase1.local"

DEFAULT_PAYLOAD: dict[str, Any] = {
    "candidates": ["2026-05-26T14:00:00Z"],
    "duration_minutes": 30,
}


def build_signed_residue(
    *,
    signer: Signer,
    ledger_owner: str,
    sequence: int,
    previous_hash: str,
    actor: str | None = None,
    counterpart: str = OWNER_B,
    operation: Operation = Operation.PROPOSAL,
    action_type: ActionType = ActionType.EMIT,
    task_id: str = "task-1",
    context_id: str = "ctx-1",
    timestamp: str = "2026-05-23T15:30:00Z",
    payload: dict | None = None,
    payload_schema: str = "meshycal.scheduling/proposal-v1",
) -> Residue:
    """Build a Residue with a real Ed25519 signature over its canonical bytes."""
    payload = payload if payload is not None else DEFAULT_PAYLOAD
    fields = {
        "ledger_owner": ledger_owner,
        "task_id": task_id,
        "context_id": context_id,
        "sequence": sequence,
        "previous_hash": previous_hash,
        "timestamp": timestamp,
        "actor": actor or ledger_owner,
        "counterpart": counterpart,
        "action_type": action_type,
        "operation": operation,
        "payload_hash": content_hash(canonical_json(payload)),
        "payload_schema": payload_schema,
    }
    canonical = canonical_json({**fields, "action_type": fields["action_type"].value,
                                 "operation": fields["operation"].value})
    signature = signer.sign(canonical)
    return Residue(**fields, signature=signature)


@pytest.fixture
def signer_a() -> Signer:
    return Signer.generate()


@pytest.fixture
def signer_b() -> Signer:
    return Signer.generate()


# -- Construction & metadata ---------------------------------------------


class TestConstruction:
    def test_open_in_memory(self) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        assert ledger.ledger_owner == OWNER_A
        assert ledger.next_sequence == 0
        assert ledger.head_hash == ""
        assert len(ledger) == 0
        ledger.close()

    def test_open_on_disk_creates_file(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A):
            assert db.exists()

    def test_reopen_existing_with_same_owner(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A):
            pass
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.ledger_owner == OWNER_A

    def test_reopen_with_wrong_owner_raises(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A):
            pass
        with pytest.raises(LedgerOwnerMismatch, match=OWNER_B):
            ProvenanceLedger(db_path=db, ledger_owner=OWNER_B)

    def test_empty_owner_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ProvenanceLedger(db_path=":memory:", ledger_owner="")

    def test_context_manager_closes_connection(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.next_sequence == 0
        # After close, reopening must succeed.
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.next_sequence == 0


# -- Append happy paths --------------------------------------------------


class TestAppendHappyPath:
    def test_append_first_entry_to_empty_ledger(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        residue = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
        )
        head = ledger.append(residue)
        assert head != ""
        assert len(head) == 64
        assert len(ledger) == 1
        assert ledger.next_sequence == 1
        assert ledger.head_hash == head

    def test_append_chains_two_entries(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        first_hash = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=first_hash,
            operation=Operation.ACCEPTANCE,
        )
        ledger.append(second)
        assert len(ledger) == 2
        assert ledger.verify_chain() is True

    def test_append_return_value_is_next_previous_hash(
        self, signer_a: Signer
    ) -> None:
        """The hash returned by append() must be the value the next entry's
        previous_hash should equal."""
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        returned = ledger.append(first)
        assert returned == ledger.head_hash


# -- Append validation ---------------------------------------------------


class TestAppendValidation:
    def test_rejects_wrong_ledger_owner(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        residue = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_B, sequence=0, previous_hash=""
        )
        with pytest.raises(LedgerOwnerMismatch, match=OWNER_B):
            ledger.append(residue)
        assert len(ledger) == 0

    def test_rejects_sequence_too_high(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        residue = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=1, previous_hash=""
        )
        with pytest.raises(SequenceGap, match="Expected sequence 0"):
            ledger.append(residue)

    def test_rejects_sequence_too_low(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        ledger.append(first)
        # Now appending sequence=0 again must fail.
        dup = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        with pytest.raises(SequenceGap, match="Expected sequence 1"):
            ledger.append(dup)

    def test_rejects_wrong_previous_hash(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        ledger.append(first)
        bogus_prev = "a" * 64
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=bogus_prev,
        )
        with pytest.raises(BrokenChain):
            ledger.append(second)

    def test_first_entry_must_have_empty_previous_hash(
        self, signer_a: Signer
    ) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        bogus_prev = "a" * 64
        residue = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash=bogus_prev,
        )
        with pytest.raises(BrokenChain):
            ledger.append(residue)


# -- Phase 2 hardening: duplicate-entry rejection (ARCH §11.1) ------------


class TestDuplicateEntryRejection:
    """Phase 2 defense-in-depth backstop: the ledger refuses to record a
    second entry with the same (task_id, action_type, operation) tuple.

    In normal operation the inbound gateway's nonce seen-set catches replays
    earlier, but if that misses (e.g., process restart inside the clock-skew
    window), the ledger itself refuses the duplicate.
    """

    def test_duplicate_task_action_operation_rejected(
        self, signer_a: Signer
    ) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            task_id="task-replay-target",
            action_type=ActionType.RECEIVE,
            operation=Operation.PROPOSAL,
        )
        prev_hash = ledger.append(first)

        duplicate = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=prev_hash,
            task_id="task-replay-target",
            action_type=ActionType.RECEIVE,
            operation=Operation.PROPOSAL,
            # Different context_id and timestamp, but same tuple.
            context_id="ctx-replay",
            timestamp="2026-05-23T15:30:01Z",
        )
        with pytest.raises(DuplicateEntry, match="already exists"):
            ledger.append(duplicate)

    def test_different_action_type_same_task_ok(
        self, signer_a: Signer
    ) -> None:
        """EMIT and RECEIVE entries for the same task_id+operation are
        intentionally distinct — that's the normal request/response pattern
        on the originating side."""
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        emit = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            task_id="task-1",
            action_type=ActionType.EMIT,
            operation=Operation.PROPOSAL,
        )
        prev = ledger.append(emit)

        receive = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=prev,
            task_id="task-1",
            action_type=ActionType.RECEIVE,
            operation=Operation.PROPOSAL,
        )
        ledger.append(receive)
        assert len(ledger) == 2

    def test_different_operation_same_task_ok(self, signer_a: Signer) -> None:
        """A multi-turn task with PROPOSAL then COUNTER on the same direction
        is legitimate — only exact (task, direction, op) tuples are duplicate."""
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        proposal = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            task_id="task-1",
            action_type=ActionType.EMIT,
            operation=Operation.PROPOSAL,
        )
        prev = ledger.append(proposal)
        counter = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=prev,
            task_id="task-1",
            action_type=ActionType.EMIT,
            operation=Operation.COUNTER,
        )
        ledger.append(counter)
        assert len(ledger) == 2

    def test_different_task_same_action_operation_ok(
        self, signer_a: Signer
    ) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            task_id="task-1",
            action_type=ActionType.RECEIVE,
            operation=Operation.PROPOSAL,
        )
        prev = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=prev,
            task_id="task-2",
            action_type=ActionType.RECEIVE,
            operation=Operation.PROPOSAL,
        )
        ledger.append(second)
        assert len(ledger) == 2


# -- Queries -------------------------------------------------------------


class TestQueries:
    def test_get_all_orders_by_sequence(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        head = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=head,
            operation=Operation.ACCEPTANCE,
        )
        ledger.append(second)
        rows = ledger.get_all()
        assert [r.sequence for r in rows] == [0, 1]
        assert rows[0].operation == Operation.PROPOSAL
        assert rows[1].operation == Operation.ACCEPTANCE

    def test_get_by_task_filters(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            task_id="task-A",
        )
        head = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=head,
            task_id="task-B",
            operation=Operation.ACCEPTANCE,
        )
        ledger.append(second)
        assert len(ledger.get_by_task("task-A")) == 1
        assert ledger.get_by_task("task-A")[0].task_id == "task-A"
        assert len(ledger.get_by_task("task-B")) == 1
        assert ledger.get_by_task("nonexistent") == []

    def test_get_by_context_filters(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=0,
            previous_hash="",
            context_id="ctx-X",
        )
        head = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=head,
            context_id="ctx-Y",
            operation=Operation.ACCEPTANCE,
        )
        ledger.append(second)
        assert [r.context_id for r in ledger.get_by_context("ctx-X")] == ["ctx-X"]
        assert [r.context_id for r in ledger.get_by_context("ctx-Y")] == ["ctx-Y"]


# -- verify_chain --------------------------------------------------------


class TestVerifyChain:
    def test_empty_ledger_chain_is_valid(self) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        assert ledger.verify_chain() is True

    def test_clean_two_entry_chain_is_valid(self, signer_a: Signer) -> None:
        ledger = ProvenanceLedger(db_path=":memory:", ledger_owner=OWNER_A)
        first = build_signed_residue(
            signer=signer_a, ledger_owner=OWNER_A, sequence=0, previous_hash=""
        )
        head = ledger.append(first)
        second = build_signed_residue(
            signer=signer_a,
            ledger_owner=OWNER_A,
            sequence=1,
            previous_hash=head,
            operation=Operation.ACCEPTANCE,
        )
        ledger.append(second)
        assert ledger.verify_chain() is True

    def test_on_disk_tamper_breaks_chain(
        self, tmp_path: Path, signer_a: Signer
    ) -> None:
        """Directly mutate the DB outside the API; verify_chain must catch it."""
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            first = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=0,
                previous_hash="",
            )
            ledger.append(first)
        # Tamper directly via sqlite, replacing the entry_json with a
        # valid-but-different Residue (different timestamp).
        with sqlite3.connect(db) as raw:
            row = raw.execute(
                "SELECT entry_json FROM residue_entries WHERE sequence=0"
            ).fetchone()
            tampered = row[0].replace(
                "2026-05-23T15:30:00Z", "2099-01-01T00:00:00Z"
            )
            raw.execute(
                "UPDATE residue_entries SET entry_json = ? WHERE sequence=0",
                (tampered,),
            )
        # Reopen: the entry still parses (it's a valid Residue) but its
        # canonical hash no longer matches what previous_hash would have
        # been. For sequence=0 the chain assertion is `previous_hash == ""`
        # which is still true post-tamper, so for this specific tamper we
        # also need to add a sequence=1 to detect the break. Do so via the
        # API to anchor the broken link.
        # Easier: tamper sequence's value to be wrong instead.
        with sqlite3.connect(db) as raw:
            raw.execute(
                "UPDATE residue_entries SET entry_json = "
                "json_set(entry_json, '$.sequence', 99) "
                "WHERE sequence=0"
            )
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.verify_chain() is False

    def test_invalid_json_on_disk_returns_false_not_raises(
        self, tmp_path: Path, signer_a: Signer
    ) -> None:
        """If a row's stored bytes can't be parsed as JSON, verify_chain
        must return False (not raise). Per verify_chain's contract: an
        undecodable row is, by definition, an invalid chain link.

        Note on the Phase 2 UNIQUE INDEX: the index uses ``json_extract``,
        so SQLite refuses ``UPDATE ... SET entry_json = 'not valid json'``
        at the SQL layer (the index would corrupt). To simulate an attacker
        with raw file access (who bypasses SQLite's checks entirely), we
        drop the index first then tamper, on the same open ledger instance
        so the schema-init path doesn't run again. This reflects the actual
        threat model: SQL-layer constraints don't defend against bytes-on-disk
        attacks; verify_chain does.
        """
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            first = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=0,
                previous_hash="",
            )
            ledger.append(first)
            # Reach into the open connection (no reopen — that would
            # re-run _init_schema and fail to recreate the dropped index).
            conn = ledger._conn  # type: ignore[attr-defined]
            conn.execute(
                "DROP INDEX IF EXISTS idx_residue_unique_task_action_op"
            )
            # Belt-and-suspenders: prove the index is actually gone, so this
            # test cannot silently pass for the wrong reason if a future
            # change makes the index resilient to invalid JSON.
            present = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name = 'idx_residue_unique_task_action_op'"
            ).fetchone()
            assert present is None
            conn.execute(
                "UPDATE residue_entries SET entry_json = 'not valid json' "
                "WHERE sequence=0"
            )
            conn.commit()
            assert ledger.verify_chain() is False

    def test_schema_invalid_row_returns_false_not_raises(
        self, tmp_path: Path, signer_a: Signer
    ) -> None:
        """Valid JSON but not a valid Residue (missing required field) →
        verify_chain returns False, not raises ValidationError."""
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            first = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=0,
                previous_hash="",
            )
            ledger.append(first)
        with sqlite3.connect(db) as raw:
            raw.execute(
                "UPDATE residue_entries SET entry_json = '{\"version\": 1}' "
                "WHERE sequence=0"
            )
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.verify_chain() is False

    def test_broken_chain_link_detected(
        self, tmp_path: Path, signer_a: Signer
    ) -> None:
        """Two valid entries, then on-disk mutate entry-1's previous_hash."""
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            first = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=0,
                previous_hash="",
            )
            head = ledger.append(first)
            second = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=1,
                previous_hash=head,
                operation=Operation.ACCEPTANCE,
            )
            ledger.append(second)
            assert ledger.verify_chain() is True
        with sqlite3.connect(db) as raw:
            raw.execute(
                "UPDATE residue_entries SET entry_json = "
                "json_set(entry_json, '$.previous_hash', ?) "
                "WHERE sequence=1",
                ("b" * 64,),
            )
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.verify_chain() is False


# -- Cold reload (SPEC §5 assertion 14) ---------------------------------


class TestColdReload:
    def test_ledger_survives_close_and_reopen(
        self, tmp_path: Path, signer_a: Signer
    ) -> None:
        db = tmp_path / "ledger.sqlite"
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            first = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=0,
                previous_hash="",
            )
            head = ledger.append(first)
            second = build_signed_residue(
                signer=signer_a,
                ledger_owner=OWNER_A,
                sequence=1,
                previous_hash=head,
                operation=Operation.ACCEPTANCE,
            )
            ledger.append(second)
            entries_before = ledger.get_all()
        # Process boundary: open from cold.
        with ProvenanceLedger(db_path=db, ledger_owner=OWNER_A) as ledger:
            assert ledger.verify_chain() is True
            entries_after = ledger.get_all()
            assert entries_before == entries_after
            assert ledger.next_sequence == 2
