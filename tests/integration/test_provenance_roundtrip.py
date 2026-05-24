"""In-process provenance round-trip integration tests.

Per demos/phase_1/SPEC.md §7 and §8: steps 1-3 are pure-Mesherra and can
run as an in-process round-trip *before* the A2A wire exists in step 4.
This file exercises the cross-module mechanic — model + crypto + ledger
working together to produce matched signed entries on two principals'
ledgers — without any networking. When step 4 lands, the
``emit_then_receive`` helper below is the function that gets replaced with
real A2A SendMessage / receive callback wiring; if these tests still pass
with the wire in place, the wire works.

SPEC §5 assertion coverage delivered here (no-wire equivalent):

  * #1  two entries on each ledger
  * #2  hash chain valid on both
  * #3  every signature verifies under the actor's public key
  * #5/#6  emit/receive action_type pairing
  * #7  payload_hash byte-equal across A's emit-0 and B's receive-0
  * #8/#9  task_id and context_id equal across both sides
  * #12 acceptance payload_hash byte-equal across B's emit-1 and A's receive-1
  * #13 acceptance slot is one of the originally-proposed candidates
  * #14 cold-reload re-verify (close ledgers, reopen from disk, verify chains +
       re-verify signatures from cold)

The remaining cross-ledger assertions (#4 timestamp ordering, #10/#11 the
B-side acceptance pairing) are orchestrator-level concerns in step 7's
``run_demo.py``; they will be verified end-to-end there once the demo runs.

No real principal identifiers, calendar data, or keys appear in fixtures —
all keys are generated per test (``Signer.generate``); principal ids use
the synthetic ``@phase1.local`` domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.models.primitives import ActionType, Operation, Residue
from mesherra.provenance.ledger import ProvenanceLedger

# -- Constants & synthetic test data -------------------------------------


OWNER_A = "user-a@phase1.local"
OWNER_B = "user-b@phase1.local"

TASK_ID = "task-7f3a"
CONTEXT_ID = "ctx-1b2c"

TIMESTAMP_A_EMIT = "2026-05-23T15:30:00Z"
TIMESTAMP_B_RECEIVE_PROPOSAL = "2026-05-23T15:30:01Z"
TIMESTAMP_B_EMIT = "2026-05-23T15:30:02Z"
TIMESTAMP_A_RECEIVE_ACCEPTANCE = "2026-05-23T15:30:03Z"

PROPOSAL_PAYLOAD_SCHEMA = "meshycal.scheduling/proposal-v1"

PROPOSAL_PAYLOAD: dict[str, Any] = {
    "candidates": [
        "2026-05-26T14:00:00Z",
        "2026-05-27T10:00:00Z",
        "2026-05-28T16:30:00Z",
    ],
    "duration_minutes": 30,
}

ACCEPTANCE_PAYLOAD: dict[str, Any] = {
    "candidates": ["2026-05-26T14:00:00Z"],
    "duration_minutes": 30,
}


# -- Principal helper ----------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """A Phase 1 principal: id, key material, ledger.

    Stand-in for an Agent until Phase 2 lands the real type. Holds exactly
    what a phase-1 round-trip needs: an identifier, an Ed25519 signer, and
    an open ledger shard. Construct via :func:`make_principal`.
    """

    principal_id: str
    signer: Signer
    ledger: ProvenanceLedger


def make_principal(*, principal_id: str, db_dir: Path) -> Principal:
    """Build a Principal with a fresh keypair and an on-disk ledger.

    ``db_dir`` is typically pytest's ``tmp_path`` so each test gets its own
    isolated SQLite files. The ledger file is named after the principal id
    for clarity in any post-run inspection.
    """
    signer = Signer.generate()
    db_path = db_dir / f"{_safe_filename(principal_id)}.sqlite"
    ledger = ProvenanceLedger(db_path=db_path, ledger_owner=principal_id)
    return Principal(principal_id=principal_id, signer=signer, ledger=ledger)


def _safe_filename(principal_id: str) -> str:
    return principal_id.replace("@", "_at_").replace("/", "_")


# -- emit_then_receive: the heart of the helper --------------------------


def emit_then_receive(
    *,
    sender: Principal,
    receiver: Principal,
    operation: Operation,
    payload: dict[str, Any],
    task_id: str = TASK_ID,
    context_id: str = CONTEXT_ID,
    timestamp_emit: str,
    timestamp_receive: str,
    payload_schema: str = PROPOSAL_PAYLOAD_SCHEMA,
) -> tuple[Residue, Residue]:
    """Simulate sender→receiver flow without the A2A wire.

    Mechanic (will become A2A SendMessage in step 4):

    1. Sender computes ``payload_hash``, builds emit entry, signs it,
       appends to their ledger.
    2. The entry's canonical bytes are conceptually transmitted to the
       receiver (here: returned as a Residue object).
    3. Receiver constructs a Verifier from the sender's *published public
       key only* (not from their Signer) and verifies the sender's
       signature. If this fails, raise — the wire is broken and no
       receive entry should be written.
    4. Receiver builds the matching receive entry with the same
       ``payload_hash`` / ``task_id`` / ``context_id`` / ``payload_schema``,
       signs it with their own key, appends to their ledger.

    Returns ``(sender_emit_entry, receiver_receive_entry)``.

    Both entries share: ``task_id``, ``context_id``, ``payload_hash``,
    ``payload_schema``, ``operation``, ``actor`` (=sender),
    ``counterpart`` (=receiver). They differ in: ``ledger_owner``
    (each side's own), ``action_type`` (emit vs receive), ``timestamp``,
    ``signature``, ``sequence`` (each side's own next index),
    ``previous_hash`` (each side's own prior head).

    This asymmetry is exactly what SPEC §3 prescribes: per-side
    accountability, not joint signature.
    """
    payload_hash = content_hash(canonical_json(payload))

    sender_emit_entry = _sign_and_append(
        ledger=sender.ledger,
        signer=sender.signer,
        actor=sender.principal_id,
        counterpart=receiver.principal_id,
        action_type=ActionType.EMIT,
        operation=operation,
        task_id=task_id,
        context_id=context_id,
        timestamp=timestamp_emit,
        payload_hash=payload_hash,
        payload_schema=payload_schema,
    )

    sender_verifier_from_public_only = Verifier.from_b64(
        sender.signer.public_key_b64()
    )
    sender_signed_bytes = canonical_json(sender_emit_entry.to_signing_payload())
    if not sender_verifier_from_public_only.verify(
        sender_signed_bytes, sender_emit_entry.signature
    ):
        raise RuntimeError(
            f"Sender {sender.principal_id} signature did not verify "
            "under their published public key — wire is broken; no "
            "receive entry will be written."
        )

    receiver_receive_entry = _sign_and_append(
        ledger=receiver.ledger,
        signer=receiver.signer,
        actor=sender.principal_id,
        counterpart=receiver.principal_id,
        action_type=ActionType.RECEIVE,
        operation=operation,
        task_id=task_id,
        context_id=context_id,
        timestamp=timestamp_receive,
        payload_hash=payload_hash,
        payload_schema=payload_schema,
    )

    return sender_emit_entry, receiver_receive_entry


def _sign_and_append(
    *,
    ledger: ProvenanceLedger,
    signer: Signer,
    actor: str,
    counterpart: str,
    action_type: ActionType,
    operation: Operation,
    task_id: str,
    context_id: str,
    timestamp: str,
    payload_hash: str,
    payload_schema: str,
) -> Residue:
    """Build a Residue, sign its canonical bytes, append to ledger.

    The fields dict is constructed with enum *values* (strings) so the
    canonical bytes match what ``Residue.to_signing_payload`` produces at
    verification time (Pydantic serializes enums to their string value via
    ``model_dump(mode="json")``).
    """
    fields = {
        "version": 1,
        "ledger_owner": ledger.ledger_owner,
        "task_id": task_id,
        "context_id": context_id,
        "sequence": ledger.next_sequence,
        "previous_hash": ledger.head_hash,
        "timestamp": timestamp,
        "actor": actor,
        "counterpart": counterpart,
        "action_type": action_type.value,
        "operation": operation.value,
        "payload_hash": payload_hash,
        "payload_schema": payload_schema,
    }
    signature = signer.sign(canonical_json(fields))
    residue = Residue(**fields, signature=signature)
    ledger.append(residue)
    return residue


# -- Fixtures ------------------------------------------------------------


@pytest.fixture
def principal_a(tmp_path: Path) -> Principal:
    return make_principal(principal_id=OWNER_A, db_dir=tmp_path)


@pytest.fixture
def principal_b(tmp_path: Path) -> Principal:
    return make_principal(principal_id=OWNER_B, db_dir=tmp_path)


@pytest.fixture
def proposal_pair(
    principal_a: Principal, principal_b: Principal
) -> tuple[Residue, Residue]:
    """A's proposal → B's receive of proposal. Sequence 0 on both sides."""
    return emit_then_receive(
        sender=principal_a,
        receiver=principal_b,
        operation=Operation.PROPOSAL,
        payload=PROPOSAL_PAYLOAD,
        timestamp_emit=TIMESTAMP_A_EMIT,
        timestamp_receive=TIMESTAMP_B_RECEIVE_PROPOSAL,
    )


@pytest.fixture
def round_trip_pairs(
    principal_a: Principal, principal_b: Principal
) -> tuple[tuple[Residue, Residue], tuple[Residue, Residue]]:
    """Full demo flow: A proposes → B accepts. Returns ((proposal pair), (acceptance pair))."""
    proposal_pair = emit_then_receive(
        sender=principal_a,
        receiver=principal_b,
        operation=Operation.PROPOSAL,
        payload=PROPOSAL_PAYLOAD,
        timestamp_emit=TIMESTAMP_A_EMIT,
        timestamp_receive=TIMESTAMP_B_RECEIVE_PROPOSAL,
    )
    acceptance_pair = emit_then_receive(
        sender=principal_b,
        receiver=principal_a,
        operation=Operation.ACCEPTANCE,
        payload=ACCEPTANCE_PAYLOAD,
        timestamp_emit=TIMESTAMP_B_EMIT,
        timestamp_receive=TIMESTAMP_A_RECEIVE_ACCEPTANCE,
    )
    return proposal_pair, acceptance_pair


# -- Tests ---------------------------------------------------------------
# Each team agent fills in one of the slots below.


class TestProposalEmitReceive:
    """Half-round-trip: A emits a proposal, B receives.

    Locks in the cross-module mechanic where step 1 (model), step 2 (crypto),
    and step 3 (ledger) cooperate to produce matched signed entries on two
    independent ledgers.
    """

    def test_emit_and_receive_share_payload_hash(self, proposal_pair):
        """SPEC §5 #7: A's emit-0 and B's receive-0 carry byte-equal payload_hash of PROPOSAL_PAYLOAD."""
        a_emit, b_receive = proposal_pair
        expected_hash = content_hash(canonical_json(PROPOSAL_PAYLOAD))
        assert a_emit.payload_hash == b_receive.payload_hash
        assert a_emit.payload_hash == expected_hash

    def test_emit_and_receive_share_linkage_fields(
        self, proposal_pair: tuple[Residue, Residue]
    ) -> None:
        """Lock in cross-ledger linkage: task_id, context_id, payload_schema, operation, and actor/counterpart match across A's emit and B's receive."""
        a_emit, b_receive = proposal_pair

        assert a_emit.task_id == b_receive.task_id
        assert a_emit.context_id == b_receive.context_id
        assert a_emit.payload_schema == b_receive.payload_schema
        assert a_emit.operation == b_receive.operation

        assert a_emit.task_id == TASK_ID
        assert a_emit.context_id == CONTEXT_ID
        assert a_emit.payload_schema == PROPOSAL_PAYLOAD_SCHEMA
        assert a_emit.operation == Operation.PROPOSAL
        assert b_receive.operation == Operation.PROPOSAL

        assert a_emit.actor == OWNER_A
        assert b_receive.actor == OWNER_A
        assert a_emit.counterpart == OWNER_B
        assert b_receive.counterpart == OWNER_B

    def test_action_types_are_inverse(
        self, proposal_pair: tuple[Residue, Residue]
    ) -> None:
        """Lock in per-side accountability: A emits, B receives, both proposal."""
        a_emit, b_receive = proposal_pair

        assert a_emit.action_type == ActionType.EMIT
        assert b_receive.action_type == ActionType.RECEIVE

        assert a_emit.operation == Operation.PROPOSAL
        assert b_receive.operation == Operation.PROPOSAL

        assert a_emit.ledger_owner == OWNER_A
        assert b_receive.ledger_owner == OWNER_B

    def test_b_verifies_a_signature_with_only_public_key(
        self,
        proposal_pair: tuple[Residue, Residue],
        principal_a: Principal,
    ) -> None:
        """SPEC §5 #3: B verifies A's emit signature using only the published public key, no private material."""
        a_emit, _ = proposal_pair
        published_public_key_b64 = principal_a.signer.public_key_b64()
        verifier = Verifier.from_b64(published_public_key_b64)
        canonical_bytes = canonical_json(a_emit.to_signing_payload())
        assert verifier.verify(canonical_bytes, a_emit.signature) is True

    def test_b_rejects_signature_over_tampered_payload(
        self, proposal_pair, principal_a
    ):
        """Tessera coherence: tampered bytes must hard-fail verification (soft-pass not allowed)."""
        a_emit, _ = proposal_pair
        verifier = Verifier.from_b64(principal_a.signer.public_key_b64())
        original_payload = a_emit.to_signing_payload()
        original_bytes = canonical_json(original_payload)
        tampered_payload = dict(original_payload)
        tampered_payload["payload_hash"] = "0" * len(original_payload["payload_hash"])
        tampered_bytes = canonical_json(tampered_payload)
        assert tampered_bytes != original_bytes
        assert verifier.verify(tampered_bytes, a_emit.signature) is False


class TestFullProposalAcceptanceRoundTrip:
    """Full Phase 1 demo flow minus the wire: proposal-then-acceptance.

    Two entries per ledger; matched payload hashes on both turns; the
    accepted slot is one of the proposed candidates. This is the "no-wire
    dress rehearsal" of the Phase 1 demo.
    """

    def test_round_trip_yields_valid_chains_on_both_sides(
        self,
        round_trip_pairs: tuple[tuple[Residue, Residue], tuple[Residue, Residue]],
        principal_a: Principal,
        principal_b: Principal,
    ) -> None:
        """Demo round-trip lands exactly two sequenced entries per ledger and both chains verify."""
        assert len(principal_a.ledger) == 2
        assert len(principal_b.ledger) == 2
        assert [e.sequence for e in principal_a.ledger.get_all()] == [0, 1]
        assert [e.sequence for e in principal_b.ledger.get_all()] == [0, 1]
        assert principal_a.ledger.verify_chain() is True
        assert principal_b.ledger.verify_chain() is True

    def test_acceptance_payload_hashes_match_across_ledgers(
        self,
        round_trip_pairs: tuple[tuple[Residue, Residue], tuple[Residue, Residue]],
    ) -> None:
        """SPEC §5 #12: B's acceptance emit and A's acceptance receive carry the same payload_hash, equal to content_hash of canonical ACCEPTANCE_PAYLOAD."""
        _proposal_pair, acceptance_pair = round_trip_pairs
        b_emits_acceptance, a_receives_acceptance = acceptance_pair
        assert b_emits_acceptance.payload_hash == a_receives_acceptance.payload_hash
        expected_hash = content_hash(canonical_json(ACCEPTANCE_PAYLOAD))
        assert b_emits_acceptance.payload_hash == expected_hash

    def test_acceptance_slot_is_one_of_proposed_candidates(self):
        """Fixture-coherence check: ACCEPTANCE_PAYLOAD names exactly one slot from PROPOSAL_PAYLOAD.

        The semantic SPEC §5 #13 check (the slot accepted by the *agent* is one
        the *agent* proposed) lives in step 7's run_demo.py, where slot selection
        is real behavior. Here we only ensure the test fixtures themselves
        respect the constraint so the rest of the file exercises a realistic
        scenario.
        """
        assert len(ACCEPTANCE_PAYLOAD["candidates"]) == 1
        chosen_slot = ACCEPTANCE_PAYLOAD["candidates"][0]
        assert chosen_slot in PROPOSAL_PAYLOAD["candidates"]


class TestColdReverify:
    """SPEC §5 assertion 14: ledgers persist after termination and re-verify.

    Two SQLite files on disk; close both; reopen from cold; verify chains;
    re-verify every signature using only the publicly-available public keys.
    This is the full Phase 1 trust promise demonstrated end-to-end without
    any network.
    """

    def test_both_ledgers_survive_close_and_reopen(
        self,
        principal_a: Principal,
        principal_b: Principal,
        round_trip_pairs: tuple[tuple[Residue, Residue], tuple[Residue, Residue]],
    ) -> None:
        """Cold reload: ledger files re-open after termination and re-verify their chains."""
        del round_trip_pairs  # fixture used for its side effect of populating ledgers
        path_a = principal_a.ledger.db_path
        path_b = principal_b.ledger.db_path
        entries_a_before = principal_a.ledger.get_all()
        entries_b_before = principal_b.ledger.get_all()
        principal_a.ledger.close()
        principal_b.ledger.close()
        with ProvenanceLedger(db_path=path_a, ledger_owner=OWNER_A) as reopened_a:
            assert len(reopened_a.get_all()) == 2
            assert reopened_a.verify_chain() is True
            assert reopened_a.get_all() == entries_a_before
        with ProvenanceLedger(db_path=path_b, ledger_owner=OWNER_B) as reopened_b:
            assert len(reopened_b.get_all()) == 2
            assert reopened_b.verify_chain() is True
            assert reopened_b.get_all() == entries_b_before

    def test_signatures_reverify_after_cold_reload(
        self,
        principal_a,
        principal_b,
        round_trip_pairs,
    ) -> None:
        """Every signed entry re-verifies under its ledger_owner's public key after a cold reload.

        Lookup is by ``entry.ledger_owner`` (not ``entry.actor``) — each entry
        on a ledger was signed by that ledger's owner with their own key.
        """
        del round_trip_pairs
        public_keys = {
            OWNER_A: principal_a.signer.public_key_b64(),
            OWNER_B: principal_b.signer.public_key_b64(),
        }
        path_a = principal_a.ledger.db_path
        path_b = principal_b.ledger.db_path

        principal_a.ledger.close()
        principal_b.ledger.close()

        with ProvenanceLedger(db_path=path_a, ledger_owner=OWNER_A) as ledger_a, \
             ProvenanceLedger(db_path=path_b, ledger_owner=OWNER_B) as ledger_b:
            for ledger in (ledger_a, ledger_b):
                entries = ledger.get_all()
                assert len(entries) == 2
                for entry in entries:
                    verifier = Verifier.from_b64(public_keys[entry.ledger_owner])
                    canonical_bytes = canonical_json(entry.to_signing_payload())
                    assert verifier.verify(canonical_bytes, entry.signature) is True
