"""Full SDK round-trip integration tests for Phase 1 step 5.

Two Mesherra instances on localhost. Real Ed25519 keys. Real on-disk ledgers.
Real A2A wire. The full Phase 1 demo flow without the MeshyCal scheduling
agents (step 6) or the orchestrator (step 7).

If these tests pass, the Mesherra trust-layer plumbing is sound end-to-end:

* SendClaim sign + verify across the wire works.
* Both principals' ledgers receive matched entries with shared payload_hash,
  task_id, context_id, payload_schema.
* Hash-chain integrity holds on both ledgers.
* Cold reload re-verifies the chains.

These are the SDK-level analogues of the SPEC §5 assertions. Step 7's
``run_demo.py`` will run the full 14 assertions end-to-end including the
scheduling agent logic in step 6.

No real principal data: synthetic ids, per-test generated keys, synthetic
calendar slots.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from mesherra.a2a_adapter import A2AAdapter
from mesherra.crypto.primitives import Signer
from mesherra.gateways.inbound import IncomingMessage, OutgoingResponse
from mesherra.gateways.outbound import PeerSignatureVerificationError
from mesherra.identity import StaticDirectoryClient, UnknownPrincipalError
from mesherra.models.primitives import ActionType, Operation
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import Mesherra

OWNER_A = "user-a@phase1.local"
OWNER_B = "user-b@phase1.local"

PROPOSAL_PAYLOAD = {
    "candidates": [
        "2026-05-26T14:00:00Z",
        "2026-05-27T10:00:00Z",
        "2026-05-28T16:30:00Z",
    ],
    "duration_minutes": 30,
}
PAYLOAD_SCHEMA = "meshycal.scheduling/proposal-v1"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _safe_filename(principal_id: str) -> str:
    return principal_id.replace("@", "_at_").replace("/", "_")


def _make_mesherra(
    *,
    principal_id: str,
    signer: Signer,
    db_dir: Path,
    public_key_directory: dict[str, str],
) -> tuple[Mesherra, ProvenanceLedger]:
    """Build a Mesherra instance bound to a fresh on-disk ledger."""
    db_path = db_dir / f"{_safe_filename(principal_id)}.sqlite"
    ledger = ProvenanceLedger(db_path=db_path, ledger_owner=principal_id)
    adapter = A2AAdapter()
    sdk = Mesherra(
        principal_id=principal_id,
        signer=signer,
        ledger=ledger,
        adapter=adapter,
        directory=StaticDirectoryClient(public_key_directory),
    )
    return sdk, ledger


class TestSdkFullRoundTrip:
    """The full Phase 1 demo flow at the SDK level (no MeshyCal agents yet).

    A sends a proposal to B; B's consumer handler picks the first slot and
    returns an acceptance; A receives the acceptance. Both ledgers end up
    with two entries each, the chains valid, all signatures verifying.
    """

    async def test_proposal_acceptance_round_trip(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()

        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }

        a_sdk, a_ledger = _make_mesherra(
            principal_id=OWNER_A,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        b_sdk, b_ledger = _make_mesherra(
            principal_id=OWNER_B,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        # B's consumer handler: pick the first proposed candidate.
        async def b_consumer(msg: IncomingMessage) -> OutgoingResponse:
            assert msg.sender_principal_id == OWNER_A
            assert msg.operation == Operation.PROPOSAL
            chosen = msg.payload["candidates"][0]
            return OutgoingResponse(
                payload={"candidates": [chosen], "duration_minutes": 30},
                operation=Operation.ACCEPTANCE,
            )

        b_sdk.on_message(b_consumer)
        # A registers a placeholder handler too (A2AAdapter requires one before
        # start_listener; A never receives in this test, but the requirement is
        # symmetric for the future bi-directional flow).
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )

        try:
            # A initiates: send proposal to B.
            result = await a_sdk.send_to(
                peer_url=f"http://127.0.0.1:{b_port}/",
                peer_principal_id=OWNER_B,
                payload=PROPOSAL_PAYLOAD,
                payload_schema=PAYLOAD_SCHEMA,
                operation=Operation.PROPOSAL,
            )

            # A's outbound result.
            assert result.response_sender_principal_id == OWNER_B
            assert result.response_operation == Operation.ACCEPTANCE
            assert result.response_payload["candidates"] == [
                PROPOSAL_PAYLOAD["candidates"][0]
            ]
            assert result.task_id != ""

            # A's ledger: 2 entries (emit proposal, receive acceptance).
            a_entries = a_ledger.get_all()
            assert len(a_entries) == 2
            assert a_entries[0].action_type == ActionType.EMIT
            assert a_entries[0].operation == Operation.PROPOSAL
            assert a_entries[0].actor == OWNER_A
            assert a_entries[0].counterpart == OWNER_B
            assert a_entries[1].action_type == ActionType.RECEIVE
            assert a_entries[1].operation == Operation.ACCEPTANCE
            assert a_entries[1].actor == OWNER_B
            assert a_entries[1].counterpart == OWNER_A
            assert a_ledger.verify_chain() is True

            # B's ledger: 2 entries (receive proposal, emit acceptance).
            b_entries = b_ledger.get_all()
            assert len(b_entries) == 2
            assert b_entries[0].action_type == ActionType.RECEIVE
            assert b_entries[0].operation == Operation.PROPOSAL
            assert b_entries[0].actor == OWNER_A
            assert b_entries[0].counterpart == OWNER_B
            assert b_entries[1].action_type == ActionType.EMIT
            assert b_entries[1].operation == Operation.ACCEPTANCE
            assert b_entries[1].actor == OWNER_B
            assert b_entries[1].counterpart == OWNER_A
            assert b_ledger.verify_chain() is True

            # Cross-ledger linkage on the proposal turn (SPEC §5 #7, #8, #9).
            assert a_entries[0].payload_hash == b_entries[0].payload_hash
            assert a_entries[0].task_id == b_entries[0].task_id
            assert a_entries[0].context_id == b_entries[0].context_id
            assert a_entries[0].payload_schema == b_entries[0].payload_schema

            # Cross-ledger linkage on the acceptance turn (SPEC §5 #12).
            assert a_entries[1].payload_hash == b_entries[1].payload_hash
            assert a_entries[1].task_id == b_entries[1].task_id
            assert a_entries[1].context_id == b_entries[1].context_id

            # Both task_id and context_id span the whole exchange.
            assert a_entries[0].task_id == a_entries[1].task_id
            assert a_entries[0].context_id == a_entries[1].context_id
        finally:
            await b_handle.stop()


class TestSdkColdReverify:
    """SPEC §5 #14 at the SDK level: ledgers persist and re-verify cold."""

    async def test_both_ledgers_survive_close_and_reopen(
        self, tmp_path: Path
    ) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }
        a_sdk, a_ledger = _make_mesherra(
            principal_id=OWNER_A,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        b_sdk, b_ledger = _make_mesherra(
            principal_id=OWNER_B,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        async def b_consumer(msg: IncomingMessage) -> OutgoingResponse:
            return OutgoingResponse(
                payload={"candidates": [msg.payload["candidates"][0]], "duration_minutes": 30},
                operation=Operation.ACCEPTANCE,
            )

        b_sdk.on_message(b_consumer)
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            await a_sdk.send_to(
                peer_url=f"http://127.0.0.1:{b_port}/",
                peer_principal_id=OWNER_B,
                payload=PROPOSAL_PAYLOAD,
                payload_schema=PAYLOAD_SCHEMA,
                operation=Operation.PROPOSAL,
            )

            # Capture paths and entries before close.
            a_path = a_ledger.db_path
            b_path = b_ledger.db_path
            a_entries_before = a_ledger.get_all()
            b_entries_before = b_ledger.get_all()
        finally:
            await b_handle.stop()

        a_ledger.close()
        b_ledger.close()

        # Reopen cold and re-verify.
        with ProvenanceLedger(db_path=a_path, ledger_owner=OWNER_A) as a_re:
            assert a_re.verify_chain() is True
            assert a_re.get_all() == a_entries_before
        with ProvenanceLedger(db_path=b_path, ledger_owner=OWNER_B) as b_re:
            assert b_re.verify_chain() is True
            assert b_re.get_all() == b_entries_before


class TestSdkErrorPaths:
    """The gateways must hard-fail on auth violations rather than silently
    write residues."""

    async def test_unknown_peer_principal_raises(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        # Directory deliberately omits OWNER_B.
        a_sdk, _ = _make_mesherra(
            principal_id=OWNER_A,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory={OWNER_A: a_signer.public_key_b64()},
        )
        with pytest.raises(UnknownPrincipalError, match=OWNER_B):
            await a_sdk.send_to(
                peer_url="http://127.0.0.1:9999/",
                peer_principal_id=OWNER_B,
                payload=PROPOSAL_PAYLOAD,
                payload_schema=PAYLOAD_SCHEMA,
                operation=Operation.PROPOSAL,
            )

    async def test_peer_signs_with_wrong_key_rejection(
        self, tmp_path: Path
    ) -> None:
        """If B's actual signing key differs from the directory entry, A's
        outbound gateway must reject the response and raise."""
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        wrong_b_signer = Signer.generate()  # what A thinks B uses

        # Directory binds OWNER_B to wrong_b_signer's public key — but B is
        # actually signing with b_signer. Verification will fail on A's side.
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: wrong_b_signer.public_key_b64(),
        }
        a_sdk, _ = _make_mesherra(
            principal_id=OWNER_A,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        # B uses its real key (mismatched against the directory).
        b_sdk, _ = _make_mesherra(
            principal_id=OWNER_B,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory={
                OWNER_A: a_signer.public_key_b64(),
                OWNER_B: b_signer.public_key_b64(),  # B's own directory correct
            },
        )

        async def b_consumer(msg: IncomingMessage) -> OutgoingResponse:
            return OutgoingResponse(
                payload={"candidates": [msg.payload["candidates"][0]], "duration_minutes": 30},
                operation=Operation.ACCEPTANCE,
            )

        b_sdk.on_message(b_consumer)
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            with pytest.raises(PeerSignatureVerificationError):
                await a_sdk.send_to(
                    peer_url=f"http://127.0.0.1:{b_port}/",
                    peer_principal_id=OWNER_B,
                    payload=PROPOSAL_PAYLOAD,
                    payload_schema=PAYLOAD_SCHEMA,
                    operation=Operation.PROPOSAL,
                )
        finally:
            await b_handle.stop()


class TestSdkLedgerAccessors:
    """The Phase 1 attest / get_residue / get_residue_chain surface."""

    async def test_get_residue_and_chain_after_round_trip(
        self, tmp_path: Path
    ) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }
        a_sdk, _ = _make_mesherra(
            principal_id=OWNER_A,
            signer=a_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )
        b_sdk, _ = _make_mesherra(
            principal_id=OWNER_B,
            signer=b_signer,
            db_dir=tmp_path,
            public_key_directory=public_keys,
        )

        async def b_consumer(msg: IncomingMessage) -> OutgoingResponse:
            return OutgoingResponse(
                payload={"candidates": [msg.payload["candidates"][0]], "duration_minutes": 30},
                operation=Operation.ACCEPTANCE,
            )

        b_sdk.on_message(b_consumer)
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            ctx_id = "ctx-accessor-test"
            result = await a_sdk.send_to(
                peer_url=f"http://127.0.0.1:{b_port}/",
                peer_principal_id=OWNER_B,
                payload=PROPOSAL_PAYLOAD,
                payload_schema=PAYLOAD_SCHEMA,
                operation=Operation.PROPOSAL,
                context_id=ctx_id,
            )

            entries_by_task = a_sdk.get_residue(result.task_id)
            assert len(entries_by_task) == 2

            entries_by_context = a_sdk.get_residue_chain(ctx_id)
            assert len(entries_by_context) == 2

            bundle = a_sdk.attest(result.task_id)
            assert bundle.task_id == result.task_id
            assert len(bundle.entries) == 2
        finally:
            await b_handle.stop()
