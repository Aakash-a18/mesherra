"""End-to-end replay-defense integration tests (Phase 2 hardening per ARCH §11.1).

These tests prove that captured-envelope replays are rejected by the
inbound gateway in two scenarios:

1. **Timestamp outside the clock-skew window** — an envelope from too far
   in the past (or future) is rejected even though its signature is valid.
2. **Replayed nonce within the window** — a fresh, signature-valid envelope
   is accepted on first arrival, then the *same envelope* fails on
   redelivery.

We use real Ed25519 keys, real on-disk ledgers, and the full inbound
gateway pipeline. The clock the ReplayProtector uses is injected (rather
than wall-clock) so the tests are deterministic.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mesherra.a2a_adapter import A2AAdapter, MesherraEnvelope
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.inbound import (
    InboundGateway,
    IncomingMessage,
    OutgoingResponse,
)
from mesherra.gateways.replay import (
    ReplayedNonceError,
    ReplayProtector,
    TimestampOutsideWindowError,
)
from mesherra.models.primitives import Operation, SendClaim
from mesherra.provenance.ledger import ProvenanceLedger


OWNER_A = "user-a@phase1.local"
OWNER_B = "user-b@phase1.local"

PAYLOAD = {"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30}
PAYLOAD_SCHEMA = "meshycal.scheduling/proposal-v1"


def _build_signed_envelope(
    *,
    signer: Signer,
    sender_principal_id: str,
    context_id: str,
    timestamp: str,
    nonce: str | None = None,
    payload: dict | None = None,
    operation: Operation = Operation.PROPOSAL,
    task_id: str = "task-replay-test",
    payload_schema: str = PAYLOAD_SCHEMA,
) -> MesherraEnvelope:
    """Build a real signature-bearing envelope with explicit timestamp / nonce."""
    if payload is None:
        payload = PAYLOAD
    if nonce is None:
        nonce = str(uuid.uuid4())
    payload_hash = content_hash(canonical_json(payload))
    send_claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=payload_schema,
        operation=operation,
        sender_principal_id=sender_principal_id,
        context_id=context_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    signature = signer.sign(canonical_json(send_claim.to_signing_bytes_input()))
    return MesherraEnvelope(
        task_id=task_id,
        context_id=context_id,
        sender_principal_id=sender_principal_id,
        payload=payload,
        payload_schema=payload_schema,
        operation=operation,
        timestamp=timestamp,
        nonce=nonce,
        send_claim_signature=signature,
    )


class _MutableClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now = self._now + timedelta(seconds=seconds)


def _build_b_gateway(
    *,
    signer: Signer,
    public_key_directory: dict[str, str],
    ledger_path: Path,
    replay_protector: ReplayProtector,
) -> InboundGateway:
    ledger = ProvenanceLedger(db_path=ledger_path, ledger_owner=OWNER_B)
    gateway = InboundGateway(
        principal_id=OWNER_B,
        signer=signer,
        ledger=ledger,
        public_key_directory=public_key_directory,
        replay_protector=replay_protector,
    )

    async def consumer(_msg: IncomingMessage) -> OutgoingResponse:
        return OutgoingResponse(
            payload={"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30},
            operation=Operation.ACCEPTANCE,
        )

    gateway.register_consumer(consumer)
    return gateway


class TestTimestampOutsideWindow:
    async def test_envelope_with_old_timestamp_rejected(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }

        clock = _MutableClock(datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC))
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)

        gateway = _build_b_gateway(
            signer=b_signer,
            public_key_directory=public_keys,
            ledger_path=tmp_path / "b.sqlite",
            replay_protector=rp,
        )

        # Build a signature-valid envelope from 10 minutes ago — way outside
        # the 60-second skew window.
        stale_envelope = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id=OWNER_A,
            context_id="ctx-stale",
            timestamp="2026-05-24T11:50:00Z",
        )

        try:
            raised: Exception | None = None
            try:
                await gateway.handle_inbound(stale_envelope)
            except TimestampOutsideWindowError as e:
                raised = e
            assert raised is not None, "Stale envelope should have been rejected"
            assert "from now" in str(raised)
        finally:
            gateway._ledger.close()  # type: ignore[attr-defined]

    async def test_envelope_with_future_timestamp_rejected(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }

        clock = _MutableClock(datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC))
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)

        gateway = _build_b_gateway(
            signer=b_signer,
            public_key_directory=public_keys,
            ledger_path=tmp_path / "b.sqlite",
            replay_protector=rp,
        )

        future_envelope = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id=OWNER_A,
            context_id="ctx-future",
            timestamp="2030-01-01T00:00:00Z",
        )

        try:
            raised: Exception | None = None
            try:
                await gateway.handle_inbound(future_envelope)
            except TimestampOutsideWindowError as e:
                raised = e
            assert raised is not None
        finally:
            gateway._ledger.close()  # type: ignore[attr-defined]


class TestNonceReplay:
    async def test_first_envelope_accepted_replay_rejected(
        self, tmp_path: Path
    ) -> None:
        """The whole point of nonce-based replay defense: a captured envelope
        re-delivered within the window is rejected on the second arrival,
        even though its signature is still valid."""
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }

        clock = _MutableClock(datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC))
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)

        gateway = _build_b_gateway(
            signer=b_signer,
            public_key_directory=public_keys,
            ledger_path=tmp_path / "b.sqlite",
            replay_protector=rp,
        )

        envelope = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id=OWNER_A,
            context_id="ctx-replay",
            timestamp="2026-05-24T12:00:00Z",
        )

        try:
            # First delivery: accepted (B's gateway produces a response).
            response = await gateway.handle_inbound(envelope)
            assert response is not None
            assert response.operation == Operation.ACCEPTANCE

            # Replay attempt: the SAME envelope, same nonce, same signature.
            # The seen-set rejects it.
            raised: Exception | None = None
            try:
                await gateway.handle_inbound(envelope)
            except ReplayedNonceError as e:
                raised = e
            assert raised is not None, "Replay should have been rejected"
            assert "already observed" in str(raised)
        finally:
            gateway._ledger.close()  # type: ignore[attr-defined]

    async def test_different_nonces_from_same_sender_both_accepted(
        self, tmp_path: Path
    ) -> None:
        """Two legitimate distinct sends from the same sender both go
        through — only exact nonce duplicates are rejected."""
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }

        clock = _MutableClock(datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC))
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)

        gateway = _build_b_gateway(
            signer=b_signer,
            public_key_directory=public_keys,
            ledger_path=tmp_path / "b.sqlite",
            replay_protector=rp,
        )

        env_1 = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id=OWNER_A,
            context_id="ctx-1",
            timestamp="2026-05-24T12:00:00Z",
            task_id="task-1",
        )
        env_2 = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id=OWNER_A,
            context_id="ctx-2",
            timestamp="2026-05-24T12:00:01Z",
            task_id="task-2",
        )
        assert env_1.nonce != env_2.nonce  # fresh UUIDs

        try:
            await gateway.handle_inbound(env_1)
            await gateway.handle_inbound(env_2)
            assert len(rp) == 2
        finally:
            gateway._ledger.close()  # type: ignore[attr-defined]
