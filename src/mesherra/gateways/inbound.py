"""Inbound Gateway.

Implements ARCHITECTURE.md §13.3. The single airlock for incoming messages.

Phase 1 pipeline (with Phase 2 hardening per ARCH §11.1):

1. (Phase 2+ Schema check against Schema Registry — Phase 1 trusts the
   caller's schema declaration)
2. (Phase 2+ Sender resolution via Identity Directory — Phase 1 uses a
   caller-supplied public-key directory)
3. SendClaim signature verification.
3a. Clock-skew window check (Phase 2 hardening): reject if
    ``envelope.timestamp`` is outside ``now ± MESHERRA_CLOCK_SKEW_SECONDS``.
3b. (sender_principal_id, nonce) replay check (Phase 2 hardening): reject
    if the same nonce has been observed from the same sender within the
    seen-set's TTL window.
4. (Phase 2+ Policy decision — Phase 1 always allows)
5. Build & sign receive Residue; append to ledger.
6. Invoke consumer handler; package response.

Order rationale: steps 3a/3b run AFTER signature verification (3) so the
seen-set is only populated by signature-verified envelopes from known
senders — an attacker can't fill it with unverified traffic.

No consumer code receives raw envelopes; the gateway is the only path
between the A2A adapter and the consumer's business logic.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from mesherra.a2a_adapter import MesherraEnvelope
from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.identity import DirectoryClient, UnknownPrincipalError
from mesherra.models.primitives import ActionType, Operation, Residue, SendClaim
from mesherra.provenance.ledger import ProvenanceLedger

from .outbound import GatewayError, PeerSignatureVerificationError
from .replay import (
    ReplayedNonceError,
    ReplayProtector,
    TimestampOutsideWindowError,
)

# -- Consumer-facing types ----------------------------------------------


@dataclass(frozen=True)
class IncomingMessage:
    """What the consumer handler receives — a verified inbound observation.

    No trust-layer concerns (signatures, hashes) leak to the consumer; those
    are the gateway's responsibility. The consumer reasons about the payload.
    """

    sender_principal_id: str
    context_id: str
    task_id: str
    payload: dict[str, Any]
    payload_schema: str
    operation: Operation


@dataclass(frozen=True)
class OutgoingResponse:
    """What the consumer handler may return — a response payload to send back.

    Returning ``None`` from the handler completes the task with no response
    (fire-and-forget on the receive side).
    """

    payload: dict[str, Any]
    operation: Operation
    payload_schema: str | None = None  # default: echo incoming schema


class ConsumerHandler(Protocol):
    async def __call__(
        self, message: IncomingMessage
    ) -> OutgoingResponse | None:
        ...


# -- InboundGateway -----------------------------------------------------


class InboundGateway:
    """The airlock for incoming messages."""

    def __init__(
        self,
        *,
        principal_id: str,
        signer: Signer,
        ledger: ProvenanceLedger,
        directory: DirectoryClient,
        replay_protector: ReplayProtector,
    ) -> None:
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._directory = directory
        self._replay_protector = replay_protector
        self._consumer: ConsumerHandler | None = None

    def register_consumer(self, handler: ConsumerHandler) -> None:
        """Register the consumer's business-logic handler.

        Calling twice replaces the previous handler. There is one consumer
        per gateway; callers needing fan-out implement it themselves.
        """
        self._consumer = handler

    async def handle_inbound(
        self, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        """The function the A2A adapter calls when a Message arrives.

        Implements the gateway pipeline. Returns the response envelope
        (with our SendClaim signature) if the consumer produced one;
        returns None otherwise.

        Raises:
            UnknownPrincipalError: sender_principal_id not in directory.
            PeerSignatureVerificationError: SendClaim signature did not verify.
            TimestampOutsideWindowError: envelope.timestamp outside skew window.
            ReplayedNonceError: (sender, nonce) already observed within window.
            GatewayError: register_consumer was never called.
        """
        if self._consumer is None:
            raise GatewayError(
                "Call register_consumer(...) before handle_inbound(...)."
            )

        sender = envelope.sender_principal_id
        # Resolve via the Directory. An unknown sender raises
        # UnknownPrincipalError; the resolved record's public key is the
        # key the SendClaim signature is verified against.
        sender_record = await self._directory.resolve(sender)

        # Step 3: SendClaim verification.
        if not self._verify_inbound_send_claim(
            envelope, sender_public_key_b64=sender_record.public_key_b64
        ):
            raise PeerSignatureVerificationError(
                f"Inbound SendClaim from {sender!r} did not verify under "
                "their published public key."
            )

        # Steps 3a/3b: replay defenses, after signature verification so the
        # nonce seen-set is only populated by verified envelopes from known
        # senders. Timestamp check first because it's pure (no state mutation);
        # nonce check last because it records.
        self._replay_protector.check_timestamp(envelope.timestamp)
        self._replay_protector.check_and_record_nonce(sender, envelope.nonce)

        # Step 5: write our receive Residue.
        payload_hash = content_hash(canonical_json(envelope.payload))
        receive_timestamp = _utc_now_iso()
        self._append_residue(
            task_id=envelope.task_id,
            context_id=envelope.context_id,
            timestamp=receive_timestamp,
            action_type=ActionType.RECEIVE,
            operation=envelope.operation,
            actor=sender,
            counterpart=self._principal_id,
            payload_hash=payload_hash,
            payload_schema=envelope.payload_schema,
        )

        # Step 6: invoke consumer handler.
        incoming = IncomingMessage(
            sender_principal_id=sender,
            context_id=envelope.context_id,
            task_id=envelope.task_id,
            payload=envelope.payload,
            payload_schema=envelope.payload_schema,
            operation=envelope.operation,
        )
        outgoing = await self._consumer(incoming)
        if outgoing is None:
            return None

        # Build the response: our emit Residue + our SendClaim + envelope.
        response_payload = outgoing.payload
        response_schema = outgoing.payload_schema or envelope.payload_schema
        response_payload_hash = content_hash(canonical_json(response_payload))
        response_timestamp = _utc_now_iso()

        self._append_residue(
            task_id=envelope.task_id,
            context_id=envelope.context_id,
            timestamp=response_timestamp,
            action_type=ActionType.EMIT,
            operation=outgoing.operation,
            actor=self._principal_id,
            counterpart=sender,
            payload_hash=response_payload_hash,
            payload_schema=response_schema,
        )

        return self._build_response_envelope(
            task_id=envelope.task_id,
            context_id=envelope.context_id,
            payload=response_payload,
            payload_hash=response_payload_hash,
            payload_schema=response_schema,
            operation=outgoing.operation,
            timestamp=response_timestamp,
            nonce=str(uuid.uuid4()),
        )

    # -- internals ------------------------------------------------------

    def _verify_inbound_send_claim(
        self,
        envelope: MesherraEnvelope,
        *,
        sender_public_key_b64: str,
    ) -> bool:
        """Verify the inbound SendClaim against the pre-resolved sender key.

        Sync helper — the directory resolution happened in handle_inbound
        before this is called. Keeps the verifier pure and avoids any I/O
        in the signature-bytes-reconstruction path.
        """
        sender = envelope.sender_principal_id
        verifier = Verifier.from_b64(sender_public_key_b64)
        send_claim = SendClaim(
            payload_hash=content_hash(canonical_json(envelope.payload)),
            payload_schema=envelope.payload_schema,
            operation=envelope.operation,
            sender_principal_id=sender,
            context_id=envelope.context_id,
            timestamp=envelope.timestamp,
            nonce=envelope.nonce,
        )
        canonical_bytes = canonical_json(send_claim.to_signing_bytes_input())
        return verifier.verify(canonical_bytes, envelope.send_claim_signature)

    def _build_response_envelope(
        self,
        *,
        task_id: str,
        context_id: str,
        payload: dict[str, Any],
        payload_hash: str,
        payload_schema: str,
        operation: Operation,
        timestamp: str,
        nonce: str,
    ) -> MesherraEnvelope:
        send_claim = SendClaim(
            payload_hash=payload_hash,
            payload_schema=payload_schema,
            operation=operation,
            sender_principal_id=self._principal_id,
            context_id=context_id,
            timestamp=timestamp,
            nonce=nonce,
        )
        signature = self._signer.sign(
            canonical_json(send_claim.to_signing_bytes_input())
        )
        return MesherraEnvelope(
            task_id=task_id,
            context_id=context_id,
            sender_principal_id=self._principal_id,
            payload=payload,
            payload_schema=payload_schema,
            operation=operation,
            timestamp=timestamp,
            nonce=nonce,
            send_claim_signature=signature,
        )

    def _append_residue(
        self,
        *,
        task_id: str,
        context_id: str,
        timestamp: str,
        action_type: ActionType,
        operation: Operation,
        actor: str,
        counterpart: str,
        payload_hash: str,
        payload_schema: str,
    ) -> Residue:
        # Intentional duplication with OutboundGateway._append_residue per
        # CLAUDE.md #10. See the matched twin's comment for rationale.
        fields = {
            "version": 1,
            "ledger_owner": self._ledger.ledger_owner,
            "task_id": task_id,
            "context_id": context_id,
            "sequence": self._ledger.next_sequence,
            "previous_hash": self._ledger.head_hash,
            "timestamp": timestamp,
            "actor": actor,
            "counterpart": counterpart,
            "action_type": action_type.value,
            "operation": operation.value,
            "payload_hash": payload_hash,
            "payload_schema": payload_schema,
        }
        signature = self._signer.sign(canonical_json(fields))
        residue = Residue(**fields, signature=signature)
        self._ledger.append(residue)
        return residue


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
