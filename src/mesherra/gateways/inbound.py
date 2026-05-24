"""Inbound Gateway.

Implements ARCHITECTURE.md §13.3. The single airlock for incoming messages.

Pipeline (Phase 1 + Phase 2 hardening + Phase 3 scoping):

1. (Phase 2+ Schema check against Schema Registry — still trusts the
   caller's schema declaration in v0)
2. Sender resolution via Identity Directory (Phase 2 shipped).
3. SendClaim signature verification.
3a. Clock-skew window check (Phase 2 hardening): reject if
    ``envelope.timestamp`` is outside ``now ± MESHERRA_CLOCK_SKEW_SECONDS``.
3b. (sender_principal_id, nonce) replay check (Phase 2 hardening): reject
    if the same nonce has been observed from the same sender within the
    seen-set's TTL window.
4. Policy decision (Phase 3). Consult the PolicyEngine against the user's
   signed policy for (payload, schema, direction=INBOUND). On
   ALLOW_SCOPED, narrow what reaches the consumer handler; on BLOCK /
   ESCALATE, raise rather than dispatch. Bypassed when no PolicyStore is
   injected (preserves Phase 1/2 test surface).
5. Build & sign receive Residue over the *wire bytes* (preserves
   tessera-fit with the sender's emit hash regardless of any inbound
   scoping applied locally for our handler).
6. Invoke consumer handler with the (possibly scoped) payload; package
   response.

Order rationale: steps 3a/3b run AFTER signature verification (3) so the
seen-set is only populated by signature-verified envelopes from known
senders — an attacker can't fill it with unverified traffic. Step 4 runs
AFTER replay checks so policy logic doesn't see replays.

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
from mesherra.policy import (
    Direction,
    PolicyEngine,
    PolicyStore,
    Verdict,
)
from mesherra.provenance.ledger import ProvenanceLedger

from .outbound import (
    GatewayError,
    PeerSignatureVerificationError,
    PolicyBlocked,
    PolicyEscalationRequired,
)
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
        policy_store: PolicyStore | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._directory = directory
        self._replay_protector = replay_protector
        # Phase 3 inbound policy enforcement (ARCH §13.3 step 4 of pipeline).
        # Bypass mode when ``policy_store`` is None — preserves Phase 1/2
        # test surface; otherwise default-deny stance per SPEC §2.2 step 2.
        self._policy_store = policy_store
        self._policy_engine = policy_engine or (
            PolicyEngine() if policy_store is not None else None
        )
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

        # Step 4 (Phase 3): inbound policy decision. May raise PolicyBlocked
        # or PolicyEscalationRequired; on ALLOW_SCOPED, narrows what reaches
        # the consumer. The receive Residue's payload_hash is unaffected —
        # it always records the *wire bytes* (envelope.payload) so the
        # tessera-fit invariant with the sender's emit Residue is preserved.
        consumer_payload = self._apply_inbound_policy(
            payload=envelope.payload, payload_schema=envelope.payload_schema
        )

        # Step 5: write our receive Residue (over the wire bytes, regardless
        # of any local scoping we applied for our handler).
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

        # Step 6: invoke consumer handler with the (possibly scoped) payload.
        incoming = IncomingMessage(
            sender_principal_id=sender,
            context_id=envelope.context_id,
            task_id=envelope.task_id,
            payload=consumer_payload,
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

    def _apply_inbound_policy(
        self, *, payload: dict[str, Any], payload_schema: str
    ) -> dict[str, Any]:
        """Run the user's policy on the inbound payload.

        Bypass mode (no store) returns ``payload`` unchanged. With a store
        present:

        * ALLOW          → return ``payload`` unchanged.
        * ALLOW_SCOPED   → return the engine's scoped subset (what the
                            handler will actually see).
        * BLOCK          → raise :class:`PolicyBlocked`. No Residue, no
                            handler call. The wire bytes were still seen
                            and signature-verified; refusing them at the
                            policy gate is the user's choice.
        * ESCALATE       → raise :class:`PolicyEscalationRequired`.
        """
        if self._policy_store is None or self._policy_engine is None:
            return payload
        signed = self._policy_store.get_current()
        decision = self._policy_engine.evaluate(
            payload=payload,
            payload_schema=payload_schema,
            direction=Direction.INBOUND,
            policy=signed.doc,
        )
        if decision.verdict is Verdict.ALLOW:
            return payload
        if decision.verdict is Verdict.ALLOW_SCOPED:
            return decision.scoped_payload or {}
        if decision.verdict is Verdict.BLOCK:
            raise PolicyBlocked(
                f"Inbound payload (schema={payload_schema!r}) blocked by "
                f"policy v{signed.doc.version}: {decision.reason}"
            )
        raise PolicyEscalationRequired(
            f"Inbound payload (schema={payload_schema!r}) requires "
            f"user escalation per policy v{signed.doc.version}. "
            "Phase 3 v0 treats this as a refusal."
        )

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
