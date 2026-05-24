"""Outbound Gateway.

Implements ARCHITECTURE.md §13.2. The single airlock for outgoing messages.

Phase 1 responsibilities (per the doc's ordered pipeline):

Pre-send:
1. (Phase 2+ Policy decision — skipped in Phase 1)
2. (Phase 2+ Peer resolution via Identity Directory — Phase 1 uses caller-supplied
   public-key directory)
3. SendClaim signing.
4. Hand to A2A SDK Adapter.

Post-response:
5. Build and sign emit Residue (with now-known task_id from response).
6. Append to Provenance Ledger.
7. Verify peer's SendClaim on response.
8. Build and sign receive Residue for response. Append.

The gateway is the only path from consumer code to the A2A wire.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mesherra.a2a_adapter import A2AAdapter, MesherraEnvelope
from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.models.primitives import ActionType, Operation, Residue, SendClaim
from mesherra.provenance.ledger import ProvenanceLedger

# -- Exceptions ----------------------------------------------------------


class GatewayError(Exception):
    """Base class for outbound/inbound gateway errors."""


class PeerSignatureVerificationError(GatewayError):
    """The peer's response SendClaim signature did not verify.

    Either the peer's published public key is wrong, the peer signed
    different bytes than they sent, or there was tampering in transit.
    The gateway raises rather than silently appending an unverified
    response residue.
    """


class UnknownPrincipalError(GatewayError):
    """The peer's principal id is not in the public-key directory.

    Phase 1: directory is caller-supplied (a dict). Phase 2: Identity
    Directory does the lookup with mTLS-verified AgentCards.
    """


# -- Result type --------------------------------------------------------


@dataclass(frozen=True)
class OutboundResult:
    """What ``OutboundGateway.send`` returns to the caller.

    Captures the peer's response payload plus the now-known A2A-assigned
    ``task_id`` (which the caller may need for subsequent operations
    within the same task).
    """

    response_payload: dict[str, Any]
    response_operation: Operation
    response_sender_principal_id: str
    task_id: str
    context_id: str


# -- OutboundGateway -----------------------------------------------------


class OutboundGateway:
    """The airlock for outgoing messages."""

    def __init__(
        self,
        *,
        principal_id: str,
        signer: Signer,
        ledger: ProvenanceLedger,
        adapter: A2AAdapter,
        public_key_directory: dict[str, str],
    ) -> None:
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._adapter = adapter
        self._public_key_directory = public_key_directory

    async def send(
        self,
        *,
        peer_url: str,
        peer_principal_id: str,
        payload: dict[str, Any],
        payload_schema: str,
        operation: Operation,
        context_id: str | None = None,
    ) -> OutboundResult:
        """Send a signed payload to a peer; await response; record both residues.

        Phase 1 assumes request-response (peer always responds). Fire-and-forget
        sends raise NotImplementedError. Phase 2 may add a separate
        ``fire_and_forget`` method.

        Raises:
            UnknownPrincipalError: peer_principal_id not in the directory.
            PeerSignatureVerificationError: peer's response did not verify.
            NotImplementedError: peer returned no response (fire-and-forget).
        """
        if peer_principal_id not in self._public_key_directory:
            raise UnknownPrincipalError(
                f"Peer principal {peer_principal_id!r} not in public-key "
                f"directory; known: {sorted(self._public_key_directory)}"
            )

        context_id = context_id or str(uuid.uuid4())
        send_timestamp = _utc_now_iso()
        nonce = str(uuid.uuid4())
        payload_hash = content_hash(canonical_json(payload))

        outbound_envelope = self._build_outbound_envelope(
            context_id=context_id,
            payload=payload,
            payload_hash=payload_hash,
            payload_schema=payload_schema,
            operation=operation,
            timestamp=send_timestamp,
            nonce=nonce,
        )

        response_envelope = await self._adapter.send_envelope(
            peer_url=peer_url, envelope=outbound_envelope
        )

        if response_envelope is None:
            raise NotImplementedError(
                "Fire-and-forget send is Phase 2+. Phase 1 demo flow is "
                "always request-response."
            )

        if not self._verify_peer_send_claim(response_envelope):
            raise PeerSignatureVerificationError(
                f"Response SendClaim from {response_envelope.sender_principal_id!r} "
                "did not verify under their published public key."
            )

        assigned_task_id = response_envelope.task_id
        if not assigned_task_id:
            raise GatewayError(
                "Response envelope has empty task_id; A2A server should have "
                "assigned one. Possible adapter bug."
            )

        # Step 5-6: emit Residue for our original outbound.
        self._append_residue(
            task_id=assigned_task_id,
            context_id=context_id,
            timestamp=send_timestamp,
            action_type=ActionType.EMIT,
            operation=operation,
            actor=self._principal_id,
            counterpart=peer_principal_id,
            payload_hash=payload_hash,
            payload_schema=payload_schema,
        )

        # Step 8: receive Residue for the peer's response.
        response_payload_hash = content_hash(
            canonical_json(response_envelope.payload)
        )
        self._append_residue(
            task_id=assigned_task_id,
            context_id=context_id,
            timestamp=_utc_now_iso(),
            action_type=ActionType.RECEIVE,
            operation=response_envelope.operation,
            actor=response_envelope.sender_principal_id,
            counterpart=self._principal_id,
            payload_hash=response_payload_hash,
            payload_schema=response_envelope.payload_schema,
        )

        return OutboundResult(
            response_payload=response_envelope.payload,
            response_operation=response_envelope.operation,
            response_sender_principal_id=response_envelope.sender_principal_id,
            task_id=assigned_task_id,
            context_id=context_id,
        )

    # -- internals ------------------------------------------------------

    def _build_outbound_envelope(
        self,
        *,
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
            task_id="",
            context_id=context_id,
            sender_principal_id=self._principal_id,
            payload=payload,
            payload_schema=payload_schema,
            operation=operation,
            timestamp=timestamp,
            nonce=nonce,
            send_claim_signature=signature,
        )

    def _verify_peer_send_claim(self, response_envelope: MesherraEnvelope) -> bool:
        peer = response_envelope.sender_principal_id
        if peer not in self._public_key_directory:
            return False
        verifier = Verifier.from_b64(self._public_key_directory[peer])
        send_claim = SendClaim(
            payload_hash=content_hash(canonical_json(response_envelope.payload)),
            payload_schema=response_envelope.payload_schema,
            operation=response_envelope.operation,
            sender_principal_id=peer,
            context_id=response_envelope.context_id,
            timestamp=response_envelope.timestamp,
            nonce=response_envelope.nonce,
        )
        canonical_bytes = canonical_json(send_claim.to_signing_bytes_input())
        return verifier.verify(canonical_bytes, response_envelope.send_claim_signature)

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
        # Intentional duplication with InboundGateway._append_residue per
        # CLAUDE.md #10 ("don't abstract prematurely"). The two callers have
        # different lifecycles (request-context vs response-context inside an
        # adapter callback). Revisit if Phase 2 adds a third Residue producer
        # (rejection logger) with a similar shape.
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
    """Current UTC time as ISO-8601 with seconds precision and 'Z' suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
