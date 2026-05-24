"""Outbound Gateway.

Implements ARCHITECTURE.md §13.2. The single airlock for outgoing messages.

Pipeline (Phase 1 + Phase 2 hardening + Phase 3 scoping):

Pre-send:
1. Policy decision (Phase 3). Consult the PolicyEngine for the user's
   signed policy against (payload, schema, direction=OUTBOUND). On
   ALLOW_SCOPED, narrow the payload to permitted fields and re-check
   that no blocked path survives (defense-in-depth). On BLOCK / ESCALATE,
   raise rather than send. Bypassed entirely if no PolicyStore is
   injected (preserves Phase 1/2 test surface).
2. Peer resolution via Identity Directory (Phase 2).
3. SendClaim signing over the *post-scoping* payload hash.
4. Hand to A2A SDK Adapter.

Post-response:
5. Verify peer's SendClaim on response.
6. Build and sign emit Residue (with now-known task_id from response).
7. Append to Provenance Ledger.
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
from mesherra.identity import DirectoryClient, UnknownPrincipalError
from mesherra.models.primitives import ActionType, Operation, Residue, SendClaim
from mesherra.policy import (
    Direction,
    PolicyEngine,
    PolicyStore,
    Verdict,
)
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


# -- Policy-decision exceptions (Phase 3) --------------------------------


class PolicyBlocked(GatewayError):
    """The policy engine refused this message (verdict = BLOCK).

    Carries the engine's reason in the message so the operator can see
    why the send was refused (default-deny on an unmatched schema, an
    empty allow-list, or all fields removed). The send never reaches the
    A2A wire; no Residue is written.
    """


class PolicyEscalationRequired(GatewayError):
    """The policy engine returned ESCALATE.

    Phase 3 v0 never produces this verdict (the engine has no conditional
    rule types yet), but the gateway handles it defensively so a future
    engine returning ESCALATE fails closed rather than silently sending.
    """


class PolicyScopingFailed(GatewayError):
    """Defense-in-depth: the post-scope payload still contained a blocked path.

    This indicates a bug in the engine — every matched outbound_block
    path must be absent from the scoped payload. The gateway catches it
    before signing the SendClaim so a buggy engine cannot leak data on
    the wire.
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
        directory: DirectoryClient,
        policy_store: PolicyStore | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._adapter = adapter
        self._directory = directory
        # Phase 3 policy enforcement (ARCH §13.4). If ``policy_store`` is
        # None, the gateway runs in bypass mode (no engine call, all messages
        # pass) — preserves Phase 1/2 test surfaces that never injected a
        # store. When a store IS provided, the engine's default-deny stance
        # kicks in for unmatched (schema, direction) per SPEC §2.2 step 2.
        self._policy_store = policy_store
        self._policy_engine = policy_engine or (
            PolicyEngine() if policy_store is not None else None
        )

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
        # Step 1: Policy decision (Phase 3).
        outgoing_payload = self._apply_outbound_policy(
            payload=payload, payload_schema=payload_schema
        )

        # Resolve the peer through the Directory up-front so an unknown
        # principal fails fast before we do any work. The resolved record
        # is used again post-response to verify the peer's SendClaim
        # (kept in a local rather than re-fetched to avoid double I/O).
        peer = await self._directory.resolve(peer_principal_id)

        context_id = context_id or str(uuid.uuid4())
        send_timestamp = _utc_now_iso()
        nonce = str(uuid.uuid4())
        payload_hash = content_hash(canonical_json(outgoing_payload))

        outbound_envelope = self._build_outbound_envelope(
            context_id=context_id,
            payload=outgoing_payload,
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

        if not self._verify_peer_send_claim(
            response_envelope, peer_public_key_b64=peer.public_key_b64
        ):
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

    def _apply_outbound_policy(
        self, *, payload: dict[str, Any], payload_schema: str
    ) -> dict[str, Any]:
        """Run the user's policy on the outbound payload and return what
        should actually go on the wire.

        Bypass mode (no store injected) returns ``payload`` unchanged —
        Phase 1/2 test surfaces never injected a store, and that
        backwards-compatible path is explicit per SPEC §7.

        With a store present, the engine's verdict drives the outcome:

        * ALLOW          → return payload unchanged.
        * ALLOW_SCOPED   → run defense-in-depth re-check, then return
                            the engine's scoped payload.
        * BLOCK          → raise :class:`PolicyBlocked`.
        * ESCALATE       → raise :class:`PolicyEscalationRequired`.
        """
        if self._policy_store is None or self._policy_engine is None:
            return payload
        signed = self._policy_store.get_current()
        decision = self._policy_engine.evaluate(
            payload=payload,
            payload_schema=payload_schema,
            direction=Direction.OUTBOUND,
            policy=signed.doc,
        )
        if decision.verdict is Verdict.ALLOW:
            return payload
        if decision.verdict is Verdict.ALLOW_SCOPED:
            scoped = decision.scoped_payload or {}
            self._assert_no_blocked_path_survived(
                scoped=scoped,
                payload_schema=payload_schema,
                policy_rules=signed.doc.rules,
            )
            return scoped
        if decision.verdict is Verdict.BLOCK:
            raise PolicyBlocked(
                f"Outbound payload (schema={payload_schema!r}) blocked by "
                f"policy v{signed.doc.version}: {decision.reason}"
            )
        # ESCALATE: never produced by the v0 engine, but handled here so a
        # future engine can't quietly bypass the airlock.
        raise PolicyEscalationRequired(
            f"Outbound payload (schema={payload_schema!r}) requires "
            f"user escalation per policy v{signed.doc.version}. "
            "Phase 3 v0 treats this as a refusal."
        )

    def _assert_no_blocked_path_survived(
        self,
        *,
        scoped: dict[str, Any],
        payload_schema: str,
        policy_rules: list[Any],
    ) -> None:
        """Defense-in-depth: every outbound_block path in every matched rule
        must be absent from the scoped payload. If anything survived, the
        engine has a bug — raise rather than sign over the bytes."""
        for rule in policy_rules:
            if rule.match.schema_uri != payload_schema:
                continue
            if rule.match.direction not in (
                Direction.OUTBOUND, Direction.BOTH
            ):
                continue
            for path in rule.outbound_block or []:
                if _path_present(scoped, path):
                    raise PolicyScopingFailed(
                        f"Defense-in-depth: blocked field {path!r} still "
                        f"present in scoped payload (schema={payload_schema!r}). "
                        "Engine returned ALLOW_SCOPED but did not strip "
                        "the field. This is an engine bug — failing closed."
                    )

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

    def _verify_peer_send_claim(
        self,
        response_envelope: MesherraEnvelope,
        *,
        peer_public_key_b64: str,
    ) -> bool:
        """Verify the peer's response SendClaim against the pre-resolved key.

        The caller (``send``) has already resolved the peer via the Directory,
        so this method takes the resolved public key as an argument rather
        than doing its own lookup. Keeps the verifier pure (no I/O) and
        avoids redundant directory traffic when the real HTTPDirectoryClient
        lands.
        """
        peer_principal_id = response_envelope.sender_principal_id
        verifier = Verifier.from_b64(peer_public_key_b64)
        send_claim = SendClaim(
            payload_hash=content_hash(canonical_json(response_envelope.payload)),
            payload_schema=response_envelope.payload_schema,
            operation=response_envelope.operation,
            sender_principal_id=peer_principal_id,
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


def _path_present(payload: dict[str, Any], path: str) -> bool:
    """Return True if the dotted ``path`` reaches a value in ``payload``.

    Local helper rather than importing ``policy.engine._read_path`` —
    keeps the gateway's defense-in-depth check independent of engine
    internals (the engine is the thing being defended against; a shared
    helper would be self-referential).
    """
    cur: Any = payload
    for seg in path.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return False
        cur = cur[seg]
    return True
