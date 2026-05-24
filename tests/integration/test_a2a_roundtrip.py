"""In-process A2A round-trip integration tests for the adapter (step 4).

Starts a real A2A HTTP listener on a localhost port, then sends real
envelopes via the adapter's client side. Proves the full wire integration —
the conversion functions, the uvicorn lifecycle, the JSON-RPC routes, the
AgentExecutor, the Client — all wired together.

These tests use REAL Ed25519 keypairs and sign real SendClaim objects per
ARCHITECTURE.md §13.10. They demonstrate that:

* A's SendClaim signature can be verified on B's side using only the
  envelope fields (no shared private state required).
* The wire round-trip preserves all envelope fields end-to-end.
* The fire-and-forget pattern (handler returns None) also works.

These are the tests step 6's MeshyCal agents and step 7's orchestrator
need to pass before the demo can be expected to work.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from mesherra.a2a_adapter import (
    A2AAdapter,
    MesherraEnvelope,
)
from mesherra.crypto.primitives import (
    Signer,
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.models.primitives import Operation, SendClaim

# pytest-asyncio is in auto mode (per pyproject.toml).


def _free_port() -> int:
    """Bind to port 0, ask the OS what port we got, close, return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _build_signed_envelope(
    *,
    signer: Signer,
    sender_principal_id: str,
    context_id: str,
    payload: dict[str, Any],
    timestamp: str,
    operation: Operation = Operation.PROPOSAL,
    task_id: str = "",
    payload_schema: str = "meshycal.scheduling/proposal-v1",
) -> MesherraEnvelope:
    """Build a MesherraEnvelope with a real SendClaim signature.

    Mirrors what step 5's Outbound Gateway will do: build the SendClaim from
    the fields available pre-send, sign it, and construct the envelope.
    """
    payload_hash = content_hash(canonical_json(payload))
    send_claim = SendClaim(
        payload_hash=payload_hash,
        payload_schema=payload_schema,
        operation=operation,
        sender_principal_id=sender_principal_id,
        context_id=context_id,
        timestamp=timestamp,
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
        send_claim_signature=signature,
    )


def _verify_send_claim(envelope: MesherraEnvelope, public_key_b64: str) -> bool:
    """Mirror what step 5's Inbound Gateway will do for SendClaim verification.

    Reconstruct the SendClaim from envelope fields (computing payload_hash
    from envelope.payload), canonical-encode, and verify against the sender's
    published public key. No shared private state required.
    """
    verifier = Verifier.from_b64(public_key_b64)
    send_claim = SendClaim(
        payload_hash=content_hash(canonical_json(envelope.payload)),
        payload_schema=envelope.payload_schema,
        operation=envelope.operation,
        sender_principal_id=envelope.sender_principal_id,
        context_id=envelope.context_id,
        timestamp=envelope.timestamp,
    )
    canonical_bytes = canonical_json(send_claim.to_signing_bytes_input())
    return verifier.verify(canonical_bytes, envelope.send_claim_signature)


class TestEndToEndRoundTrip:
    """The full Phase 1 step 4 mechanic in one test.

    Sender A2AAdapter sends a signed-SendClaim envelope to a Receiver A2AAdapter
    running on localhost. The Receiver's handler verifies the SendClaim
    using only the envelope fields and the sender's published public key,
    then returns a signed response envelope. The response makes it back to
    the Sender, which verifies the receiver's SendClaim in turn.
    """

    async def test_request_response_round_trip_with_real_signatures(self) -> None:
        # Each side has its own keypair. Public keys are exchanged out-of-band
        # (Phase 2 lights up the Identity Directory; here we just pass them in).
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        a_public_key_b64 = a_signer.public_key_b64()
        b_public_key_b64 = b_signer.public_key_b64()

        received_envelopes: list[MesherraEnvelope] = []

        async def b_handler(envelope: MesherraEnvelope) -> MesherraEnvelope | None:
            # Mirror what the Inbound Gateway will do in step 5:
            # verify A's SendClaim using ONLY the published public key.
            assert _verify_send_claim(envelope, a_public_key_b64)
            received_envelopes.append(envelope)

            # Build B's response (acceptance) with B's own signed SendClaim.
            chosen_slot = envelope.payload["candidates"][0]
            return _build_signed_envelope(
                signer=b_signer,
                sender_principal_id="user-b@phase1.local",
                context_id=envelope.context_id,
                payload={"candidates": [chosen_slot], "duration_minutes": 30},
                timestamp="2026-05-23T15:30:01Z",
                operation=Operation.ACCEPTANCE,
                task_id=envelope.task_id,  # B propagates the assigned id
            )

        receiver = A2AAdapter()
        receiver.register_handler(b_handler)
        port = _free_port()
        handle = await receiver.start_listener(
            host="127.0.0.1", port=port, agent_name="receiver-b"
        )

        try:
            sender = A2AAdapter()
            outbound = _build_signed_envelope(
                signer=a_signer,
                sender_principal_id="user-a@phase1.local",
                context_id="ctx-test-1",
                payload={
                    "candidates": [
                        "2026-05-26T14:00:00Z",
                        "2026-05-27T10:00:00Z",
                    ],
                    "duration_minutes": 30,
                },
                timestamp="2026-05-23T15:30:00Z",
                task_id="",  # first message; A2A assigns
            )

            response = await sender.send_envelope(
                peer_url=f"http://127.0.0.1:{port}/", envelope=outbound
            )

            assert len(received_envelopes) == 1
            received = received_envelopes[0]
            assert received.context_id == outbound.context_id
            assert received.sender_principal_id == outbound.sender_principal_id
            assert received.payload == outbound.payload
            assert received.payload_schema == outbound.payload_schema
            assert received.timestamp == outbound.timestamp
            assert received.send_claim_signature == outbound.send_claim_signature
            assert received.task_id != ""  # A2A assigned one
            assigned_task_id = received.task_id

            assert response is not None
            assert response.task_id == assigned_task_id
            assert response.context_id == outbound.context_id
            assert response.sender_principal_id == "user-b@phase1.local"
            assert response.payload["candidates"] == [
                outbound.payload["candidates"][0]
            ]

            # The whole point: A can verify B's response with ONLY B's
            # public key, no shared private state.
            assert _verify_send_claim(response, b_public_key_b64)

            # Protobuf Value represents all numbers as float64, but JCS
            # canonicalizes int N and float N.0 to the same bytes. Verify
            # the round-trip preserves the *canonical* payload bytes — this
            # is what step 5's gateway will reconstruct payload_hash from.
            assert content_hash(canonical_json(received.payload)) == content_hash(
                canonical_json(outbound.payload)
            )
            assert content_hash(canonical_json(response.payload)) == content_hash(
                canonical_json({"candidates": [outbound.payload["candidates"][0]], "duration_minutes": 30})
            )
        finally:
            await handle.stop()

    async def test_tampered_payload_fails_send_claim_verification(self) -> None:
        """If a man-in-the-middle changes the payload, B's SendClaim
        verification must hard-fail. Tessera coherence at the wire boundary."""
        a_signer = Signer.generate()
        a_public_key_b64 = a_signer.public_key_b64()

        # Build a legitimately-signed envelope.
        legit = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id="user-a@phase1.local",
            context_id="ctx-tamper-1",
            payload={"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30},
            timestamp="2026-05-23T15:30:00Z",
        )
        # Construct a tampered envelope by mutating only the payload but
        # keeping the original signature. This simulates an MitM attacker.
        tampered = legit.model_copy(
            update={
                "payload": {
                    "candidates": ["2099-01-01T00:00:00Z"],  # different slot
                    "duration_minutes": 30,
                }
            }
        )
        assert _verify_send_claim(legit, a_public_key_b64) is True
        assert _verify_send_claim(tampered, a_public_key_b64) is False

    async def test_tampered_operation_fails_send_claim_verification(self) -> None:
        """If a MitM flips PROPOSAL→ACCEPTANCE on the wire, SendClaim
        verification must hard-fail. Without this, an attacker could coerce
        one party into appearing to agree to a proposal they only
        acknowledged — the receiver branches on `operation`, and an
        unsigned operation would be silently honored."""
        a_signer = Signer.generate()
        a_public_key_b64 = a_signer.public_key_b64()

        legit = _build_signed_envelope(
            signer=a_signer,
            sender_principal_id="user-a@phase1.local",
            context_id="ctx-op-tamper-1",
            payload={"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30},
            timestamp="2026-05-23T15:30:00Z",
            operation=Operation.PROPOSAL,
        )
        tampered = legit.model_copy(update={"operation": Operation.ACCEPTANCE})
        assert _verify_send_claim(legit, a_public_key_b64) is True
        assert _verify_send_claim(tampered, a_public_key_b64) is False

    async def test_fire_and_forget_round_trip(self) -> None:
        """Handler returning None completes the task with no response."""
        a_signer = Signer.generate()
        received_envelopes: list[MesherraEnvelope] = []

        async def handler(envelope: MesherraEnvelope) -> None:
            received_envelopes.append(envelope)
            return None

        receiver = A2AAdapter()
        receiver.register_handler(handler)
        port = _free_port()
        handle = await receiver.start_listener(
            host="127.0.0.1", port=port, agent_name="fire-and-forget-agent"
        )

        try:
            sender = A2AAdapter()
            outbound = _build_signed_envelope(
                signer=a_signer,
                sender_principal_id="user-a@phase1.local",
                context_id="ctx-fnf-1",
                payload={
                    "candidates": ["2026-05-26T14:00:00Z"],
                    "duration_minutes": 30,
                },
                timestamp="2026-05-23T15:30:00Z",
            )
            response = await sender.send_envelope(
                peer_url=f"http://127.0.0.1:{port}/", envelope=outbound
            )
            assert response is None
            assert len(received_envelopes) == 1
            assert received_envelopes[0].context_id == outbound.context_id
            assert received_envelopes[0].payload == outbound.payload
            assert received_envelopes[0].send_claim_signature == outbound.send_claim_signature
        finally:
            await handle.stop()


class TestAdapterLifecycle:
    async def test_start_listener_without_handler_raises(self) -> None:
        adapter = A2AAdapter()
        with pytest.raises(RuntimeError, match="register_handler"):
            await adapter.start_listener(
                host="127.0.0.1", port=_free_port(), agent_name="no-handler"
            )

    async def test_subscribe_to_task_raises_not_implemented(self) -> None:
        adapter = A2AAdapter()
        with pytest.raises(NotImplementedError, match="Phase 2/3"):
            await adapter.subscribe_to_task("task-x")

    async def test_listener_stops_cleanly(self) -> None:
        """After handle.stop() the port is released and the serve task exits."""
        async def handler(envelope):
            return None

        adapter = A2AAdapter()
        adapter.register_handler(handler)
        port = _free_port()
        handle = await adapter.start_listener(
            host="127.0.0.1", port=port, agent_name="lifecycle-test"
        )
        await handle.stop()
        assert handle.serve_task.done()
