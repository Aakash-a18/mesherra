"""MesherraEnvelope — the boundary type between Mesherra and a2a-sdk.

Per ARCHITECTURE.md §13.10. This Pydantic model is the ONLY type that crosses
out of the ``a2a_adapter`` module into the rest of Mesherra. All other modules
in Mesherra (the Inbound/Outbound Gateways, the SDK, consumers) operate on
``MesherraEnvelope`` instances and never touch a protobuf message.

The adapter's pure conversion functions (in ``wire.py``) translate between
this Pydantic shape and the protobuf ``a2a.types.Message`` shape per the
field-mapping table in ARCHITECTURE.md §13.10.

Trust model (per the Phase 1 design decision documented in §13.10):

* The signed object on the wire is a :class:`SendClaim` (defined in
  ``models/primitives.py``), NOT a full Residue. The SendClaim contains
  only fields available before A2A assigns ``task_id``: payload_hash,
  payload_schema, operation, sender_principal_id, context_id, timestamp.
* ``send_claim_signature`` is the sender's Ed25519 signature over the
  canonical JCS bytes of the SendClaim.
* Residue entries are built and signed POST-response in each ledger, with
  the now-known ``task_id`` from A2A's response.

That separation is what makes Phase 1 implementable on top of A2A 1.0:
A2A assigns ``task_id`` only after the server-side roundtrip, so the
sender cannot sign a residue that includes ``task_id`` before sending.
The SendClaim signature is what crosses the wire; the Residue signature
is what anchors each ledger.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mesherra.models.primitives import Operation


class MesherraEnvelope(BaseModel):
    """The boundary shape between Mesherra and the A2A wire.

    Constructed by the SDK before send (sender side) or by the adapter on
    receive (receiver side). The adapter is the single translator between
    this Pydantic shape and the protobuf ``a2a.types.Message`` shape.

    Instances are immutable (``frozen=True``) so that signed-and-sent
    envelopes cannot be silently mutated by callers between construction
    and transmission.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "mesherra.a2a_adapter/envelope-v1",
            "title": "Mesherra A2A Envelope v1",
        },
    )

    task_id: str = Field(
        default="",
        description=(
            "A2A task identifier. Empty on the first message of a new task "
            "— A2A's server assigns one and returns it in the response. "
            "Populated on every subsequent message in the same task, and on "
            "every inbound (received) envelope. Mesherra residue entries "
            "(which are written AFTER the response arrives) always carry "
            "a non-empty task_id; the Residue model enforces that separately."
        ),
    )
    context_id: str = Field(min_length=1)
    sender_principal_id: str = Field(min_length=1)
    payload: dict[str, Any]
    payload_schema: str = Field(min_length=1)
    operation: Operation = Field(
        description=(
            "Semantic action this send represents (PROPOSAL, COUNTER, "
            "ACCEPTANCE, REJECTION). Travels in metadata on the wire AND is "
            "part of the signed SendClaim so a MitM cannot flip "
            "proposal↔acceptance without invalidating the signature. The "
            "receiver also uses this value to write its receive Residue with "
            "the correct operation."
        ),
    )
    timestamp: str = Field(
        min_length=1,
        description=(
            "ISO-8601 UTC timestamp captured at send time. Travels on the "
            "wire so the receiver can reconstruct the canonical SendClaim "
            "bytes to verify ``send_claim_signature``. Also provides a small "
            "amount of replay defense; Phase 2+ will layer nonces on top."
        ),
    )
    send_claim_signature: str = Field(
        min_length=1,
        description=(
            "Sender's Ed25519 signature (base64) over the canonical JCS "
            "bytes of the SendClaim: "
            "{payload_hash, payload_schema, operation, sender_principal_id, "
            "context_id, timestamp}. Receiver reconstructs the SendClaim "
            "from envelope fields (computing payload_hash from envelope.payload) "
            "and verifies. See ARCHITECTURE.md §13.3 step 3."
        ),
    )
