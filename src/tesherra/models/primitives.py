"""Tesherra primitive models.

Per ARCHITECTURE.md section 3 (Core concepts).

Defines the core types: Agent, Object, Layer, Handshake, Policy, Residue, Promotion.

Phase 1 implements Residue (the append-only signed entry that anchors the
provenance vertical slice) and the supporting ActionType / Operation enums.
The other primitives remain stubs until Phase 2/3 needs them.

Schema authority: this module is the source of truth for the residue shape.
The JSON Schema mirror at ``tesherra/src/tesherra/provenance/entry_v1.json`` is
generated against this model and exists for runtime validation and cross-
language consumers; it must stay byte-equivalent on the field-set level.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# -- Layers ----------------------------------------------------------------


class LayerKind(str, Enum):
    """Default layer types per ARCHITECTURE.md section 3.3.

    Consumers / Delegations may define richer domain-specific layer types
    on top of these defaults; the primitive set is intentionally small.
    """

    PERSONAL = "personal"
    SHARED = "shared"
    PUBLIC = "public"


# -- Promotion modes & mutability -----------------------------------------


class PromotionMode(str, Enum):
    """Per ARCHITECTURE.md section 3.7."""

    REFERENCE = "reference"  # revocable handle, owner retains canonical state
    COPY = "copy"            # irrevocable bytes; conditions honor-system


class Mutability(str, Enum):
    """Per ARCHITECTURE.md section 3.2 and 3.7."""

    STATIC = "static"  # snapshot at promotion time; on-demand pull
    LIVE = "live"      # streamed updates via A2A SubscribeToTask


# -- Provenance: action and operation enums -------------------------------


class ActionType(str, Enum):
    """Direction of the action from this ledger's perspective.

    Per demos/phase_1/SPEC.md section 3.

    - EMIT: this ledger's owner performed the action (the actor equals the
      ledger_owner).
    - RECEIVE: this ledger's owner observed an action performed by a remote
      principal (the actor is the counterpart).
    """

    EMIT = "emit"
    RECEIVE = "receive"


class Operation(str, Enum):
    """What kind of action occurred in a negotiation.

    Phase 1 covers the four scheduling-negotiation operations. Phase 2/3 may
    extend this to Object promotion lifecycle (promoted, revoked, etc.).
    """

    PROPOSAL = "proposal"
    COUNTER = "counter"
    ACCEPTANCE = "acceptance"
    REJECTION = "rejection"


# -- Residue (Phase 1 implementation) -------------------------------------


_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX64_OR_EMPTY_PATTERN = re.compile(r"^([0-9a-f]{64}|)$")


class Residue(BaseModel):
    """A single append-only signed entry in a principal's provenance ledger.

    Schema ID: ``tesherra.provenance/entry-v1``
    Spec: ARCHITECTURE.md section 3.6 and demos/phase_1/SPEC.md section 3.

    Each entry records one action that this ledger's owner took or observed.
    Two matching entries on the two parties' ledgers (with identical task_id,
    context_id, payload_hash, and payload_schema) link the perspectives:
    the actor's "emit" entry and the counterpart's "receive" entry.

    In v0, residue is primarily forensic (audit and dispute resolution).
    Preventive uses emerge in v1+ as the trust graph fills out.

    Instances are immutable (``frozen=True``) so an appended entry cannot be
    mutated in place; any "amendment" must be a new entry that references
    the prior one.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "tesherra.provenance/entry-v1",
            "title": "Tesherra Provenance Ledger Entry v1",
        },
    )

    # Schema version. Always 1 for entry-v1.
    version: Literal[1] = 1

    # Principal that owns this ledger shard. All entries in this ledger
    # belong to this principal.
    ledger_owner: str = Field(min_length=1)

    # The A2A task.id this entry pertains to.
    task_id: str = Field(min_length=1)

    # The A2A context_id tying multi-turn interactions together.
    context_id: str = Field(min_length=1)

    # Monotonic per-ledger entry index. Starts at 0.
    sequence: int = Field(ge=0)

    # SHA-256 hex of the previous entry in this ledger. Empty string for sequence=0.
    previous_hash: str

    # ISO 8601 UTC timestamp of when this entry was recorded.
    timestamp: str = Field(min_length=1)

    # Principal that performed the action. For emit entries this equals
    # ledger_owner; for receive entries it is the remote principal.
    actor: str = Field(min_length=1)

    # Principal on the other side of the interaction.
    counterpart: str = Field(min_length=1)

    # Direction of the action from this ledger's perspective.
    action_type: ActionType

    # What kind of action it was.
    operation: Operation

    # SHA-256 (hex) of the canonical JSON encoding of the payload referenced
    # by this entry. The payload itself is not stored in the entry; entries
    # are content-addressed.
    payload_hash: str

    # Schema ID of the payload that was hashed (e.g.,
    # ``meshycal.scheduling/proposal-v1``).
    payload_schema: str = Field(min_length=1)

    # Ed25519 signature (base64) over the canonical JSON of this entry with
    # the signature field omitted. Verified against the actor's public key
    # resolved through the Identity Directory.
    signature: str = Field(min_length=1)

    @field_validator("payload_hash")
    @classmethod
    def _validate_payload_hash(cls, v: str) -> str:
        if not _HEX64_PATTERN.match(v):
            raise ValueError(
                "payload_hash must be exactly 64 lowercase hexadecimal characters "
                "(SHA-256 hex digest)"
            )
        return v

    @field_validator("previous_hash")
    @classmethod
    def _validate_previous_hash(cls, v: str) -> str:
        if not _HEX64_OR_EMPTY_PATTERN.match(v):
            raise ValueError(
                "previous_hash must be 64 lowercase hexadecimal characters "
                "or the empty string (for sequence=0)"
            )
        return v

    def to_signing_payload(self) -> dict[str, Any]:
        """Return the dict form of this entry with the signature field omitted.

        The signature is computed over the canonical JSON encoding of THIS
        return value, not over the full entry. Omitting (not blanking) the
        signature is the convention required by demos/phase_1/SPEC.md
        section 4.
        """
        data = self.model_dump(mode="json")
        data.pop("signature", None)
        return data


# -- Other primitive stubs (Phase 2+) -------------------------------------


class Agent:
    """A principal. Has identity, intent, authority, zone standing.

    See ARCHITECTURE.md section 3.1.

    Status: Phase 2 (identity verification ships this).
    """

    def __init__(self, principal_id: str, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Agent is implemented in Phase 2 (identity verification)."
        )


class Object:
    """A passive resource (calendar, document, contract, etc.).

    Has owner, home layer, per-viewer layer-membership, type properties,
    residue. See ARCHITECTURE.md sections 3.2 and 3.7.

    NOT the same as A2A's Artifact (which is narrowly the output of a Task).

    Status: Phase 2/3 (Object promotion lifecycle ships this).
    """

    def __init__(self, object_id: str, owner: str, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Object is implemented in Phase 2/3 (Object promotion lifecycle)."
        )


class Layer:
    """A visibility zone. See ARCHITECTURE.md section 3.3.

    Status: Phase 2/3 (used by Object promotion).
    """

    def __init__(self, kind: LayerKind, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Layer is implemented in Phase 2/3 (used by Object promotion)."
        )


class Handshake:
    """A continuous, stateful trust negotiation between agents.

    Spans one or more A2A Tasks, tied together by context_id.
    See ARCHITECTURE.md section 3.4.

    Status: Phase 2 (identity verification + multi-turn state).
    """

    def __init__(self, context_id: str, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Handshake is implemented in Phase 2 (identity verification)."
        )


class Policy:
    """The user-authored constitution. Signed by the user.

    See ARCHITECTURE.md section 3.5.

    Status: Phase 3 (scoped disclosure ships this).
    """

    def __init__(self, user_id: str, version: int, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Policy is implemented in Phase 3 (scoped disclosure)."
        )


class Promotion:
    """The act by which an owner changes an Object's layer-membership for
    a specific counterpart.

    See ARCHITECTURE.md sections 3.7 and CLAUDE.md vocabulary.

    A Promotion is a signed event that produces matching residue entries
    on both sides (owner records authorization; receiver records grant) and
    yields a PromotionHandle that is transmitted across the boundary.

    Status: Phase 2/3 (Object promotion lifecycle).
    """

    def __init__(
        self,
        object_id: str,
        owner: str,
        receiver: str,
        mode: PromotionMode,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError(
            "Promotion is implemented in Phase 2/3 (Object promotion lifecycle)."
        )


class PromotionHandle:
    """The wire-format artifact transmitted across the boundary by a Promotion.

    See ARCHITECTURE.md section 3.7 ("Object data flow across boundaries")
    for the full data-flow semantics.

    Fields (per ARCHITECTURE.md section 3.7):
        object_id        — stable promotion identifier (UUID-style), assigned
                           once at promotion time, stable across the lifetime
                           of the promotion (including across live updates).
                           Distinct from content_hash.
        content_hash     — hash of the canonical representation at the current
                           state. Static promotions have one content_hash for
                           the lifetime; live promotions emit a new one per
                           update.
        schema_ref       — pointer to the published schema in the Schema
                           Registry (e.g., "meshycal.scheduling/proposal-v1").
        scope            — scope spec: which fields or slice the receiver
                           may see.
        mode             — PromotionMode.REFERENCE or PromotionMode.COPY.
        expiry           — ISO 8601 timestamp when the promotion auto-revokes.
        fetch_endpoint   — reference mode: owner's airlock URL where scoped
                           data is fetched on demand. None for copy mode.
        owner_signature  — owner's principal signature over the canonical
                           encoding of the handle.
        scoped_payload   — copy mode only: the actual scoped bytes,
                           canonical-encoded and signed. None for reference mode.

    Status: Phase 2/3 (the owner-is-canonical wire shape; encoded here from
    day one so an implementer cannot accidentally introduce a shared-state
    pathway, but the actual semantics ship with Object promotion).
    """

    def __init__(
        self,
        object_id: str,
        content_hash: bytes,
        schema_ref: str,
        scope: dict[str, Any],
        mode: PromotionMode,
        expiry: str,
        owner_signature: bytes,
        fetch_endpoint: str | None = None,
        scoped_payload: bytes | None = None,
    ) -> None:
        raise NotImplementedError(
            "PromotionHandle is implemented in Phase 2/3 "
            "(Object promotion lifecycle)."
        )
