"""Mesherra primitive models.

Per ARCHITECTURE.md section 3 (Core concepts).

Defines the core types: Agent, Object, Layer, Handshake, Policy, Residue, Promotion.

Phase 1 implements Residue (the append-only signed entry that anchors the
provenance vertical slice) and the supporting ActionType / Operation enums.
The other primitives remain stubs until Phase 2/3 needs them.

Schema authority: this module is the source of truth for the residue shape.
The JSON Schema mirror at ``mesherra/src/mesherra/provenance/entry_v1.json`` is
generated against this model and exists for runtime validation and cross-
language consumers; it must stay byte-equivalent on the field-set level.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mesherra.crypto.primitives import canonical_json, content_hash

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


# -- Subscription primitives (Phase 4 Slice 2) ----------------------------


class SubscriptionRole(str, Enum):
    """Which side of a live subscription a given ``active_subscriptions``
    row represents. Both roles coexist in one principal's ObjectStore
    (a principal can own some promotions and have received others)."""

    OWNER = "owner"
    RECEIVER = "receiver"


class SubscriptionStatus(str, Enum):
    """Lifecycle states of a live subscription row.

    Per SLICE_2_SPEC §4 and §7.2. The state graph is documented and
    enforced by :meth:`validate_transition` (a pure-function rule on this
    enum that the ObjectStore and the inbound handlers both delegate to,
    so there is a single source of truth for legal transitions).
    """

    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    EXPIRED = "expired"
    CLOSED_BY_RECEIVER = "closed_by_receiver"

    @classmethod
    def validate_transition(
        cls,
        from_status: SubscriptionStatus,
        to_status: SubscriptionStatus,
    ) -> None:
        """Raise :class:`InvalidSubscriptionTransition` if the move is illegal.

        Legal graph (SLICE_2_SPEC §7.2 matrices, condensed):

        * ``active``         → ``active`` | ``disconnected`` | ``expired`` | ``closed_by_receiver``
        * ``disconnected``   → ``active`` | ``disconnected`` | ``expired`` | ``closed_by_receiver``
        * ``closed_by_receiver`` → ``active`` | ``closed_by_receiver``
        * ``expired``        → ``expired`` (terminal; cannot revive)
        """
        if to_status not in _LEGAL_TRANSITIONS[from_status]:
            raise InvalidSubscriptionTransition(
                f"illegal subscription status transition: "
                f"{from_status.value!r} -> {to_status.value!r}"
            )


_LEGAL_TRANSITIONS: dict[SubscriptionStatus, frozenset[SubscriptionStatus]] = {
    SubscriptionStatus.ACTIVE: frozenset({
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.DISCONNECTED,
        SubscriptionStatus.EXPIRED,
        SubscriptionStatus.CLOSED_BY_RECEIVER,
    }),
    SubscriptionStatus.DISCONNECTED: frozenset({
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.DISCONNECTED,
        SubscriptionStatus.EXPIRED,
        SubscriptionStatus.CLOSED_BY_RECEIVER,
    }),
    SubscriptionStatus.CLOSED_BY_RECEIVER: frozenset({
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CLOSED_BY_RECEIVER,
    }),
    SubscriptionStatus.EXPIRED: frozenset({SubscriptionStatus.EXPIRED}),
}


class InvalidSubscriptionTransition(Exception):
    """Raised by :meth:`SubscriptionStatus.validate_transition` when a caller
    asks for a state move that the SLICE_2_SPEC §7.2 graph forbids
    (e.g., reviving an expired subscription)."""


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
    """What kind of action occurred in a negotiation or Object lifecycle event.

    Phase 1 covers the four scheduling-negotiation operations. Phase 4
    Slice 1 (demos/phase_4/SPEC.md §8.3) adds four Object-promotion
    operations. Phase 4 Slice 2 (demos/phase_4/SLICE_2_SPEC.md §3) adds
    three more for the live-reference subscription lifecycle.

    The SQLite ``operation`` column is plain TEXT with no CHECK constraint,
    so each additive extension leaves existing ledger rows valid.
    """

    # Phase 1 — scheduling-negotiation operations.
    PROPOSAL = "proposal"
    COUNTER = "counter"
    ACCEPTANCE = "acceptance"
    REJECTION = "rejection"

    # Phase 4 Slice 1 — Object promotion lifecycle (SPEC §8.3).
    PROMOTE = "promote"                  # owner issues a PromotionHandle
    FETCH = "fetch"                      # receiver requests scoped data
    FETCH_RESPONSE = "fetch_response"    # owner returns scoped data
    FETCH_DENIED = "fetch_denied"        # owner rejects (expired/revoked/stolen)

    # Phase 4 Slice 2 — live reference subscription lifecycle (SLICE_2_SPEC §3).
    SUBSCRIBE = "subscribe"              # receiver requests subscription
    UNSUBSCRIBE = "unsubscribe"          # receiver requests teardown
    OBJECT_UPDATE = "object_update"      # owner pushes a new scoped snapshot


# -- Pattern helpers ------------------------------------------------------


_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX64_OR_EMPTY_PATTERN = re.compile(r"^([0-9a-f]{64}|)$")


# -- SendClaim (pre-send signed object on the A2A wire) -------------------


class SendClaim(BaseModel):
    """The signed object on the A2A wire that attests "the sender really sent
    this payload, with this semantic operation, in this context at this time."

    Per ARCHITECTURE.md §13.10 and SPEC §2a (SendClaim schema). A SendClaim is
    signed BEFORE the message hits the wire (so before A2A assigns the
    ``task_id``), and the signature travels in ``Message.metadata`` for the
    receiver to verify. The receiver reconstructs the canonical SendClaim
    bytes from the envelope fields they were given, hashes, and verifies the
    sender's signature.

    The SendClaim is intentionally *separate* from Residue:

    * **SendClaim** lives on the wire, is signed pre-send, and contains only
      fields known before the A2A roundtrip (so no task_id, no sequence, no
      previous_hash, no ledger state). The seven fields are:
      ``payload_hash``, ``payload_schema``, ``operation``,
      ``sender_principal_id``, ``context_id``, ``timestamp``, ``nonce``.
    * **Residue** lives in each ledger, is signed post-roundtrip (once the
      A2A-assigned ``task_id`` is known), and contains the ledger-relative
      fields (sequence, previous_hash, etc.). Each ledger owner signs their
      own Residue with their own key.

    Both signatures are by the same actor (the sender) but over different
    objects with different purposes:

    * SendClaim signature → "I really sent this payload as this operation"
    * Residue signature → "I attest this is my ledger view of the exchange"

    The ``operation`` field is included in the signed payload to preserve
    tessera fit: the receiver branches on it (e.g., MeshyCal acceptance vs
    counter), and an unsigned ``operation`` would let an in-transit attacker
    flip ``proposal`` → ``acceptance`` while the SendClaim still verified.
    The two halves would *appear* to fit while attesting different semantic
    claims — A signed "I sent these bytes," B acted on a different operation
    than A signed. Signing ``operation`` closes the gap and keeps the
    invariant: the halves either fit on every signed sub-field, or they
    don't fit at all.

    ``nonce`` is a sender-generated random value (Phase 2: UUID4, 128 bits of
    entropy) included in the signed SendClaim so the receiver can detect
    replays: even if an attacker captures a valid envelope and resends it
    inside the clock-skew window, the inbound gateway's per-sender nonce
    cache rejects the duplicate. Combined with ``timestamp`` (bounded skew
    window) this closes the Phase 1 replay gap documented in
    ARCHITECTURE.md §11.1.

    Schema ID: ``mesherra.a2a_adapter/send-claim-v1``
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "mesherra.a2a_adapter/send-claim-v1",
            "title": "Mesherra A2A SendClaim v1",
        },
    )

    payload_hash: str
    payload_schema: str = Field(min_length=1)
    operation: Operation
    sender_principal_id: str = Field(min_length=1)
    context_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    nonce: str = Field(min_length=1)

    @field_validator("payload_hash")
    @classmethod
    def _validate_payload_hash(cls, v: str) -> str:
        if not _HEX64_PATTERN.match(v):
            raise ValueError(
                "payload_hash must be exactly 64 lowercase hexadecimal "
                "characters (SHA-256 hex digest of the canonical payload)"
            )
        return v

    def to_signing_bytes_input(self) -> dict[str, Any]:
        """Return the dict form for canonical encoding by the signer/verifier.

        The signer computes ``signature = Signer.sign(canonical_json(this_dict))``;
        the verifier reconstructs the same dict from envelope fields and runs
        the same ``canonical_json`` + ``Verifier.verify`` pair.
        """
        return self.model_dump(mode="json")


# -- Residue (Phase 1 implementation) -------------------------------------


class Residue(BaseModel):
    """A single append-only signed entry in a principal's provenance ledger.

    Schema ID: ``mesherra.provenance/entry-v1``
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
            "$id": "mesherra.provenance/entry-v1",
            "title": "Mesherra Provenance Ledger Entry v1",
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
    # NOTE: Phase 1 enforces non-emptiness only. Strict ISO-8601 parsing and
    # clock-skew tolerance land with Phase 1 step 2 (Crypto), where the
    # timestamp is produced at signing time by the Signer.
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
    # NOTE: Phase 1 enforces non-emptiness only. Strict base64 + Ed25519
    # signature-length validation lands with Phase 1 step 2 (Crypto), where
    # the Signer/Verifier round-trip is the load-bearing test.
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

        IMPORTANT — caller responsibility: this method returns a Python dict.
        The signature is computed over the **canonical JSON encoding** (JCS,
        RFC 8785) of this dict, NOT over the dict itself and NOT over
        ``json.dumps(...)`` output (Python's default JSON serializer is not
        canonical and will produce different bytes across processes).

        The caller (Phase 1 step 2's Signer.sign) must do::

            from jcs import canonicalize
            from hashlib import sha256

            canonical_bytes = canonicalize(residue.to_signing_payload())
            signature = signer.sign(canonical_bytes)
            # ... then construct a new Residue with this signature

        Omitting (not blanking) the signature key is the convention required
        by demos/phase_1/SPEC.md section 4: hashing must be over the
        *signature-less* canonical encoding, otherwise the signed bytes would
        contain the signature being computed (a chicken-and-egg).
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


class Object(BaseModel):
    """A passive resource: a calendar, a document, a meeting agreement.

    Schema ID: ``mesherra.object/object-v1``
    Spec: ARCHITECTURE.md sections 3.2 and 3.7; demos/phase_4/SPEC.md section 2.

    Owner-is-canonical: the owner's stack holds the authoritative state. Every
    other principal who perceives the Object does so through a scoped, signed
    Promotion (§3.7). NOT the same as A2A's Artifact (which is narrowly the
    output of a Task).

    ``content_hash`` is computed by the model itself from ``state`` via
    JCS canonical-JSON + SHA-256. Callers may omit it (the model fills it in)
    or pass it explicitly (the model verifies it matches; a mismatch raises
    ValidationError). This makes content_hash impossible to lie about at the
    model boundary.

    Instances are immutable (``frozen=True``). Mutation produces a new Object
    instance via functional update — the ObjectStore persists the new instance,
    bumping ``object_version`` and recomputing ``content_hash``. This keeps the
    "owner mutated the Object at sequence N" history queryable from residue
    without ever allowing in-place change of a previously-attested state.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "mesherra.object/object-v1",
            "title": "Mesherra Object v1",
        },
    )

    # Schema version. Always 1 for object-v1.
    version: Literal[1] = 1

    # Stable Object identifier, UUID-style. Assigned by ObjectStore at create;
    # never changes across the Object's lifetime (including across mutations).
    object_id: str = Field(min_length=1)

    # Principal that canonically owns this Object. Mutations are owner-only
    # (the SDK enforces this; the model trusts construction).
    owner: str = Field(min_length=1)

    # Default visibility layer when no active Promotion grants a viewer access.
    home_layer: LayerKind

    # static: snapshot at promotion time. live: continuously updated reference
    # (Slice 2).
    mutability: Mutability

    # Schema ID for the state payload (e.g., meshycal.scheduling/calendar-v1).
    # Trusted in Slice 1; full schema-registry verification lands when the
    # Schema Registry stub ships.
    schema_ref: str = Field(min_length=1)

    # The Object's actual content. Free-form dict; structure governed by
    # schema_ref. canonical_json + SHA-256 of this field is what content_hash
    # commits to.
    state: dict[str, Any]

    # Monotonic per-Object version. Starts at 1; the ObjectStore bumps on
    # every mutation (which produces a new Object instance via functional
    # update). The model enforces >= 1; the store enforces monotonicity.
    object_version: int = Field(ge=1)

    # SHA-256 (hex) of canonical_json(state). Computed by the model. Callers
    # may omit (model fills) or pass explicitly (model verifies match).
    # Lowercase hex only — same discipline as Residue.payload_hash.
    content_hash: str = ""

    # ISO 8601 UTC timestamp of creation.
    created_at: str = Field(min_length=1)

    # ISO 8601 UTC timestamp of last mutation. Equals created_at at create.
    updated_at: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _compute_or_verify_content_hash(cls, data: Any) -> Any:
        """Fill in content_hash from state, or verify a caller-supplied one
        matches. Runs BEFORE field validation so the resulting content_hash
        still has to pass the format validator below.

        Per SPEC §2 construction invariants: content_hash is computed by the
        model, not the caller. A wrong content_hash raises ValidationError —
        this makes it impossible to lie about content_hash at the model
        boundary (a forger would also have to forge the state to match).
        """
        if not isinstance(data, dict):
            return data
        state = data.get("state")
        if not isinstance(state, dict):
            # Let the field validator surface the type error.
            return data
        expected = content_hash(canonical_json(state))
        supplied = data.get("content_hash", "")
        if supplied == "":
            data["content_hash"] = expected
        elif supplied != expected:
            raise ValueError(
                f"content_hash mismatch: state hashes to {expected!r}, "
                f"but content_hash was {supplied!r}"
            )
        return data

    @field_validator("content_hash")
    @classmethod
    def _validate_content_hash_format(cls, v: str) -> str:
        if not _HEX64_PATTERN.match(v):
            raise ValueError(
                "content_hash must be exactly 64 lowercase hexadecimal "
                "characters (SHA-256 hex digest of canonical_json(state))"
            )
        return v


class Layer(BaseModel):
    """A visibility zone: the computed answer to "who can see this Object right now."

    Spec: ARCHITECTURE.md section 3.3; demos/phase_4/SPEC.md section 3.

    Layer is a value type, not a stored entity (Slice 1). It is constructed
    on demand by the SDK to answer ``is_visible_to(viewer)`` queries. The
    persistent state lives on each Object (its ``home_layer``) plus the
    active Promotions (which grant additional visibility); Layer is the
    *projection* of those facts at query time.

    Visibility rules (per SPEC §3):

    | kind     | members                                  | visible to             |
    |----------|------------------------------------------|------------------------|
    | personal | {owner}                                  | only the listed members |
    | shared   | {owner, *counterparts with promotions}   | only the listed members |
    | public   | frozenset()                              | any authenticated principal |
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: LayerKind

    # Principals with visibility into this Layer projection. Frozen for value
    # semantics (order-independent equality, safe to use as a key). Empty
    # for ``public`` (anyone qualifies); typically just the owner for
    # ``personal``; owner plus counterparts for ``shared``.
    members: frozenset[str]

    @field_validator("members", mode="before")
    @classmethod
    def _coerce_to_frozenset(cls, v: Any) -> frozenset[str]:
        """Accept any iterable of strings; store as a frozenset for value
        semantics. Lists are the common call-site shape; this saves callers
        from having to wrap with frozenset() themselves."""
        if isinstance(v, frozenset):
            return v
        try:
            return frozenset(v)
        except TypeError as exc:
            raise ValueError(
                f"members must be an iterable of principal-id strings, got {type(v).__name__}"
            ) from exc

    @field_validator("members")
    @classmethod
    def _validate_member_strings(cls, v: frozenset[str]) -> frozenset[str]:
        for m in v:
            if not isinstance(m, str) or not m:
                raise ValueError("every member must be a non-empty principal-id string")
        return v

    def is_visible_to(self, principal: str) -> bool:
        """Return True if ``principal`` may perceive Objects in this Layer.

        Per SPEC §3 visibility table: ``public`` admits any principal;
        ``personal`` and ``shared`` admit only their listed members.
        """
        if self.kind is LayerKind.PUBLIC:
            return True
        return principal in self.members


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


def _parse_iso_utc(value: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp string. Accepts the ``Z`` suffix
    that the Phase 4 SPEC uses throughout. Raises ValueError on malformed
    input — the caller (a validator) wraps it as ValidationError."""
    # Python 3.11+ fromisoformat accepts the Z suffix directly, but we
    # normalize for safety in case a sub-3.11 environment is ever wedged in.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


class Promotion(BaseModel):
    """The LOCAL event recorded by an owner when authorizing a counterpart
    to perceive an Object.

    Spec: ARCHITECTURE.md sections 3.7 and CLAUDE.md vocabulary;
    demos/phase_4/SPEC.md section 4.

    Producing a Promotion has three side effects (each handled by other
    components, not by this model):

    1. A ``PromotionHandle`` (the wire artifact — see below) signed by the
       owner and transmitted to the receiver.
    2. Paired Residue entries on both ledgers (owner EMIT ``promote``,
       receiver RECEIVE ``promote``), written by the gateways.
    3. A row in the owner's ``ObjectStore.promotions`` table tying
       ``promotion_id`` to ``(object_id, snapshot_state, scope, expiry,
       receiver)``.

    Slice 1 ships ``mode == REFERENCE`` and ``mutability == STATIC`` only.
    For static promotions, ``snapshot_state`` is the scoped slice of the
    Object's state at promotion-creation time, stored once and returned
    verbatim on every fetch. ``snapshot_content_hash`` is the cryptographic
    anchor linking the wire handle to the bytes the receiver actually sees —
    the validator computes it from ``snapshot_state`` and rejects mismatch.

    LIVE (Slice 2) and COPY (Slice 3) cross-fields are encoded in this model
    now so the shapes are locked even before their handling code ships.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Stable Promotion identifier, UUID-style. Assigned by the SDK at create.
    promotion_id: str = Field(min_length=1)

    # The Object being promoted. Stable for the Object's lifetime.
    object_id: str = Field(min_length=1)

    # Principal who owns the Object and authorized this promotion.
    owner: str = Field(min_length=1)

    # Principal authorized to perceive the Object through this promotion.
    # The Slice 1 stolen-handle assertion (§9 #16) binds fetches to this.
    receiver: str = Field(min_length=1)

    # reference: receiver fetches on demand (Slice 1). copy: bytes go on the
    # wire in the handle's scoped_payload (Slice 3).
    mode: PromotionMode

    # static: snapshot stored at promotion-create, returned on every fetch
    # (Slice 1). live: streamed updates via SubscribeToTask (Slice 2).
    mutability: Mutability

    # Field allow-list (Slice 1) governing what the receiver may perceive.
    # Schema-aware projection / slice predicates / per-viewer visibility
    # are deferred to Slice 2+ per SPEC §4.1.
    scope: dict[str, Any]

    # ISO 8601 UTC timestamp when this promotion auto-revokes. Must be
    # strictly after ``created_at``.
    expiry: str = Field(min_length=1)

    # The scoped Object state at promotion-creation time (static only).
    # Returned verbatim on every fetch for the lifetime of this promotion.
    # None for live (Slice 2) — updates push the new state per event.
    snapshot_state: dict[str, Any] | None = None

    # SHA-256 (hex) of canonical_json(snapshot_state). Computed by the
    # model when snapshot_state is present; verified to match if caller
    # supplies it. Same discipline as Object.content_hash.
    snapshot_content_hash: str = ""

    # reference mode: owner's airlock URL where scoped data is fetched on
    # demand. None for copy mode.
    fetch_endpoint: str | None = None

    # ISO 8601 UTC timestamp of promotion creation.
    created_at: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _compute_or_verify_snapshot_hash(cls, data: Any) -> Any:
        """If snapshot_state is present, fill in / verify snapshot_content_hash
        the same way Object does for content_hash. Live promotions (Slice 2)
        have no snapshot_state and skip this step."""
        if not isinstance(data, dict):
            return data
        snapshot = data.get("snapshot_state")
        if isinstance(snapshot, dict):
            expected = content_hash(canonical_json(snapshot))
            supplied = data.get("snapshot_content_hash", "")
            if supplied == "":
                data["snapshot_content_hash"] = expected
            elif supplied != expected:
                raise ValueError(
                    f"snapshot_content_hash mismatch: snapshot_state hashes to "
                    f"{expected!r}, but snapshot_content_hash was {supplied!r}"
                )
        return data

    @field_validator("snapshot_content_hash")
    @classmethod
    def _validate_snapshot_hash_format(cls, v: str) -> str:
        # An empty string is only legitimate for live promotions where
        # snapshot_state is None. The mode-validator below enforces the
        # cross-field rule; here we just check the format if present.
        if v == "":
            return v
        if not _HEX64_PATTERN.match(v):
            raise ValueError(
                "snapshot_content_hash must be exactly 64 lowercase "
                "hexadecimal characters (SHA-256 hex digest)"
            )
        return v

    @field_validator("fetch_endpoint")
    @classmethod
    def _validate_fetch_endpoint(cls, v: str | None) -> str | None:
        # The cross-field validator below handles mode-coupling; here we
        # only forbid the empty-string footgun.
        if v == "":
            raise ValueError("fetch_endpoint must be a non-empty URL or None")
        return v

    @model_validator(mode="after")
    def _validate_cross_fields(self) -> Promotion:
        # owner != receiver
        if self.owner == self.receiver:
            raise ValueError("owner cannot promote to themselves (owner == receiver)")

        # expiry strictly after created_at
        try:
            created_dt = _parse_iso_utc(self.created_at)
            expiry_dt = _parse_iso_utc(self.expiry)
        except ValueError as exc:
            raise ValueError(f"created_at/expiry must be ISO 8601: {exc}") from exc
        if expiry_dt <= created_dt:
            raise ValueError(
                f"expiry ({self.expiry}) must be strictly after created_at "
                f"({self.created_at})"
            )

        # mode + fetch_endpoint pairing
        if self.mode is PromotionMode.REFERENCE and self.fetch_endpoint is None:
            raise ValueError("reference mode requires a fetch_endpoint")
        if self.mode is PromotionMode.COPY and self.fetch_endpoint is not None:
            raise ValueError("copy mode forbids fetch_endpoint")

        # mutability + snapshot_state pairing (Slice 1: static requires snapshot)
        if self.mutability is Mutability.STATIC and self.snapshot_state is None:
            raise ValueError("static mutability requires snapshot_state")
        if self.mutability is Mutability.LIVE and self.snapshot_state is not None:
            raise ValueError("live mutability forbids snapshot_state (Slice 2)")

        return self


class PromotionHandle(BaseModel):
    """The signed WIRE artifact transmitted across the boundary by a Promotion.

    Schema ID: ``mesherra.object/promotion-handle-v1``
    Spec: ARCHITECTURE.md section 3.7; demos/phase_4/SPEC.md section 5.

    The owner signs this handle (Ed25519 over canonical_json of the handle
    with ``owner_signature`` omitted) before it leaves the airlock. The
    receiver verifies the signature against the owner's public key resolved
    through the Identity Directory.

    In **reference mode** the handle carries enough for the receiver to
    fetch scoped data and verify it (``fetch_endpoint`` + ``snapshot_content_hash``)
    but not the data itself — the data stays on the owner's stack.

    In **copy mode** (Slice 3) the handle carries the scoped bytes inline
    in ``scoped_payload``; there is no fetch_endpoint. The owner cannot
    revoke a copy promotion; any conditions are honor-system.

    Cross-field invariants (all enforced by validators):
    - ``mode == reference`` → ``fetch_endpoint`` required; ``scoped_payload`` absent
    - ``mode == copy``      → ``scoped_payload`` required; ``fetch_endpoint`` absent
    - ``expiry > issued_at``
    - ``owner != receiver``

    Same canonical-signing-omission rule as Residue: the signed bytes are
    ``canonical_json(handle.to_signing_payload())`` where ``to_signing_payload``
    omits the ``owner_signature`` key entirely (not blanked — removed).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "mesherra.object/promotion-handle-v1",
            "title": "Mesherra PromotionHandle v1",
        },
    )

    version: Literal[1] = 1

    promotion_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    receiver: str = Field(min_length=1)
    schema_ref: str = Field(min_length=1)
    mode: PromotionMode
    mutability: Mutability
    scope: dict[str, Any]

    # SHA-256 (hex, lowercase) of canonical_json(scoped snapshot at
    # promotion-creation time). The receiver checks every fetch response
    # against this; static promotions never change this; live promotions
    # (Slice 2) emit a new content_hash per push in a separate envelope.
    snapshot_content_hash: str

    # reference mode only: where the receiver fetches scoped data.
    fetch_endpoint: str | None = None

    # copy mode only (Slice 3): the bytes themselves, canonical-encoded.
    scoped_payload: str | None = None

    expiry: str = Field(min_length=1)
    issued_at: str = Field(min_length=1)

    # Ed25519 signature (base64) over canonical_json of this handle with
    # ``owner_signature`` omitted. Verified against owner's public key
    # resolved through the Identity Directory.
    owner_signature: str = Field(min_length=1)

    @field_validator("snapshot_content_hash")
    @classmethod
    def _validate_snapshot_hash_format(cls, v: str) -> str:
        if not _HEX64_PATTERN.match(v):
            raise ValueError(
                "snapshot_content_hash must be exactly 64 lowercase "
                "hexadecimal characters (SHA-256 hex digest)"
            )
        return v

    @field_validator("fetch_endpoint", "scoped_payload")
    @classmethod
    def _no_empty_strings(cls, v: str | None) -> str | None:
        if v == "":
            raise ValueError("must be a non-empty value or None")
        return v

    @model_validator(mode="after")
    def _validate_cross_fields(self) -> PromotionHandle:
        if self.owner == self.receiver:
            raise ValueError("owner cannot promote to themselves (owner == receiver)")

        try:
            issued_dt = _parse_iso_utc(self.issued_at)
            expiry_dt = _parse_iso_utc(self.expiry)
        except ValueError as exc:
            raise ValueError(f"issued_at/expiry must be ISO 8601: {exc}") from exc
        if expiry_dt <= issued_dt:
            raise ValueError(
                f"expiry ({self.expiry}) must be strictly after issued_at "
                f"({self.issued_at})"
            )

        if self.mode is PromotionMode.REFERENCE:
            if self.fetch_endpoint is None:
                raise ValueError("reference mode requires fetch_endpoint")
            if self.scoped_payload is not None:
                raise ValueError("reference mode forbids scoped_payload")
        elif self.mode is PromotionMode.COPY:
            if self.scoped_payload is None:
                raise ValueError("copy mode requires scoped_payload")
            if self.fetch_endpoint is not None:
                raise ValueError("copy mode forbids fetch_endpoint")

        return self

    def to_signing_payload(self) -> dict[str, Any]:
        """Return the dict form for canonical-encoding by the signer/verifier.

        Per SPEC §5 / §6: signature is over ``canonical_json(this_dict)``
        with the ``owner_signature`` field *omitted* (not blanked — removed).
        Same convention as Residue.to_signing_payload (Phase 1 SPEC §4).
        """
        data = self.model_dump(mode="json")
        data.pop("owner_signature", None)
        return data


class ActiveSubscription(BaseModel):
    """One row in the per-principal ObjectStore's ``active_subscriptions``
    table — the live-state record of a subscription on a live reference
    promotion.

    Spec: SLICE_2_SPEC §5 (storage shape) and §4 (lifecycle).

    Unlike the Slice 1 ``promotions`` table (append-only), this row is
    update-mutated: ``status`` and ``last_pushed_object_version`` advance
    over the subscription's lifetime. The history of those state changes
    lives in the residue ledger (the SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE
    entries), not here — this is *state*, not *history*.

    ``role`` distinguishes owner-side from receiver-side rows so a single
    principal acting as both can store both kinds of rows in one table.
    The store's (promotion_id, role) PRIMARY KEY enforces that pairing.

    The model itself is frozen (each transition produces a new instance
    via functional update); the store layer enforces legal transitions
    via :meth:`SubscriptionStatus.validate_transition` before persisting.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    promotion_id: str = Field(min_length=1)

    # Owner-side: the receiver of the promotion. Receiver-side: the owner.
    counterpart: str = Field(min_length=1)

    role: SubscriptionRole

    # NULL until the first push is observed (receiver-side) or sent
    # (owner-side). Otherwise matches an Object.object_version which is
    # always >= 1 (see Object model).
    last_pushed_object_version: int | None = Field(default=None, ge=1)

    status: SubscriptionStatus

    # ISO 8601 UTC timestamp of subscription creation.
    subscribed_at: str = Field(min_length=1)

    # ISO 8601 UTC timestamp of the most recent status change. Equals
    # ``subscribed_at`` at create; bumps on every transition. The cross-
    # field validator enforces ``last_status_change_at >= subscribed_at``.
    last_status_change_at: str = Field(min_length=1)

    # Owner-side: the receiver's A2A listener URL. The owner's
    # ``update_object`` push fan-out uses this. None on receiver-side
    # rows (the receiver doesn't push under this row); None on owner-side
    # rows from clients that don't supply a URL in SubscribeRequest (in
    # which case the owner cannot push at all and the row will mark
    # disconnected on the first mutation).
    peer_url: str | None = None

    @model_validator(mode="after")
    def _validate_timestamps(self) -> ActiveSubscription:
        try:
            subscribed_dt = _parse_iso_utc(self.subscribed_at)
            change_dt = _parse_iso_utc(self.last_status_change_at)
        except ValueError as exc:
            raise ValueError(
                f"subscribed_at/last_status_change_at must be ISO 8601: {exc}"
            ) from exc
        if change_dt < subscribed_dt:
            raise ValueError(
                f"last_status_change_at ({self.last_status_change_at}) cannot be "
                f"before subscribed_at ({self.subscribed_at})"
            )
        return self
