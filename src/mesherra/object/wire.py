"""Phase 4 Object-promotion wire-payload models.

These Pydantic models describe the payload shapes that flow on the A2A
wire for the Phase 4 promotion lifecycle (SPEC §8.2 + §8.3, plus Slice 2's
live-reference extension SLICE_2_SPEC §2-3).

| Operation        | Payload model     | Schema URI                          |
|------------------|-------------------|-------------------------------------|
| PROMOTE          | PromotionHandle   | mesherra.object/promotion-handle-v1 |
| PROMOTE (resp)   | PromotionAck      | mesherra.object/promotion-ack-v1    |
| FETCH            | FetchRequest      | mesherra.object/fetch-v1            |
| FETCH_RESPONSE   | FetchResponse     | mesherra.object/fetch-response-v1   |
| FETCH_DENIED     | FetchDenied       | mesherra.object/fetch-denied-v1     |
| OBJECT_UPDATE    | ObjectUpdate      | mesherra.object/object-update-v1    |

PromotionHandle is defined in models/primitives.py (it's the only Phase 4
wire artifact that crosses identity boundaries and warrants its own JSON
Schema mirror). The remaining payloads are Mesherra-internal wire shapes;
their Pydantic definition is the source of truth.

All models are ``frozen=True`` and ``extra="forbid"`` — defense-in-depth
against silent drift in wire bytes between this version and any future
extension.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mesherra.crypto.primitives import canonical_json, content_hash

# -- Schema-ID constants (single source of truth) -----------------------

FETCH_REQUEST_SCHEMA: Literal["mesherra.object/fetch-v1"] = (
    "mesherra.object/fetch-v1"
)
FETCH_RESPONSE_SCHEMA: Literal["mesherra.object/fetch-response-v1"] = (
    "mesherra.object/fetch-response-v1"
)
FETCH_DENIED_SCHEMA: Literal["mesherra.object/fetch-denied-v1"] = (
    "mesherra.object/fetch-denied-v1"
)
PROMOTION_ACK_SCHEMA: Literal["mesherra.object/promotion-ack-v1"] = (
    "mesherra.object/promotion-ack-v1"
)
OBJECT_UPDATE_SCHEMA: Literal["mesherra.object/object-update-v1"] = (
    "mesherra.object/object-update-v1"
)

# Slice 2 subscribe / unsubscribe / update-ack schema URIs.
SUBSCRIBE_REQUEST_SCHEMA: Literal["mesherra.object/subscribe-v1"] = (
    "mesherra.object/subscribe-v1"
)
SUBSCRIBE_ACK_SCHEMA: Literal["mesherra.object/subscribe-ack-v1"] = (
    "mesherra.object/subscribe-ack-v1"
)
SUBSCRIBE_DENIED_SCHEMA: Literal["mesherra.object/subscribe-denied-v1"] = (
    "mesherra.object/subscribe-denied-v1"
)
UNSUBSCRIBE_REQUEST_SCHEMA: Literal["mesherra.object/unsubscribe-v1"] = (
    "mesherra.object/unsubscribe-v1"
)
UNSUBSCRIBE_ACK_SCHEMA: Literal["mesherra.object/unsubscribe-ack-v1"] = (
    "mesherra.object/unsubscribe-ack-v1"
)
UNSUBSCRIBE_DENIED_SCHEMA: Literal["mesherra.object/unsubscribe-denied-v1"] = (
    "mesherra.object/unsubscribe-denied-v1"
)
OBJECT_UPDATE_ACK_SCHEMA: Literal["mesherra.object/object-update-ack-v1"] = (
    "mesherra.object/object-update-ack-v1"
)
OBJECT_UPDATE_DENIED_SCHEMA: Literal["mesherra.object/object-update-denied-v1"] = (
    "mesherra.object/object-update-denied-v1"
)

# Denial-reason Literal types. SLICE_2_SPEC §7.2 / §7.3 pin the reasons.
SubscribeDenialReason = Literal[
    "unknown_promotion",
    "receiver_mismatch",
    "not_live_promotion",
    "expired",
]
UnsubscribeDenialReason = Literal["not_active", "expired"]
ObjectUpdateDenialReason = Literal["expired", "version_regression"]

# Documented denial reasons (SPEC §8.2, §9 #16). Pinning this set as a
# Literal forces callers to use a known reason; an unrecognized value
# would otherwise quietly flow to the receiver's residue without any
# downstream system knowing what it meant.
DenialReason = Literal[
    "expired",
    "revoked",
    "receiver_mismatch",
    "unknown_promotion",
    "scope_violation",
]


# -- FetchRequest -------------------------------------------------------


class FetchRequest(BaseModel):
    """Receiver-side payload requesting scoped data for a held PromotionHandle.

    Travels with ``operation = Operation.FETCH`` and
    ``payload_schema = FETCH_REQUEST_SCHEMA``. The owner's airlock looks
    the promotion up by ``promotion_id`` and either returns a
    ``FetchResponse`` or a ``FetchDenied``.

    ``fetch_sequence`` is per-handle monotonic (SPEC §8.2 step 2) so the
    integration test can prove fetch ordering and the receiver can
    correlate request to response when multiple fetches are in flight.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": FETCH_REQUEST_SCHEMA,
            "title": "Mesherra Object Fetch Request v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    fetch_sequence: int = Field(ge=1)


# -- FetchResponse ------------------------------------------------------


class FetchResponse(BaseModel):
    """Owner-side payload returning the scoped snapshot for a fetch.

    The receiver validates ``SHA-256(JCS(snapshot_state)) ==
    handle.snapshot_content_hash`` and ``snapshot_content_hash`` echoes
    back from the owner so the residue carries the binding hash
    explicitly (the receiver re-verifies rather than trusting the field).

    Note: ``fetch_sequence`` is deliberately NOT in this model. SPEC §9 #8
    requires that two fetches against the same static-reference promotion
    produce byte-equal residue payload_hashes (the static-snapshot
    invariant). Including a per-fetch counter in the response payload
    would break that property. The receiver correlates request to
    response via the A2A task_id (each fetch is a distinct A2A task);
    the counter belongs in the request only.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": FETCH_RESPONSE_SCHEMA,
            "title": "Mesherra Object Fetch Response v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    snapshot_state: dict[str, Any]
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


# -- FetchDenied --------------------------------------------------------


class FetchDenied(BaseModel):
    """Owner-side payload refusing a fetch.

    Reasons are pinned by the ``DenialReason`` Literal so the receiver
    (and anyone reading the residue) can rely on a known small set.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": FETCH_DENIED_SCHEMA,
            "title": "Mesherra Object Fetch Denied v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    fetch_sequence: int = Field(ge=1)
    reason: DenialReason


# -- PromotionAck -------------------------------------------------------


class PromotionAck(BaseModel):
    """Receiver-side payload confirming receipt of a PromotionHandle.

    Slice 1 ships the smallest possible ack — the handle was accepted,
    signature verified, and persisted in the receiver's ObjectStore. No
    "not received" variant exists; if the gateway raised, the request
    would have failed before the ack was built and the residue would
    have been written by the airlock's error path.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": PROMOTION_ACK_SCHEMA,
            "title": "Mesherra Object Promotion Ack v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    received: Literal[True] = True


# -- ObjectUpdate (Slice 2) ---------------------------------------------


class ObjectUpdate(BaseModel):
    """Owner-pushed scoped snapshot for a subscribed live reference promotion.

    Travels with ``operation = Operation.OBJECT_UPDATE`` and
    ``payload_schema = OBJECT_UPDATE_SCHEMA``. Sent on every owner-side
    mutation of a LIVE Object, to every receiver with an active subscription.

    ``object_version`` is the Object's monotonic version at push time
    (SLICE_2_SPEC §2). Sequencing comes from this field rather than a
    fetch-style counter because pushes are owner-driven and per-receiver
    ordering is preserved by the owner's serial send loop (§7.4).

    ``snapshot_content_hash`` commits to JCS(snapshot_state). The model
    enforces equality on construction (same defense as Object/Promotion);
    the receiver handler recomputes again on receive (§7.3). The pair of
    checks closes the gap where an attacker could substitute a tampered
    state alongside a stale hash on the wire.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": OBJECT_UPDATE_SCHEMA,
            "title": "Mesherra Object Update v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    object_version: int = Field(ge=1)
    snapshot_state: dict[str, Any]
    snapshot_content_hash: str = Field(default="", pattern=r"^([0-9a-f]{64}|)$")

    @model_validator(mode="before")
    @classmethod
    def _compute_or_verify_snapshot_hash(cls, data: Any) -> Any:
        """Same fill-or-verify convention as ``Object.content_hash`` and
        ``Promotion.snapshot_content_hash``: caller may omit the hash and
        the model derives it from ``snapshot_state``; if supplied, it must
        match. A wrong hash raises ValidationError — impossible to forge
        the binding at the model boundary."""
        if not isinstance(data, dict):
            return data
        state = data.get("snapshot_state")
        if not isinstance(state, dict):
            return data  # let the field validator surface the type error
        expected = content_hash(canonical_json(state))
        supplied = data.get("snapshot_content_hash", "")
        if supplied == "":
            data["snapshot_content_hash"] = expected
        elif supplied != expected:
            raise ValueError(
                f"snapshot_content_hash mismatch: snapshot_state hashes to "
                f"{expected!r}, but snapshot_content_hash was {supplied!r}"
            )
        return data


# -- Subscribe / Unsubscribe / Update-ack payloads (Slice 2) ------------


class SubscribeRequest(BaseModel):
    """Receiver → owner: ``please subscribe me to this live promotion``.

    Travels with ``operation = Operation.SUBSCRIBE``. The owner's handler
    looks up the promotion, checks ``promotion.receiver == sender_principal``
    (§9 #16 stolen-handle invariant), confirms ``mutability == LIVE`` and
    ``now < expiry``, then inserts or updates the owner-side
    ``active_subscriptions`` row per §7.2 SUBSCRIBE matrix.

    ``receiver_url`` is the receiver's A2A listener URL. The owner stores
    it on the subscription row and uses it as the push target in
    ``update_object`` fan-out. Optional in Slice 2 v0 (older clients
    may omit), but in practice required for the owner to be able to
    push at all — without a URL the subscription is "receive-fetches-only"
    and the owner will mark it disconnected on the first mutation. The
    production version of this lives in the A2A AgentCard exchange;
    Slice 2 carries it explicitly until the AgentCard surface is wired.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": SUBSCRIBE_REQUEST_SCHEMA,
            "title": "Mesherra Object Subscribe Request v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    receiver_url: str | None = None


class SubscribeAck(BaseModel):
    """Owner → receiver: ``subscription is active``.

    Per Slice 1 ack convention (cf. ``PromotionAck``): positive-only.
    Denial flows through :class:`SubscribeDenied`.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": SUBSCRIBE_ACK_SCHEMA,
            "title": "Mesherra Object Subscribe Ack v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    subscribed: Literal[True] = True


class SubscribeDenied(BaseModel):
    """Owner → receiver: subscription request refused.

    Reasons per SLICE_2_SPEC §7.2 SUBSCRIBE matrix:

    * ``unknown_promotion`` — no promotion with this ID on the owner's store.
    * ``receiver_mismatch`` — sender_principal != promotion.receiver (the
      §9 #16 stolen-handle invariant extends here from Slice 1's FETCH check).
    * ``not_live_promotion`` — promotion.mutability == STATIC; cannot subscribe.
    * ``expired`` — promotion past its expiry (or its row already EXPIRED).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": SUBSCRIBE_DENIED_SCHEMA,
            "title": "Mesherra Object Subscribe Denied v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    reason: SubscribeDenialReason


class UnsubscribeRequest(BaseModel):
    """Receiver → owner: ``please tear down my subscription``.

    Travels with ``operation = Operation.UNSUBSCRIBE``. The owner marks
    the row ``closed_by_receiver`` per §7.2 UNSUBSCRIBE matrix and stops
    pushing on the next mutation.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": UNSUBSCRIBE_REQUEST_SCHEMA,
            "title": "Mesherra Object Unsubscribe Request v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)


class UnsubscribeAck(BaseModel):
    """Owner → receiver: ``subscription closed``."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": UNSUBSCRIBE_ACK_SCHEMA,
            "title": "Mesherra Object Unsubscribe Ack v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    unsubscribed: Literal[True] = True


class UnsubscribeDenied(BaseModel):
    """Owner → receiver: unsubscribe refused.

    Reasons per SLICE_2_SPEC §7.2 UNSUBSCRIBE matrix:

    * ``not_active`` — no row exists for this (promotion, role) pair.
    * ``expired`` — row exists but has already moved to EXPIRED via the
      wall-clock path; ack would imply the receiver caused the close.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": UNSUBSCRIBE_DENIED_SCHEMA,
            "title": "Mesherra Object Unsubscribe Denied v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    reason: UnsubscribeDenialReason


class ObjectUpdateAck(BaseModel):
    """Receiver → owner: ``push v=N processed``.

    ``object_version`` echoes the version that was just processed so the
    owner can advance ``last_pushed_object_version`` without ambiguity
    (§7.1 step 3g). The receiver's handler will have already verified
    signature, content_hash, and version monotonicity before this ack.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": OBJECT_UPDATE_ACK_SCHEMA,
            "title": "Mesherra Object Update Ack v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    object_version: int = Field(ge=1)
    received: Literal[True] = True


class ObjectUpdateDenied(BaseModel):
    """Receiver → owner: push not processed.

    Reasons per SLICE_2_SPEC §7.3 soft-failure handling:

    * ``expired`` — receiver's handle is past its expiry; further pushes
      will continue to be denied until the owner stops sending.
    * ``version_regression`` — ``payload.object_version <= last_pushed``;
      either the owner replayed (shouldn't happen given §7.4's per-receiver
      send-ordering invariant) or version semantics broke.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "$id": OBJECT_UPDATE_DENIED_SCHEMA,
            "title": "Mesherra Object Update Denied v1",
        },
    )

    version: Literal[1] = 1
    promotion_id: str = Field(min_length=1)
    object_version: int = Field(ge=1)
    reason: ObjectUpdateDenialReason
