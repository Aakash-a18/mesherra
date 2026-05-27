"""ObjectInboundHandler — the trust-layer routine for Phase 4 operations.

The InboundGateway dispatches Phase 4 operations to this handler before
they would otherwise reach the consumer's business logic. These are NOT
consumer operations — they are part of Mesherra's own wire protocol for
Object promotion, and the consumer (MeshyCal, etc.) does not need to
(and must not) implement them.

Slice 1 responsibilities (SPEC §8.1, §8.2):

PROMOTE (Bob receives a handle from Alice):
1. Reconstruct the PromotionHandle from the payload.
2. Verify ``handle.owner_signature`` against ``handle.owner``'s public
   key resolved via the Directory.
3. Slice 1 constraint: ``sender_principal_id == handle.owner`` (no
   handle forwarding). Future slices may relax this once a forwarding
   protocol is specified.
4. Persist via :meth:`ObjectStore.record_received_handle` (which itself
   verifies ``handle.receiver == this principal``, the second line of
   defense behind the airlock's own checks).
5. Return a :class:`PromotionAck`.

FETCH (Alice receives a fetch request from Bob):
1. Reconstruct the :class:`FetchRequest` from the payload.
2. Look up the promotion in our store. Not found → ``unknown_promotion``.
3. ``sender_principal_id != promotion.receiver`` → ``receiver_mismatch``
   (SPEC §9 #16 stolen-handle invariant).
4. ``now > promotion.expiry`` → ``expired``.
5. Otherwise build a :class:`FetchResponse` from the pre-stored
   ``snapshot_state`` (Slice 1 is static-reference; the snapshot is
   captured at promotion time and returned unchanged regardless of
   later owner mutations).

Slice 2 responsibilities (SLICE_2_SPEC §§7.2-7.3):

SUBSCRIBE (Alice receives subscribe from Bob): pre-state branching per
the §7.2 SUBSCRIBE matrix — denial for not-LIVE / expired / receiver
mismatch / unknown promotion, idempotent / recovery / fresh-state
transitions for the other rows.

UNSUBSCRIBE (Alice receives unsubscribe from Bob): mark row
``closed_by_receiver`` per §7.2 UNSUBSCRIBE matrix. Idempotent on a row
already in that state.

OBJECT_UPDATE (Bob receives a push from Alice): validate handle, sender,
mutability, expiry, version monotonicity, and content_hash. Soft
failures (expired, version regression) return ObjectUpdateDenied; hard
failures (forwarded path, hash mismatch, malformed) raise.

Why a separate handler (not the consumer): these operations are part
of Mesherra's trust contract. Letting the consumer override them would
let domain code violate the privacy invariants (§9 #15, #16). The
InboundGateway dispatches these operations here BEFORE the consumer
ever sees them.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mesherra.crypto.primitives import (
    Verifier,
    canonical_json,
    content_hash,
)
from mesherra.identity import DirectoryClient
from mesherra.models.primitives import (
    Mutability,
    Operation,
    PromotionHandle,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import (
    ObjectStore,
    PromotionNotFound,
    SubscriptionNotFound,
)
from mesherra.object.wire import (
    FETCH_DENIED_SCHEMA,
    FETCH_RESPONSE_SCHEMA,
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_DENIED_SCHEMA,
    PROMOTION_ACK_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_DENIED_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_DENIED_SCHEMA,
    DenialReason,
    FetchDenied,
    FetchRequest,
    FetchResponse,
    ObjectUpdate,
    ObjectUpdateAck,
    ObjectUpdateDenialReason,
    ObjectUpdateDenied,
    PromotionAck,
    SubscribeAck,
    SubscribeDenialReason,
    SubscribeDenied,
    SubscribeRequest,
    UnsubscribeAck,
    UnsubscribeDenialReason,
    UnsubscribeDenied,
    UnsubscribeRequest,
)

# Signature: (handle, new_state, object_version) -> awaitable. Trust-layer
# verification happens before this fires; the consumer sees only verified
# data.
ObjectUpdateCallback = Callable[
    [PromotionHandle, dict[str, Any], int], Awaitable[None]
]


class InvalidPromotionHandleSignature(Exception):
    """Raised by ``handle_promote`` when the handle's ``owner_signature``
    cannot be verified against the handle's declared owner.

    Also raised when ``sender_principal_id != handle.owner`` (Slice 1's
    no-forwarding constraint) — the airlock has no way to prove that the
    handle was actually authorized by the third-party owner if the
    sender isn't them.
    """


class InvalidObjectUpdatePayload(Exception):
    """Raised by ``handle_object_update`` for §7.3 "hard failures":

    * receiver-side has no PromotionHandle for the cited promotion (no
      subscription relationship exists at all);
    * ``sender_principal_id != handle.owner`` (forwarded-push attack,
      same shape as Slice 1's PROMOTE no-forwarding rule);
    * ``handle.mutability != LIVE`` (owner pushing under a STATIC handle);
    * ``SHA-256(JCS(snapshot_state)) != snapshot_content_hash`` after
      Pydantic decode (defense-in-depth recomputation on the wire bytes;
      the model already checks at construction).

    Soft failures (expired handle, version regression, missing
    subscription row) return :class:`ObjectUpdateDenied` instead — the
    owner can transition to ``disconnected`` and back off gracefully.
    """


@dataclass(frozen=True)
class HandlerOutput:
    """What :class:`ObjectInboundHandler` returns for a Phase 4 operation.

    The InboundGateway packages this into an
    :class:`OutgoingResponse` and the response envelope, then writes the
    EMIT residue and ships back to the sender.
    """

    operation: Operation
    payload: dict[str, Any]
    payload_schema: str


class ObjectInboundHandler:
    """Trust-layer inbound routine for Phase 4 PROMOTE and FETCH.

    Constructed once per Mesherra instance, alongside the ObjectStore.
    Stateless across calls — all persistent state lives in the store.
    """

    def __init__(
        self,
        *,
        principal_id: str,
        object_store: ObjectStore,
        directory: DirectoryClient,
    ) -> None:
        self._principal_id = principal_id
        self._object_store = object_store
        self._directory = directory
        self._object_update_callback: ObjectUpdateCallback | None = None

    def register_object_update_callback(
        self, callback: ObjectUpdateCallback
    ) -> None:
        """Wire the receiver-side OBJECT_UPDATE callback (SDK calls this
        from :meth:`Mesherra.on_object_update`).

        One callback per Mesherra instance, applied uniformly to every
        live promotion this principal has subscribed to. Multi-handler
        fan-out is out of scope; the consumer can multiplex inside one
        callback if needed.

        Replace-on-call: the most recent registration wins. Re-registering
        while pushes are in flight is the caller's responsibility — Slice
        2 v0 does not lock or serialize through this method.
        """
        self._object_update_callback = callback

    # -- PROMOTE --------------------------------------------------------

    async def handle_promote(
        self,
        *,
        payload: dict[str, Any],
        sender_principal_id: str,
    ) -> HandlerOutput:
        handle = PromotionHandle.model_validate(payload)

        # Slice 1: only direct issuance — sender must be the handle's owner.
        # Forwarding (sender ≠ owner, but handle is owner-signed) is a
        # legitimate future flow but requires a separate threat model;
        # rejecting it here keeps Slice 1's invariants narrow.
        if sender_principal_id != handle.owner:
            raise InvalidPromotionHandleSignature(
                f"Sender {sender_principal_id!r} is not the handle's owner "
                f"{handle.owner!r}. Slice 1 forbids forwarded handles."
            )

        # Verify owner_signature against owner's directory-resolved key.
        # The InboundGateway has already verified the SendClaim (envelope
        # signature) — this is the second signature, the one that binds
        # the handle's *contents* to the owner regardless of who carries
        # it on the wire. Verifying both is defense-in-depth: the
        # SendClaim is checked even for forwarded handles in future
        # slices, but the handle.owner_signature is what makes the
        # persisted handle authoritative for downstream use.
        owner_record = await self._directory.resolve(handle.owner)
        verifier = Verifier.from_b64(owner_record.public_key_b64)
        signing_bytes = canonical_json(handle.to_signing_payload())
        if not verifier.verify(signing_bytes, handle.owner_signature):
            raise InvalidPromotionHandleSignature(
                f"Handle.owner_signature for promotion {handle.promotion_id!r} "
                f"did not verify under owner {handle.owner!r}'s public key."
            )

        # Persist. The store enforces handle.receiver == self._principal_id
        # (raises OwnershipChangeRejected otherwise) as the second line of
        # defense behind the airlock's checks.
        self._object_store.record_received_handle(handle)

        ack = PromotionAck(promotion_id=handle.promotion_id)
        return HandlerOutput(
            operation=Operation.PROMOTE,
            payload=ack.model_dump(),
            payload_schema=PROMOTION_ACK_SCHEMA,
        )

    # -- FETCH ----------------------------------------------------------

    async def handle_fetch(
        self,
        *,
        payload: dict[str, Any],
        sender_principal_id: str,
    ) -> HandlerOutput:
        req = FetchRequest.model_validate(payload)

        try:
            promotion = self._object_store.get_promotion(req.promotion_id)
        except PromotionNotFound:
            return self._denied(req, "unknown_promotion")

        if sender_principal_id != promotion.receiver:
            # SPEC §9 #16: stolen-handle rejected. The handle's wire
            # presentation by a non-receiver does not authorize a fetch.
            return self._denied(req, "receiver_mismatch")

        now = datetime.now(UTC)
        expiry = _parse_iso_utc(promotion.expiry)
        if now > expiry:
            return self._denied(req, "expired")

        # Slice 1 STATIC: snapshot_state was captured at promotion-create
        # time and is returned unchanged on every fetch (snapshot frozen).
        # Slice 2 LIVE: compute the scoped state fresh from the Object's
        # current state — promotion.snapshot_state is None for LIVE
        # (Promotion model enforces "live mutability forbids
        # snapshot_state"). The current-state read is the §6.2 LIVE-fetch
        # semantics.
        if promotion.mutability is Mutability.LIVE:
            try:
                obj = self._object_store.get(promotion.object_id)
            except Exception:
                # Defensive: an Object that vanished from under the
                # promotion is treated as not-fetchable. Slice 2 v0 maps
                # this to unknown_promotion (the cleanest user-facing
                # reason); a dedicated reason can be added if needed.
                return self._denied(req, "unknown_promotion")
            scope_fields = set(promotion.scope.get("fields", []))
            snapshot = {k: v for k, v in obj.state.items() if k in scope_fields}
        else:
            snapshot = promotion.snapshot_state or {}
        # We recompute snapshot_content_hash from the canonical bytes
        # rather than echoing promotion.snapshot_content_hash. For STATIC
        # this catches storage corruption (snapshot_state diverging from
        # the stored hash). For LIVE it's the canonical hash of the
        # current scoped state; the receiver does NOT compare it to
        # handle.snapshot_content_hash (SDK §6.2 branches on mutability).
        snapshot_hash = content_hash(canonical_json(snapshot))
        resp = FetchResponse(
            promotion_id=req.promotion_id,
            snapshot_state=snapshot,
            snapshot_content_hash=snapshot_hash,
        )
        return HandlerOutput(
            operation=Operation.FETCH_RESPONSE,
            payload=resp.model_dump(),
            payload_schema=FETCH_RESPONSE_SCHEMA,
        )

    # -- SUBSCRIBE (Slice 2, owner-side) --------------------------------

    async def handle_subscribe(
        self,
        *,
        payload: dict[str, Any],
        sender_principal_id: str,
    ) -> HandlerOutput:
        """Receiver requests subscription. SLICE_2_SPEC §7.2 SUBSCRIBE.

        Pre-state branching: ``get_subscription`` is consulted BEFORE
        ``update_subscription_status`` so a row in ``expired`` produces a
        ``SubscribeDenied(expired)`` (a wire response) rather than the
        store-level :class:`InvalidSubscriptionTransition` (a caller bug
        signal). The two error channels mean different things; mixing
        them up would leak protocol semantics through internal exceptions.
        """
        req = SubscribeRequest.model_validate(payload)

        try:
            promotion = self._object_store.get_promotion(req.promotion_id)
        except PromotionNotFound:
            return self._subscribe_denied(req, "unknown_promotion")

        if sender_principal_id != promotion.receiver:
            # SLICE_2_SPEC §9 #12: Eve cannot subscribe with Bob's handle.
            return self._subscribe_denied(req, "receiver_mismatch")

        if promotion.mutability is not Mutability.LIVE:
            return self._subscribe_denied(req, "not_live_promotion")

        now = datetime.now(UTC)
        if now > _parse_iso_utc(promotion.expiry):
            return self._subscribe_denied(req, "expired")

        try:
            existing = self._object_store.get_subscription(
                promotion_id=req.promotion_id, role=SubscriptionRole.OWNER
            )
        except SubscriptionNotFound:
            existing = None

        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if existing is None:
            self._object_store.record_subscription(
                promotion_id=req.promotion_id,
                counterpart=sender_principal_id,
                role=SubscriptionRole.OWNER,
                subscribed_at=now_iso,
                peer_url=req.receiver_url,
            )
        elif existing.status is SubscriptionStatus.EXPIRED:
            # Cannot revive — §7.2 row 5. Denial flows over the wire so the
            # receiver knows to give up rather than retry indefinitely.
            return self._subscribe_denied(req, "expired")
        elif existing.status is SubscriptionStatus.CLOSED_BY_RECEIVER:
            # Treat as fresh subscription: clear last_pushed first so the
            # receiver-side gap detection starts from NULL on the next
            # push, then transition status back to active. Refresh the
            # peer_url too — the receiver may have moved listener URLs
            # while the row was closed.
            self._object_store.update_subscription_status(
                promotion_id=req.promotion_id,
                role=SubscriptionRole.OWNER,
                new_status=SubscriptionStatus.ACTIVE,
                changed_at=now_iso,
            )
            self._object_store.reset_subscription_pushed_version(
                promotion_id=req.promotion_id, role=SubscriptionRole.OWNER
            )
            if req.receiver_url is not None and req.receiver_url != existing.peer_url:
                self._object_store.update_subscription_peer_url(
                    promotion_id=req.promotion_id,
                    role=SubscriptionRole.OWNER,
                    peer_url=req.receiver_url,
                )
        elif existing.status is SubscriptionStatus.DISCONNECTED:
            self._object_store.update_subscription_status(
                promotion_id=req.promotion_id,
                role=SubscriptionRole.OWNER,
                new_status=SubscriptionStatus.ACTIVE,
                changed_at=now_iso,
            )
            # The receiver may have moved listener URLs while we were
            # disconnected — refresh on recovery so subsequent pushes
            # don't keep hitting the stale endpoint.
            if req.receiver_url is not None and req.receiver_url != existing.peer_url:
                self._object_store.update_subscription_peer_url(
                    promotion_id=req.promotion_id,
                    role=SubscriptionRole.OWNER,
                    peer_url=req.receiver_url,
                )
        # else ACTIVE: idempotent no-op (no peer_url refresh — the
        # subscription is healthy by definition; if the receiver wants
        # to update their URL they should unsubscribe and re-subscribe).

        ack = SubscribeAck(promotion_id=req.promotion_id)
        return HandlerOutput(
            operation=Operation.SUBSCRIBE,
            payload=ack.model_dump(),
            payload_schema=SUBSCRIBE_ACK_SCHEMA,
        )

    # -- UNSUBSCRIBE (Slice 2, owner-side) ------------------------------

    async def handle_unsubscribe(
        self,
        *,
        payload: dict[str, Any],
        sender_principal_id: str,
    ) -> HandlerOutput:
        """Receiver requests teardown. SLICE_2_SPEC §7.2 UNSUBSCRIBE.

        ``sender_principal_id != promotion.receiver`` is collapsed to
        ``not_active`` rather than its own denial reason — leaking the
        existence of someone else's subscription row to Eve would be a
        small but unnecessary side-channel. ``not_active`` is the same
        response Eve would get if the row genuinely didn't exist.
        """
        req = UnsubscribeRequest.model_validate(payload)

        try:
            existing = self._object_store.get_subscription(
                promotion_id=req.promotion_id, role=SubscriptionRole.OWNER
            )
        except SubscriptionNotFound:
            return self._unsubscribe_denied(req, "not_active")

        # Sender must be the legitimate receiver. Collapse to not_active
        # to avoid leaking row existence; same wire shape Eve would see
        # for a non-existent promotion.
        try:
            promotion = self._object_store.get_promotion(req.promotion_id)
        except PromotionNotFound:
            return self._unsubscribe_denied(req, "not_active")
        if sender_principal_id != promotion.receiver:
            return self._unsubscribe_denied(req, "not_active")

        if existing.status is SubscriptionStatus.EXPIRED:
            return self._unsubscribe_denied(req, "expired")

        if existing.status is SubscriptionStatus.CLOSED_BY_RECEIVER:
            # Idempotent: §7.2 row 3.
            ack = UnsubscribeAck(promotion_id=req.promotion_id)
            return HandlerOutput(
                operation=Operation.UNSUBSCRIBE,
                payload=ack.model_dump(),
                payload_schema=UNSUBSCRIBE_ACK_SCHEMA,
            )

        # active | disconnected → closed_by_receiver.
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self._object_store.update_subscription_status(
            promotion_id=req.promotion_id,
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.CLOSED_BY_RECEIVER,
            changed_at=now_iso,
        )
        ack = UnsubscribeAck(promotion_id=req.promotion_id)
        return HandlerOutput(
            operation=Operation.UNSUBSCRIBE,
            payload=ack.model_dump(),
            payload_schema=UNSUBSCRIBE_ACK_SCHEMA,
        )

    # -- OBJECT_UPDATE (Slice 2, receiver-side) -------------------------

    async def handle_object_update(
        self,
        *,
        payload: dict[str, Any],
        sender_principal_id: str,
    ) -> HandlerOutput:
        """Receive an owner-pushed snapshot. SLICE_2_SPEC §7.3.

        Hard failures raise :class:`InvalidObjectUpdatePayload`; soft
        failures return :class:`ObjectUpdateDenied`. The Pydantic model's
        construction-time hash check is the first line of defense; this
        method recomputes again from the raw payload dict (per §7.3
        "defense-in-depth recomputation") so a payload that bypassed
        ``model_validate`` is still caught.
        """
        # Defense-in-depth: recompute hash from the raw payload BEFORE
        # full Pydantic validation. If a tampered wire payload pre-decode
        # had a valid hash internally but the bytes were mutated, model
        # construction would catch it — but the wire payload may have
        # arrived through paths that bypass model_validate. Belt and
        # braces.
        if not isinstance(payload, dict):
            raise InvalidObjectUpdatePayload(
                "payload must be a dict (decoded JSON object)"
            )
        state_in_payload = payload.get("snapshot_state")
        hash_in_payload = payload.get("snapshot_content_hash")
        if isinstance(state_in_payload, dict) and isinstance(hash_in_payload, str):
            recomputed = content_hash(canonical_json(state_in_payload))
            if recomputed != hash_in_payload:
                raise InvalidObjectUpdatePayload(
                    f"snapshot_content_hash mismatch on the wire: "
                    f"declared {hash_in_payload!r}, recomputed {recomputed!r}"
                )

        update = ObjectUpdate.model_validate(payload)

        # Receiver-side handle lookup. The owner pushed under a particular
        # promotion_id; without our matching handle, there is no
        # subscription relationship — hard failure.
        try:
            handle = self._object_store.get_received_handle(update.promotion_id)
        except PromotionNotFound as exc:
            raise InvalidObjectUpdatePayload(
                f"no received handle for promotion_id={update.promotion_id!r}; "
                "owner is pushing without an established subscription"
            ) from exc

        # Forwarded-path attack: only the handle's stated owner may push.
        if sender_principal_id != handle.owner:
            raise InvalidObjectUpdatePayload(
                f"sender {sender_principal_id!r} is not the handle owner "
                f"{handle.owner!r}; forwarded pushes are forbidden in Slice 2"
            )

        # LIVE-only operation.
        if handle.mutability is not Mutability.LIVE:
            raise InvalidObjectUpdatePayload(
                f"handle {update.promotion_id!r} is not live; OBJECT_UPDATE "
                "applies only to live reference promotions"
            )

        # Subscription-row lookup. Missing row = receiver never subscribed
        # (or already cleaned up); soft denial so the owner can mark its
        # side disconnected and back off.
        try:
            subscription = self._object_store.get_subscription(
                promotion_id=update.promotion_id, role=SubscriptionRole.RECEIVER
            )
        except SubscriptionNotFound:
            return self._object_update_denied(update, "expired")

        # Expiry: a handle past its expiry can no longer carry valid
        # pushes; soft denial.
        now = datetime.now(UTC)
        if now > _parse_iso_utc(handle.expiry):
            return self._object_update_denied(update, "expired")

        # Version monotonicity: forward jumps are gap-tolerant (§8); a
        # regression or repeat is soft-denied. The owner-side serial
        # send-ordering invariant (§7.4) means this shouldn't happen in
        # practice — but if it does, we surface the disagreement rather
        # than silently bumping last_pushed backward.
        last = subscription.last_pushed_object_version
        if last is not None and update.object_version <= last:
            return self._object_update_denied(update, "version_regression")

        # Persist + invoke callback.
        # Use a single internal helper to avoid the SubscriptionVersionConflict
        # path; we've already verified strict-greater above.
        self._object_store.update_subscription_pushed_version(
            promotion_id=update.promotion_id,
            role=SubscriptionRole.RECEIVER,
            object_version=update.object_version,
        )
        if self._object_update_callback is not None:
            await self._object_update_callback(
                handle, update.snapshot_state, update.object_version
            )

        ack = ObjectUpdateAck(
            promotion_id=update.promotion_id,
            object_version=update.object_version,
        )
        return HandlerOutput(
            operation=Operation.OBJECT_UPDATE,
            payload=ack.model_dump(),
            payload_schema=OBJECT_UPDATE_ACK_SCHEMA,
        )

    # -- internals ------------------------------------------------------

    def _denied(self, req: FetchRequest, reason: DenialReason) -> HandlerOutput:
        denied = FetchDenied(
            promotion_id=req.promotion_id,
            fetch_sequence=req.fetch_sequence,
            reason=reason,
        )
        return HandlerOutput(
            operation=Operation.FETCH_DENIED,
            payload=denied.model_dump(),
            payload_schema=FETCH_DENIED_SCHEMA,
        )

    def _subscribe_denied(
        self, req: SubscribeRequest, reason: SubscribeDenialReason
    ) -> HandlerOutput:
        denied = SubscribeDenied(promotion_id=req.promotion_id, reason=reason)
        return HandlerOutput(
            operation=Operation.SUBSCRIBE,
            payload=denied.model_dump(),
            payload_schema=SUBSCRIBE_DENIED_SCHEMA,
        )

    def _unsubscribe_denied(
        self, req: UnsubscribeRequest, reason: UnsubscribeDenialReason
    ) -> HandlerOutput:
        denied = UnsubscribeDenied(promotion_id=req.promotion_id, reason=reason)
        return HandlerOutput(
            operation=Operation.UNSUBSCRIBE,
            payload=denied.model_dump(),
            payload_schema=UNSUBSCRIBE_DENIED_SCHEMA,
        )

    def _object_update_denied(
        self, update: ObjectUpdate, reason: ObjectUpdateDenialReason
    ) -> HandlerOutput:
        denied = ObjectUpdateDenied(
            promotion_id=update.promotion_id,
            object_version=update.object_version,
            reason=reason,
        )
        return HandlerOutput(
            operation=Operation.OBJECT_UPDATE,
            payload=denied.model_dump(),
            payload_schema=OBJECT_UPDATE_DENIED_SCHEMA,
        )


def _parse_iso_utc(s: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp, accepting both ``Z`` suffix and
    explicit ``+00:00`` offset forms.

    Local helper rather than importing from gateways.replay — keeps the
    object module independent of gateway internals. The two will
    converge if a shared parse utility becomes valuable.
    """
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)
