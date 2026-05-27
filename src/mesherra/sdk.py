"""Mesherra SDK / Public API.

Per ARCHITECTURE.md §13.1. The only surface consumers (MeshyCal, future
Delegations) interact with. Everything else in Mesherra is internal.

Phase 1 surface (the provenance vertical slice):

* :meth:`Mesherra.send_to` — send a signed payload to a peer (via Outbound
  Gateway), record both residues, return the peer's response.
* :meth:`Mesherra.on_message` — register a consumer handler for inbound
  messages. Registration wires through the Inbound Gateway, which wires
  through the A2A adapter.
* :meth:`Mesherra.start_listener` — start the per-agent A2A HTTP listener.
  Requires :meth:`on_message` to have been called first.
* :meth:`Mesherra.get_residue_chain` / :meth:`get_residue` — retrieve
  provenance from the local ledger.
* :meth:`Mesherra.attest` — produce a signed attestation bundle for a
  completed task.

Phase 3 (shipped):

* :meth:`get_policy` / :meth:`update_policy` — round-trip the user's
  signed policy through the per-principal :class:`PolicyStore`. Bypass
  mode (no store injected at construction) raises ``RuntimeError`` on
  either call to surface the misconfiguration explicitly.

Phase 2/3 deferred SDK helpers (still ``NotImplementedError``):

* :meth:`register_principal` — Identity Directory **shipped in Phase 2**
  but registration is currently done by the orchestrator via direct HTTP
  to ``POST /principals``. An SDK wrapper is deferred until a real
  consumer needs it.
* :meth:`verify` — AgentCard signature verification helper. Phase 2's
  Directory + ``HTTPDirectoryClient`` already do this on every resolve;
  this SDK-level helper would expose it as an explicit API for advanced
  consumers. Deferred.

Construct with explicit dependencies — Phase 1 is dependency-injection-first
so tests and the demo orchestrator can wire fake/synthetic components.
A higher-level factory (``Mesherra.from_config(env)``) will land when
ARCHITECTURE.md §13.5 (Identity Directory) is real in Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mesherra.a2a_adapter import A2AAdapter, ListenerHandle
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.inbound import (
    ConsumerHandler,
    InboundGateway,
)
from mesherra.gateways.outbound import GatewayError, OutboundGateway, OutboundResult
from mesherra.gateways.replay import ReplayProtector
from mesherra.identity import DirectoryClient
from mesherra.models.primitives import (
    LayerKind,
    Mutability,
    Object,
    Operation,
    Promotion,
    PromotionHandle,
    PromotionMode,
    Residue,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.handler import ObjectInboundHandler, ObjectUpdateCallback
from mesherra.object.store import ObjectStore, SubscriptionNotFound
from mesherra.object.wire import (
    FETCH_REQUEST_SCHEMA,
    OBJECT_UPDATE_ACK_SCHEMA,
    OBJECT_UPDATE_SCHEMA,
    SUBSCRIBE_ACK_SCHEMA,
    SUBSCRIBE_DENIED_SCHEMA,
    SUBSCRIBE_REQUEST_SCHEMA,
    UNSUBSCRIBE_ACK_SCHEMA,
    UNSUBSCRIBE_DENIED_SCHEMA,
    UNSUBSCRIBE_REQUEST_SCHEMA,
    FetchDenied,
    FetchRequest,
    FetchResponse,
    ObjectUpdate,
    SubscribeAck,
    SubscribeDenied,
    SubscribeRequest,
    UnsubscribeAck,
    UnsubscribeDenied,
    UnsubscribeRequest,
)
from mesherra.policy import (
    PolicyEngine,
    PolicyStore,
    SignedPolicyDoc,
    sign_policy_doc,
)
from mesherra.provenance.ledger import ProvenanceLedger


class OwnershipError(Exception):
    """Raised by SDK Object-mutation paths when the requesting principal
    is not the Object's owner.

    Mesherra's owner-is-canonical commitment (ARCH §3.7) means only an
    Object's owner can mutate it. This exception fires at the SDK layer as
    the user-visible API boundary. The ObjectStore's own owner-mismatch
    check is the defensive second line behind it.
    """


class PromotionFetchDenied(Exception):
    """Raised by :meth:`Mesherra.fetch_object` when the owner returned a
    FETCH_DENIED response (expired promotion, revoked, receiver mismatch,
    or unknown promotion). The exception message carries the owner's
    structured ``reason`` so callers can branch on it.
    """


class FetchContentHashMismatch(Exception):
    """The owner returned a FETCH_RESPONSE whose ``snapshot_state``
    canonical hash does not match the ``snapshot_content_hash`` the
    handle committed to.

    Either the owner is misbehaving (returning bytes that diverge from
    their own commitment) or the handle has been tampered with. Either
    way, do NOT use the returned snapshot — it is not the data the owner
    signed under at promotion time. This is the §9 #15 / #12 byte-equal
    guarantee at the receiver's gate.
    """


class SubscriptionDenied(Exception):
    """Raised by :meth:`Mesherra.subscribe_to_object` or
    :meth:`Mesherra.unsubscribe_from_object` when the owner returned a
    SubscribeDenied / UnsubscribeDenied response.

    The structured ``reason`` (e.g., ``expired``, ``receiver_mismatch``,
    ``not_live_promotion``, ``not_active``) travels in the exception
    message so callers can branch on it without needing to inspect the
    raw wire payload.
    """


@dataclass(frozen=True)
class AttestationBundle:
    """Signed attestation produced by :meth:`Mesherra.attest`.

    Phase 1 bundles the entries for a given task_id. Phase 2 will add a
    signature over the canonical bytes of the bundle so the recipient can
    verify the whole package as a unit.
    """

    task_id: str
    entries: list[Residue]


class Mesherra:
    """Public SDK surface. The consumer's single entry point into Mesherra.

    Each running agent process owns one Mesherra instance: their principal,
    their key, their ledger, their A2A listener. Multi-tenant servers
    (Phase 2+) will host multiple Mesherra instances behind a router.
    """

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
        replay_protector: ReplayProtector | None = None,
        object_store: ObjectStore | None = None,
    ) -> None:
        if ledger.ledger_owner != principal_id:
            raise ValueError(
                f"Ledger owner {ledger.ledger_owner!r} must match principal_id "
                f"{principal_id!r}; pointing two principals at one ledger is "
                "an unrecoverable state."
            )
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._adapter = adapter
        # Phase 2 Identity Directory (ARCH §13.5). Consumers inject either a
        # StaticDirectoryClient (tests, demo) or an HTTPDirectoryClient
        # (production, ships in sub-step 2). The gateways resolve every peer
        # through this client — no other path from gateway to public key.
        self._directory = directory
        # Phase 2 replay defense (ARCH §11.1). Consumers may inject a custom
        # ReplayProtector (typically for tests that need a controllable
        # clock); production usage falls through to MESHERRA_CLOCK_SKEW_SECONDS.
        self._replay_protector = replay_protector or ReplayProtector.from_env()
        # Phase 3 policy enforcement (ARCH §13.4 / §13.6). Both arguments are
        # optional: passing a ``policy_store`` activates outbound + inbound
        # scoping (with default-deny on unmatched schemas per SPEC §2.2);
        # omitting it puts the gateways in bypass mode for Phase 1/2 test
        # surfaces. If a store is provided without an explicit engine, a
        # default ``PolicyEngine()`` is constructed (stateless; no config).
        self._policy_store = policy_store
        self._policy_engine = policy_engine or (
            PolicyEngine() if policy_store is not None else None
        )
        # Phase 4 Object/Promotion persistence (ARCH §13.12). Optional;
        # when absent, all Object/Promotion SDK methods raise RuntimeError
        # — same bypass-mode discipline as policy_store. When present, the
        # store's owner_principal_id must match this Mesherra's principal.
        if object_store is not None and object_store.owner_principal_id != principal_id:
            raise ValueError(
                f"ObjectStore owner {object_store.owner_principal_id!r} must "
                f"match principal_id {principal_id!r}; pointing two principals "
                "at one object store is an unrecoverable state."
            )
        self._object_store = object_store
        # When an object_store is wired, the InboundGateway needs an
        # ObjectInboundHandler so it can dispatch incoming PROMOTE/FETCH
        # to the trust-layer routine rather than the consumer (see
        # gateways/inbound.py for the dispatch policy). Without an
        # object_store there's no place to persist received handles, so
        # the handler is omitted and PROMOTE/FETCH inbound would raise
        # TrustLayerHandlerNotWired — explicit fail-loud.
        self._object_handler: ObjectInboundHandler | None = (
            ObjectInboundHandler(
                principal_id=principal_id,
                object_store=object_store,
                directory=self._directory,
            )
            if object_store is not None
            else None
        )
        self._outbound = OutboundGateway(
            principal_id=principal_id,
            signer=signer,
            ledger=ledger,
            adapter=adapter,
            directory=self._directory,
            policy_store=self._policy_store,
            policy_engine=self._policy_engine,
        )
        self._inbound = InboundGateway(
            principal_id=principal_id,
            signer=signer,
            ledger=ledger,
            directory=self._directory,
            replay_protector=self._replay_protector,
            policy_store=self._policy_store,
            policy_engine=self._policy_engine,
            object_handler=self._object_handler,
        )
        # Wire the inbound gateway into the adapter. No consumer is
        # registered yet; :meth:`on_message` does that.
        adapter.register_handler(self._inbound.handle_inbound)

    # -- properties -----------------------------------------------------

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def public_key_b64(self) -> str:
        """The base64 public key this principal publishes for peers.

        Phase 1: agent configs include this string in their public-key
        directory. Phase 2: the Identity Directory serves it.
        """
        return self._signer.public_key_b64()

    # -- outbound -------------------------------------------------------

    async def send_to(
        self,
        *,
        peer_url: str,
        peer_principal_id: str,
        payload: dict[str, Any],
        payload_schema: str,
        operation: Operation,
        context_id: str | None = None,
    ) -> OutboundResult:
        """Send a signed payload to a peer; record both residues; return result.

        See :class:`OutboundGateway` for the ordered pipeline. Phase 1 is
        request-response only; the result includes the A2A-assigned
        ``task_id`` so callers can issue subsequent operations on the same task.
        """
        return await self._outbound.send(
            peer_url=peer_url,
            peer_principal_id=peer_principal_id,
            payload=payload,
            payload_schema=payload_schema,
            operation=operation,
            context_id=context_id,
        )

    # -- inbound --------------------------------------------------------

    def on_message(self, handler: ConsumerHandler) -> None:
        """Register a consumer handler for inbound messages.

        The handler receives an :class:`IncomingMessage` and may return an
        :class:`OutgoingResponse` (request-response) or ``None``
        (fire-and-forget). Trust-layer concerns (verification, residue
        writes) are handled by the Inbound Gateway before the handler is
        invoked.
        """
        self._inbound.register_consumer(handler)

    async def start_listener(
        self,
        *,
        host: str,
        port: int,
        agent_name: str,
        agent_version: str = "0.1.0",
    ) -> ListenerHandle:
        """Boot the per-agent A2A HTTP listener.

        Thin pass-through to the adapter; named here so consumers don't
        need to reach into the adapter directly. Requires :meth:`on_message`
        to have been called first (the adapter enforces this).
        """
        return await self._adapter.start_listener(
            host=host,
            port=port,
            agent_name=agent_name,
            agent_version=agent_version,
        )

    # -- ledger accessors -----------------------------------------------

    def get_residue(self, task_id: str) -> list[Residue]:
        """Return all residue entries pertaining to ``task_id``."""
        return self._ledger.get_by_task(task_id)

    def get_residue_chain(self, context_id: str) -> list[Residue]:
        """Return the full ordered residue chain for ``context_id``.

        Includes both this principal's emit entries and receive entries
        for the conversation.
        """
        return self._ledger.get_by_context(context_id)

    def attest(self, task_id: str) -> AttestationBundle:
        """Produce a signed attestation for a completed task.

        Phase 1 returns the entries verbatim, bundled. Phase 2 will sign
        the bundle as a whole so a recipient can verify it as a unit.
        """
        entries = self._ledger.get_by_task(task_id)
        return AttestationBundle(task_id=task_id, entries=entries)

    # -- Phase 4 Object / Promotion surface ----------------------------

    def create_object(
        self,
        *,
        state: dict[str, Any],
        home_layer: LayerKind,
        mutability: Mutability,
        schema_ref: str,
    ) -> Object:
        """Create a new Object owned by this principal and persist it.

        The SDK auto-generates ``object_id`` (UUID4) and the ``created_at``
        / ``updated_at`` timestamps (current UTC, equal at create). The
        Object's ``owner`` is filled from ``self.principal_id`` — callers
        cannot create Objects on someone else's behalf through this API.

        ``content_hash`` is auto-computed by the Object model from ``state``.
        """
        self._require_object_store()
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        obj = Object(
            object_id=str(uuid4()),
            owner=self._principal_id,
            home_layer=home_layer,
            mutability=mutability,
            schema_ref=schema_ref,
            state=state,
            object_version=1,
            created_at=now,
            updated_at=now,
        )
        assert self._object_store is not None  # narrowed by _require_object_store
        self._object_store.put(obj)
        return obj

    async def update_object(
        self, object_id: str, new_state: dict[str, Any]
    ) -> Object:
        """Mutate an Object's ``state``, persist a new version, and
        (for LIVE) push the new scoped snapshot to every active
        subscriber.

        Slice 1 behavior preserved: bumps ``object_version`` by 1,
        recomputes ``content_hash``, stamps ``updated_at``, preserves
        ``created_at``. Raises :class:`OwnershipError` if the loaded
        Object's owner is not this principal.

        Slice 2 (SLICE_2_SPEC §7.1) extension: after the persist, if any
        live promotion of ``object_id`` has an active owner-side
        subscription, the SDK pushes an OBJECT_UPDATE per receiver
        through the outbound airlock (sequential per §7.1 step 3).

        Push failures (denial response, transport raise) are
        best-effort: the affected subscription is marked
        ``disconnected`` and ``update_object`` returns the new Object
        successfully — the mutation is the authoritative event, the
        push is its notification. Receivers reconcile via FETCH per the
        drop-and-fetch model (§7.4).

        For STATIC objects (and LIVE objects with no active
        subscriptions) the push branch is skipped entirely.
        """
        self._require_object_store()
        assert self._object_store is not None
        existing = self._object_store.get(object_id)
        if existing.owner != self._principal_id:
            raise OwnershipError(
                f"Cannot update Object {object_id!r}: owner is "
                f"{existing.owner!r}, not this principal "
                f"{self._principal_id!r}. Only the owner can mutate."
            )
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        updated = Object(
            object_id=existing.object_id,
            owner=existing.owner,
            home_layer=existing.home_layer,
            mutability=existing.mutability,
            schema_ref=existing.schema_ref,
            state=new_state,
            object_version=existing.object_version + 1,
            created_at=existing.created_at,
            updated_at=now,
        )
        self._object_store.put(updated)

        # Slice 2 push fan-out. STATIC objects skip the JOIN (no rows).
        if updated.mutability is Mutability.LIVE:
            await self._push_live_updates(updated)

        return updated

    async def _push_live_updates(self, obj: Object) -> None:
        """For every active owner-side subscription of a live promotion
        of ``obj.object_id``, send an OBJECT_UPDATE with the scoped
        slice of the new state. Per SLICE_2_SPEC §7.1 step 3:
        sequential within one update_object call; failures mark the
        subscription disconnected without raising."""
        assert self._object_store is not None
        subs = self._object_store.list_active_subscriptions_for_object(
            object_id=obj.object_id
        )
        for sub in subs:
            try:
                promotion = self._object_store.get_promotion(sub.promotion_id)
            except Exception:
                # Promotion vanished out from under us (cold reload
                # mismatch?). Skip — defense-in-depth.
                continue
            # Expiry guard per §7.1 step 3b: stop pushing past expiry,
            # mark expired locally.
            if _wall_clock_past(promotion.expiry):
                self._mark_subscription_status(
                    promotion_id=sub.promotion_id,
                    role=SubscriptionRole.OWNER,
                    new_status=SubscriptionStatus.EXPIRED,
                )
                continue

            scope_fields = set(promotion.scope.get("fields", []))
            scoped_state = {
                k: v for k, v in obj.state.items() if k in scope_fields
            }
            update = ObjectUpdate(
                promotion_id=sub.promotion_id,
                object_version=obj.object_version,
                snapshot_state=scoped_state,
            )
            # Push target is the receiver's A2A listener URL captured on
            # the subscription row when they subscribed. Without it the
            # owner has no way to reach the receiver — mark disconnected.
            if not sub.peer_url:
                self._mark_subscription_status(
                    promotion_id=sub.promotion_id,
                    role=SubscriptionRole.OWNER,
                    new_status=SubscriptionStatus.DISCONNECTED,
                )
                continue
            try:
                result = await self._outbound.send(
                    peer_url=sub.peer_url,
                    peer_principal_id=promotion.receiver,
                    payload=update.model_dump(),
                    payload_schema=OBJECT_UPDATE_SCHEMA,
                    operation=Operation.OBJECT_UPDATE,
                )
            except Exception:
                # Transient transport failure — receiver unreachable,
                # peer signature verification on response failed, etc.
                # Same recovery path as a denial: mark disconnected,
                # don't propagate (the mutation already succeeded).
                self._mark_subscription_status(
                    promotion_id=sub.promotion_id,
                    role=SubscriptionRole.OWNER,
                    new_status=SubscriptionStatus.DISCONNECTED,
                )
                continue

            if result.response_payload_schema == OBJECT_UPDATE_ACK_SCHEMA:
                # Positive ack — bump last_pushed. Per §7.4 step 3, a
                # successful push to a DISCONNECTED row is the recovery
                # signal: transition it back to ACTIVE so future
                # bookkeeping reflects the live connection.
                self._object_store.update_subscription_pushed_version(
                    promotion_id=sub.promotion_id,
                    role=SubscriptionRole.OWNER,
                    object_version=obj.object_version,
                )
                if sub.status is SubscriptionStatus.DISCONNECTED:
                    self._mark_subscription_status(
                        promotion_id=sub.promotion_id,
                        role=SubscriptionRole.OWNER,
                        new_status=SubscriptionStatus.ACTIVE,
                    )
            else:
                # ObjectUpdateDenied (expired or version_regression).
                self._mark_subscription_status(
                    promotion_id=sub.promotion_id,
                    role=SubscriptionRole.OWNER,
                    new_status=SubscriptionStatus.DISCONNECTED,
                )

    def _mark_subscription_status(
        self,
        *,
        promotion_id: str,
        role: SubscriptionRole,
        new_status: SubscriptionStatus,
    ) -> None:
        """Best-effort status transition wrapper. Swallows
        InvalidSubscriptionTransition (e.g. trying to revive an
        already-expired row) since the push path is the SDK's *attempt*
        at recovery, not the authority on legal transitions."""
        assert self._object_store is not None
        from mesherra.models.primitives import InvalidSubscriptionTransition
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        try:
            self._object_store.update_subscription_status(
                promotion_id=promotion_id,
                role=role,
                new_status=new_status,
                changed_at=now_iso,
            )
        except InvalidSubscriptionTransition:
            pass

    def promote(
        self,
        *,
        object_id: str,
        receiver: str,
        scope: dict[str, Any],
        expiry: str,
        mode: PromotionMode = PromotionMode.REFERENCE,
        mutability: Mutability = Mutability.STATIC,
        fetch_endpoint_base: str | None = None,
    ) -> tuple[Promotion, PromotionHandle]:
        """Authorize ``receiver`` to perceive ``object_id`` under ``scope``.

        Slice 1: reference mode + static mutability only. The scoped
        snapshot is computed at promotion-creation time and stored on the
        Promotion row; subsequent fetches by the receiver return this
        snapshot regardless of later owner mutations.

        Returns ``(Promotion, PromotionHandle)`` — the local event record
        and the signed wire artifact respectively. The handle is fully
        signed and ready for the outbound airlock (Phase 4 step 7 wires
        it through ``send_to`` with operation == ``promote``).

        ``fetch_endpoint_base`` defaults to a placeholder for tests; in
        production callers pass the owner's listener URL. The full endpoint
        is ``{base}/mesherra/objects/fetch/{promotion_id}``.
        """
        self._require_object_store()
        assert self._object_store is not None
        obj = self._object_store.get(object_id)
        if obj.owner != self._principal_id:
            raise OwnershipError(
                f"Cannot promote Object {object_id!r}: owner is "
                f"{obj.owner!r}, not this principal "
                f"{self._principal_id!r}. Only the owner can issue promotions."
            )

        scope_fields: list[str] = list(scope.get("fields", []))
        snapshot_state: dict[str, Any] = {
            k: v for k, v in obj.state.items() if k in scope_fields
        }
        # The handle's snapshot_content_hash is the receiver's initial
        # commitment. For STATIC, it matches the Promotion row's frozen
        # snapshot. For LIVE (SLICE_2_SPEC §6.2), the spec calls for
        # computing the hash over the scoped slice of the Object's
        # current state at promotion-creation time — gives the receiver
        # a verifiable commitment to compare against the first push.
        scoped_hash = content_hash(canonical_json(snapshot_state))

        promotion_id = str(uuid4())
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        base = fetch_endpoint_base or "https://owner.example"
        fetch_endpoint = f"{base}/mesherra/objects/fetch/{promotion_id}"

        promotion = Promotion(
            promotion_id=promotion_id,
            object_id=object_id,
            owner=self._principal_id,
            receiver=receiver,
            mode=mode,
            mutability=mutability,
            scope=scope,
            expiry=expiry,
            snapshot_state=snapshot_state if mutability is Mutability.STATIC else None,
            fetch_endpoint=fetch_endpoint if mode is PromotionMode.REFERENCE else None,
            created_at=now,
        )

        # Construct an unsigned handle to compute the canonical signing
        # bytes, then re-construct with the real signature attached.
        # For LIVE, promotion.snapshot_content_hash is empty (no stored
        # snapshot); the handle gets the freshly-computed scoped_hash.
        handle_snapshot_hash = (
            promotion.snapshot_content_hash
            if mutability is Mutability.STATIC
            else scoped_hash
        )
        unsigned_handle = PromotionHandle(
            promotion_id=promotion_id,
            object_id=object_id,
            owner=self._principal_id,
            receiver=receiver,
            schema_ref=obj.schema_ref,
            mode=mode,
            mutability=mutability,
            scope=scope,
            snapshot_content_hash=handle_snapshot_hash,
            fetch_endpoint=fetch_endpoint if mode is PromotionMode.REFERENCE else None,
            scoped_payload=None,  # Slice 3 only
            expiry=expiry,
            issued_at=now,
            owner_signature="placeholder",  # replaced below
        )
        signed_bytes = canonical_json(unsigned_handle.to_signing_payload())
        signature = self._signer.sign(signed_bytes)
        handle = unsigned_handle.model_copy(update={"owner_signature": signature})

        self._object_store.record_promotion(promotion)
        return promotion, handle

    async def fetch_object(
        self,
        *,
        handle: PromotionHandle,
        peer_url: str,
        fetch_sequence: int = 1,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        """Fetch the scoped snapshot for a held PromotionHandle.

        Wraps a FETCH send through the outbound airlock. The owner's
        gateway returns either FETCH_RESPONSE (with the scoped snapshot)
        or FETCH_DENIED (with a documented reason). On FETCH_RESPONSE,
        validates the returned snapshot's canonical hash matches the
        ``snapshot_content_hash`` the handle committed to — divergence
        raises :class:`FetchContentHashMismatch` (the receiver-side gate
        on the §9 #15 / #12 byte-equal guarantee).

        Does NOT require an ``object_store`` (the handle is the caller's
        responsibility); the SDK only needs the outbound path to be wired.

        Args:
            handle: A PromotionHandle previously received from ``handle.owner``.
            peer_url: The owner's A2A endpoint. Out-of-band knowledge in
                Slice 1; future slices may resolve this from the handle.
            fetch_sequence: Per-handle monotonic counter (SPEC §8.2 step 2).
                Slice 1: caller-managed; future work persists this in the
                received_handles row.
            context_id: Optional A2A context id; auto-generated if omitted.

        Returns:
            The owner's scoped snapshot — the dict whose canonical hash
            equals ``handle.snapshot_content_hash``.

        Raises:
            PromotionFetchDenied: owner returned FETCH_DENIED.
            FetchContentHashMismatch: response bytes don't match handle's
                committed snapshot hash.
            GatewayError: owner returned an unexpected operation.
        """
        req = FetchRequest(
            promotion_id=handle.promotion_id, fetch_sequence=fetch_sequence
        )
        result = await self._outbound.send(
            peer_url=peer_url,
            peer_principal_id=handle.owner,
            payload=req.model_dump(),
            payload_schema=FETCH_REQUEST_SCHEMA,
            operation=Operation.FETCH,
            context_id=context_id,
        )

        if result.response_operation is Operation.FETCH_DENIED:
            denied = FetchDenied.model_validate(result.response_payload)
            raise PromotionFetchDenied(
                f"Owner {handle.owner!r} denied fetch for promotion "
                f"{handle.promotion_id!r}: reason={denied.reason!r}"
            )

        if result.response_operation is not Operation.FETCH_RESPONSE:
            # Defensive: the wire protocol pins only FETCH_RESPONSE /
            # FETCH_DENIED as legitimate responses. An unexpected operation
            # is either a confused peer or a confused protocol revision —
            # don't trust the payload.
            raise GatewayError(
                f"Unexpected response operation "
                f"{result.response_operation.value!r} for fetch of "
                f"promotion {handle.promotion_id!r}; "
                f"expected {Operation.FETCH_RESPONSE.value!r} or "
                f"{Operation.FETCH_DENIED.value!r}."
            )

        resp = FetchResponse.model_validate(result.response_payload)

        # Slice 2 (SLICE_2_SPEC §6.2): the hash-vs-handle check is
        # STATIC-only. For LIVE handles, the Object's state may have
        # mutated since the handle was issued; handle.snapshot_content_hash
        # only commits to the promotion-creation snapshot as an *initial*
        # commitment. A LIVE fetch returns the owner's current scoped
        # state, whose hash is the response's own field — there is no
        # cross-time commitment to check against.
        if handle.mutability is Mutability.STATIC:
            computed = content_hash(canonical_json(resp.snapshot_state))
            if computed != handle.snapshot_content_hash:
                raise FetchContentHashMismatch(
                    f"Fetched snapshot for promotion {handle.promotion_id!r} "
                    f"has content_hash {computed!r} but handle committed to "
                    f"{handle.snapshot_content_hash!r}. Refusing the payload."
                )

        return resp.snapshot_state

    async def subscribe_to_object(
        self,
        *,
        handle: PromotionHandle,
        peer_url: str,
        context_id: str | None = None,
        my_url: str | None = None,
    ) -> None:
        """Open a live subscription against a received PromotionHandle.

        SLICE_2_SPEC §6.1. Only valid for LIVE handles; STATIC raises
        :class:`ValueError`. Idempotent within Slice 2: re-subscribing
        while the local row is already ACTIVE short-circuits without
        sending another wire op (mirrors the owner-side handler's
        idempotency at §7.2 row 2).

        ``my_url`` is this receiver's A2A listener URL. It rides on the
        SubscribeRequest so the owner can record it on their owner-side
        subscription row; the owner uses it as the push target in
        ``update_object`` fan-out. Without it, the owner cannot push
        and will mark the subscription disconnected on the first
        mutation. The production version of this lives in the A2A
        AgentCard exchange; Slice 2 carries it explicitly until that
        surface is wired.

        Sends SUBSCRIBE via the outbound airlock, awaits the owner's
        SubscribeAck (records the receiver-side ``active_subscriptions``
        row) or SubscribeDenied (raises :class:`SubscriptionDenied` with
        the structured reason; no local row is created on denial).
        """
        self._require_object_store()
        assert self._object_store is not None

        if handle.mutability is not Mutability.LIVE:
            raise ValueError(
                f"subscribe_to_object requires a LIVE handle; "
                f"promotion {handle.promotion_id!r} is {handle.mutability.value!r}"
            )

        # Idempotency check: short-circuit if we already have an active
        # receiver-side row. The §7.2 SUBSCRIBE matrix is idempotent on
        # ACTIVE, so the wire round-trip would be wasted bytes; skipping
        # it locally is a strict superset of the spec semantics.
        try:
            existing = self._object_store.get_subscription(
                promotion_id=handle.promotion_id, role=SubscriptionRole.RECEIVER
            )
            if existing.status is SubscriptionStatus.ACTIVE:
                return
        except SubscriptionNotFound:
            existing = None

        req = SubscribeRequest(
            promotion_id=handle.promotion_id, receiver_url=my_url
        )
        result = await self._outbound.send(
            peer_url=peer_url,
            peer_principal_id=handle.owner,
            payload=req.model_dump(),
            payload_schema=SUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.SUBSCRIBE,
            context_id=context_id,
        )

        if result.response_payload_schema == SUBSCRIBE_DENIED_SCHEMA:
            denied = SubscribeDenied.model_validate(result.response_payload)
            raise SubscriptionDenied(
                f"Owner {handle.owner!r} denied subscribe for promotion "
                f"{handle.promotion_id!r}: reason={denied.reason!r}"
            )

        # Positive ack → record (or transition) the receiver-side row.
        SubscribeAck.model_validate(result.response_payload)  # validate shape
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if existing is None:
            self._object_store.record_subscription(
                promotion_id=handle.promotion_id,
                counterpart=handle.owner,
                role=SubscriptionRole.RECEIVER,
                subscribed_at=now_iso,
            )
        else:
            # Transition existing row back to ACTIVE; reset last_pushed
            # for the CLOSED_BY_RECEIVER fresh-subscription case (mirrors
            # the owner-side handler at §7.2 row 4).
            self._object_store.update_subscription_status(
                promotion_id=handle.promotion_id,
                role=SubscriptionRole.RECEIVER,
                new_status=SubscriptionStatus.ACTIVE,
                changed_at=now_iso,
            )
            if existing.status is SubscriptionStatus.CLOSED_BY_RECEIVER:
                self._object_store.reset_subscription_pushed_version(
                    promotion_id=handle.promotion_id,
                    role=SubscriptionRole.RECEIVER,
                )

    async def unsubscribe_from_object(
        self,
        *,
        handle: PromotionHandle,
        peer_url: str,
        context_id: str | None = None,
    ) -> None:
        """Close an active subscription.

        SLICE_2_SPEC §6.1. Sends UNSUBSCRIBE to the owner; on ack marks
        the local receiver-side row ``closed_by_receiver``. A denial
        from the owner (``not_active`` / ``expired``) raises
        :class:`SubscriptionDenied`.

        Calling unsubscribe on a row that is already
        ``closed_by_receiver`` still sends the wire op (the owner may
        not know about the prior unsubscribe; bandwidth is cheap and the
        owner's handler is idempotent at §7.2 UNSUBSCRIBE row 3).
        """
        self._require_object_store()
        assert self._object_store is not None

        req = UnsubscribeRequest(promotion_id=handle.promotion_id)
        result = await self._outbound.send(
            peer_url=peer_url,
            peer_principal_id=handle.owner,
            payload=req.model_dump(),
            payload_schema=UNSUBSCRIBE_REQUEST_SCHEMA,
            operation=Operation.UNSUBSCRIBE,
            context_id=context_id,
        )

        if result.response_payload_schema == UNSUBSCRIBE_DENIED_SCHEMA:
            denied = UnsubscribeDenied.model_validate(result.response_payload)
            raise SubscriptionDenied(
                f"Owner {handle.owner!r} denied unsubscribe for promotion "
                f"{handle.promotion_id!r}: reason={denied.reason!r}"
            )

        UnsubscribeAck.model_validate(result.response_payload)
        try:
            existing = self._object_store.get_subscription(
                promotion_id=handle.promotion_id, role=SubscriptionRole.RECEIVER
            )
        except SubscriptionNotFound:
            return  # nothing local to update; owner's ack is enough

        if existing.status is SubscriptionStatus.CLOSED_BY_RECEIVER:
            return  # already there; idempotent

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self._object_store.update_subscription_status(
            promotion_id=handle.promotion_id,
            role=SubscriptionRole.RECEIVER,
            new_status=SubscriptionStatus.CLOSED_BY_RECEIVER,
            changed_at=now_iso,
        )

    def on_object_update(self, callback: ObjectUpdateCallback) -> None:
        """Register the receiver-side OBJECT_UPDATE callback.

        SLICE_2_SPEC §6.1. Signature: ``async (handle: PromotionHandle,
        new_state: dict, object_version: int) -> None``. Trust-layer
        verification (signature, content_hash, version monotonicity,
        mutability check, subscription-row lookup) happens in the inbound
        handler BEFORE the callback fires — the consumer receives only
        verified data.

        Requires an ``object_store`` (the inbound handler is built atop
        it). Calling without one raises :class:`RuntimeError`.
        """
        self._require_object_store()
        assert self._object_handler is not None
        self._object_handler.register_object_update_callback(callback)

    def get_object(self, object_id: str) -> Object:
        """Return the canonical Object from this principal's store."""
        self._require_object_store()
        assert self._object_store is not None
        return self._object_store.get(object_id)

    def list_objects(self) -> list[Object]:
        """List all Objects this principal owns."""
        self._require_object_store()
        assert self._object_store is not None
        return self._object_store.list()

    def list_promotions_for_object(self, object_id: str) -> list[Promotion]:
        """List all Promotions this principal has issued for ``object_id``."""
        self._require_object_store()
        assert self._object_store is not None
        return self._object_store.list_promotions_for_object(object_id)

    def _require_object_store(self) -> None:
        if self._object_store is None:
            raise RuntimeError(
                "This Mesherra instance has no object_store (bypass mode). "
                "Construct Mesherra(... object_store=...) to enable Object "
                "and Promotion methods."
            )

    # -- Phase 2/3 surface ---------------------------------------------

    def register_principal(self) -> None:
        raise NotImplementedError(
            "register_principal as an SDK helper is deferred. Phase 2's "
            "Identity Directory is shipped — register by POSTing to the "
            "directory's /principals endpoint directly. See mesherra.identity."
        )

    def verify(self, agent_card: Any) -> Any:
        raise NotImplementedError(
            "An explicit SDK-level verify(AgentCard) is deferred. Phase 2's "
            "HTTPDirectoryClient verifies the directory's signature on every "
            "resolve; consumers do not need to verify cards by hand."
        )

    def get_policy(self) -> SignedPolicyDoc:
        """Return the current signed policy from the PolicyStore.

        Raises :class:`mesherra.policy.PolicyNotFound` if no policy has
        been saved for this principal. Raises ``RuntimeError`` if this
        Mesherra instance was constructed without a ``policy_store``
        (bypass mode — there is no policy to return).
        """
        if self._policy_store is None:
            raise RuntimeError(
                "This Mesherra instance has no policy_store (bypass mode). "
                "Construct Mesherra(... policy_store=...) to enable policy."
            )
        return self._policy_store.get_current()

    def update_policy(self, doc: Any) -> SignedPolicyDoc:
        """Sign ``doc`` with this principal's signing key and persist it.

        ``doc`` must be a :class:`mesherra.policy.PolicyDoc`. The version
        must be strictly greater than the latest stored version (the
        store enforces monotonicity). Returns the resulting
        :class:`SignedPolicyDoc`.
        """
        if self._policy_store is None:
            raise RuntimeError(
                "This Mesherra instance has no policy_store (bypass mode). "
                "Construct Mesherra(... policy_store=...) to enable policy."
            )
        signed = sign_policy_doc(doc=doc, signer=self._signer)
        self._policy_store.save_signed(signed)
        return signed


def _wall_clock_past(iso_timestamp: str) -> bool:
    """True if ``datetime.now(UTC) > parsed(iso_timestamp)``.

    Local helper for the live-push expiry check (SLICE_2_SPEC §7.1
    step 3b). Accepts both ``Z`` suffix and explicit ``+00:00`` offset
    forms; same parse contract as the gateway internals.
    """
    s = iso_timestamp
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    expiry_dt = datetime.fromisoformat(s)
    return datetime.now(UTC) > expiry_dt
