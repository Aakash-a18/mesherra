"""Per-principal SQLite persistence for Mesherra Objects and Promotions.

Implements ARCHITECTURE.md section 13.12 and demos/phase_4/SPEC.md section 7.

Parallel to provenance.ledger.ProvenanceLedger: one SQLite file per
principal, self-describing meta row, denormalized indexed columns plus a
canonical-JSON source-of-truth column. Append-and-update for Objects;
append-only for Promotions (Slice 1).

Three tables:

* ``object_meta`` — records the owning principal + schema_version. A wrong
  principal on reopen raises ``ObjectStoreOwnerMismatch`` rather than
  silently re-keying.
* ``objects`` — the canonical JSON in ``object_json`` is the source of
  truth; ``owner``, ``home_layer``, ``object_version``, ``content_hash``,
  and ``updated_at`` are denormalized for indexed lookup.
* ``promotions`` — Promotions the owner has issued. Append-only in Slice 1.
* ``received_handles`` — PromotionHandles the owner has received from other
  principals (counterpart side). Append-only.

Invariants enforced (per SPEC §2 and the theory-aligner audit):

* **Insert path:** ``object_version == 1`` and ``created_at == updated_at``.
* **Update path:** ``object_version`` must be strictly greater than the
  current stored version (monotonic).
* **Owner-locked:** every Object and Promotion ``owner`` must match
  ``self._owner_principal_id``; received handles must have ``receiver ==
  self._owner_principal_id``.
* **Promotion → Object link:** record_promotion rejects a promotion whose
  ``object_id`` has no row in ``objects``.

The store trusts that Object / Promotion / PromotionHandle instances it
receives have already passed model validation (content_hash matches state,
mode + fetch_endpoint pairing, owner != receiver, etc.). The store's job
is the *cross-instance* invariants (uniqueness, monotonicity, principal
match) that the per-instance models cannot enforce.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from mesherra.models.primitives import (
    ActiveSubscription,
    Object,
    Promotion,
    PromotionHandle,
    SubscriptionRole,
    SubscriptionStatus,
)

SCHEMA_VERSION = "1"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS object_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    home_layer TEXT NOT NULL,
    object_version INTEGER NOT NULL CHECK (object_version >= 1),
    object_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_objects_owner ON objects(owner);
CREATE INDEX IF NOT EXISTS idx_objects_content_hash ON objects(content_hash);

CREATE TABLE IF NOT EXISTS promotions (
    promotion_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    receiver TEXT NOT NULL,
    mode TEXT NOT NULL,
    mutability TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    snapshot_state_json TEXT,
    snapshot_content_hash TEXT NOT NULL,
    expiry TEXT NOT NULL,
    created_at TEXT NOT NULL,
    promotion_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_promotions_object ON promotions(object_id);
CREATE INDEX IF NOT EXISTS idx_promotions_receiver ON promotions(receiver);

CREATE TABLE IF NOT EXISTS received_handles (
    promotion_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    object_id TEXT NOT NULL,
    handle_json TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_received_handles_owner ON received_handles(owner);

CREATE TABLE IF NOT EXISTS active_subscriptions (
    promotion_id TEXT NOT NULL,
    counterpart TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'receiver')),
    last_pushed_object_version INTEGER,
    status TEXT NOT NULL CHECK (status IN ('active', 'disconnected', 'expired', 'closed_by_receiver')),
    subscribed_at TEXT NOT NULL,
    last_status_change_at TEXT NOT NULL,
    peer_url TEXT,
    PRIMARY KEY (promotion_id, role)
);

CREATE INDEX IF NOT EXISTS idx_active_subscriptions_counterpart
    ON active_subscriptions(counterpart);
CREATE INDEX IF NOT EXISTS idx_active_subscriptions_status
    ON active_subscriptions(status);
"""


# -- Exceptions --------------------------------------------------------------


class ObjectStoreError(Exception):
    """Base class for all ObjectStore-level errors."""


class ObjectStoreOwnerMismatch(ObjectStoreError):
    """A store was asked to handle data belonging to a different principal.

    Raised on reopen with the wrong owner, on ``put`` of an Object whose
    ``owner`` doesn't match the store's principal, on ``record_promotion``
    of a Promotion whose ``owner`` doesn't match, or on an attempted
    owner-change update. Same discipline as ProvenanceLedger's owner check.
    """


class ObjectNotFound(ObjectStoreError):
    """``get(object_id)`` called with an unknown id."""


class PromotionNotFound(ObjectStoreError):
    """``get_promotion`` or ``get_received_handle`` called with an unknown id."""


class ObjectVersionConflict(ObjectStoreError):
    """``put(obj)`` update path saw a non-monotonic ``object_version``.

    The store requires that every update bumps ``object_version`` strictly
    higher than the currently-stored version. This catches accidental
    overwrites and bookkeeping bugs at the storage layer (the SDK gate
    catches non-owner mutations earlier in the call path).
    """


class OwnershipChangeRejected(ObjectStoreError):
    """An update attempted to change an Object's owner, or a received
    handle was addressed to someone other than this store's principal.

    Mesherra's owner-is-canonical commitment (ARCH §3.7) is incompatible
    with owner transfer at this layer; ownership of an Object is fixed at
    create. The same logic applies to received handles: a handle addressed
    to Eve has no business landing in Alice's store.
    """


class SubscriptionNotFound(ObjectStoreError):
    """Lookup or update against an (promotion_id, role) tuple that has no
    row in ``active_subscriptions``."""


class SubscriptionVersionConflict(ObjectStoreError):
    """``update_subscription_pushed_version`` saw a non-strictly-greater
    version.

    SLICE_2_SPEC §7.3 requires monotonic forward motion on
    ``last_pushed_object_version``. The handler enforces it on receive;
    this store-level backstop catches the same shape one layer deeper
    so a buggy caller can't silently downgrade the row.
    """


# -- ObjectStore --------------------------------------------------------------


class ObjectStore:
    """Per-principal SQLite-backed store for Objects, issued Promotions, and
    received PromotionHandles.

    One instance owns one SQLite connection. Use as a context manager to
    close cleanly, or call :meth:`close` explicitly.

    Path resolution is the caller's job (config via env per CLAUDE.md #7).
    Use ``:memory:`` for ephemeral testing; pass a filesystem path for
    cross-process persistence and cold-reload verification.
    """

    def __init__(self, *, db_path: Path | str, owner_principal_id: str) -> None:
        if not owner_principal_id:
            raise ValueError("owner_principal_id must be a non-empty principal id")
        self._db_path = str(db_path)
        self._owner = owner_principal_id
        self._conn: sqlite3.Connection | None = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        try:
            self._init_schema()
            self._init_or_validate_meta()
        except Exception:
            self._conn.close()
            self._conn = None
            raise

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ObjectStore:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- properties ---------------------------------------------------------

    @property
    def owner_principal_id(self) -> str:
        return self._owner

    @property
    def db_path(self) -> str:
        return self._db_path

    # -- Object API ---------------------------------------------------------

    def put(self, obj: Object) -> None:
        """Insert or update an Object.

        Insert path (no existing row for ``object_id``):
            - ``obj.owner`` must equal this store's owner
            - ``obj.object_version`` must equal 1
            - ``obj.created_at`` must equal ``obj.updated_at``

        Update path (existing row):
            - ``obj.owner`` must still equal this store's owner (no transfer)
            - ``obj.object_version`` must be strictly greater than the
              stored version (monotonic)
            - ``obj.created_at`` must equal the stored row's ``created_at``
              (immutable at create)

        Raises ObjectStoreOwnerMismatch, ObjectStoreError, ObjectVersionConflict.
        """
        if obj.owner != self._owner:
            raise ObjectStoreOwnerMismatch(
                f"Object owner {obj.owner!r} does not match this store's "
                f"principal {self._owner!r}"
            )

        existing = self._fetch_object_row(obj.object_id)
        if existing is None:
            # Insert path.
            if obj.object_version != 1:
                raise ObjectStoreError(
                    f"insert requires object_version == 1, got "
                    f"{obj.object_version}"
                )
            if obj.created_at != obj.updated_at:
                raise ObjectStoreError(
                    f"insert requires created_at == updated_at, got "
                    f"{obj.created_at!r} and {obj.updated_at!r}"
                )
            self._insert_object(obj)
            return

        # Update path.
        stored = Object.model_validate(json.loads(existing["object_json"]))
        if obj.object_version <= stored.object_version:
            raise ObjectVersionConflict(
                f"update requires strictly monotonic object_version: "
                f"stored {stored.object_version}, got {obj.object_version}"
            )
        if obj.created_at != stored.created_at:
            raise ObjectStoreError(
                f"created_at is immutable: stored {stored.created_at!r}, "
                f"got {obj.created_at!r}"
            )
        self._update_object(obj)

    def get(self, object_id: str) -> Object:
        row = self._fetch_object_row(object_id)
        if row is None:
            raise ObjectNotFound(f"no Object with object_id={object_id!r}")
        return Object.model_validate(json.loads(row["object_json"]))

    def list(self) -> list[Object]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT object_json FROM objects ORDER BY object_id ASC"
        ).fetchall()
        return [Object.model_validate(json.loads(r[0])) for r in rows]

    # -- Promotion API ------------------------------------------------------

    def record_promotion(self, promotion: Promotion) -> None:
        """Append a Promotion. Append-only in Slice 1."""
        if promotion.owner != self._owner:
            raise ObjectStoreOwnerMismatch(
                f"Promotion owner {promotion.owner!r} does not match this "
                f"store's principal {self._owner!r}"
            )
        if self._fetch_object_row(promotion.object_id) is None:
            raise ObjectStoreError(
                f"Promotion references unknown object_id "
                f"{promotion.object_id!r}; create the Object first"
            )

        promotion_bytes = promotion.model_dump_json()
        scope_bytes = json.dumps(promotion.scope, sort_keys=True)
        snapshot_bytes = (
            json.dumps(promotion.snapshot_state, sort_keys=True)
            if promotion.snapshot_state is not None
            else None
        )
        assert self._conn is not None
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO promotions "
                    "(promotion_id, object_id, owner, receiver, mode, "
                    " mutability, scope_json, snapshot_state_json, "
                    " snapshot_content_hash, expiry, created_at, promotion_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        promotion.promotion_id,
                        promotion.object_id,
                        promotion.owner,
                        promotion.receiver,
                        promotion.mode.value,
                        promotion.mutability.value,
                        scope_bytes,
                        snapshot_bytes,
                        promotion.snapshot_content_hash,
                        promotion.expiry,
                        promotion.created_at,
                        promotion_bytes,
                    ),
                )
        except sqlite3.IntegrityError as e:
            raise ObjectStoreError(
                f"promotion_id {promotion.promotion_id!r} already recorded; "
                "Slice 1 is append-only"
            ) from e

    def get_promotion(self, promotion_id: str) -> Promotion:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT promotion_json FROM promotions WHERE promotion_id = ?",
            (promotion_id,),
        ).fetchone()
        if row is None:
            raise PromotionNotFound(
                f"no Promotion with promotion_id={promotion_id!r}"
            )
        return Promotion.model_validate(json.loads(row[0]))

    def list_promotions_for_object(self, object_id: str) -> list[Promotion]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT promotion_json FROM promotions "
            "WHERE object_id = ? ORDER BY created_at ASC",
            (object_id,),
        ).fetchall()
        return [Promotion.model_validate(json.loads(r[0])) for r in rows]

    def list_promotions_for_receiver(self, receiver: str) -> list[Promotion]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT promotion_json FROM promotions "
            "WHERE receiver = ? ORDER BY created_at ASC",
            (receiver,),
        ).fetchall()
        return [Promotion.model_validate(json.loads(r[0])) for r in rows]

    # -- Received-handle API (counterpart side) ----------------------------

    def record_received_handle(self, handle: PromotionHandle) -> None:
        """Persist a PromotionHandle received from another owner.

        Refuses any handle whose ``receiver`` is not this store's principal —
        a handle addressed to Eve has no business landing in Alice's store.
        This is a second line of defense behind the airlock's own
        sender_principal_id check (the §9 #16 stolen-handle assertion).
        """
        if handle.receiver != self._owner:
            raise OwnershipChangeRejected(
                f"received handle is addressed to {handle.receiver!r}, "
                f"not this store's principal {self._owner!r}"
            )
        handle_bytes = handle.model_dump_json()
        # received_at — caller-controlled would be cleanest, but Slice 1
        # uses issued_at as a reasonable proxy until the gateway hands us
        # a fresher timestamp.
        received_at = handle.issued_at
        assert self._conn is not None
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO received_handles "
                    "(promotion_id, owner, object_id, handle_json, received_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        handle.promotion_id,
                        handle.owner,
                        handle.object_id,
                        handle_bytes,
                        received_at,
                    ),
                )
        except sqlite3.IntegrityError as e:
            raise ObjectStoreError(
                f"received handle {handle.promotion_id!r} already recorded"
            ) from e

    def get_received_handle(self, promotion_id: str) -> PromotionHandle:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT handle_json FROM received_handles WHERE promotion_id = ?",
            (promotion_id,),
        ).fetchone()
        if row is None:
            raise PromotionNotFound(
                f"no received handle with promotion_id={promotion_id!r}"
            )
        return PromotionHandle.model_validate(json.loads(row[0]))

    def list_received_handles(self) -> list[PromotionHandle]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT handle_json FROM received_handles ORDER BY received_at ASC"
        ).fetchall()
        return [PromotionHandle.model_validate(json.loads(r[0])) for r in rows]

    # -- Active-subscription API (Slice 2) --------------------------------

    def record_subscription(
        self,
        *,
        promotion_id: str,
        counterpart: str,
        role: SubscriptionRole,
        subscribed_at: str,
        peer_url: str | None = None,
    ) -> None:
        """Insert a fresh active subscription row.

        Initial state per SLICE_2_SPEC §7.2 SUBSCRIBE matrix: ``status =
        'active'``, ``last_pushed_object_version = NULL``,
        ``last_status_change_at = subscribed_at`` (creation IS the first
        transition). Caller supplies ``subscribed_at`` — the store has no
        clock source (CLAUDE.md #7: configuration via callers, not
        hardcoded inside reusable components).

        ``peer_url`` is owner-side only: the receiver's A2A listener URL
        captured from the SubscribeRequest, used by the push fan-out
        path. None on receiver-side rows and on owner-side rows from
        callers that omit it (those rows are not push-eligible).

        Idempotency at this layer: a duplicate (promotion_id, role) PK
        raises sqlite3.IntegrityError. The handler (step 6) is responsible
        for the §7.2 idempotent-re-subscribe semantics — calling
        ``get_subscription`` first and either no-op'ing or transitioning
        via ``update_subscription_status`` as appropriate.
        """
        sub = ActiveSubscription(
            promotion_id=promotion_id,
            counterpart=counterpart,
            role=role,
            last_pushed_object_version=None,
            status=SubscriptionStatus.ACTIVE,
            subscribed_at=subscribed_at,
            last_status_change_at=subscribed_at,
            peer_url=peer_url,
        )
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT INTO active_subscriptions "
                "(promotion_id, counterpart, role, last_pushed_object_version, "
                " status, subscribed_at, last_status_change_at, peer_url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sub.promotion_id,
                    sub.counterpart,
                    sub.role.value,
                    sub.last_pushed_object_version,
                    sub.status.value,
                    sub.subscribed_at,
                    sub.last_status_change_at,
                    sub.peer_url,
                ),
            )

    def get_subscription(
        self, *, promotion_id: str, role: SubscriptionRole
    ) -> ActiveSubscription:
        """Return the ActiveSubscription row for (promotion_id, role).

        Raises :class:`SubscriptionNotFound` if no row exists.
        """
        row = self._fetch_subscription_row(promotion_id, role)
        if row is None:
            raise SubscriptionNotFound(
                f"no subscription for promotion_id={promotion_id!r} "
                f"role={role.value!r}"
            )
        return _row_to_subscription(row)

    def update_subscription_status(
        self,
        *,
        promotion_id: str,
        role: SubscriptionRole,
        new_status: SubscriptionStatus,
        changed_at: str,
    ) -> None:
        """Transition the row's ``status``, bumping ``last_status_change_at``.

        Delegates the legality check to
        :meth:`SubscriptionStatus.validate_transition` — single source of
        truth for the §7.2 state graph. An illegal transition raises
        :class:`InvalidSubscriptionTransition` and the row is left
        untouched (the validator runs before the UPDATE).
        """
        existing = self._fetch_subscription_row(promotion_id, role)
        if existing is None:
            raise SubscriptionNotFound(
                f"no subscription for promotion_id={promotion_id!r} "
                f"role={role.value!r}"
            )
        current_status = SubscriptionStatus(existing["status"])
        SubscriptionStatus.validate_transition(current_status, new_status)

        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "UPDATE active_subscriptions SET "
                " status = ?, last_status_change_at = ? "
                "WHERE promotion_id = ? AND role = ?",
                (new_status.value, changed_at, promotion_id, role.value),
            )

    def update_subscription_pushed_version(
        self,
        *,
        promotion_id: str,
        role: SubscriptionRole,
        object_version: int,
    ) -> None:
        """Set ``last_pushed_object_version`` to ``object_version``.

        Strict-monotonicity check: ``object_version`` must be greater than
        any previously-recorded value (NULL counts as -infinity for this
        comparison — first push always succeeds). Equality is rejected per
        §7.3's "strictly greater than" wording.

        Raises :class:`SubscriptionNotFound` for missing rows,
        :class:`SubscriptionVersionConflict` for non-strictly-greater values.
        """
        existing = self._fetch_subscription_row(promotion_id, role)
        if existing is None:
            raise SubscriptionNotFound(
                f"no subscription for promotion_id={promotion_id!r} "
                f"role={role.value!r}"
            )
        current_version = existing["last_pushed_object_version"]
        if current_version is not None and object_version <= current_version:
            raise SubscriptionVersionConflict(
                f"last_pushed_object_version must be strictly greater than "
                f"{current_version}; got {object_version}"
            )

        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "UPDATE active_subscriptions SET "
                " last_pushed_object_version = ? "
                "WHERE promotion_id = ? AND role = ?",
                (object_version, promotion_id, role.value),
            )

    def update_subscription_peer_url(
        self,
        *,
        promotion_id: str,
        role: SubscriptionRole,
        peer_url: str | None,
    ) -> None:
        """Overwrite ``peer_url`` on an existing subscription row.

        Used by the re-subscribe path (SLICE_2_SPEC §7.2 SUBSCRIBE matrix
        rows 3-4) when the receiver may have moved listener URLs while
        the row was DISCONNECTED or CLOSED_BY_RECEIVER. Without this
        refresh, the owner would keep pushing to a stale URL after
        recovery and silently re-enter the disconnected loop.
        """
        existing = self._fetch_subscription_row(promotion_id, role)
        if existing is None:
            raise SubscriptionNotFound(
                f"no subscription for promotion_id={promotion_id!r} "
                f"role={role.value!r}"
            )
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "UPDATE active_subscriptions SET "
                " peer_url = ? "
                "WHERE promotion_id = ? AND role = ?",
                (peer_url, promotion_id, role.value),
            )

    def reset_subscription_pushed_version(
        self, *, promotion_id: str, role: SubscriptionRole
    ) -> None:
        """Set ``last_pushed_object_version`` back to NULL.

        Used by the §7.2 SUBSCRIBE re-entry path when an existing row in
        ``closed_by_receiver`` transitions to ``active`` — the receiver is
        starting a fresh subscription and must FETCH for current state
        before relying on the next push (the spec defers that obligation
        to the consumer; the store just makes sure no stale ``last_pushed``
        from the prior subscription leaks into the new lifecycle).
        """
        existing = self._fetch_subscription_row(promotion_id, role)
        if existing is None:
            raise SubscriptionNotFound(
                f"no subscription for promotion_id={promotion_id!r} "
                f"role={role.value!r}"
            )
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "UPDATE active_subscriptions SET "
                " last_pushed_object_version = NULL "
                "WHERE promotion_id = ? AND role = ?",
                (promotion_id, role.value),
            )

    def list_active_subscriptions_for_object(
        self, *, object_id: str
    ) -> list[ActiveSubscription]:
        """Return owner-side, push-eligible subscriptions whose promotion
        is LIVE and points to ``object_id``.

        Hot path for ``Mesherra.update_object`` (Slice 2 step 10): given a
        just-mutated Object, enumerate every receiver that needs a push.
        Per SLICE_2_SPEC §7.4 step 3, **disconnected rows are also
        push-eligible** — the next mutation is the spec's defined retry
        trigger, and a successful retry transitions the row back to
        ACTIVE. Only EXPIRED and CLOSED_BY_RECEIVER rows are filtered out;
        those are terminal states for the owner-side push path.

        STATIC promotions are filtered out (they never carry pushes).
        Receiver-side rows (role='receiver') are excluded by construction.
        """
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT s.promotion_id, s.counterpart, s.role, "
            " s.last_pushed_object_version, s.status, "
            " s.subscribed_at, s.last_status_change_at, s.peer_url "
            "FROM active_subscriptions s "
            "JOIN promotions p ON s.promotion_id = p.promotion_id "
            "WHERE p.object_id = ? "
            "  AND p.mutability = 'live' "
            "  AND s.role = 'owner' "
            "  AND s.status IN ('active', 'disconnected') "
            "ORDER BY s.subscribed_at ASC, s.promotion_id ASC",
            (object_id,),
        ).fetchall()
        return [
            _row_to_subscription({
                "promotion_id": r[0],
                "counterpart": r[1],
                "role": r[2],
                "last_pushed_object_version": r[3],
                "status": r[4],
                "subscribed_at": r[5],
                "last_status_change_at": r[6],
                "peer_url": r[7],
            })
            for r in rows
        ]

    # -- internals ---------------------------------------------------------

    def _init_schema(self) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    def _init_or_validate_meta(self) -> None:
        assert self._conn is not None
        rows = dict(
            self._conn.execute("SELECT key, value FROM object_meta").fetchall()
        )
        if "owner_principal_id" not in rows:
            with self._conn:
                self._conn.executemany(
                    "INSERT INTO object_meta (key, value) VALUES (?, ?)",
                    [
                        ("owner_principal_id", self._owner),
                        ("schema_version", SCHEMA_VERSION),
                    ],
                )
            return
        if rows["owner_principal_id"] != self._owner:
            raise ObjectStoreOwnerMismatch(
                f"DB at {self._db_path!r} is owned by "
                f"{rows['owner_principal_id']!r}, not {self._owner!r}"
            )
        recorded_schema = rows.get("schema_version", "")
        if recorded_schema != SCHEMA_VERSION:
            raise ObjectStoreError(
                f"DB at {self._db_path!r} has schema_version "
                f"{recorded_schema!r}; this code expects {SCHEMA_VERSION!r}"
            )

    def _fetch_object_row(self, object_id: str) -> dict[str, str] | None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT object_json FROM objects WHERE object_id = ?",
            (object_id,),
        ).fetchone()
        if row is None:
            return None
        return {"object_json": row[0]}

    def _insert_object(self, obj: Object) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT INTO objects "
                "(object_id, owner, home_layer, object_version, "
                " object_json, content_hash, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    obj.object_id,
                    obj.owner,
                    obj.home_layer.value,
                    obj.object_version,
                    obj.model_dump_json(),
                    obj.content_hash,
                    obj.updated_at,
                ),
            )

    def _update_object(self, obj: Object) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "UPDATE objects SET "
                " home_layer = ?, "
                " object_version = ?, "
                " object_json = ?, "
                " content_hash = ?, "
                " updated_at = ? "
                "WHERE object_id = ?",
                (
                    obj.home_layer.value,
                    obj.object_version,
                    obj.model_dump_json(),
                    obj.content_hash,
                    obj.updated_at,
                    obj.object_id,
                ),
            )

    def _fetch_subscription_row(
        self, promotion_id: str, role: SubscriptionRole
    ) -> dict[str, object] | None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT promotion_id, counterpart, role, last_pushed_object_version, "
            " status, subscribed_at, last_status_change_at, peer_url "
            "FROM active_subscriptions WHERE promotion_id = ? AND role = ?",
            (promotion_id, role.value),
        ).fetchone()
        if row is None:
            return None
        return {
            "promotion_id": row[0],
            "counterpart": row[1],
            "role": row[2],
            "last_pushed_object_version": row[3],
            "status": row[4],
            "subscribed_at": row[5],
            "last_status_change_at": row[6],
            "peer_url": row[7],
        }


def _row_to_subscription(row: dict[str, object]) -> ActiveSubscription:
    """Reconstruct an ActiveSubscription from a SQLite row dict.

    The model's own validators run; a row that somehow violates an
    invariant (e.g., a manually-edited DB) surfaces as a ValidationError
    rather than slipping through as a malformed instance.
    """
    return ActiveSubscription(
        promotion_id=row["promotion_id"],  # type: ignore[arg-type]
        counterpart=row["counterpart"],  # type: ignore[arg-type]
        role=SubscriptionRole(row["role"]),
        last_pushed_object_version=row["last_pushed_object_version"],  # type: ignore[arg-type]
        status=SubscriptionStatus(row["status"]),
        subscribed_at=row["subscribed_at"],  # type: ignore[arg-type]
        last_status_change_at=row["last_status_change_at"],  # type: ignore[arg-type]
        peer_url=row.get("peer_url"),  # type: ignore[arg-type]
    )
