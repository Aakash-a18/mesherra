"""Unit tests for ObjectStore's active_subscriptions table.

Covers Phase 4 Slice 2 step 5 per ``demos/phase_4/SLICE_2_SPEC.md`` §5.

The active_subscriptions table is **update-mutated** (unlike Slice 1's
append-only ``promotions``). Each row's ``status`` and
``last_pushed_object_version`` advance over the subscription's life. The
history of those changes lives in the residue ledger as SUBSCRIBE /
UNSUBSCRIBE / OBJECT_UPDATE entries.

Tested here:

- Schema: ``active_subscriptions`` table exists after ObjectStore init;
  cold-reopen of a Slice 1 store creates the table without losing data.
- ``record_subscription``: happy path; rejects duplicate (promotion_id, role);
  owner and receiver roles for the same promotion_id can coexist.
- ``get_subscription``: returns the persisted ``ActiveSubscription``;
  raises ``SubscriptionNotFound`` for unknown rows.
- ``update_subscription_status``: legal transitions persist + bump
  ``last_status_change_at``; illegal transitions raise
  ``InvalidSubscriptionTransition`` and do NOT mutate the row.
- ``update_subscription_pushed_version``: persists a strictly-greater
  version; rejects regressions with ``SubscriptionVersionConflict``
  (defense-in-depth backstop for the handler's check at §7.3).
- ``list_active_subscriptions_for_object``: returns owner-side rows whose
  promotion is LIVE and whose status is 'active'. STATIC promotions and
  non-active rows are filtered out.
- Cold reload: subscription rows survive process restart.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mesherra.models.primitives import (
    ActiveSubscription,
    InvalidSubscriptionTransition,
    LayerKind,
    Mutability,
    Object,
    Promotion,
    PromotionMode,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import (
    ObjectStore,
    SubscriptionNotFound,
    SubscriptionVersionConflict,
)

OWNER = "alice@phase4.local"
RECEIVER = "bob@phase4.local"


# -- Fixtures -------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ObjectStore:
    db = tmp_path / "alice.objectstore.sqlite"
    s = ObjectStore(db_path=db, owner_principal_id=OWNER)
    yield s
    s.close()


@pytest.fixture
def base_state() -> dict[str, Any]:
    return {"candidates": ["2026-06-01T09:00:00Z"], "duration_minutes": 30}


@pytest.fixture
def live_object(base_state: dict[str, Any]) -> Object:
    return Object(
        object_id="obj-live-1",
        owner=OWNER,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.LIVE,
        schema_ref="meshycal.scheduling/calendar-v1",
        state=base_state,
        object_version=1,
        created_at="2026-05-27T20:00:00Z",
        updated_at="2026-05-27T20:00:00Z",
    )


@pytest.fixture
def static_object(base_state: dict[str, Any]) -> Object:
    return Object(
        object_id="obj-static-1",
        owner=OWNER,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.STATIC,
        schema_ref="meshycal.scheduling/calendar-v1",
        state=base_state,
        object_version=1,
        created_at="2026-05-27T20:00:00Z",
        updated_at="2026-05-27T20:00:00Z",
    )


@pytest.fixture
def live_promotion(base_state: dict[str, Any]) -> Promotion:
    return Promotion(
        promotion_id="prm-live-1",
        object_id="obj-live-1",
        owner=OWNER,
        receiver=RECEIVER,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.LIVE,
        scope={"fields": ["candidates", "duration_minutes"]},
        expiry="2026-06-30T00:00:00Z",
        snapshot_state=None,  # live: no snapshot stored
        fetch_endpoint="https://alice.example/mesherra/fetch/prm-live-1",
        created_at="2026-05-27T20:00:00Z",
    )


@pytest.fixture
def static_promotion(base_state: dict[str, Any]) -> Promotion:
    return Promotion(
        promotion_id="prm-static-1",
        object_id="obj-static-1",
        owner=OWNER,
        receiver=RECEIVER,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates"]},
        expiry="2026-06-30T00:00:00Z",
        snapshot_state={"candidates": ["2026-06-01T09:00:00Z"]},
        fetch_endpoint="https://alice.example/mesherra/fetch/prm-static-1",
        created_at="2026-05-27T20:00:00Z",
    )


# -- Schema -----------------------------------------------------


class TestSchema:
    def test_active_subscriptions_table_exists(self, store: ObjectStore) -> None:
        # Reach into the connection only for this schema-introspection assertion;
        # the rest of the file uses the public API.
        conn: sqlite3.Connection = store._conn  # type: ignore[attr-defined]
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name='active_subscriptions'"
        ).fetchone()
        assert row is not None, "active_subscriptions table not created"


# -- record_subscription / get_subscription ----------------------


class TestRecordAndGet:
    def test_record_then_get_round_trip(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        sub = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.promotion_id == "prm-live-1"
        assert sub.counterpart == RECEIVER
        assert sub.role is SubscriptionRole.OWNER
        assert sub.status is SubscriptionStatus.ACTIVE
        assert sub.last_pushed_object_version is None
        assert sub.subscribed_at == "2026-05-27T21:00:00Z"
        assert sub.last_status_change_at == "2026-05-27T21:00:00Z"

    def test_get_unknown_subscription_raises(self, store: ObjectStore) -> None:
        with pytest.raises(SubscriptionNotFound):
            store.get_subscription(
                promotion_id="prm-never", role=SubscriptionRole.OWNER
            )

    def test_duplicate_same_role_rejected(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        with pytest.raises(Exception):  # IntegrityError from PK uniqueness
            store.record_subscription(
                promotion_id="prm-live-1",
                counterpart=RECEIVER,
                role=SubscriptionRole.OWNER,
                subscribed_at="2026-05-27T22:00:00Z",
            )

    def test_owner_and_receiver_roles_coexist(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # A principal who is both owner of one promotion and receiver of
        # another (or, in test contortion, both for the same promotion_id —
        # the table allows it because the PK is (promotion_id, role)). The
        # principle: role is the second half of the key.
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=OWNER,
            role=SubscriptionRole.RECEIVER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        # Both rows now exist on this one store.
        owner_row = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        receiver_row = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.RECEIVER
        )
        assert owner_row.role is SubscriptionRole.OWNER
        assert receiver_row.role is SubscriptionRole.RECEIVER


# -- update_subscription_status ----------------------------------


class TestUpdateStatus:
    def _seed(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )

    def test_legal_transition_persists(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        self._seed(store, live_object, live_promotion)
        store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.DISCONNECTED,
            changed_at="2026-05-27T22:00:00Z",
        )
        sub = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.DISCONNECTED
        assert sub.last_status_change_at == "2026-05-27T22:00:00Z"

    def test_illegal_transition_raises_and_does_not_persist(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # Walk to EXPIRED then try to go back to ACTIVE — illegal per
        # SLICE_2_SPEC §7.2.
        self._seed(store, live_object, live_promotion)
        store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.EXPIRED,
            changed_at="2026-05-27T22:00:00Z",
        )
        with pytest.raises(InvalidSubscriptionTransition):
            store.update_subscription_status(
                promotion_id="prm-live-1",
                role=SubscriptionRole.OWNER,
                new_status=SubscriptionStatus.ACTIVE,
                changed_at="2026-05-27T23:00:00Z",
            )
        # Row must still be EXPIRED — failed transitions are atomic.
        sub = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.status is SubscriptionStatus.EXPIRED
        assert sub.last_status_change_at == "2026-05-27T22:00:00Z"

    def test_update_status_unknown_row_raises(self, store: ObjectStore) -> None:
        with pytest.raises(SubscriptionNotFound):
            store.update_subscription_status(
                promotion_id="prm-never",
                role=SubscriptionRole.OWNER,
                new_status=SubscriptionStatus.DISCONNECTED,
                changed_at="2026-05-27T22:00:00Z",
            )


# -- update_subscription_pushed_version -------------------------


class TestUpdatePushedVersion:
    def _seed(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )

    def test_first_push_persists(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        self._seed(store, live_object, live_promotion)
        store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=2,
        )
        sub = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.last_pushed_object_version == 2

    def test_monotonic_advance(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        self._seed(store, live_object, live_promotion)
        store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=2,
        )
        store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=3,
        )
        sub = store.get_subscription(
            promotion_id="prm-live-1", role=SubscriptionRole.OWNER
        )
        assert sub.last_pushed_object_version == 3

    def test_regression_rejected(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # §7.3 / §8: receiver-side handler rejects version_regression.
        # Store-level backstop catches the same shape one layer deeper.
        self._seed(store, live_object, live_promotion)
        store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=5,
        )
        with pytest.raises(SubscriptionVersionConflict):
            store.update_subscription_pushed_version(
                promotion_id="prm-live-1",
                role=SubscriptionRole.OWNER,
                object_version=4,
            )

    def test_equal_version_rejected(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # §7.3: "object_version strictly greater than last_pushed_object_version".
        # Equality is not strictly greater.
        self._seed(store, live_object, live_promotion)
        store.update_subscription_pushed_version(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            object_version=3,
        )
        with pytest.raises(SubscriptionVersionConflict):
            store.update_subscription_pushed_version(
                promotion_id="prm-live-1",
                role=SubscriptionRole.OWNER,
                object_version=3,
            )

    def test_update_pushed_version_unknown_row_raises(
        self, store: ObjectStore
    ) -> None:
        with pytest.raises(SubscriptionNotFound):
            store.update_subscription_pushed_version(
                promotion_id="prm-never",
                role=SubscriptionRole.OWNER,
                object_version=1,
            )


# -- list_active_subscriptions_for_object -----------------------


class TestListActiveForObject:
    def test_filters_to_active_owner_live_only(
        self,
        store: ObjectStore,
        live_object: Object,
        static_object: Object,
        live_promotion: Promotion,
        static_promotion: Promotion,
    ) -> None:
        # Seed two promotions on two objects: one LIVE with active sub,
        # one STATIC (which can't have subs in normal flow but a misuse
        # could put one in — we want the filter to drop it).
        # Also seed: a LIVE promotion with a CLOSED_BY_RECEIVER sub (filtered),
        # and another live promotion with no sub at all (filtered).
        store.put(live_object)
        store.put(static_object)
        store.record_promotion(live_promotion)
        store.record_promotion(static_promotion)

        # The expected hit: active owner-side sub for live promotion.
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )

        # Second live promotion on the same object, but with sub
        # closed_by_receiver — must NOT appear.
        live_2 = live_promotion.model_copy(
            update={"promotion_id": "prm-live-2", "receiver": "carol@phase4.local"}
        )
        store.record_promotion(live_2)
        store.record_subscription(
            promotion_id="prm-live-2",
            counterpart="carol@phase4.local",
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        store.update_subscription_status(
            promotion_id="prm-live-2",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.CLOSED_BY_RECEIVER,
            changed_at="2026-05-27T22:00:00Z",
        )

        subs = store.list_active_subscriptions_for_object(object_id="obj-live-1")
        assert len(subs) == 1
        assert subs[0].promotion_id == "prm-live-1"
        assert subs[0].status is SubscriptionStatus.ACTIVE

        # Nothing for the static-promotion object.
        assert store.list_active_subscriptions_for_object(object_id="obj-static-1") == []

    def test_returns_empty_when_no_subs(
        self, store: ObjectStore, live_object: Object
    ) -> None:
        store.put(live_object)
        assert store.list_active_subscriptions_for_object(object_id="obj-live-1") == []

    def test_includes_disconnected_rows(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # SLICE_2_SPEC §7.4 step 3: a DISCONNECTED row is still
        # push-eligible — the next mutation is the spec's defined retry
        # trigger. Filtering them out would prevent owner-driven recovery.
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.DISCONNECTED,
            changed_at="2026-05-27T22:00:00Z",
        )
        subs = store.list_active_subscriptions_for_object(object_id="obj-live-1")
        assert len(subs) == 1
        assert subs[0].status is SubscriptionStatus.DISCONNECTED

    def test_excludes_expired_and_closed(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # Terminal states for owner-side push: EXPIRED and
        # CLOSED_BY_RECEIVER. These do NOT participate in the §7.4
        # owner-driven retry loop.
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=RECEIVER,
            role=SubscriptionRole.OWNER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        store.update_subscription_status(
            promotion_id="prm-live-1",
            role=SubscriptionRole.OWNER,
            new_status=SubscriptionStatus.EXPIRED,
            changed_at="2026-05-27T22:00:00Z",
        )
        assert store.list_active_subscriptions_for_object(object_id="obj-live-1") == []

    def test_ignores_receiver_side_rows(
        self,
        store: ObjectStore,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        # Only role='owner' rows are push targets. A receiver-side row on
        # this same store is bookkeeping, not a fan-out hint.
        store.put(live_object)
        store.record_promotion(live_promotion)
        store.record_subscription(
            promotion_id="prm-live-1",
            counterpart=OWNER,
            role=SubscriptionRole.RECEIVER,
            subscribed_at="2026-05-27T21:00:00Z",
        )
        assert store.list_active_subscriptions_for_object(object_id="obj-live-1") == []


# -- Cold reload -----------------------------------------------


class TestColdReload:
    def test_subscriptions_survive_restart(
        self,
        tmp_path: Path,
        live_object: Object,
        live_promotion: Promotion,
    ) -> None:
        db = tmp_path / "cold-reload.sqlite"
        s1 = ObjectStore(db_path=db, owner_principal_id=OWNER)
        try:
            s1.put(live_object)
            s1.record_promotion(live_promotion)
            s1.record_subscription(
                promotion_id="prm-live-1",
                counterpart=RECEIVER,
                role=SubscriptionRole.OWNER,
                subscribed_at="2026-05-27T21:00:00Z",
            )
            s1.update_subscription_pushed_version(
                promotion_id="prm-live-1",
                role=SubscriptionRole.OWNER,
                object_version=3,
            )
        finally:
            s1.close()

        s2 = ObjectStore(db_path=db, owner_principal_id=OWNER)
        try:
            sub = s2.get_subscription(
                promotion_id="prm-live-1", role=SubscriptionRole.OWNER
            )
            assert sub.last_pushed_object_version == 3
            assert sub.status is SubscriptionStatus.ACTIVE
            # The §9 #16 cold-reload invariant: a freshly-opened store
            # reads back the same row the closing process wrote.
            assert isinstance(sub, ActiveSubscription)
        finally:
            s2.close()
