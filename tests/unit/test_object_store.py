"""Unit tests for ObjectStore.

Covers Phase 4 Slice 1 step 4 per demos/phase_4/SPEC.md section 7.

ObjectStore is the per-principal SQLite persistence layer for Objects,
issued Promotions, and received PromotionHandles. Parallel in shape and
discipline to ProvenanceLedger (Phase 1).

Three tables:
- ``object_meta`` — self-describing (records owner_principal_id, schema version)
- ``objects`` — canonical JSON + denormalized columns for query
- ``promotions`` — issued by the owner (append-only in Slice 1)
- ``received_handles`` — handles received from other owners (counterpart side)

Tested here:
- Construction + self-describing meta + wrong-principal rejection
- put() insert-vs-update semantics with monotonic version invariant
- Insert-time invariants (object_version == 1, created_at == updated_at)
- Update-time invariants (monotonic version, owner unchanged, timestamps)
- Promotions: append-only, lookup helpers
- Received handles: append + lookup
- Cold-reload: write, close, re-open, re-read — bytes are stable

Pure unit tests with SQLite ``:memory:`` databases — fast, no fixtures
needed, no I/O beyond the in-memory DB.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mesherra.models.primitives import (
    LayerKind,
    Mutability,
    Object,
    Promotion,
    PromotionHandle,
    PromotionMode,
)
from mesherra.object.store import (
    ObjectNotFound,
    ObjectStore,
    ObjectStoreError,
    ObjectStoreOwnerMismatch,
    ObjectVersionConflict,
    OwnershipChangeRejected,
    PromotionNotFound,
)

OWNER = "alice@phase4.local"
RECEIVER = "bob@phase4.local"


# -- Fixtures -----------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ObjectStore:
    """A fresh ObjectStore on a real file (so reopen tests work)."""
    db = tmp_path / "alice.objectstore.sqlite"
    s = ObjectStore(db_path=db, owner_principal_id=OWNER)
    yield s
    s.close()


@pytest.fixture
def base_state() -> dict[str, Any]:
    return {
        "candidates": ["2026-06-01T09:00:00Z", "2026-06-01T14:00:00Z"],
        "duration_minutes": 30,
    }


@pytest.fixture
def base_object(base_state: dict[str, Any]) -> Object:
    return Object(
        object_id="obj-7f3a",
        owner=OWNER,
        home_layer=LayerKind.PERSONAL,
        mutability=Mutability.STATIC,
        schema_ref="meshycal.scheduling/calendar-v1",
        state=base_state,
        object_version=1,
        created_at="2026-05-26T20:00:00Z",
        updated_at="2026-05-26T20:00:00Z",
    )


@pytest.fixture
def base_promotion(base_state: dict[str, Any]) -> Promotion:
    return Promotion(
        promotion_id="prm-1a2b",
        object_id="obj-7f3a",
        owner=OWNER,
        receiver=RECEIVER,
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates", "duration_minutes"]},
        expiry="2026-06-02T00:00:00Z",
        snapshot_state=base_state,
        fetch_endpoint="https://alice.example/mesherra/objects/fetch/prm-1a2b",
        created_at="2026-05-26T20:00:00Z",
    )


@pytest.fixture
def received_handle() -> PromotionHandle:
    return PromotionHandle(
        promotion_id="prm-9z8y",
        object_id="obj-other",
        owner="carol@phase4.local",
        receiver=OWNER,
        schema_ref="meshycal.scheduling/calendar-v1",
        mode=PromotionMode.REFERENCE,
        mutability=Mutability.STATIC,
        scope={"fields": ["candidates"]},
        snapshot_content_hash="b" * 64,
        fetch_endpoint="https://carol.example/mesherra/objects/fetch/prm-9z8y",
        expiry="2026-06-10T00:00:00Z",
        issued_at="2026-05-26T21:00:00Z",
        owner_signature="placeholder-base64",
    )


# -- Construction + self-describing meta --------------------------------------


class TestConstruction:
    def test_constructs_with_required_args(self, store: ObjectStore) -> None:
        assert store.owner_principal_id == OWNER

    def test_empty_owner_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            ObjectStore(db_path=tmp_path / "x.sqlite", owner_principal_id="")

    def test_in_memory_db_works(self) -> None:
        # Useful for tests / ephemeral use. Same shape as ProvenanceLedger.
        s = ObjectStore(db_path=":memory:", owner_principal_id=OWNER)
        assert s.owner_principal_id == OWNER
        s.close()

    def test_close_is_idempotent(self, store: ObjectStore) -> None:
        store.close()
        store.close()  # second close must not raise


class TestSelfDescribingMeta:
    def test_stamps_owner_on_first_open(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "x.sqlite"
        s = ObjectStore(db_path=db, owner_principal_id=OWNER)
        s.close()
        # File now has an object_meta row for the owner; re-open with the
        # same owner works.
        s2 = ObjectStore(db_path=db, owner_principal_id=OWNER)
        assert s2.owner_principal_id == OWNER
        s2.close()

    def test_wrong_owner_on_reopen_raises(self, tmp_path: Path) -> None:
        db = tmp_path / "x.sqlite"
        s = ObjectStore(db_path=db, owner_principal_id=OWNER)
        s.close()
        with pytest.raises(ObjectStoreOwnerMismatch):
            ObjectStore(db_path=db, owner_principal_id="someone-else@elsewhere")


# -- put() insert path --------------------------------------------------------


class TestPutInsert:
    def test_insert_roundtrips(self, store: ObjectStore, base_object: Object) -> None:
        store.put(base_object)
        loaded = store.get(base_object.object_id)
        assert loaded == base_object

    def test_insert_with_non_one_version_rejected(
        self, store: ObjectStore, base_state: dict[str, Any]
    ) -> None:
        # SPEC §2: object_version == 1 at create.
        obj = Object(
            object_id="obj-bad-init",
            owner=OWNER,
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state=base_state,
            object_version=2,  # not 1 — insert must refuse
            created_at="2026-05-26T20:00:00Z",
            updated_at="2026-05-26T20:00:00Z",
        )
        with pytest.raises(ObjectStoreError):
            store.put(obj)

    def test_insert_with_mismatched_timestamps_rejected(
        self, store: ObjectStore, base_state: dict[str, Any]
    ) -> None:
        # SPEC §2: created_at == updated_at at create.
        obj = Object(
            object_id="obj-bad-ts",
            owner=OWNER,
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state=base_state,
            object_version=1,
            created_at="2026-05-26T20:00:00Z",
            updated_at="2026-05-26T20:00:01Z",  # off by one second — refuse
        )
        with pytest.raises(ObjectStoreError):
            store.put(obj)

    def test_insert_with_foreign_owner_rejected(
        self, store: ObjectStore, base_state: dict[str, Any]
    ) -> None:
        # A store is bound to one principal; foreign Objects must not land
        # in it. Same discipline as ProvenanceLedger's owner check.
        obj = Object(
            object_id="obj-foreign",
            owner="someone-else@elsewhere",  # not OWNER
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state=base_state,
            object_version=1,
            created_at="2026-05-26T20:00:00Z",
            updated_at="2026-05-26T20:00:00Z",
        )
        with pytest.raises(ObjectStoreOwnerMismatch):
            store.put(obj)


# -- put() update path --------------------------------------------------------


def _make_updated(obj: Object, new_state: dict[str, Any], new_version: int,
                  new_updated_at: str) -> Object:
    return Object(
        object_id=obj.object_id,
        owner=obj.owner,
        home_layer=obj.home_layer,
        mutability=obj.mutability,
        schema_ref=obj.schema_ref,
        state=new_state,
        object_version=new_version,
        created_at=obj.created_at,
        updated_at=new_updated_at,
    )


class TestPutUpdate:
    def test_update_bumps_version(
        self, store: ObjectStore, base_object: Object, base_state: dict[str, Any]
    ) -> None:
        store.put(base_object)
        new_state = {**base_state, "duration_minutes": 60}
        updated = _make_updated(
            base_object,
            new_state=new_state,
            new_version=2,
            new_updated_at="2026-05-26T20:05:00Z",
        )
        store.put(updated)
        loaded = store.get(base_object.object_id)
        assert loaded.object_version == 2
        assert loaded.state["duration_minutes"] == 60
        assert loaded.created_at == base_object.created_at  # preserved
        assert loaded.updated_at == "2026-05-26T20:05:00Z"  # bumped

    def test_update_with_non_monotonic_version_rejected(
        self, store: ObjectStore, base_object: Object, base_state: dict[str, Any]
    ) -> None:
        store.put(base_object)
        backwards = _make_updated(
            base_object,
            new_state={**base_state, "duration_minutes": 60},
            new_version=1,  # same as current — must reject
            new_updated_at="2026-05-26T20:05:00Z",
        )
        with pytest.raises(ObjectVersionConflict):
            store.put(backwards)

    def test_update_with_lower_version_rejected(
        self, store: ObjectStore, base_object: Object, base_state: dict[str, Any]
    ) -> None:
        # First bump to version 3, then try to put version 2 — must reject.
        store.put(base_object)
        v3 = _make_updated(
            base_object, new_state=base_state, new_version=3,
            new_updated_at="2026-05-26T20:05:00Z",
        )
        store.put(v3)
        v2 = _make_updated(
            base_object, new_state=base_state, new_version=2,
            new_updated_at="2026-05-26T20:06:00Z",
        )
        with pytest.raises(ObjectVersionConflict):
            store.put(v2)

    def test_update_cannot_change_owner(
        self, store: ObjectStore, base_object: Object, base_state: dict[str, Any]
    ) -> None:
        store.put(base_object)
        # Construct an Object that's been "rehomed" — same id, different
        # owner. The model accepts this; the store must refuse, both as a
        # principal-mismatch guard and as an ownership-transfer guard.
        hijacked = Object(
            object_id=base_object.object_id,
            owner="someone-else@elsewhere",  # owner changed
            home_layer=LayerKind.PERSONAL,
            mutability=Mutability.STATIC,
            schema_ref=base_object.schema_ref,
            state=base_state,
            object_version=2,
            created_at=base_object.created_at,
            updated_at="2026-05-26T20:05:00Z",
        )
        # The principal-mismatch check fires first (this store is alice's;
        # the hijacked Object claims someone-else owns it).
        with pytest.raises(ObjectStoreOwnerMismatch):
            store.put(hijacked)


# -- get / list ---------------------------------------------------------------


class TestGetAndList:
    def test_get_missing_raises(self, store: ObjectStore) -> None:
        with pytest.raises(ObjectNotFound):
            store.get("does-not-exist")

    def test_list_empty(self, store: ObjectStore) -> None:
        assert store.list() == []

    def test_list_returns_all_objects(
        self, store: ObjectStore, base_object: Object, base_state: dict[str, Any]
    ) -> None:
        store.put(base_object)
        # Insert a second, different Object.
        second = Object(
            object_id="obj-second",
            owner=OWNER,
            home_layer=LayerKind.SHARED,
            mutability=Mutability.STATIC,
            schema_ref="meshycal.scheduling/calendar-v1",
            state={**base_state, "duration_minutes": 45},
            object_version=1,
            created_at="2026-05-27T10:00:00Z",
            updated_at="2026-05-27T10:00:00Z",
        )
        store.put(second)
        ids = {o.object_id for o in store.list()}
        assert ids == {"obj-7f3a", "obj-second"}


# -- promotions ---------------------------------------------------------------


class TestPromotions:
    def test_record_and_lookup_by_id(
        self, store: ObjectStore, base_object: Object, base_promotion: Promotion
    ) -> None:
        store.put(base_object)
        store.record_promotion(base_promotion)
        got = store.get_promotion(base_promotion.promotion_id)
        assert got == base_promotion

    def test_get_promotion_missing_raises(self, store: ObjectStore) -> None:
        with pytest.raises(PromotionNotFound):
            store.get_promotion("does-not-exist")

    def test_list_promotions_for_object(
        self, store: ObjectStore, base_object: Object, base_promotion: Promotion
    ) -> None:
        store.put(base_object)
        store.record_promotion(base_promotion)
        # Second promotion for the same Object to a different receiver.
        second = base_promotion.model_copy(update={
            "promotion_id": "prm-2c3d",
            "receiver": "carol@phase4.local",
            "fetch_endpoint": "https://alice.example/mesherra/objects/fetch/prm-2c3d",
        })
        store.record_promotion(second)
        for_obj = store.list_promotions_for_object(base_object.object_id)
        ids = {p.promotion_id for p in for_obj}
        assert ids == {"prm-1a2b", "prm-2c3d"}

    def test_list_promotions_for_receiver(
        self, store: ObjectStore, base_object: Object, base_promotion: Promotion
    ) -> None:
        store.put(base_object)
        store.record_promotion(base_promotion)
        for_bob = store.list_promotions_for_receiver(RECEIVER)
        assert len(for_bob) == 1
        assert for_bob[0].promotion_id == "prm-1a2b"
        # Different receiver: empty.
        assert store.list_promotions_for_receiver("nobody@nowhere") == []

    def test_duplicate_promotion_id_rejected(
        self, store: ObjectStore, base_object: Object, base_promotion: Promotion
    ) -> None:
        # Append-only: a promotion_id is recorded exactly once.
        store.put(base_object)
        store.record_promotion(base_promotion)
        with pytest.raises(ObjectStoreError):
            store.record_promotion(base_promotion)

    def test_promotion_for_unknown_object_rejected(
        self, store: ObjectStore, base_promotion: Promotion
    ) -> None:
        # Foreign-key-style invariant: promotion must reference a known Object.
        with pytest.raises(ObjectStoreError):
            store.record_promotion(base_promotion)

    def test_promotion_for_foreign_owner_rejected(
        self,
        store: ObjectStore,
        base_object: Object,
        base_promotion: Promotion,
    ) -> None:
        # A promotion's owner must match the store's principal.
        store.put(base_object)
        foreign = base_promotion.model_copy(update={
            "promotion_id": "prm-foreign",
            "owner": "someone-else@elsewhere",
        })
        with pytest.raises(ObjectStoreOwnerMismatch):
            store.record_promotion(foreign)


# -- received handles (counterpart side) --------------------------------------


class TestReceivedHandles:
    def test_record_and_lookup(
        self, store: ObjectStore, received_handle: PromotionHandle
    ) -> None:
        store.record_received_handle(received_handle)
        got = store.get_received_handle(received_handle.promotion_id)
        assert got == received_handle

    def test_list_received_handles(
        self, store: ObjectStore, received_handle: PromotionHandle
    ) -> None:
        store.record_received_handle(received_handle)
        all_handles = store.list_received_handles()
        assert len(all_handles) == 1
        assert all_handles[0] == received_handle

    def test_get_received_handle_missing_raises(self, store: ObjectStore) -> None:
        with pytest.raises(PromotionNotFound):
            store.get_received_handle("does-not-exist")

    def test_handle_addressed_to_someone_else_rejected(
        self, store: ObjectStore, received_handle: PromotionHandle
    ) -> None:
        # A store should only accept handles whose receiver matches its
        # principal. The architecture's stolen-handle guard (§9 #16) lives
        # at the airlock; the store is a second line of defense.
        wrong_receiver = received_handle.model_copy(update={"receiver": "eve@elsewhere"})
        with pytest.raises(OwnershipChangeRejected):
            store.record_received_handle(wrong_receiver)


# -- cold reload (the SPEC §9 assertion 17 dry-run for storage) --------------


class TestColdReload:
    def test_objects_promotions_handles_survive_close_and_reopen(
        self,
        tmp_path: Path,
        base_object: Object,
        base_promotion: Promotion,
        received_handle: PromotionHandle,
    ) -> None:
        db = tmp_path / "cold-reload.sqlite"
        s1 = ObjectStore(db_path=db, owner_principal_id=OWNER)
        s1.put(base_object)
        s1.record_promotion(base_promotion)
        s1.record_received_handle(received_handle)
        s1.close()

        # Cold reopen — same files, fresh process-state.
        s2 = ObjectStore(db_path=db, owner_principal_id=OWNER)
        try:
            assert s2.get(base_object.object_id) == base_object
            assert s2.get_promotion(base_promotion.promotion_id) == base_promotion
            assert s2.get_received_handle(received_handle.promotion_id) == received_handle
        finally:
            s2.close()
