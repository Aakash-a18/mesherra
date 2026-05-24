"""Unit tests for the Identity Directory's SQLite-backed store.

The store is the smallest piece of Phase 2 sub-step 2 — pure CRUD with the
``register once, resolve forever`` invariant. The FastAPI server layered
on top is exercised by the integration tests; this file pins down the
storage contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mesherra.identity.store import (
    DirectoryStore,
    PrincipalAlreadyRegistered,
    PrincipalNotFound,
)

PRINCIPAL_A = "user-a@phase1.local"
PRINCIPAL_B = "user-b@phase1.local"
KEY_A = "A" * 44  # 32 bytes base64
KEY_B = "B" * 44
STAMP = "2026-05-24T12:00:00Z"


class TestRegisterAndResolve:
    def test_round_trip_in_memory(self) -> None:
        with DirectoryStore(db_path=":memory:") as store:
            store.register(
                principal_id=PRINCIPAL_A,
                public_key_b64=KEY_A,
                registered_at=STAMP,
            )
            assert store.get_record(PRINCIPAL_A).public_key_b64 == KEY_A
            assert len(store) == 1

    def test_two_principals_coexist(self) -> None:
        with DirectoryStore(db_path=":memory:") as store:
            store.register(
                principal_id=PRINCIPAL_A,
                public_key_b64=KEY_A,
                registered_at=STAMP,
            )
            store.register(
                principal_id=PRINCIPAL_B,
                public_key_b64=KEY_B,
                registered_at=STAMP,
            )
            assert store.get_record(PRINCIPAL_A).public_key_b64 == KEY_A
            assert store.get_record(PRINCIPAL_B).public_key_b64 == KEY_B
            assert store.get_record(PRINCIPAL_A).registered_at == STAMP
            assert len(store) == 2

    def test_resolve_unknown_principal_raises(self) -> None:
        with DirectoryStore(db_path=":memory:") as store:
            with pytest.raises(PrincipalNotFound, match="No record"):
                store.get_record(PRINCIPAL_A)

    def test_double_register_rejected(self) -> None:
        """v0 has no key-rotation flow — the store refuses a second register
        for the same principal_id. This prevents a write-side attacker from
        silently swapping a registered key."""
        with DirectoryStore(db_path=":memory:") as store:
            store.register(
                principal_id=PRINCIPAL_A,
                public_key_b64=KEY_A,
                registered_at=STAMP,
            )
            with pytest.raises(PrincipalAlreadyRegistered, match="already registered"):
                store.register(
                    principal_id=PRINCIPAL_A,
                    public_key_b64="different-key",
                    registered_at=STAMP,
                )
            # The original key survived the failed write.
            assert store.get_record(PRINCIPAL_A).public_key_b64 == KEY_A


class TestPersistence:
    def test_records_survive_close_and_reopen(self, tmp_path: Path) -> None:
        db = tmp_path / "directory.sqlite"
        with DirectoryStore(db_path=db) as store:
            store.register(
                principal_id=PRINCIPAL_A,
                public_key_b64=KEY_A,
                registered_at=STAMP,
            )
        # Cold reload.
        with DirectoryStore(db_path=db) as store:
            assert store.get_record(PRINCIPAL_A).public_key_b64 == KEY_A
            assert len(store) == 1
