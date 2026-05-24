"""Unit tests for the SQLite-backed PolicyStore."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mesherra.crypto.primitives import Signer
from mesherra.policy import (
    Match,
    PolicyDoc,
    Rule,
    SignedPolicyDoc,
    sign_policy_doc,
)
from mesherra.policy.store import (
    NonMonotonicPolicyVersion,
    PolicyNotFound,
    PolicyPrincipalMismatch,
    PolicyStore,
    PolicyStoreError,
    PolicyVerificationFailed,
)


def _doc(*, principal_id: str = "user-a@phase3.local", version: int = 1) -> PolicyDoc:
    return PolicyDoc(
        principal_id=principal_id,
        version=version,
        issued_at="2026-05-24T12:00:00Z",
        rules=[
            Rule(
                match=Match(schema="meshycal.scheduling/proposal-v1"),
                outbound_block=["calendar_titles"],
            )
        ],
    )


class TestLifecycle:
    def test_constructor_requires_principal_and_key(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            PolicyStore(db_path=tmp_path / "x.sqlite", principal_id="", public_key_b64="abc")
        with pytest.raises(ValueError):
            PolicyStore(db_path=tmp_path / "x.sqlite", principal_id="p", public_key_b64="")

    def test_context_manager_closes(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            assert len(store) == 0
        # After exit, further calls raise (closed connection).
        with pytest.raises(Exception):
            len(store)

    def test_in_memory_works(self) -> None:
        signer = Signer.generate()
        store = PolicyStore(
            db_path=":memory:",
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        )
        assert len(store) == 0
        store.close()


class TestSaveAndLoadRoundtrip:
    def test_save_then_get_current(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        signed = sign_policy_doc(doc=_doc(), signer=signer)
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            store.save_signed(signed)
            loaded = store.get_current()
        assert loaded.signature_b64 == signed.signature_b64
        assert loaded.doc.principal_id == signed.doc.principal_id
        assert loaded.doc.version == signed.doc.version
        assert loaded.doc.rules == signed.doc.rules

    def test_get_version_specific(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        v1 = sign_policy_doc(doc=_doc(version=1), signer=signer)
        v2 = sign_policy_doc(doc=_doc(version=2), signer=signer)
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            store.save_signed(v1)
            store.save_signed(v2)
            assert store.get_current().doc.version == 2
            assert store.get_version(1).doc.version == 1
            assert store.get_version(2).doc.version == 2

    def test_get_current_when_empty_raises_policy_not_found(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            with pytest.raises(PolicyNotFound):
                store.get_current()

    def test_get_version_unknown_raises(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            with pytest.raises(PolicyNotFound):
                store.get_version(99)


class TestPrincipalBinding:
    def test_cross_principal_save_rejected(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        signed = sign_policy_doc(
            doc=_doc(principal_id="user-b@phase3.local"), signer=signer
        )
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            with pytest.raises(PolicyPrincipalMismatch):
                store.save_signed(signed)


class TestMonotonicity:
    def test_lower_version_rejected(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        v1 = sign_policy_doc(doc=_doc(version=1), signer=signer)
        v2 = sign_policy_doc(doc=_doc(version=2), signer=signer)
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            store.save_signed(v2)
            with pytest.raises(NonMonotonicPolicyVersion):
                store.save_signed(v1)

    def test_same_version_rejected(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        v1a = sign_policy_doc(doc=_doc(version=1), signer=signer)
        v1b = sign_policy_doc(doc=_doc(version=1), signer=signer)
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            store.save_signed(v1a)
            with pytest.raises(NonMonotonicPolicyVersion):
                store.save_signed(v1b)


class TestSignatureVerification:
    def test_wrong_key_at_read_raises(self, tmp_path: Path) -> None:
        signer_a = Signer.generate()
        signer_b = Signer.generate()
        signed_by_a = sign_policy_doc(doc=_doc(), signer=signer_a)
        # Store bound to B's key; if it accepts A's signed doc at write,
        # it must reject at read.
        with PolicyStore(
            db_path=tmp_path / "p.sqlite",
            principal_id="user-a@phase3.local",
            public_key_b64=signer_b.public_key_b64(),
        ) as store:
            store.save_signed(signed_by_a)
            with pytest.raises(PolicyVerificationFailed):
                store.get_current()

    def test_corrupted_doc_on_disk_fails_verify(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        signed = sign_policy_doc(doc=_doc(), signer=signer)
        db_path = tmp_path / "p.sqlite"
        with PolicyStore(
            db_path=db_path,
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            store.save_signed(signed)
        # Mutate the stored doc_json directly.
        with sqlite3.connect(db_path) as raw:
            raw.execute(
                "UPDATE policy_versions SET issued_at = ? "
                "WHERE principal_id = ? AND version = ?",
                ("2099-01-01T00:00:00Z", "user-a@phase3.local", 1),
            )
            raw.execute(
                "UPDATE policy_versions SET doc_json = REPLACE("
                "doc_json, '2026-05-24T12:00:00Z', '2099-01-01T00:00:00Z') "
                "WHERE principal_id = ? AND version = ?",
                ("user-a@phase3.local", 1),
            )
            raw.commit()
        with PolicyStore(
            db_path=db_path,
            principal_id="user-a@phase3.local",
            public_key_b64=signer.public_key_b64(),
        ) as store:
            with pytest.raises(PolicyVerificationFailed):
                store.get_current()


class TestSchemaVersion:
    def test_schema_meta_initialized_on_first_open(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        db_path = tmp_path / "p.sqlite"
        with PolicyStore(
            db_path=db_path,
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        ):
            pass
        with sqlite3.connect(db_path) as raw:
            row = raw.execute(
                "SELECT value FROM policy_meta WHERE key = ?",
                ("schema_version",),
            ).fetchone()
        assert row is not None and row[0] == "1"

    def test_schema_version_mismatch_fails_fast(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        db_path = tmp_path / "p.sqlite"
        with PolicyStore(
            db_path=db_path,
            principal_id="p",
            public_key_b64=signer.public_key_b64(),
        ):
            pass
        with sqlite3.connect(db_path) as raw:
            raw.execute(
                "UPDATE policy_meta SET value = ? WHERE key = ?",
                ("999", "schema_version"),
            )
            raw.commit()
        with pytest.raises(PolicyStoreError):
            PolicyStore(
                db_path=db_path,
                principal_id="p",
                public_key_b64=signer.public_key_b64(),
            )
