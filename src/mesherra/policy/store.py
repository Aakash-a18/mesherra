"""Policy Store.

Implements ARCHITECTURE.md §13.6 and demos/phase_3/SPEC.md §5.

SQLite-backed storage for the user's signed policy. Per-principal: one
``PolicyStore`` instance serves one principal's policies, bound at
construction to that principal's public key for signature verification.
Sharing a store across principals is not supported in v0 — the binding is
load-bearing for the read-time signature check.

Properties (per architecture):

* **User-owned**: only the bound principal's signing key can produce a
  policy that this store will accept on read. A signature failure at read
  is :class:`PolicyVerificationFailed`.
* **Versioned**: every saved policy is a row keyed by ``(principal_id,
  version)``. Versions are monotonically increasing — non-monotonic insert
  raises :class:`NonMonotonicPolicyVersion`. ``get_current()`` returns the
  highest version.
* **Schema-validated**: the store's own SQL schema is versioned via
  ``schema_meta``; mismatch is fail-fast (matches Phase 2's
  ``DirectoryStore``).
* **Local-first**: SQLite on disk (or ``:memory:`` for tests). Replication
  / E2E-encrypted backup ships in a later phase.

Lifecycle conventions mirror :class:`mesherra.identity.store.DirectoryStore`
and :class:`mesherra.provenance.ledger.ProvenanceLedger`: context-manager
wrapped, fail-fast on schema mismatch, synchronous I/O.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from mesherra.crypto.primitives import Verifier, canonical_json

from .models import PolicyDoc, SignedPolicyDoc

SCHEMA_VERSION = "1"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS policy_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    principal_id  TEXT NOT NULL,
    version       INTEGER NOT NULL,
    issued_at     TEXT NOT NULL,
    doc_json      TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    saved_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (principal_id, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_latest
    ON policy_versions (principal_id, version DESC);
"""


# -- Exceptions ----------------------------------------------------------


class PolicyStoreError(Exception):
    """Base class for policy-store-level errors."""


class PolicyNotFound(PolicyStoreError):
    """No policy row exists for the bound principal."""


class PolicyVerificationFailed(PolicyStoreError):
    """The stored signature did not verify against the bound public key.

    Distinct from PolicyNotFound: the row exists but its signature is bad.
    Treat as tampering or a key-rotation event the v0 store can't yet
    handle (Phase 3.5+ adds rotation).
    """


class NonMonotonicPolicyVersion(PolicyStoreError):
    """Attempted to save a policy whose version is <= an existing version.

    Versions are append-only and must increase by at least 1.
    """


class PolicyPrincipalMismatch(PolicyStoreError):
    """The signed doc's principal_id doesn't match this store's bound principal.

    One store serves one principal; cross-principal saves are refused.
    """


# -- PolicyStore --------------------------------------------------------


class PolicyStore:
    """SQLite-backed signed-policy storage for one principal.

    Construct via ``PolicyStore(db_path=..., principal_id=..., public_key_b64=...)``.
    All reads verify the stored signature against ``public_key_b64``; all
    writes assert the saved doc's ``principal_id`` matches the bound one.

    Use as a context manager or call :meth:`close` explicitly.
    """

    def __init__(
        self,
        *,
        db_path: Path | str,
        principal_id: str,
        public_key_b64: str,
    ) -> None:
        if not principal_id:
            raise ValueError("principal_id must be non-empty")
        if not public_key_b64:
            raise ValueError("public_key_b64 must be non-empty")
        self._db_path = str(db_path)
        self._principal_id = principal_id
        self._public_key_b64 = public_key_b64
        self._verifier = Verifier.from_b64(public_key_b64)
        self._conn = sqlite3.connect(self._db_path)
        try:
            self._init_schema()
            self._init_or_validate_meta()
        except Exception:
            self._conn.close()
            raise

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None  # type: ignore[assignment]

    def __enter__(self) -> PolicyStore:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- properties -----------------------------------------------------

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def public_key_b64(self) -> str:
        return self._public_key_b64

    # -- core API -------------------------------------------------------

    def save_signed(self, signed: SignedPolicyDoc) -> None:
        """Persist a new signed policy version.

        Enforces principal binding and version monotonicity. The store does
        NOT re-verify the signature here — signing is the caller's
        responsibility at write time; verification is done at read time
        where the value matters (a corrupted-at-rest signature would
        surface on the next :meth:`get_current` call).
        """
        if signed.doc.principal_id != self._principal_id:
            raise PolicyPrincipalMismatch(
                f"Signed doc is for principal {signed.doc.principal_id!r}; "
                f"this store is bound to {self._principal_id!r}."
            )
        latest = self._current_version_number()
        if latest is not None and signed.doc.version <= latest:
            raise NonMonotonicPolicyVersion(
                f"Attempted to save policy version {signed.doc.version} but "
                f"latest stored version is {latest}. Versions are "
                "append-only and must increase."
            )
        doc_json = json.dumps(
            signed.doc.to_signing_payload(),
            separators=(",", ":"),
            sort_keys=True,
        )
        with self._conn:
            self._conn.execute(
                "INSERT INTO policy_versions "
                "(principal_id, version, issued_at, doc_json, signature_b64) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    signed.doc.principal_id,
                    signed.doc.version,
                    signed.doc.issued_at,
                    doc_json,
                    signed.signature_b64,
                ),
            )

    def get_current(self) -> SignedPolicyDoc:
        """Return the highest-version signed policy for the bound principal.

        Verifies the stored signature against the bound public key on every
        read. Raises :class:`PolicyVerificationFailed` on signature
        mismatch (caller treats this as tampering), :class:`PolicyNotFound`
        if no policy has ever been saved.
        """
        row = self._conn.execute(
            "SELECT version, doc_json, signature_b64 "
            "FROM policy_versions WHERE principal_id = ? "
            "ORDER BY version DESC LIMIT 1",
            (self._principal_id,),
        ).fetchone()
        if row is None:
            raise PolicyNotFound(
                f"No policy stored for principal {self._principal_id!r}."
            )
        _version, doc_json, signature_b64 = row
        doc_dict = json.loads(doc_json)
        doc = PolicyDoc.model_validate(doc_dict)
        signed = SignedPolicyDoc(doc=doc, signature_b64=str(signature_b64))
        canonical = canonical_json(doc.to_signing_payload())
        if not self._verifier.verify(canonical, signed.signature_b64):
            raise PolicyVerificationFailed(
                f"Stored signature for principal {self._principal_id!r} "
                f"version {doc.version} did not verify against the bound "
                "public key. Treat as tampering or a key-rotation event."
            )
        return signed

    def get_version(self, version: int) -> SignedPolicyDoc:
        """Return a specific policy version. Same verification contract as
        :meth:`get_current`."""
        row = self._conn.execute(
            "SELECT doc_json, signature_b64 "
            "FROM policy_versions WHERE principal_id = ? AND version = ?",
            (self._principal_id, version),
        ).fetchone()
        if row is None:
            raise PolicyNotFound(
                f"No policy version {version} for principal "
                f"{self._principal_id!r}."
            )
        doc_json, signature_b64 = row
        doc_dict = json.loads(doc_json)
        doc = PolicyDoc.model_validate(doc_dict)
        signed = SignedPolicyDoc(doc=doc, signature_b64=str(signature_b64))
        canonical = canonical_json(doc.to_signing_payload())
        if not self._verifier.verify(canonical, signed.signature_b64):
            raise PolicyVerificationFailed(
                f"Stored signature for principal {self._principal_id!r} "
                f"version {version} did not verify."
            )
        return signed

    def __len__(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM policy_versions WHERE principal_id = ?",
            (self._principal_id,),
        ).fetchone()
        return int(row[0])

    # -- internals ------------------------------------------------------

    def _current_version_number(self) -> int | None:
        row = self._conn.execute(
            "SELECT version FROM policy_versions "
            "WHERE principal_id = ? ORDER BY version DESC LIMIT 1",
            (self._principal_id,),
        ).fetchone()
        return None if row is None else int(row[0])

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    def _init_or_validate_meta(self) -> None:
        rows = dict(
            self._conn.execute("SELECT key, value FROM policy_meta").fetchall()
        )
        if "schema_version" not in rows:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO policy_meta (key, value) VALUES (?, ?)",
                    ("schema_version", SCHEMA_VERSION),
                )
            return
        if rows["schema_version"] != SCHEMA_VERSION:
            raise PolicyStoreError(
                f"DB at {self._db_path!r} has schema_version "
                f"{rows['schema_version']!r}; this code expects "
                f"{SCHEMA_VERSION!r}"
            )
