"""Directory Store.

Implements ARCHITECTURE.md §13.7. SQLite-backed storage for the Identity
Directory's principal records.

v0 properties:

* **One row per principal.** ``principal_id`` is the primary key; a principal
  registers once and is then resolvable. Re-registration with the same id
  raises ``PrincipalAlreadyRegistered`` — Phase 2 has no key-rotation flow.
  Phase 3+ will add a signed key-rotation operation that produces a new row
  with a chain back to the previous one (similar in shape to how Residue
  references previous_hash).
* **Synchronous I/O.** Same rationale as ``ProvenanceLedger`` (§13.8):
  tiny per-call cost, single-writer in v0, async wrappers can layer on top
  via ``asyncio.to_thread`` if needed. The FastAPI server endpoints that
  consume this store run the calls inside ``async def`` handlers and that's
  fine for v0 traffic levels.
* **Path-based.** Caller supplies ``db_path`` (per CLAUDE.md #7, the
  Directory service reads the path from ``MESHERRA_DIRECTORY_STORE_URL``
  at startup). Use ``:memory:`` for ephemeral tests.

Phase 2 sub-step 2 deliberately does NOT do:

* Signature verification at store level — that's the client's job
  (HTTPDirectoryClient verifies the Directory's signature on every read
  in sub-step 3).
* Authentication on write — sub-step 2 has no auth; anyone who can
  reach the Directory service can register. Sub-step 4 or Phase 2.5 will
  add operator-signed registration.
* List / enumeration over HTTP — the registry is private metadata.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class StoredPrincipal:
    """A persisted principal record as the store returns it."""

    principal_id: str
    public_key_b64: str
    registered_at: str

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS directory_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    public_key_b64 TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
"""


# -- Exceptions ----------------------------------------------------------


class DirectoryStoreError(Exception):
    """Base class for directory-store-level errors."""


class PrincipalAlreadyRegistered(DirectoryStoreError):
    """Attempted to register a principal that already exists.

    v0 has no key-rotation flow — once a principal is registered, the
    operator must explicitly remove the row before re-registering. This
    behavior is intentional: it prevents an attacker who somehow got
    write access from silently swapping a principal's public key.
    """


class PrincipalNotFound(DirectoryStoreError):
    """No record for the requested principal_id."""


# -- DirectoryStore ------------------------------------------------------


class DirectoryStore:
    """SQLite-backed storage for the Identity Directory.

    Use as a context manager to guarantee the connection is closed, or
    call :meth:`close` explicitly. One process per store file; the store
    does no cross-process locking beyond what SQLite provides natively.
    """

    def __init__(self, *, db_path: Path | str) -> None:
        self._db_path = str(db_path)
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

    def __enter__(self) -> DirectoryStore:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- core API -------------------------------------------------------

    def register(
        self,
        *,
        principal_id: str,
        public_key_b64: str,
        registered_at: str,
    ) -> None:
        """Insert a new principal record. Raises if the id already exists."""
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO principals "
                    "(principal_id, public_key_b64, registered_at) "
                    "VALUES (?, ?, ?)",
                    (principal_id, public_key_b64, registered_at),
                )
        except sqlite3.IntegrityError as e:
            raise PrincipalAlreadyRegistered(
                f"Principal {principal_id!r} is already registered. v0 has no "
                "key-rotation flow; an operator must delete the existing row "
                "before re-registering."
            ) from e

    def get_record(self, principal_id: str) -> StoredPrincipal:
        """Return the full persisted record or raise PrincipalNotFound.

        Sub-step 3 returns the full row (not just the public key) so the
        Directory service can sign over the same fields it persisted —
        including ``registered_at`` — without re-querying.
        """
        row = self._conn.execute(
            "SELECT principal_id, public_key_b64, registered_at "
            "FROM principals WHERE principal_id = ?",
            (principal_id,),
        ).fetchone()
        if row is None:
            raise PrincipalNotFound(
                f"No record for principal {principal_id!r} in the directory."
            )
        return StoredPrincipal(
            principal_id=str(row[0]),
            public_key_b64=str(row[1]),
            registered_at=str(row[2]),
        )

    def __len__(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM principals").fetchone()
        return int(row[0])

    # -- internals ------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    def _init_or_validate_meta(self) -> None:
        rows = dict(
            self._conn.execute("SELECT key, value FROM directory_meta").fetchall()
        )
        if "schema_version" not in rows:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO directory_meta (key, value) VALUES (?, ?)",
                    ("schema_version", SCHEMA_VERSION),
                )
            return
        if rows["schema_version"] != SCHEMA_VERSION:
            raise DirectoryStoreError(
                f"DB at {self._db_path!r} has schema_version "
                f"{rows['schema_version']!r}; this code expects "
                f"{SCHEMA_VERSION!r}"
            )
