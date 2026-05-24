"""Mesherra Provenance Ledger.

Implements ARCHITECTURE.md section 13.8 and demos/phase_1/SPEC.md section 7
step 3.

A single principal's append-only signed log. One ledger = one principal =
one SQLite file. The file is self-describing: a metadata row records which
principal owns it, so pointing the wrong DB at a Ledger instance fails
loudly rather than silently corrupting cross-principal state.

Phase 1 responsibilities:

* Validate and append signed Residue entries.
* Maintain hash-chain integrity (entry N's ``previous_hash`` must equal
  the canonical hash of entry N-1 with signature omitted).
* Maintain monotonic per-ledger sequence (no gaps, no out-of-order, no
  duplicates).
* Index by ``task_id`` and ``context_id`` for the SDK's lookup paths.
* Self-verify the hash chain after a cold reload (SPEC §5 assertion 14).

Phase 1 deliberately does NOT do:

* Signature verification — that needs public-key resolution which is the
  SDK / Identity Directory's job, not the ledger's. The ledger trusts its
  caller to have constructed a valid Residue. Hash-chain integrity is local
  state; signatures need external state.
* Multi-principal sharding in one file — one DB per principal is simpler
  and cleaner; the SQLite file IS the shard.
* Async I/O — Phase 1 ops are tiny (handful of inserts) and synchronous.
  An async SDK can wrap via ``asyncio.to_thread``.
* Postgres / pluggable backends — SQLite is the v0 backend per
  ARCHITECTURE.md section 13.8.

Append-only is enforced by NOT exposing update/delete methods. Phase 2+
may add SQL-level triggers; Phase 1 trusts the API surface.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from mesherra.crypto.primitives import canonical_json, content_hash
from mesherra.models.primitives import Residue

SCHEMA_VERSION = "1"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ledger_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS residue_entries (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    task_id TEXT NOT NULL,
    context_id TEXT NOT NULL,
    entry_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_residue_task ON residue_entries(task_id);
CREATE INDEX IF NOT EXISTS idx_residue_context ON residue_entries(context_id);

-- Phase 2 hardening per ARCH §11.1: defense-in-depth backstop against
-- replay. The Inbound Gateway's (sender_principal_id, nonce) seen-set
-- is the primary defense; this index ensures that even if the seen-set
-- misses (e.g., process restart within the skew window), the ledger
-- itself refuses to record the same (task_id, action_type, operation)
-- tuple twice. Uniqueness is enforced over JSON-extracted columns so the
-- existing entry_json blob remains the single source of truth.
-- Portability note (ARCH §13.8 "Future: pluggable for distributed ledger"):
-- this expression index requires SQLite's JSON1 extension (built in since
-- 3.38). A Postgres swap will need to translate this to a generated
-- column or `jsonb_path_query(entry_json, '$.action_type')` expression.
CREATE UNIQUE INDEX IF NOT EXISTS idx_residue_unique_task_action_op
    ON residue_entries(
        task_id,
        json_extract(entry_json, '$.action_type'),
        json_extract(entry_json, '$.operation')
    );
"""


# -- Exceptions ----------------------------------------------------------


class LedgerError(Exception):
    """Base class for all ledger-level errors."""


class LedgerOwnerMismatch(LedgerError):
    """A Residue's ``ledger_owner`` does not match this ledger's owner.

    Raised either on open (DB file owned by a different principal) or on
    append (entry belongs to a different principal). Either way, the right
    answer is "you've pointed at the wrong file" — never silently re-key.
    """


class SequenceGap(LedgerError):
    """A Residue's ``sequence`` is not the next expected per-ledger index.

    The ledger expects strictly monotonic sequences starting at 0, no gaps,
    no duplicates. Raised when an entry's ``sequence`` is not exactly
    ``len(ledger)`` at append time.
    """


class BrokenChain(LedgerError):
    """A Residue's ``previous_hash`` does not match the prior entry's hash.

    The previous_hash is computed as ``content_hash(canonical_json(prior.to_signing_payload()))``.
    Raised on append when the chain link is invalid, and surfaced by
    ``verify_chain()`` when an on-disk entry's link is invalid.
    """


class DuplicateEntry(LedgerError):
    """An entry with the same ``(task_id, action_type, operation)`` already exists.

    Raised on append when the ledger already holds a residue entry with the
    same tuple. This is the Phase 2 defense-in-depth backstop against the
    replay vector described in ARCHITECTURE.md §11.1: the Inbound Gateway's
    (sender_principal_id, nonce) seen-set is the primary defense, but if it
    misses (e.g., process restart inside the clock-skew window), the ledger
    itself refuses to record the duplicate. The application is expected to
    treat this as a hard failure — a single ledger should never contain two
    entries claiming the same task/direction/operation.
    """


# -- ProvenanceLedger ----------------------------------------------------


class ProvenanceLedger:
    """Append-only SQLite-backed ledger for one principal's signed residue.

    One instance owns one SQLite connection. Use as a context manager to
    ensure the connection is closed cleanly, or call :meth:`close`
    explicitly.

    Path resolution is the caller's job (config via env per CLAUDE.md #7).
    Use ``:memory:`` for ephemeral testing; pass a filesystem path for
    Phase 1 demos and the cold re-verify in SPEC §5 assertion 14.
    """

    def __init__(self, *, db_path: Path | str, ledger_owner: str) -> None:
        if not ledger_owner:
            raise ValueError("ledger_owner must be a non-empty principal id")
        self._db_path = str(db_path)
        self._ledger_owner = ledger_owner
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        try:
            self._init_schema()
            self._init_or_validate_meta()
        except Exception:
            self._conn.close()
            raise

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        """Close the underlying SQLite connection. Safe to call repeatedly."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None  # type: ignore[assignment]

    def __enter__(self) -> ProvenanceLedger:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # -- properties -----------------------------------------------------

    @property
    def ledger_owner(self) -> str:
        return self._ledger_owner

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def next_sequence(self) -> int:
        """The sequence number the next appended entry must carry."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(sequence), -1) FROM residue_entries"
        ).fetchone()
        return int(row[0]) + 1

    @property
    def head_hash(self) -> str:
        """Canonical hash of the most recent entry (signature omitted).

        Returns the empty string when the ledger holds no entries — the
        value a sequence=0 entry's ``previous_hash`` must equal (per the
        Residue model's ``^([0-9a-f]{64}|)$`` pattern).
        """
        row = self._conn.execute(
            "SELECT entry_json FROM residue_entries "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return ""
        return _hash_of_signing_payload(_residue_from_row(row[0]))

    # -- core API -------------------------------------------------------

    def append(self, residue: Residue) -> str:
        """Validate ``residue`` against this ledger and append it.

        Returns the canonical signature-omitted hash of the just-appended
        entry — i.e., the value a *subsequent* entry's ``previous_hash``
        must equal. Callers building the next entry should keep this.

        Raises:
            LedgerOwnerMismatch: residue.ledger_owner != self.ledger_owner.
            SequenceGap: residue.sequence is not next_sequence.
            BrokenChain: residue.previous_hash does not match head_hash.
            DuplicateEntry: an entry with the same (task_id, action_type,
                operation) already exists. Phase 2 defense-in-depth per
                ARCH §11.1.
        """
        if residue.ledger_owner != self._ledger_owner:
            raise LedgerOwnerMismatch(
                f"Residue ledger_owner {residue.ledger_owner!r} does not "
                f"match this ledger's owner {self._ledger_owner!r}"
            )

        expected_sequence = self.next_sequence
        if residue.sequence != expected_sequence:
            raise SequenceGap(
                f"Expected sequence {expected_sequence}, got "
                f"{residue.sequence}"
            )

        expected_previous = self.head_hash
        if residue.previous_hash != expected_previous:
            raise BrokenChain(
                f"Expected previous_hash {expected_previous!r}, got "
                f"{residue.previous_hash!r}"
            )

        entry_bytes = canonical_json(residue.model_dump(mode="json"))
        entry_text = entry_bytes.decode("utf-8")
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO residue_entries "
                    "(sequence, task_id, context_id, entry_json) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        residue.sequence,
                        residue.task_id,
                        residue.context_id,
                        entry_text,
                    ),
                )
        except sqlite3.IntegrityError as e:
            # The UNIQUE INDEX on (task_id, action_type, operation) refused
            # to record a duplicate. SQLite raises IntegrityError for both
            # PRIMARY KEY collisions (sequence) and UNIQUE INDEX collisions;
            # the message disambiguates. Sequence collisions are caught
            # above by the next_sequence check, so anything reaching here
            # is a (task_id, action_type, operation) duplicate.
            raise DuplicateEntry(
                f"A residue entry for task_id={residue.task_id!r}, "
                f"action_type={residue.action_type.value!r}, "
                f"operation={residue.operation.value!r} already exists in "
                "this ledger. This is the Phase 2 ARCH §11.1 defense-in-depth "
                "replay backstop firing — the Inbound Gateway's nonce cache "
                "should normally catch this earlier."
            ) from e
        return _hash_of_signing_payload(residue)

    def get_all(self) -> list[Residue]:
        """Return every entry in this ledger, ordered by sequence ascending."""
        rows = self._conn.execute(
            "SELECT entry_json FROM residue_entries ORDER BY sequence ASC"
        ).fetchall()
        return [_residue_from_row(r[0]) for r in rows]

    def get_by_task(self, task_id: str) -> list[Residue]:
        """All entries pertaining to a given A2A task, ordered by sequence."""
        rows = self._conn.execute(
            "SELECT entry_json FROM residue_entries "
            "WHERE task_id = ? ORDER BY sequence ASC",
            (task_id,),
        ).fetchall()
        return [_residue_from_row(r[0]) for r in rows]

    def get_by_context(self, context_id: str) -> list[Residue]:
        """All entries in a given multi-turn context, ordered by sequence."""
        rows = self._conn.execute(
            "SELECT entry_json FROM residue_entries "
            "WHERE context_id = ? ORDER BY sequence ASC",
            (context_id,),
        ).fetchall()
        return [_residue_from_row(r[0]) for r in rows]

    def __len__(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM residue_entries"
        ).fetchone()
        return int(row[0])

    # -- verification ---------------------------------------------------

    def verify_chain(self) -> bool:
        """Recompute and check the hash chain across the entire ledger.

        For each entry N:

        * The decoded JSON must round-trip through ``Residue.model_validate``
          without error (catches on-disk tampering that broke the schema).
        * ``previous_hash`` must equal the canonical hash of entry N-1
          (signature omitted), or empty string when N == 0.
        * ``sequence`` must equal its position in the ordered scan.

        Signature verification is intentionally NOT done here — that needs
        public-key resolution which is the SDK's responsibility (Phase 2:
        Identity Directory). This method checks only what the ledger can
        verify with its own on-disk state.

        Returns True iff every entry's chain link is valid. Returns False
        (does not raise) if a row's stored bytes fail to parse as a Residue —
        a row that can't be decoded is, by definition, not a valid chain link.
        """
        prior_hash = ""
        try:
            entries = self.get_all()
        except (json.JSONDecodeError, ValidationError):
            return False
        for expected_sequence, residue in enumerate(entries):
            if residue.sequence != expected_sequence:
                return False
            if residue.previous_hash != prior_hash:
                return False
            prior_hash = _hash_of_signing_payload(residue)
        return True

    # -- internals ------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    def _init_or_validate_meta(self) -> None:
        rows = dict(
            self._conn.execute("SELECT key, value FROM ledger_meta").fetchall()
        )
        if "ledger_owner" not in rows:
            with self._conn:
                self._conn.executemany(
                    "INSERT INTO ledger_meta (key, value) VALUES (?, ?)",
                    [
                        ("ledger_owner", self._ledger_owner),
                        ("schema_version", SCHEMA_VERSION),
                    ],
                )
            return
        if rows["ledger_owner"] != self._ledger_owner:
            raise LedgerOwnerMismatch(
                f"DB at {self._db_path!r} is owned by "
                f"{rows['ledger_owner']!r}, not {self._ledger_owner!r}"
            )
        recorded_schema = rows.get("schema_version", "")
        if recorded_schema != SCHEMA_VERSION:
            raise LedgerError(
                f"DB at {self._db_path!r} has schema_version "
                f"{recorded_schema!r}; this code expects "
                f"{SCHEMA_VERSION!r}"
            )


# -- helpers -------------------------------------------------------------


def _residue_from_row(entry_text: str) -> Residue:
    return Residue.model_validate(json.loads(entry_text))


def _hash_of_signing_payload(residue: Residue) -> str:
    """Compute the canonical signature-omitted hash of a Residue.

    This is the value that becomes the *next* entry's ``previous_hash``,
    and the value that participates in the hash-chain verification.
    """
    return content_hash(canonical_json(residue.to_signing_payload()))
