"""Provenance Ledger.

Implements ARCHITECTURE.md section 13.8.

The append-only signed log of every Mesherra interaction.

Properties (per architecture):
- Append-only: entries cannot be modified or deleted, only appended
- Tamper-evident: each entry references the hash of the previous
  (hash-chain or Merkle-tree)
- Per-user shard: a user can retrieve their full residue without exposing
  other users'
- Indexed by A2A task.id and context_id for fast lookup
- Referenceable: future tasks can cite prior residue via A2A's
  Message.reference_task_ids, compounding trust across interactions

v0: append-only Postgres (or SQLite for dev) table with hash-chain integrity.
Future: pluggable for distributed ledger or transparency systems.

In v0, residue is primarily forensic (audit and dispute resolution).
Preventive uses emerge in v1+ as the trust graph fills out.

Status: scaffolding only. Ships first in Phase 1.
"""

from __future__ import annotations

from typing import Any


class ProvenanceLedger:
    """Append-only signed ledger of Mesherra interactions."""

    def __init__(self) -> None:
        raise NotImplementedError

    async def append(self, entry: Any) -> str:
        """Append a signed entry. Returns the entry's content hash."""
        raise NotImplementedError

    async def get_by_task(self, task_id: str) -> list[Any]:
        """Retrieve all entries for a given A2A task."""
        raise NotImplementedError

    async def get_by_context(self, context_id: str) -> list[Any]:
        """Retrieve the full residue chain for a multi-turn conversation."""
        raise NotImplementedError

    async def verify_chain(self, task_id: str) -> bool:
        """Verify the hash chain integrity for a task's residue."""
        raise NotImplementedError
