"""Directory Store.

Implements ARCHITECTURE.md section 13.7.

Backing storage for the Identity Directory.

v0: relational database (Postgres or equivalent), Mesherra-hosted. Each row is
a principal record with signed AgentCard hash, public key, and claim metadata.
Local development uses SQLite via the URL in MESHERRA_DIRECTORY_STORE_URL.

Future: pluggable backend for decentralized models.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class DirectoryStore:
    """Backing storage for the verified-principal registry."""

    def __init__(self) -> None:
        raise NotImplementedError

    def get(self, principal_id: str) -> Any:
        raise NotImplementedError

    def put(self, principal_id: str, record: Any) -> None:
        raise NotImplementedError

    def list(self, filter: dict[str, Any] | None = None) -> list[Any]:
        raise NotImplementedError
