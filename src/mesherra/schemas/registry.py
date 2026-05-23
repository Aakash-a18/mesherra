"""Schema Registry.

Implements ARCHITECTURE.md section 13.11.

Verified registry of payload schemas published by consumers.
Sibling to the Identity Directory, with parallel mechanics.

Operations (per architecture):
    resolve_schema(id, version)              -> schema + publisher signature
    publish_schema(schema, publisher)        -> signed registration record
    list_versions(id)                        -> version history
    verify_publisher(schema, principal)      -> confirms publisher authenticity

Trust model: schemas are signed by their publisher's principal (verified
through Identity Directory). Receivers verify a schema is authentic before
accepting payloads against it.

v0: centralized, Mesherra-hosted. Same migration path to federated /
decentralized as the Identity Directory.

See ARCHITECTURE.md section 8 for the broader schema-based messaging model.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class SchemaRegistry:
    """Verified registry of consumer-published payload schemas."""

    def __init__(self) -> None:
        raise NotImplementedError

    async def resolve_schema(self, schema_id: str, version: str) -> Any:
        """Return schema definition + publisher signature."""
        raise NotImplementedError

    async def publish_schema(self, schema: Any, publisher: str) -> Any:
        """Register a new schema. Requires verified publisher principal."""
        raise NotImplementedError

    async def list_versions(self, schema_id: str) -> list[str]:
        raise NotImplementedError

    async def verify_publisher(self, schema_id: str, publisher_principal: str) -> bool:
        raise NotImplementedError
