"""Identity Directory.

Implements ARCHITECTURE.md section 13.5.

The verified registry of principals.

Operations (per architecture):
    resolve(name | URL)              -> AgentCard + verification proof
    register(principal, AgentCard)   -> signed registration record
    attest(principal_a, principal_b) -> "these two are verified peers"

v0: centralized, Tesherra-hosted. Trust root is our organizational signing key.
Future: pluggable backend designed to swap to decentralized (PKI, web-of-trust,
transparency log) without rewriting consumers.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class IdentityDirectory:
    """Verified registry of principals."""

    def __init__(self) -> None:
        raise NotImplementedError

    async def resolve(self, identifier: str) -> Any:
        """Return verified AgentCard + signature proof for a principal."""
        raise NotImplementedError

    async def register(self, principal: Any, agent_card: Any) -> Any:
        """Register or refresh a principal's record."""
        raise NotImplementedError

    async def attest(self, principal_a: str, principal_b: str) -> Any:
        """Issue a verified-peers assertion."""
        raise NotImplementedError
