"""Outbound Gateway.

Implements ARCHITECTURE.md section 13.2.

Intercepts every outgoing message before it reaches A2A.

Responsibilities:
- Receive send_to() calls from the SDK
- Consult Policy Engine for allow/scope decision
- Consult Identity Directory to resolve peer to verified endpoint
- Invoke Crypto Primitives for signing
- Write provenance entry to Ledger
- Pass envelope to A2A SDK Adapter

Hard rule: there is no path from consumer code to the A2A wire that bypasses
this gateway. All outbound traffic goes through here.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class OutboundGateway:
    """The airlock for outgoing messages."""

    def __init__(self) -> None:
        raise NotImplementedError

    async def send(self, peer: str, parts: list[Any], context: dict[str, Any]) -> Any:
        """Scope, sign, log, and dispatch an outgoing message."""
        raise NotImplementedError
