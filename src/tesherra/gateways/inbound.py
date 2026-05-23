"""Inbound Gateway.

Implements ARCHITECTURE.md section 13.3.

Intercepts every incoming A2A message before it reaches any consumer handler.

Responsibilities:
- Receive raw envelope from A2A SDK Adapter
- Verify signature via Crypto Primitives
- Resolve sender via Identity Directory
- Consult Policy Engine for accept/reject/escalate decision
- Write provenance entry to Ledger
- Deliver scoped, verified payload to consumer's registered handler

Hard rule: no consumer code receives raw A2A messages. Everything inbound
passes through here first.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any, Callable


class InboundGateway:
    """The airlock for incoming messages."""

    def __init__(self) -> None:
        raise NotImplementedError

    def register_handler(self, handler: Callable[[Any], None]) -> None:
        """Register the consumer's callback for verified inbound messages."""
        raise NotImplementedError

    async def receive(self, envelope: Any) -> Any:
        """Verify, policy-check, log, and dispatch an incoming message."""
        raise NotImplementedError
