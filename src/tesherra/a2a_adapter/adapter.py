"""A2A SDK Adapter.

Implements ARCHITECTURE.md section 13.10.

The only module in Tesherra that imports `a2a-sdk`.

Responsibilities:
- Wrap A2A's SendMessage, GetTask, SubscribeToTask, push notifications
- Translate Tesherra's envelope format <-> A2A's Message, Part, Artifact
- Map A2A TaskState transitions onto Tesherra events:
    INPUT_REQUIRED -> butler escalation
    AUTH_REQUIRED  -> identity re-verification
    COMPLETED      -> trigger attestation
- Embed signed provenance metadata into A2A Artifact.metadata on completion

Strict isolation: if A2A changes, only this module changes. No other module
in Tesherra imports `a2a-sdk` or references A2A types directly.

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class A2AAdapter:
    """Thin wrapper over the official a2a-sdk."""

    def __init__(self) -> None:
        raise NotImplementedError

    async def send_message(self, peer_url: str, envelope: Any) -> Any:
        raise NotImplementedError

    async def get_task(self, task_id: str) -> Any:
        raise NotImplementedError

    async def subscribe_to_task(self, task_id: str) -> Any:
        raise NotImplementedError

    def envelope_to_a2a(self, envelope: Any) -> Any:
        """Translate Tesherra envelope -> A2A Message/Parts."""
        raise NotImplementedError

    def a2a_to_envelope(self, message: Any) -> Any:
        """Translate A2A Message/Parts -> Tesherra envelope."""
        raise NotImplementedError
