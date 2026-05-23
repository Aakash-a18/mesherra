"""Mesherra SDK / Public API.

Implements ARCHITECTURE.md section 13.1.

The only surface consumers (MeshyCal, future Delegations) interact with.
Everything else in Mesherra is internal.

Core operations (per ARCHITECTURE.md 13.1):
    init(user_id, config)
    register_principal()
    send_to(peer, parts, opts)
    on_message(handler)
    verify(agent_card)
    attest(task_id)
    get_policy() / update_policy(policy)
    get_residue(task_id) / get_residue_chain(context_id)

Status: scaffolding only. Phase 1 fills in send_to, attest, and the residue
accessors (the provenance-vertical-slice surface).
"""

from __future__ import annotations

from typing import Any, Callable


class Mesherra:
    """Public SDK surface. Wraps the internal gateways, decision services, and adapter.

    See ARCHITECTURE.md section 13.1 for the full operations list.
    """

    def __init__(self, user_id: str, config: dict[str, Any]) -> None:
        raise NotImplementedError("Mesherra is in pre-alpha; SDK surface not yet implemented.")

    def register_principal(self) -> None:
        raise NotImplementedError

    def send_to(self, peer: str, parts: list[Any], opts: dict[str, Any] | None = None) -> Any:
        raise NotImplementedError

    def on_message(self, handler: Callable[[Any], None]) -> None:
        raise NotImplementedError

    def verify(self, agent_card: Any) -> Any:
        raise NotImplementedError

    def attest(self, task_id: str) -> Any:
        raise NotImplementedError

    def get_policy(self) -> Any:
        raise NotImplementedError

    def update_policy(self, policy: Any) -> Any:
        raise NotImplementedError

    def get_residue(self, task_id: str) -> Any:
        raise NotImplementedError

    def get_residue_chain(self, context_id: str) -> Any:
        raise NotImplementedError
