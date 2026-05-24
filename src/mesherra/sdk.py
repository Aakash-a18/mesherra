"""Mesherra SDK / Public API.

Per ARCHITECTURE.md §13.1. The only surface consumers (MeshyCal, future
Delegations) interact with. Everything else in Mesherra is internal.

Phase 1 surface (the provenance vertical slice):

* :meth:`Mesherra.send_to` — send a signed payload to a peer (via Outbound
  Gateway), record both residues, return the peer's response.
* :meth:`Mesherra.on_message` — register a consumer handler for inbound
  messages. Registration wires through the Inbound Gateway, which wires
  through the A2A adapter.
* :meth:`Mesherra.start_listener` — start the per-agent A2A HTTP listener.
  Requires :meth:`on_message` to have been called first.
* :meth:`Mesherra.get_residue_chain` / :meth:`get_residue` — retrieve
  provenance from the local ledger.
* :meth:`Mesherra.attest` — produce a signed attestation bundle for a
  completed task.

Phase 2/3 surface stays NotImplementedError:

* :meth:`register_principal` — Identity Directory ships in Phase 2.
* :meth:`verify` — AgentCard verification ships in Phase 2.
* :meth:`get_policy` / :meth:`update_policy` — Policy Engine ships in Phase 3.

Construct with explicit dependencies — Phase 1 is dependency-injection-first
so tests and the demo orchestrator can wire fake/synthetic components.
A higher-level factory (``Mesherra.from_config(env)``) will land when
ARCHITECTURE.md §13.5 (Identity Directory) is real in Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mesherra.a2a_adapter import A2AAdapter, ListenerHandle
from mesherra.crypto.primitives import Signer
from mesherra.gateways.inbound import (
    ConsumerHandler,
    InboundGateway,
)
from mesherra.gateways.outbound import OutboundGateway, OutboundResult
from mesherra.gateways.replay import ReplayProtector
from mesherra.models.primitives import Operation, Residue
from mesherra.provenance.ledger import ProvenanceLedger


@dataclass(frozen=True)
class AttestationBundle:
    """Signed attestation produced by :meth:`Mesherra.attest`.

    Phase 1 bundles the entries for a given task_id. Phase 2 will add a
    signature over the canonical bytes of the bundle so the recipient can
    verify the whole package as a unit.
    """

    task_id: str
    entries: list[Residue]


class Mesherra:
    """Public SDK surface. The consumer's single entry point into Mesherra.

    Each running agent process owns one Mesherra instance: their principal,
    their key, their ledger, their A2A listener. Multi-tenant servers
    (Phase 2+) will host multiple Mesherra instances behind a router.
    """

    def __init__(
        self,
        *,
        principal_id: str,
        signer: Signer,
        ledger: ProvenanceLedger,
        adapter: A2AAdapter,
        public_key_directory: dict[str, str],
        replay_protector: ReplayProtector | None = None,
    ) -> None:
        if ledger.ledger_owner != principal_id:
            raise ValueError(
                f"Ledger owner {ledger.ledger_owner!r} must match principal_id "
                f"{principal_id!r}; pointing two principals at one ledger is "
                "an unrecoverable state."
            )
        self._principal_id = principal_id
        self._signer = signer
        self._ledger = ledger
        self._adapter = adapter
        self._public_key_directory = dict(public_key_directory)
        # Phase 2 replay defense (ARCH §11.1). Consumers may inject a custom
        # ReplayProtector (typically for tests that need a controllable
        # clock); production usage falls through to MESHERRA_CLOCK_SKEW_SECONDS.
        self._replay_protector = replay_protector or ReplayProtector.from_env()
        self._outbound = OutboundGateway(
            principal_id=principal_id,
            signer=signer,
            ledger=ledger,
            adapter=adapter,
            public_key_directory=self._public_key_directory,
        )
        self._inbound = InboundGateway(
            principal_id=principal_id,
            signer=signer,
            ledger=ledger,
            public_key_directory=self._public_key_directory,
            replay_protector=self._replay_protector,
        )
        # Wire the inbound gateway into the adapter. No consumer is
        # registered yet; :meth:`on_message` does that.
        adapter.register_handler(self._inbound.handle_inbound)

    # -- properties -----------------------------------------------------

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def public_key_b64(self) -> str:
        """The base64 public key this principal publishes for peers.

        Phase 1: agent configs include this string in their public-key
        directory. Phase 2: the Identity Directory serves it.
        """
        return self._signer.public_key_b64()

    # -- outbound -------------------------------------------------------

    async def send_to(
        self,
        *,
        peer_url: str,
        peer_principal_id: str,
        payload: dict[str, Any],
        payload_schema: str,
        operation: Operation,
        context_id: str | None = None,
    ) -> OutboundResult:
        """Send a signed payload to a peer; record both residues; return result.

        See :class:`OutboundGateway` for the ordered pipeline. Phase 1 is
        request-response only; the result includes the A2A-assigned
        ``task_id`` so callers can issue subsequent operations on the same task.
        """
        return await self._outbound.send(
            peer_url=peer_url,
            peer_principal_id=peer_principal_id,
            payload=payload,
            payload_schema=payload_schema,
            operation=operation,
            context_id=context_id,
        )

    # -- inbound --------------------------------------------------------

    def on_message(self, handler: ConsumerHandler) -> None:
        """Register a consumer handler for inbound messages.

        The handler receives an :class:`IncomingMessage` and may return an
        :class:`OutgoingResponse` (request-response) or ``None``
        (fire-and-forget). Trust-layer concerns (verification, residue
        writes) are handled by the Inbound Gateway before the handler is
        invoked.
        """
        self._inbound.register_consumer(handler)

    async def start_listener(
        self,
        *,
        host: str,
        port: int,
        agent_name: str,
        agent_version: str = "0.1.0",
    ) -> ListenerHandle:
        """Boot the per-agent A2A HTTP listener.

        Thin pass-through to the adapter; named here so consumers don't
        need to reach into the adapter directly. Requires :meth:`on_message`
        to have been called first (the adapter enforces this).
        """
        return await self._adapter.start_listener(
            host=host,
            port=port,
            agent_name=agent_name,
            agent_version=agent_version,
        )

    # -- ledger accessors -----------------------------------------------

    def get_residue(self, task_id: str) -> list[Residue]:
        """Return all residue entries pertaining to ``task_id``."""
        return self._ledger.get_by_task(task_id)

    def get_residue_chain(self, context_id: str) -> list[Residue]:
        """Return the full ordered residue chain for ``context_id``.

        Includes both this principal's emit entries and receive entries
        for the conversation.
        """
        return self._ledger.get_by_context(context_id)

    def attest(self, task_id: str) -> AttestationBundle:
        """Produce a signed attestation for a completed task.

        Phase 1 returns the entries verbatim, bundled. Phase 2 will sign
        the bundle as a whole so a recipient can verify it as a unit.
        """
        entries = self._ledger.get_by_task(task_id)
        return AttestationBundle(task_id=task_id, entries=entries)

    # -- Phase 2/3 surface ---------------------------------------------

    def register_principal(self) -> None:
        raise NotImplementedError(
            "register_principal is implemented in Phase 2 (Identity Directory)."
        )

    def verify(self, agent_card: Any) -> Any:
        raise NotImplementedError(
            "verify is implemented in Phase 2 (AgentCard verification)."
        )

    def get_policy(self) -> Any:
        raise NotImplementedError(
            "get_policy is implemented in Phase 3 (Policy Engine)."
        )

    def update_policy(self, policy: Any) -> Any:
        raise NotImplementedError(
            "update_policy is implemented in Phase 3 (Policy Engine)."
        )
