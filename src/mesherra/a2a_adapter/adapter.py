"""A2AAdapter — the single bridge between Mesherra and a2a-sdk.

Per ARCHITECTURE.md §13.10. This module is the ONLY place in Mesherra that
imports the a2a-sdk client/server framework. All other Mesherra modules
operate on :class:`MesherraEnvelope` instances (defined in ``envelope.py``)
and use the Protocol contracts (defined here) — they never touch
``a2a.types.*``, ``a2a.client.*``, or ``a2a.server.*``.

Phase 1 surface:

* :class:`A2AAdapter.send_envelope` — outbound; wraps ``a2a.client.Client.send_message``.
* :class:`A2AAdapter.register_handler` — installs the inbound callback.
* :class:`A2AAdapter.start_listener` — boots a per-agent HTTP server using
  the a2a-sdk's request handler + JSON-RPC routes + Starlette + uvicorn.
* :class:`A2AAdapter.subscribe_to_task` — Phase 2/3, NotImplementedError.

Server location is per-agent process (ARCHITECTURE.md §13.10): each running
agent calls ``await adapter.start_listener(host, port)`` to serve its own
A2A endpoint. There is no central listener.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Protocol

import uvicorn
from a2a.client import create_client
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandlerV2
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    Message,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils import TransportProtocol
from starlette.applications import Starlette

from .envelope import MesherraEnvelope
from .wire import a2a_message_to_envelope, envelope_to_a2a_message

# -- Protocol contracts (consumed by the Inbound Gateway) ----------------


class InboundHandler(Protocol):
    """The callback the adapter invokes when a Message arrives on the wire.

    Per ARCHITECTURE.md §13.10: the adapter delivers RAW envelopes; no trust
    decisions are made here. The Inbound Gateway (§13.3) is the next layer
    up and owns verification / policy / ledger writes. Consumers register
    with the Gateway, not directly with the adapter.

    Return contract:

    * ``None`` — fire-and-forget; the adapter completes the A2A task with no
      response message.
    * a :class:`MesherraEnvelope` — the adapter wraps it in an A2A response
      Message on the same task and emits it before completing.
    """

    async def __call__(
        self, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        ...


# -- Listener handle ----------------------------------------------------


@dataclass
class ListenerHandle:
    """Handle for a running A2A listener. Use :meth:`stop` for graceful shutdown.

    Returned by :meth:`A2AAdapter.start_listener`. Holds the uvicorn server
    and the task running it so callers can shut down cleanly.
    """

    server: uvicorn.Server
    serve_task: asyncio.Task[None]

    async def stop(self) -> None:
        """Signal graceful shutdown and await the server's exit."""
        self.server.should_exit = True
        try:
            await self.serve_task
        except asyncio.CancelledError:
            pass


# -- A2AAdapter --------------------------------------------------------


class A2AAdapter:
    """The single bridge between Mesherra and a2a-sdk.

    Instances are stateful: they hold a registered :class:`InboundHandler`
    (set via :meth:`register_handler`) and, while a listener is running,
    the listener's uvicorn server. One adapter per agent process.

    The adapter does not sign, verify, or write residue — those concerns
    live in the Inbound Gateway (§13.3) and the SDK (§13.1). The adapter
    only translates wire types and runs the HTTP layer.
    """

    def __init__(self) -> None:
        self._handler: InboundHandler | None = None

    # -- inbound side (server) ------------------------------------------

    def register_handler(self, handler: InboundHandler) -> None:
        """Register the callback invoked when a Message arrives.

        Calling twice replaces the previous handler. There is one handler
        per adapter; the Inbound Gateway is expected to fan-out internally
        if multiple consumers need notification.
        """
        self._handler = handler

    async def start_listener(
        self,
        *,
        host: str,
        port: int,
        agent_name: str,
        agent_version: str = "0.1.0",
    ) -> ListenerHandle:
        """Boot a per-agent A2A HTTP listener on ``host:port``.

        Requires :meth:`register_handler` to have been called first; raises
        RuntimeError otherwise. The listener serves:

        * ``GET /.well-known/agent-card.json`` — minimal AgentCard
        * ``POST /`` — JSON-RPC entry point for ``message/send`` etc.

        Returns immediately once the server has bound the port; the
        returned :class:`ListenerHandle` provides graceful shutdown.
        """
        if self._handler is None:
            raise RuntimeError(
                "Call register_handler(...) before start_listener(...)."
            )

        agent_card = _minimal_agent_card(
            name=agent_name,
            version=agent_version,
            url=f"http://{host}:{port}/",
        )
        executor = _MesherraAgentExecutor(handler=self._handler)
        task_store = InMemoryTaskStore()
        request_handler = DefaultRequestHandlerV2(
            agent_executor=executor,
            task_store=task_store,
            agent_card=agent_card,
        )
        routes: list = []
        routes.extend(create_agent_card_routes(agent_card=agent_card))
        routes.extend(
            create_jsonrpc_routes(request_handler=request_handler, rpc_url="/")
        )
        app = Starlette(routes=routes)
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level="warning",
            lifespan="off",
        )
        server = uvicorn.Server(config)
        serve_task = asyncio.create_task(server.serve())
        await _wait_for_uvicorn_startup(server)
        return ListenerHandle(server=server, serve_task=serve_task)

    # -- outbound side (client) -----------------------------------------

    async def send_envelope(
        self, *, peer_url: str, envelope: MesherraEnvelope
    ) -> MesherraEnvelope | None:
        """Send envelope to ``peer_url``; await peer's response envelope.

        Returns the response envelope if the peer produced one, or ``None``
        if the peer's handler returned ``None`` (fire-and-forget). Raises
        :class:`mesherra.a2a_adapter.wire.WireFormatError` if the peer's
        response message is malformed.
        """
        outbound_message = envelope_to_a2a_message(
            envelope, message_id=str(uuid.uuid4())
        )
        request = SendMessageRequest(message=outbound_message)
        client = await create_client(peer_url)
        try:
            response_message = await _collect_response_message(
                client.send_message(request)
            )
        finally:
            await client.close()
        if response_message is None:
            return None
        return a2a_message_to_envelope(response_message)

    # -- Phase 2/3 surface ---------------------------------------------

    async def subscribe_to_task(self, task_id: str):
        """Stream task state updates. Phase 2/3."""
        raise NotImplementedError(
            "subscribe_to_task is implemented in Phase 2/3 (streaming + "
            "long-lived handshakes)."
        )


# -- internals ---------------------------------------------------------


class _MesherraAgentExecutor(AgentExecutor):
    """Wraps a Mesherra :class:`InboundHandler` as an a2a-sdk AgentExecutor.

    The framework calls :meth:`execute` once per inbound task. We:

    1. Convert the inbound A2A Message to a MesherraEnvelope.
    2. Invoke the registered handler.
    3. If the handler returned a response envelope, emit it as the task's
       agent-message and mark the task complete.
    4. If the handler returned None, mark the task complete with no message.

    Exceptions raised by the handler propagate; the framework converts them
    to ``TASK_STATE_ERROR`` per A2A semantics.
    """

    def __init__(self, *, handler: InboundHandler) -> None:
        self._handler = handler

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        inbound_envelope = a2a_message_to_envelope(context.message)

        task_id = context.task_id or context.message.task_id
        context_id = context.context_id or context.message.context_id

        # Phase 1 uses task-mode (the SDK's documented "asynchronous/long-
        # running" AgentExecutor workflow): enqueue a Task object first to
        # satisfy the framework's _task_created guard, then use TaskUpdater
        # for state transitions ending in complete(message=). Message-mode
        # (single Message in queue, no Task) is the SDK's other documented
        # workflow but it is structurally incompatible with TaskUpdater —
        # not a version bug.
        initial_task = Task(
            id=task_id,
            context_id=context_id,
            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
        )
        await event_queue.enqueue_event(initial_task)

        updater = TaskUpdater(
            event_queue=event_queue,
            task_id=task_id,
            context_id=context_id,
        )
        await updater.start_work()

        response_envelope = await self._handler(inbound_envelope)

        if response_envelope is not None:
            response_message = envelope_to_a2a_message(
                response_envelope, message_id=str(uuid.uuid4())
            )
            await updater.complete(message=response_message)
        else:
            await updater.complete()

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # Phase 1 does not implement cancellation. The framework calls this
        # when a client requests cancel; we publish a CANCELED status so the
        # task transitions cleanly per the AgentExecutor contract.
        task_id = context.task_id or ""
        context_id = context.context_id or ""
        updater = TaskUpdater(
            event_queue=event_queue, task_id=task_id, context_id=context_id
        )
        await updater.cancel()


def _minimal_agent_card(*, name: str, version: str, url: str) -> AgentCard:
    """Construct the minimal AgentCard required to boot a listener.

    Phase 1 publishes:

    * Name, description, version (display only).
    * Capabilities (streaming/push disabled; Phase 1 is request-response only).
    * One AgentInterface declaring JSON-RPC at ``url``. Without at least one
      supported_interface entry, an a2a client cannot select a transport and
      ``send_message`` raises ``no compatible transports found``.

    Phase 2 will add signed AgentCards with skill definitions, security
    schemes, and additional supported transports per the AgentCard
    verification flow.
    """
    return AgentCard(
        name=name,
        description=f"Mesherra-wrapped agent: {name}",
        version=version,
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        supported_interfaces=[
            AgentInterface(url=url, protocol_binding=TransportProtocol.JSONRPC.value),
        ],
    )


async def _wait_for_uvicorn_startup(
    server: uvicorn.Server, *, timeout: float = 5.0
) -> None:
    """Poll until uvicorn signals startup-complete, or raise TimeoutError.

    uvicorn sets ``server.started = True`` once all servers (i.e., the bound
    socket) are accepting connections. Without this wait, a caller of
    ``start_listener`` might race ahead and try to ``send_envelope`` to a
    port that isn't yet open.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    while not server.started:
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError(
                f"uvicorn server did not signal startup within {timeout}s"
            )
        await asyncio.sleep(0.02)


async def _collect_response_message(stream) -> Message | None:
    """Consume a ``Client.send_message`` stream and return the response Message.

    The SDK's ``send_message`` returns an ``AsyncIterator[StreamResponse]``.
    Each StreamResponse has a oneof payload: task, message, status_update,
    or artifact_update. The non-streaming aggregation typically collapses
    everything into a single ``task`` payload whose ``status.message`` holds
    the agent's response. We also handle the streaming-event shapes
    (``message``, ``status_update``) defensively so a future server that
    emits separate events still works.

    Returns None if the stream completes without surfacing a response
    Message anywhere (fire-and-forget — the peer's handler returned None).
    """
    # Phase 1's listener publishes capabilities.streaming=False, so the
    # client aggregates the conversation into a single ``task`` payload
    # and the ``status_update`` branch below is dead. We keep it for
    # forward-compatibility with Phase 2 streaming.
    async for stream_response in stream:
        if stream_response.HasField("message"):
            return stream_response.message
        if stream_response.HasField("status_update"):
            status = stream_response.status_update.status
            if status.HasField("message"):
                return status.message
        if stream_response.HasField("task"):
            task = stream_response.task
            if task.HasField("status") and task.status.HasField("message"):
                return task.status.message
    return None
