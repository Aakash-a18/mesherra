"""Directory service runtime helpers.

Boot the Identity Directory's FastAPI app in-process via uvicorn, mirroring
the ``A2AAdapter.start_listener`` pattern. Demo orchestrators and integration
tests use this to bring up the directory inside the same Python process as
the agents that talk to it; production deployments would run the same
``create_app`` factory behind a dedicated uvicorn / gunicorn server.

Lifecycle:

    handle = await start_directory_listener(
        host="127.0.0.1",
        port=0,         # 0 → OS picks a free port; handle.port reports it
        store=store,
        signer=signer,
    )
    try:
        ... use the directory ...
    finally:
        await handle.stop()

The handle exposes ``url``, ``port`` (the actual bound port — useful when
``port=0`` was passed), and the ``serve_task`` for advanced lifecycle
management (mostly tests).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import uvicorn

from mesherra.crypto.primitives import Signer

from .server import DEFAULT_RECORD_TTL_SECONDS, create_app
from .store import DirectoryStore


@dataclass
class DirectoryListenerHandle:
    """Handle for a running Directory listener."""

    server: uvicorn.Server
    serve_task: asyncio.Task[None]
    host: str
    port: int

    @property
    def url(self) -> str:
        """Root URL clients should pass to ``HTTPDirectoryClient.base_url``."""
        return f"http://{self.host}:{self.port}"

    async def stop(self) -> None:
        """Signal graceful shutdown and await the server's exit."""
        self.server.should_exit = True
        try:
            await self.serve_task
        except asyncio.CancelledError:
            pass


async def start_directory_listener(
    *,
    host: str,
    port: int,
    store: DirectoryStore,
    signer: Signer,
    record_ttl_seconds: int = DEFAULT_RECORD_TTL_SECONDS,
) -> DirectoryListenerHandle:
    """Boot the Directory's FastAPI app on ``host:port``.

    Args:
        host: Bind address. ``127.0.0.1`` for local demos; ``0.0.0.0`` for
            container deployments.
        port: Bind port. ``0`` asks the OS to pick a free one; the handle's
            ``port`` attribute reports the actual port chosen.
        store: Caller-owned :class:`DirectoryStore`. The handle does NOT
            close this on stop — that's the caller's responsibility (same
            as ``A2AAdapter.start_listener``: lifecycle of injected
            resources stays with the caller).
        signer: The Directory's own Ed25519 signing key. Its public key is
            what HTTPDirectoryClient instances pin out-of-band.
        record_ttl_seconds: Validity window for each signed record. Default
            matches ``server.DEFAULT_RECORD_TTL_SECONDS`` (1 hour).

    Returns:
        :class:`DirectoryListenerHandle` once the server has bound the port.
    """
    app = create_app(
        store=store, signer=signer, record_ttl_seconds=record_ttl_seconds
    )
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        lifespan="on",
    )
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())
    await _wait_for_uvicorn_startup(server)
    return DirectoryListenerHandle(
        server=server,
        serve_task=serve_task,
        host=host,
        port=_resolve_bound_port(server, fallback=port),
    )


async def _wait_for_uvicorn_startup(
    server: uvicorn.Server, *, timeout: float = 5.0
) -> None:
    """Poll until uvicorn signals startup-complete.

    Mirrors the helper in ``a2a_adapter/adapter.py``. uvicorn sets
    ``server.started = True`` once the socket is bound and ready.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    while not server.started:
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError(
                f"uvicorn (directory) did not signal startup within {timeout}s"
            )
        await asyncio.sleep(0.01)


def _resolve_bound_port(server: uvicorn.Server, *, fallback: int) -> int:
    """Return the actual port uvicorn bound to.

    When ``port=0`` was requested the OS assigned a real port; uvicorn
    exposes it via the underlying socket. If the introspection fails for
    any reason, returns the originally-requested port as a best-effort
    fallback.
    """
    try:
        servers = getattr(server, "servers", None) or []
        for s in servers:
            for socket in getattr(s, "sockets", []):
                addr = socket.getsockname()
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return int(addr[1])
    except Exception:
        pass
    return fallback
