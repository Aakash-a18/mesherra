"""Mesherra A2A SDK adapter.

Per ARCHITECTURE.md §13.10. The ONLY module in Mesherra that imports
``a2a-sdk``. Strict isolation: other Mesherra modules import from here,
not from ``a2a.*``.

Public API:

* :class:`MesherraEnvelope` — the boundary type used by the rest of Mesherra
* :class:`A2AAdapter` — the wire bridge (send_envelope, register_handler,
  start_listener)
* :class:`InboundHandler` — Protocol for the receive callback
* :class:`ListenerHandle` — graceful shutdown handle for a running listener
* :class:`WireFormatError` — raised when an inbound A2A message can't be
  parsed into a MesherraEnvelope
"""

from .adapter import A2AAdapter, InboundHandler, ListenerHandle
from .envelope import MesherraEnvelope
from .wire import WireFormatError

__all__ = [
    "A2AAdapter",
    "InboundHandler",
    "ListenerHandle",
    "MesherraEnvelope",
    "WireFormatError",
]
