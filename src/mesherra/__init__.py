"""Mesherra: trust layer for agent-to-agent (A2A) interaction.

Public surface lives in ``mesherra.sdk``. Internal components match the
component inventory in ``docs/ARCHITECTURE.md`` section 13. Consumers
(MeshyCal and future Delegations) should import ``Mesherra`` and
``AttestationBundle`` from this top-level package; everything else stays
internal.

Status: pre-alpha. Methods not yet implemented raise ``NotImplementedError``;
see :class:`mesherra.sdk.Mesherra` for the current phase's surface and
what remains unimplemented (the authoritative list lives there, so it
can't drift from the code).
"""

from __future__ import annotations

from mesherra.sdk import AttestationBundle, Mesherra

__version__ = "0.0.1"

__all__ = ["AttestationBundle", "Mesherra", "__version__"]
