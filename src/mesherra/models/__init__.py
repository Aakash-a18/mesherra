"""Mesherra primitive models: Agent, Object, Layer, Handshake, Policy, Residue, Promotion.

Per ARCHITECTURE.md section 3 (Core concepts) and section 3.7 (Object data flow).

These are the principal model — the source of truth for the system's conceptual
shape. The mobile/web/voice/AR renderer is disposable; this model is not.
"""

from __future__ import annotations
