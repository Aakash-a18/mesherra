"""Tesherra primitive models.

Per ARCHITECTURE.md section 3 (Core concepts).

Defines the core types: Agent, Object, Layer, Handshake, Policy, Residue, Promotion.

These are placeholders. Phase 1 firms up the Residue, Object, and minimal
Agent shapes (provenance vertical slice). Phase 2/3 develop the rest.

Status: scaffolding only. Field sets are illustrative, not final.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


# -- Layers ----------------------------------------------------------------


class LayerKind(str, Enum):
    """Default layer types per ARCHITECTURE.md section 3.3.

    Consumers / Delegations may define richer domain-specific layer types
    on top of these defaults; the primitive set is intentionally small.
    """

    PERSONAL = "personal"
    SHARED = "shared"
    PUBLIC = "public"


# -- Promotion modes & mutability -----------------------------------------


class PromotionMode(str, Enum):
    """Per ARCHITECTURE.md section 3.7."""

    REFERENCE = "reference"  # revocable handle, owner retains canonical state
    COPY = "copy"            # irrevocable bytes; conditions honor-system


class Mutability(str, Enum):
    """Per ARCHITECTURE.md section 3.2 and 3.7."""

    STATIC = "static"  # snapshot at promotion time; on-demand pull
    LIVE = "live"      # streamed updates via A2A SubscribeToTask


# -- Primitive model stubs -------------------------------------------------


class Agent:
    """A principal. Has identity, intent, authority, zone standing.

    See ARCHITECTURE.md section 3.1.
    """

    def __init__(self, principal_id: str, **kwargs: Any) -> None:
        raise NotImplementedError


class Object:
    """A passive resource (calendar, document, contract, etc.).

    Has owner, home layer, per-viewer layer-membership, type properties,
    residue. See ARCHITECTURE.md sections 3.2 and 3.7.

    NOT the same as A2A's Artifact (which is narrowly the output of a Task).
    """

    def __init__(self, object_id: str, owner: str, **kwargs: Any) -> None:
        raise NotImplementedError


class Layer:
    """A visibility zone. See ARCHITECTURE.md section 3.3."""

    def __init__(self, kind: LayerKind, **kwargs: Any) -> None:
        raise NotImplementedError


class Handshake:
    """A continuous, stateful trust negotiation between agents.

    Spans one or more A2A Tasks, tied together by context_id.
    See ARCHITECTURE.md section 3.4.
    """

    def __init__(self, context_id: str, **kwargs: Any) -> None:
        raise NotImplementedError


class Policy:
    """The user-authored constitution. Signed by the user.

    See ARCHITECTURE.md section 3.5.
    """

    def __init__(self, user_id: str, version: int, **kwargs: Any) -> None:
        raise NotImplementedError


class Residue:
    """Cryptographically signed, append-only trace.

    See ARCHITECTURE.md section 3.6.

    In v0, residue is primarily forensic (audit and dispute resolution).
    Preventive uses emerge in v1+ as the trust graph fills out.
    """

    def __init__(self, task_id: str, context_id: str, **kwargs: Any) -> None:
        raise NotImplementedError


class Promotion:
    """The act by which an owner changes an Object's layer-membership for
    a specific counterpart.

    See ARCHITECTURE.md sections 3.7 and CLAUDE.md vocabulary.

    A Promotion is a signed event that produces matching residue entries
    on both sides (owner records authorization; receiver records grant) and
    yields a PromotionHandle that is transmitted across the boundary.
    """

    def __init__(
        self,
        object_id: str,
        owner: str,
        receiver: str,
        mode: PromotionMode,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError


class PromotionHandle:
    """The wire-format artifact transmitted across the boundary by a Promotion.

    See ARCHITECTURE.md section 3.7 ("Object data flow across boundaries")
    for the full data-flow semantics.

    A PromotionHandle is what the receiver actually receives when an owner
    promotes an Object across a trust boundary. In *reference* mode the
    handle is all that crosses (the Object's state stays on the owner's side
    and is fetched on demand via fetch_endpoint). In *copy* mode the handle
    is accompanied by the scoped content as bytes, transmitted once and
    irrevocably held by the receiver.

    Encoding this commitment in the principal model from day one is what
    keeps the owner-is-canonical property visible across the system; without
    it, an implementer might accidentally introduce a shared-state pathway
    that the architecture explicitly forbids.

    Fields (per ARCHITECTURE.md section 3.7):
        object_id        — stable promotion identifier (UUID-style), assigned
                           once at promotion time, stable across the lifetime
                           of the promotion (including across live updates).
                           Distinct from content_hash.
        content_hash     — hash of the canonical representation at the current
                           state. Static promotions have one content_hash for
                           the lifetime; live promotions emit a new one per
                           update.
        schema_ref       — pointer to the published schema in the Schema
                           Registry (e.g., "meshycal.scheduling/proposal-v1").
        scope            — scope spec: which fields or slice the receiver
                           may see.
        mode             — PromotionMode.REFERENCE or PromotionMode.COPY.
        expiry           — ISO 8601 timestamp when the promotion auto-revokes.
        fetch_endpoint   — reference mode: owner's airlock URL where scoped
                           data is fetched on demand. None for copy mode.
        owner_signature  — owner's principal signature over the canonical
                           encoding of the handle.
        scoped_payload   — copy mode only: the actual scoped bytes,
                           canonical-encoded and signed. None for reference mode.

    Status: scaffolding only. Phase 2/3 implements promotion semantics; Phase 1
    only exercises this shape through provenance ledger entries that reference
    it.
    """

    def __init__(
        self,
        object_id: str,
        content_hash: bytes,
        schema_ref: str,
        scope: dict[str, Any],
        mode: PromotionMode,
        expiry: str,
        owner_signature: bytes,
        fetch_endpoint: str | None = None,
        scoped_payload: bytes | None = None,
    ) -> None:
        raise NotImplementedError
