"""Policy Engine.

Implements ARCHITECTURE.md section 13.4.

Stateless decision-maker. Given (request, current_policy, context),
returns a verdict.

Verdicts:
    allow         - pass the full payload
    allow_scoped  - pass a subset of the payload (engine specifies what)
    block         - refuse the interaction
    escalate      - surface to the user via A2A's INPUT_REQUIRED task state

Policy-version-aware: the engine validates against the version of policy the
user signed. Mismatches force re-signing rather than silent acceptance.

Status: scaffolding only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    ALLOW_SCOPED = "allow_scoped"
    BLOCK = "block"
    ESCALATE = "escalate"


class PolicyEngine:
    """Stateless policy decision-maker."""

    def __init__(self) -> None:
        raise NotImplementedError

    def evaluate(
        self,
        request: Any,
        policy: Any,
        context: dict[str, Any],
    ) -> tuple[Verdict, Any]:
        """Return (verdict, scoped_payload_or_reason)."""
        raise NotImplementedError
