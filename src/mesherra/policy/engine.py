"""Policy Engine.

Implements ARCHITECTURE.md §13.4 and demos/phase_3/SPEC.md §2.2.

Stateless decision-maker. Given ``(payload, payload_schema, direction,
policy)``, returns a :class:`PolicyDecision` carrying a :class:`Verdict`
plus, for ``ALLOW_SCOPED``, the post-scoping payload that should actually
cross the airlock.

The engine has no I/O and no clock — every dependency comes in via the
:meth:`evaluate` call, which keeps it pure and trivially testable.

Verdict semantics (SPEC §2.2 step 4):

* No matching rule for the (schema, direction) → ``BLOCK`` (default-deny).
* Working payload JCS-equal to input  → ``ALLOW``.
* Working payload is the empty dict   → ``BLOCK``.
* Otherwise                           → ``ALLOW_SCOPED``.

The engine never returns ``ESCALATE`` in v1; that verdict is reserved for
future conditional rule types. The gateways still handle ``ESCALATE``
defensively (treating it like ``BLOCK``) so a future engine producing it
fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from mesherra.crypto.primitives import canonical_json

from .models import Direction, PolicyDoc, Rule


class Verdict(str, Enum):
    ALLOW = "allow"
    ALLOW_SCOPED = "allow_scoped"
    BLOCK = "block"
    ESCALATE = "escalate"  # reserved for future conditional rules


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of one engine evaluation.

    Fields:

    * ``verdict`` — one of the four :class:`Verdict` values.
    * ``scoped_payload`` — for ``ALLOW_SCOPED``, the payload after scoping
      (a *new* dict; the input is never mutated). ``None`` for any other
      verdict.
    * ``reason`` — human-readable explanation for ``BLOCK`` /
      ``ESCALATE``. Used by gateways to populate exception messages so
      operators can see *why* a send was refused.
    * ``matched_rule_count`` — for debuggability: how many rules in the
      doc matched this (schema, direction). Zero means default-deny took
      effect.
    """

    verdict: Verdict
    scoped_payload: dict[str, Any] | None = None
    reason: str = ""
    matched_rule_count: int = 0


class PolicyEngine:
    """Stateless policy decision-maker.

    Construct once and reuse — no per-call state, no caching, no I/O. Each
    :meth:`evaluate` call returns a fresh :class:`PolicyDecision`.
    """

    def evaluate(
        self,
        *,
        payload: dict[str, Any],
        payload_schema: str,
        direction: Direction,
        policy: PolicyDoc,
    ) -> PolicyDecision:
        """Decide what to do with ``payload`` under ``policy``.

        ``direction`` must be :attr:`Direction.OUTBOUND` or
        :attr:`Direction.INBOUND`. The :attr:`Direction.BOTH` value is a
        rule-side wildcard, not an evaluation direction.
        """
        if direction not in (Direction.OUTBOUND, Direction.INBOUND):
            raise ValueError(
                f"evaluate() direction must be OUTBOUND or INBOUND; got "
                f"{direction!r}. (BOTH is a rule-side wildcard, not an "
                "evaluation direction.)"
            )

        matched = [
            r
            for r in policy.rules
            if r.match.schema_uri == payload_schema
            and r.match.direction in (direction, Direction.BOTH)
        ]
        if not matched:
            return PolicyDecision(
                verdict=Verdict.BLOCK,
                reason=(
                    f"No policy rule matches (schema={payload_schema!r}, "
                    f"direction={direction.value}). Default-deny: a schema "
                    "not named in policy is refused per ARCH §4.2."
                ),
                matched_rule_count=0,
            )

        working: dict[str, Any] = _deep_copy(payload)
        for rule in matched:
            working = _apply_rule(working, rule, direction)

        # JCS-canonical equality (SPEC §2.2 step 4).
        if canonical_json(working) == canonical_json(payload):
            return PolicyDecision(
                verdict=Verdict.ALLOW,
                matched_rule_count=len(matched),
            )
        if not working:
            return PolicyDecision(
                verdict=Verdict.BLOCK,
                reason=(
                    f"All fields removed by policy (schema={payload_schema!r}, "
                    f"direction={direction.value}, {len(matched)} rule(s) matched)."
                ),
                matched_rule_count=len(matched),
            )
        return PolicyDecision(
            verdict=Verdict.ALLOW_SCOPED,
            scoped_payload=working,
            matched_rule_count=len(matched),
        )


# -- Rule application helpers --------------------------------------------


def _apply_rule(
    payload: dict[str, Any], rule: Rule, direction: Direction
) -> dict[str, Any]:
    """Apply one rule's allow/block/max_array_size to ``payload``.

    Order: allow-list filter (if present) → block-list drop → array caps.
    The order is irrelevant for set semantics but is fixed here for
    determinism so the test suite can predict intermediate states.
    """
    if direction is Direction.OUTBOUND:
        allow = rule.outbound_allow
        block = rule.outbound_block
    else:
        allow = rule.inbound_allow
        block = rule.inbound_block

    out = payload
    if allow is not None:
        out = _apply_allow_list(out, allow)
    if block:
        out = _apply_block_list(out, block)
    if rule.max_array_size:
        out = _apply_max_array_size(out, rule.max_array_size)
    return out


def _apply_allow_list(
    payload: dict[str, Any], allow: list[str]
) -> dict[str, Any]:
    """Keep only paths in ``allow``. Allow-list semantics from SPEC §2.2:

    * An allowed path that names a top-level key keeps that whole subtree.
    * An allowed nested path keeps only that nested key (siblings dropped).
    * Anything not on the list is removed.
    """
    out: dict[str, Any] = {}
    for path in allow:
        value = _read_path(payload, path)
        if value is not _MISSING:
            _write_path(out, path, value)
    return out


def _apply_block_list(
    payload: dict[str, Any], block: list[str]
) -> dict[str, Any]:
    """Drop every listed path from ``payload`` (returns a new dict)."""
    out = _deep_copy(payload)
    for path in block:
        _drop_path(out, path)
    return out


def _apply_max_array_size(
    payload: dict[str, Any], caps: dict[str, int]
) -> dict[str, Any]:
    """Truncate arrays at the given paths to the listed maxima."""
    out = _deep_copy(payload)
    for path, cap in caps.items():
        value = _read_path(out, path)
        if isinstance(value, list) and len(value) > cap:
            _write_path(out, path, value[:cap])
    return out


# -- Path primitives -----------------------------------------------------

_MISSING = object()


def _split_path(path: str) -> list[str]:
    return path.split(".")


def _read_path(payload: dict[str, Any], path: str) -> Any:
    """Return the value at ``path`` or :data:`_MISSING` if absent / wrong type."""
    cur: Any = payload
    for seg in _split_path(path):
        if not isinstance(cur, dict) or seg not in cur:
            return _MISSING
        cur = cur[seg]
    return cur


def _write_path(payload: dict[str, Any], path: str, value: Any) -> None:
    """Write ``value`` at ``path``, creating intermediate dicts as needed.

    A pre-existing non-dict on the intermediate path is overwritten — this
    only happens when the caller is constructing a fresh payload (e.g.,
    in :func:`_apply_allow_list`), where intermediates are guaranteed-empty.
    """
    segs = _split_path(path)
    cur: dict[str, Any] = payload
    for seg in segs[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[segs[-1]] = value


def _drop_path(payload: dict[str, Any], path: str) -> None:
    """Remove the leaf at ``path``. No-op if absent.

    Empty parent dicts are intentionally kept (SPEC §2.2 step 4: nested
    paths drop only the leaf; siblings — including a now-empty parent
    object — are not implicitly dropped).
    """
    segs = _split_path(path)
    cur: Any = payload
    for seg in segs[:-1]:
        if not isinstance(cur, dict) or seg not in cur:
            return
        cur = cur[seg]
    if isinstance(cur, dict):
        cur.pop(segs[-1], None)


def _deep_copy(payload: dict[str, Any]) -> dict[str, Any]:
    """Cheap deep copy via JSON round-trip; payloads are JSON-shaped by
    contract (proposal schemas, etc.), so this preserves them faithfully."""
    import json as _json
    return _json.loads(_json.dumps(payload))
