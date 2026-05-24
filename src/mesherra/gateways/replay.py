"""Replay defense for the inbound gateway (Phase 2 hardening per ARCH §11.1).

Two cooperating checks the inbound gateway runs against every signature-verified
inbound envelope:

1. **Clock-skew window** — parse the SendClaim's ``timestamp`` and reject if
   it lies outside ``now ± clock_skew_seconds``. Phase 1 carried timestamps
   but did not enforce a window; ARCH §11.1 flagged that as the cheapest
   replay vector to close.
2. **(sender_principal_id, nonce) seen-set** — an in-process TTL-pruned set
   of pairs the gateway has already accepted from this principal. A replay
   of a captured envelope (same nonce, same sender, valid signature) is
   rejected on the second arrival. The seen-set lives for ``2 ×
   clock_skew_seconds`` after first observation, which is the worst-case
   lifetime a captured envelope can still pass the timestamp check: a
   legit send with timestamp ``t`` observed at ``t - skew`` (earliest)
   could be replayed up to ``t + skew`` (latest), i.e. up to ``2·skew``
   after first observation. Pruning at exactly ``2·skew`` is the tight
   bound — shorter would create a false-accept gap; longer is safe but
   wastes memory.

Key invariants (the aligner's load-bearing constraints from sub-step 1):

* The seen-set keys on the **byte-identical** nonce string from
  ``envelope.nonce``. Any normalization (case fold, base64-decode, hyphen
  strip) would break the property that "what was signed equals what is
  remembered" — an attacker could otherwise alter case on the wire,
  invalidate the signature, but the protector would dedupe on a
  normalized form. The current implementation does no normalization;
  whoever changes that must restore signature-bytes-match.
* The seen-set is keyed on ``(sender_principal_id, nonce)``, never on
  nonce alone. Two different principals colliding on UUID4 nonces is
  cosmically unlikely, but the per-principal scoping makes that
  property structural rather than probabilistic and prevents one
  principal's traffic from influencing another's accept/reject decisions.

The ``ReplayProtector`` is dependency-injected into the inbound gateway so
tests can wire a controllable clock. The Mesherra SDK constructs a default
one from ``MESHERRA_CLOCK_SKEW_SECONDS`` at startup (see ``sdk.py``).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta


class TimestampOutsideWindowError(Exception):
    """The SendClaim's timestamp lies outside the configured skew window.

    Raised by the inbound gateway after SendClaim signature verification
    succeeds but before the envelope is delivered to the consumer. The
    A2A response surfaces this as an authentication-style rejection.
    """


class ReplayedNonceError(Exception):
    """The (sender_principal_id, nonce) pair has already been observed.

    Raised by the inbound gateway when a captured envelope is re-delivered
    within the window where its timestamp would still pass the skew check.
    The first arrival was accepted and recorded; this is the duplicate.
    """


_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
)


def _parse_iso8601_utc(s: str) -> datetime:
    """Parse the ISO-8601 timestamps produced by ``_utc_now_iso`` in the gateways.

    Phase 1 emits ``YYYY-MM-DDTHH:MM:SSZ`` (no fractional seconds). We also
    accept fractional-second forms so that any future emitter that uses
    ``isoformat()`` (which emits microseconds) interoperates without an
    invisible regression. Anything else raises ``ValueError`` — the inbound
    gateway promotes that to ``TimestampOutsideWindowError`` because a
    timestamp it cannot parse is, for window-checking purposes, outside the
    window.
    """
    last_error: Exception | None = None
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError as e:
            last_error = e
    raise ValueError(f"Could not parse timestamp {s!r}") from last_error


class ReplayProtector:
    """Phase 2 replay defense: clock-skew check + per-principal nonce cache.

    Construct with an explicit ``clock_skew_seconds`` and (optional)
    ``now_fn`` for deterministic tests. In production, the Mesherra SDK
    reads the configuration from the environment and injects a default
    instance into the inbound gateway.

    Thread-safety: not safe across threads. Phase 1's gateway pipeline is
    single-async-task per inbound message (the A2A adapter awaits one
    handler at a time), so all access serializes. Phase 2+ multi-tenant
    servers must add a lock or move the seen-set to a shared store.
    """

    def __init__(
        self,
        *,
        clock_skew_seconds: int,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if clock_skew_seconds <= 0:
            raise ValueError(
                f"clock_skew_seconds must be positive, got {clock_skew_seconds}"
            )
        self._skew = timedelta(seconds=clock_skew_seconds)
        self._now_fn: Callable[[], datetime] = now_fn or (lambda: datetime.now(UTC))
        # (sender_principal_id, nonce) -> seen_at
        self._seen: dict[tuple[str, str], datetime] = {}

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ReplayProtector:
        """Construct from ``MESHERRA_CLOCK_SKEW_SECONDS`` in the environment.

        Defaults to 300 seconds if unset, matching ``.env.example``. Raises
        ``ValueError`` if the env var is set to a non-integer or non-positive
        value — fail-fast at startup beats silent defaults.
        """
        source = env if env is not None else os.environ
        raw = source.get("MESHERRA_CLOCK_SKEW_SECONDS", "300")
        try:
            skew = int(raw)
        except ValueError as e:
            raise ValueError(
                f"MESHERRA_CLOCK_SKEW_SECONDS={raw!r} is not an integer"
            ) from e
        return cls(clock_skew_seconds=skew)

    @property
    def clock_skew_seconds(self) -> int:
        return int(self._skew.total_seconds())

    def check_timestamp(self, timestamp_iso: str) -> None:
        """Validate that ``timestamp_iso`` is within the skew window of "now".

        Raises ``TimestampOutsideWindowError`` if outside the window or if
        the value cannot be parsed as ISO-8601 UTC.
        """
        try:
            ts = _parse_iso8601_utc(timestamp_iso)
        except ValueError as e:
            raise TimestampOutsideWindowError(
                f"Timestamp {timestamp_iso!r} is not parseable as ISO-8601 UTC; "
                "treating as outside the clock-skew window."
            ) from e
        now = self._now_fn()
        delta = abs(now - ts)
        if delta > self._skew:
            raise TimestampOutsideWindowError(
                f"Timestamp {timestamp_iso!r} is {delta.total_seconds():.1f}s "
                f"from now (limit: {self._skew.total_seconds():.0f}s). "
                "Possible replay or significant clock skew."
            )

    def check_and_record_nonce(self, sender_principal_id: str, nonce: str) -> None:
        """Record ``(sender_principal_id, nonce)`` as observed, or raise.

        Prunes expired entries first (anything older than ``2 × skew``
        from "now") so the seen-set does not grow without bound. If the
        pair has been observed within that window, raises
        ``ReplayedNonceError``.

        Mutates state — only call this after every other inbound check has
        passed (signature verification, timestamp window). Otherwise an
        attacker who can produce unsigned envelopes could fill the
        seen-set; the SendClaim signature is the gate that proves an
        envelope is worth remembering.
        """
        self._prune()
        key = (sender_principal_id, nonce)
        if key in self._seen:
            raise ReplayedNonceError(
                f"Nonce {nonce!r} from principal {sender_principal_id!r} was "
                "already observed within the replay-defense window. The "
                "first arrival was accepted; this is the duplicate."
            )
        self._seen[key] = self._now_fn()

    def _prune(self) -> None:
        cutoff = self._now_fn() - 2 * self._skew
        expired = [k for k, seen_at in self._seen.items() if seen_at < cutoff]
        for k in expired:
            del self._seen[k]

    def __len__(self) -> int:
        return len(self._seen)
