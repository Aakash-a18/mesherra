"""Unit tests for ReplayProtector (Phase 2 hardening per ARCH §11.1).

The ReplayProtector is the inbound gateway's defense against replays of
signature-valid captured envelopes. These tests pin down the two checks
in isolation, with a deterministic clock the tests can drive forward.

The integration-level proof (an end-to-end SDK round-trip where a
captured envelope is rejected on second arrival) lives in
``tests/integration/test_replay_defense.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mesherra.gateways.replay import (
    ReplayedNonceError,
    ReplayProtector,
    TimestampOutsideWindowError,
)


def _fixed_clock(t: datetime):
    """Return a callable that always reports ``t``."""

    def _now() -> datetime:
        return t

    return _now


class _MutableClock:
    """A clock the test can advance explicitly."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now = self._now + timedelta(seconds=seconds)


_T0 = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)


class TestConstruction:
    def test_zero_skew_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            ReplayProtector(clock_skew_seconds=0)

    def test_negative_skew_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            ReplayProtector(clock_skew_seconds=-1)

    def test_clock_skew_seconds_property(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=42)
        assert rp.clock_skew_seconds == 42


class TestFromEnv:
    def test_defaults_to_300_when_unset(self) -> None:
        rp = ReplayProtector.from_env(env={})
        assert rp.clock_skew_seconds == 300

    def test_reads_env_var(self) -> None:
        rp = ReplayProtector.from_env(env={"MESHERRA_CLOCK_SKEW_SECONDS": "120"})
        assert rp.clock_skew_seconds == 120

    def test_non_integer_value_fails_fast(self) -> None:
        with pytest.raises(ValueError, match="not an integer"):
            ReplayProtector.from_env(env={"MESHERRA_CLOCK_SKEW_SECONDS": "five"})

    def test_zero_value_fails_fast(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            ReplayProtector.from_env(env={"MESHERRA_CLOCK_SKEW_SECONDS": "0"})


class TestCheckTimestamp:
    def test_accepts_now(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_timestamp("2026-05-24T12:00:00Z")

    def test_accepts_within_window_past(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_timestamp("2026-05-24T11:59:01Z")

    def test_accepts_within_window_future(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_timestamp("2026-05-24T12:00:59Z")

    def test_accepts_exactly_at_window_edge(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_timestamp("2026-05-24T11:59:00Z")
        rp.check_timestamp("2026-05-24T12:01:00Z")

    def test_rejects_just_past_window(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        with pytest.raises(TimestampOutsideWindowError, match="from now"):
            rp.check_timestamp("2026-05-24T11:58:59Z")

    def test_rejects_far_past(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        with pytest.raises(TimestampOutsideWindowError):
            rp.check_timestamp("2020-01-01T00:00:00Z")

    def test_rejects_far_future(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        with pytest.raises(TimestampOutsideWindowError):
            rp.check_timestamp("2099-01-01T00:00:00Z")

    def test_unparseable_timestamp_rejected(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        with pytest.raises(TimestampOutsideWindowError, match="not parseable"):
            rp.check_timestamp("not a timestamp")

    def test_accepts_iso_with_microseconds(self) -> None:
        """If a future emitter uses isoformat() (which emits microseconds),
        the protector must still parse it. This is hedge against an
        invisible regression where the parser is too strict."""
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_timestamp("2026-05-24T12:00:00.123456Z")


class TestCheckAndRecordNonce:
    def test_first_observation_is_recorded(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        assert len(rp) == 1

    def test_replay_rejected(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        with pytest.raises(ReplayedNonceError, match="already observed"):
            rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")

    def test_different_nonce_same_sender_ok(self) -> None:
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-2")
        assert len(rp) == 2

    def test_same_nonce_different_sender_ok(self) -> None:
        """The seen-set is per-(sender, nonce) — two senders that happened to
        pick the same nonce string would not collide. Cosmically unlikely
        with UUID4 but the property is structural."""
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_and_record_nonce("user-a@phase1.local", "shared-nonce")
        rp.check_and_record_nonce("user-b@phase1.local", "shared-nonce")
        assert len(rp) == 2

    def test_seen_set_keys_on_byte_identical_string(self) -> None:
        """Aligner-flagged invariant: no normalization. 'NONCE-1' is a
        DIFFERENT nonce from 'nonce-1' because the SendClaim signs
        byte-identical bytes — if the protector normalized, an attacker
        could resend a flipped-case nonce, invalidate the signature, but
        the protector would not record it as a duplicate (the verification
        layer would catch the bad signature, but it's a layered-defense
        invariant we pin down here)."""
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=_fixed_clock(_T0))
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        rp.check_and_record_nonce("user-a@phase1.local", "NONCE-1")
        rp.check_and_record_nonce("user-a@phase1.local", " nonce-1")
        assert len(rp) == 3

    def test_pruning_evicts_old_entries(self) -> None:
        clock = _MutableClock(_T0)
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        assert len(rp) == 1
        # Advance past 2 × skew = 120s. The entry should be pruned on the
        # next operation that triggers _prune.
        clock.advance(121)
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-2")
        assert len(rp) == 1  # nonce-1 evicted

    def test_pruning_does_not_evict_within_window(self) -> None:
        clock = _MutableClock(_T0)
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        # Advance to just under 2 × skew. Entry should still be present.
        clock.advance(119)
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-2")
        assert len(rp) == 2

    def test_replay_after_eviction_succeeds(self) -> None:
        """Once a nonce has aged past 2 × skew, it can be re-recorded —
        this is correct because an envelope that old fails the timestamp
        check anyway, so the only way to land here is via a fresh send."""
        clock = _MutableClock(_T0)
        rp = ReplayProtector(clock_skew_seconds=60, now_fn=clock)
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        clock.advance(121)
        # No error — the nonce has been pruned out of the seen-set.
        rp.check_and_record_nonce("user-a@phase1.local", "nonce-1")
        assert len(rp) == 1
