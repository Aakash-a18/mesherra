"""Unit tests for the PolicyEngine.

Covers every code path of SPEC §2.2: default-deny, allow, allow_scoped,
block-by-empty, allow-list semantics, block-list semantics, max_array_size,
and the JCS-equality check that distinguishes ALLOW from ALLOW_SCOPED.
"""

from __future__ import annotations

import pytest

from mesherra.policy import Direction, Match, PolicyDoc, Rule
from mesherra.policy.engine import PolicyDecision, PolicyEngine, Verdict


SCHEMA = "meshycal.scheduling/proposal-v1"


def _policy(rules: list[Rule]) -> PolicyDoc:
    return PolicyDoc(
        principal_id="user-a@phase3.local",
        version=1,
        issued_at="2026-05-24T12:00:00Z",
        rules=rules,
    )


class TestDefaultDeny:
    def test_unmatched_schema_blocks(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema="other.thing/v1", direction=Direction.OUTBOUND),
                outbound_allow=["x"],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.BLOCK
        assert decision.matched_rule_count == 0
        assert "default-deny" in decision.reason.lower() or "no policy rule" in decision.reason.lower()

    def test_wrong_direction_doesnt_match(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.INBOUND),
                inbound_allow=["candidates"],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,  # rule is inbound
            policy=policy,
        )
        assert decision.verdict is Verdict.BLOCK

    def test_direction_both_matches_outbound(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.BOTH),
                outbound_allow=["candidates"],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW

    def test_direction_both_matches_inbound(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.BOTH),
                inbound_allow=["candidates"],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.INBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW


class TestAllowFastPath:
    def test_payload_untouched_by_block_list_returns_allow(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_block=["calendar_titles"],  # not in payload
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"], "duration_minutes": 30},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW
        assert decision.scoped_payload is None


class TestAllowScopedBlockList:
    def test_drops_top_level_blocked_field(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_block=["calendar_titles"],
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1"],
                "duration_minutes": 30,
                "calendar_titles": ["secret-mtg"],
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1"],
            "duration_minutes": 30,
        }

    def test_drops_nested_blocked_field_keeps_siblings(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_block=["constraint_hints.preferred_window"],
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1"],
                "constraint_hints": {
                    "tz": "America/New_York",
                    "preferred_window": {"start_hour": 9, "end_hour": 17},
                },
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1"],
            "constraint_hints": {"tz": "America/New_York"},
        }

    def test_block_input_payload_untouched(self) -> None:
        """The engine must not mutate the caller's payload."""
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_block=["calendar_titles"],
            )
        ])
        payload = {"candidates": ["t1"], "calendar_titles": ["x"]}
        engine.evaluate(
            payload=payload, payload_schema=SCHEMA,
            direction=Direction.OUTBOUND, policy=policy,
        )
        assert payload == {"candidates": ["t1"], "calendar_titles": ["x"]}


class TestAllowList:
    def test_keeps_only_listed_top_level(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "duration_minutes"],
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1"],
                "duration_minutes": 30,
                "calendar_titles": ["secret"],
                "attendee_emails": ["a@b"],
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1"],
            "duration_minutes": 30,
        }

    def test_top_level_allow_keeps_whole_subtree(self) -> None:
        """``constraint_hints`` on the allow-list keeps its entire subtree."""
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "constraint_hints"],
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1"],
                "constraint_hints": {
                    "tz": "America/New_York",
                    "preferred_window": {"start_hour": 9, "end_hour": 17},
                },
                "calendar_titles": ["x"],
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1"],
            "constraint_hints": {
                "tz": "America/New_York",
                "preferred_window": {"start_hour": 9, "end_hour": 17},
            },
        }

    def test_nested_allow_keeps_only_that_leaf(self) -> None:
        """``constraint_hints.tz`` allows only ``tz``, not siblings."""
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "constraint_hints.tz"],
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1"],
                "constraint_hints": {
                    "tz": "America/New_York",
                    "preferred_window": {"start_hour": 9, "end_hour": 17},
                },
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1"],
            "constraint_hints": {"tz": "America/New_York"},
        }

    def test_empty_allow_list_blocks(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=[],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.BLOCK
        assert "removed by policy" in decision.reason.lower()


class TestMaxArraySize:
    def test_truncates_oversize_array(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "duration_minutes"],
                max_array_size={"candidates": 2},
            )
        ])
        decision = engine.evaluate(
            payload={
                "candidates": ["t1", "t2", "t3", "t4"],
                "duration_minutes": 30,
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1", "t2"],
            "duration_minutes": 30,
        }

    def test_undersize_array_not_changed(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates"],
                max_array_size={"candidates": 5},
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1", "t2"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW


class TestInboundDirection:
    def test_inbound_block(self) -> None:
        engine = PolicyEngine()
        policy = _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.INBOUND),
                inbound_block=["tracking_id"],
            )
        ])
        decision = engine.evaluate(
            payload={"candidates": ["t1"], "tracking_id": "abc"},
            payload_schema=SCHEMA,
            direction=Direction.INBOUND,
            policy=policy,
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {"candidates": ["t1"]}


class TestEvaluationDirectionMustBeConcrete:
    def test_passing_both_raises(self) -> None:
        engine = PolicyEngine()
        with pytest.raises(ValueError):
            engine.evaluate(
                payload={},
                payload_schema=SCHEMA,
                direction=Direction.BOTH,
                policy=_policy([]),
            )


class TestMeshyCalDefaultPolicy:
    """End-to-end: the actual default policy template from SPEC §4 must
    behave per the demo's stated goal — strip titles/emails, keep
    candidates and the slim constraint_hints."""

    def _default(self) -> PolicyDoc:
        return _policy([
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "duration_minutes", "constraint_hints"],
                outbound_block=["calendar_titles", "attendee_emails"],
                max_array_size={"candidates": 5},
            ),
            Rule(
                match=Match(schema=SCHEMA, direction=Direction.INBOUND),
                inbound_allow=["candidates", "duration_minutes", "constraint_hints"],
            ),
        ])

    def test_full_payload_scoped_to_expected_subset(self) -> None:
        engine = PolicyEngine()
        decision = engine.evaluate(
            payload={
                "candidates": ["t1", "t2", "t3"],
                "duration_minutes": 30,
                "calendar_titles": ["sensitive-mtg"],
                "attendee_emails": ["a@b"],
                "constraint_hints": {"tz": "America/New_York"},
            },
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=self._default(),
        )
        assert decision.verdict is Verdict.ALLOW_SCOPED
        assert decision.scoped_payload == {
            "candidates": ["t1", "t2", "t3"],
            "duration_minutes": 30,
            "constraint_hints": {"tz": "America/New_York"},
        }

    def test_clean_payload_returns_allow(self) -> None:
        engine = PolicyEngine()
        decision = engine.evaluate(
            payload={"candidates": ["t1"], "duration_minutes": 30},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=self._default(),
        )
        assert decision.verdict is Verdict.ALLOW

    def test_decision_carries_match_count(self) -> None:
        engine = PolicyEngine()
        decision = engine.evaluate(
            payload={"candidates": ["t1"]},
            payload_schema=SCHEMA,
            direction=Direction.OUTBOUND,
            policy=self._default(),
        )
        assert decision.matched_rule_count == 1  # only the outbound rule
        assert isinstance(decision, PolicyDecision)
