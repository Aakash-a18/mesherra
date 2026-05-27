"""Unit tests for the Layer Pydantic model.

Covers Phase 4 Slice 1 step 2 (Models) per demos/phase_4/SPEC.md section 3.

Layer is a value type — the computed answer to "who can see this Object right
now," not a stored entity. The model is frozen, the members are a frozenset
(order-independent equality), and ``is_visible_to(principal)`` is the single
behavioral operation.

Visibility rules (per SPEC §3):
- personal: only the explicit members (typically just the owner)
- shared:   only the explicit members
- public:   any principal (members may be empty)
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mesherra.models.primitives import Layer, LayerKind


class TestConstruction:
    def test_personal_layer_constructs(self) -> None:
        layer = Layer(kind=LayerKind.PERSONAL, members=frozenset(["alice"]))
        assert layer.kind is LayerKind.PERSONAL
        assert layer.members == frozenset(["alice"])

    def test_shared_layer_with_multiple_members(self) -> None:
        layer = Layer(
            kind=LayerKind.SHARED, members=frozenset(["alice", "bob", "carol"])
        )
        assert layer.kind is LayerKind.SHARED
        assert layer.members == frozenset(["alice", "bob", "carol"])

    def test_public_layer_with_empty_members(self) -> None:
        # SPEC §3 visibility table: public + empty members → any principal.
        layer = Layer(kind=LayerKind.PUBLIC, members=frozenset())
        assert layer.kind is LayerKind.PUBLIC
        assert layer.members == frozenset()

    def test_members_accepts_list_input(self) -> None:
        # Convenience: callers usually pass a list; Pydantic should coerce.
        layer = Layer(kind=LayerKind.SHARED, members=["alice", "bob"])  # type: ignore[arg-type]
        assert layer.members == frozenset(["alice", "bob"])

    def test_member_order_independent_equality(self) -> None:
        a = Layer(kind=LayerKind.SHARED, members=frozenset(["alice", "bob"]))
        b = Layer(kind=LayerKind.SHARED, members=frozenset(["bob", "alice"]))
        assert a == b

    def test_layer_is_frozen(self) -> None:
        layer = Layer(kind=LayerKind.PERSONAL, members=frozenset(["alice"]))
        with pytest.raises(ValidationError):
            layer.kind = LayerKind.PUBLIC  # type: ignore[misc]


class TestValidation:
    @pytest.mark.parametrize(
        "bad_kind",
        ["not-a-layer", "PERSONAL", "personal_", "", "  "],
    )
    def test_rejects_invalid_kind(self, bad_kind: Any) -> None:
        with pytest.raises(ValidationError):
            Layer(kind=bad_kind, members=frozenset())

    def test_rejects_empty_member_string(self) -> None:
        with pytest.raises(ValidationError):
            Layer(kind=LayerKind.SHARED, members=frozenset(["alice", ""]))

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            Layer(
                kind=LayerKind.PERSONAL,
                members=frozenset(["alice"]),
                unknown_field="value",  # type: ignore[call-arg]
            )


class TestVisibility:
    def test_personal_layer_visible_only_to_members(self) -> None:
        layer = Layer(kind=LayerKind.PERSONAL, members=frozenset(["alice"]))
        assert layer.is_visible_to("alice") is True
        assert layer.is_visible_to("bob") is False
        assert layer.is_visible_to("eve") is False

    def test_shared_layer_visible_to_all_members(self) -> None:
        layer = Layer(kind=LayerKind.SHARED, members=frozenset(["alice", "bob"]))
        assert layer.is_visible_to("alice") is True
        assert layer.is_visible_to("bob") is True
        assert layer.is_visible_to("carol") is False

    def test_public_layer_visible_to_any_principal(self) -> None:
        layer = Layer(kind=LayerKind.PUBLIC, members=frozenset())
        assert layer.is_visible_to("alice") is True
        assert layer.is_visible_to("anyone-at-all") is True

    def test_public_layer_with_explicit_members_still_visible_to_anyone(self) -> None:
        # Public is "anyone allowed"; an explicit member list on a public
        # layer is informational, not restrictive.
        layer = Layer(kind=LayerKind.PUBLIC, members=frozenset(["alice"]))
        assert layer.is_visible_to("alice") is True
        assert layer.is_visible_to("bob") is True

    def test_personal_layer_with_no_members_visible_to_nobody(self) -> None:
        # Edge case: personal layer with no members → nothing is visible.
        # Useful as a "sealed" state.
        layer = Layer(kind=LayerKind.PERSONAL, members=frozenset())
        assert layer.is_visible_to("alice") is False
        assert layer.is_visible_to("anyone") is False

    def test_visibility_query_does_not_mutate(self) -> None:
        layer = Layer(kind=LayerKind.SHARED, members=frozenset(["alice"]))
        _ = layer.is_visible_to("bob")
        assert layer.members == frozenset(["alice"])
