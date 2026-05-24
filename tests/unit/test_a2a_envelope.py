"""Unit tests for MesherraEnvelope (the boundary type per ARCHITECTURE.md §13.10).

The envelope is the only type that crosses out of the a2a_adapter module;
its validation contract is therefore load-bearing for every consumer.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mesherra.a2a_adapter.envelope import MesherraEnvelope
from mesherra.models.primitives import Operation

VALID_FIELDS = {
    "task_id": "task-7f3a",
    "context_id": "ctx-1b2c",
    "sender_principal_id": "user-a@phase1.local",
    "payload": {"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30},
    "payload_schema": "meshycal.scheduling/proposal-v1",
    "operation": Operation.PROPOSAL,
    "timestamp": "2026-05-23T15:30:00Z",
    "send_claim_signature": "base64signature==",
}


class TestConstruction:
    def test_construction_with_valid_fields(self) -> None:
        env = MesherraEnvelope(**VALID_FIELDS)
        assert env.task_id == "task-7f3a"
        assert env.context_id == "ctx-1b2c"
        assert env.sender_principal_id == "user-a@phase1.local"
        assert env.payload == VALID_FIELDS["payload"]
        assert env.payload_schema == "meshycal.scheduling/proposal-v1"
        assert env.timestamp == "2026-05-23T15:30:00Z"
        assert env.send_claim_signature == "base64signature=="

    def test_envelope_is_frozen(self) -> None:
        env = MesherraEnvelope(**VALID_FIELDS)
        with pytest.raises(ValidationError):
            env.task_id = "different-task"  # type: ignore[misc]

    def test_envelope_rejects_extra_fields(self) -> None:
        bad = {**VALID_FIELDS, "rogue_field": "not allowed"}
        with pytest.raises(ValidationError, match="rogue_field"):
            MesherraEnvelope(**bad)

    def test_old_field_names_rejected(self) -> None:
        """The old entry_hash / entry_signature fields are gone; anyone still
        using them must update to send_claim_signature + timestamp."""
        bad = {**VALID_FIELDS, "entry_hash": "a" * 64}
        with pytest.raises(ValidationError, match="entry_hash"):
            MesherraEnvelope(**bad)

    def test_equality_is_field_by_field(self) -> None:
        a = MesherraEnvelope(**VALID_FIELDS)
        b = MesherraEnvelope(**VALID_FIELDS)
        assert a == b
        c = MesherraEnvelope(**{**VALID_FIELDS, "task_id": "different"})
        assert a != c


class TestValidation:
    @pytest.mark.parametrize(
        "field",
        [
            "context_id",
            "sender_principal_id",
            "payload_schema",
            "timestamp",
            "send_claim_signature",
        ],
    )
    def test_string_fields_reject_empty(self, field: str) -> None:
        bad = {**VALID_FIELDS, field: ""}
        with pytest.raises(ValidationError):
            MesherraEnvelope(**bad)

    def test_task_id_allows_empty(self) -> None:
        """task_id is empty on the first message of a new task (A2A assigns one in the response)."""
        env = MesherraEnvelope(**{**VALID_FIELDS, "task_id": ""})
        assert env.task_id == ""

    def test_task_id_defaults_to_empty(self) -> None:
        """Per the envelope's Field(default=""), task_id is optional at construction."""
        fields_without_task = {k: v for k, v in VALID_FIELDS.items() if k != "task_id"}
        env = MesherraEnvelope(**fields_without_task)
        assert env.task_id == ""

    def test_payload_must_be_dict(self) -> None:
        bad = {**VALID_FIELDS, "payload": "not a dict"}
        with pytest.raises(ValidationError):
            MesherraEnvelope(**bad)

    def test_payload_can_be_empty_dict(self) -> None:
        """Empty dict is structurally valid; schema validation is the
        gateway's job, not the envelope's."""
        env = MesherraEnvelope(**{**VALID_FIELDS, "payload": {}})
        assert env.payload == {}
