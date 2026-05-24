"""Unit tests for envelope ↔ A2A Message conversion (ARCHITECTURE.md §13.10).

The conversion is the *only* place protobuf wire types and Mesherra's
Pydantic envelope meet. These tests pin down that boundary.
"""

from __future__ import annotations

import pytest
from google.protobuf import struct_pb2

from mesherra.a2a_adapter.envelope import MesherraEnvelope
from mesherra.a2a_adapter.wire import (
    WireFormatError,
    a2a_message_to_envelope,
    envelope_to_a2a_message,
)
from mesherra.models.primitives import Operation


def _make_envelope(**overrides) -> MesherraEnvelope:
    defaults = {
        "task_id": "task-7f3a",
        "context_id": "ctx-1b2c",
        "sender_principal_id": "user-a@phase1.local",
        "payload": {
            "candidates": ["2026-05-26T14:00:00Z", "2026-05-27T10:00:00Z"],
            "duration_minutes": 30,
        },
        "payload_schema": "meshycal.scheduling/proposal-v1",
        "operation": Operation.PROPOSAL,
        "timestamp": "2026-05-23T15:30:00Z",
        "send_claim_signature": "base64sig==",
    }
    return MesherraEnvelope(**{**defaults, **overrides})


class TestEnvelopeToA2A:
    def test_message_id_is_propagated(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="msg-abc")
        assert msg.message_id == "msg-abc"

    def test_task_and_context_ids_set(self) -> None:
        env = _make_envelope(task_id="task-XYZ", context_id="ctx-XYZ")
        msg = envelope_to_a2a_message(env, message_id="m")
        assert msg.task_id == "task-XYZ"
        assert msg.context_id == "ctx-XYZ"

    def test_payload_lives_in_parts0_data(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        assert len(msg.parts) == 1
        first = msg.parts[0]
        assert first.HasField("data"), "Payload must be in Part.data, not Part.text/raw/url"
        assert first.data.HasField("struct_value")

    def test_metadata_contains_exactly_the_five_namespaced_keys(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        assert msg.HasField("metadata")
        keys = set(msg.metadata.fields.keys())
        assert keys == {
            "mesherra.send_claim.sender_principal_id",
            "mesherra.send_claim.payload_schema",
            "mesherra.send_claim.operation",
            "mesherra.send_claim.timestamp",
            "mesherra.send_claim.signature",
        }

    def test_metadata_values_match_envelope(self) -> None:
        env = _make_envelope(
            timestamp="2099-01-01T12:34:56Z",
            send_claim_signature="sig123==",
            payload_schema="some/schema-v9",
            sender_principal_id="user-z@example.test",
            operation=Operation.ACCEPTANCE,
        )
        msg = envelope_to_a2a_message(env, message_id="m")
        md = msg.metadata.fields
        assert md["mesherra.send_claim.timestamp"].string_value == "2099-01-01T12:34:56Z"
        assert md["mesherra.send_claim.signature"].string_value == "sig123=="
        assert md["mesherra.send_claim.payload_schema"].string_value == "some/schema-v9"
        assert md["mesherra.send_claim.sender_principal_id"].string_value == "user-z@example.test"
        assert md["mesherra.send_claim.operation"].string_value == "acceptance"


class TestA2AToEnvelope:
    def test_round_trip_is_identity(self) -> None:
        original = _make_envelope()
        msg = envelope_to_a2a_message(original, message_id="m")
        back = a2a_message_to_envelope(msg)
        assert back == original

    def test_round_trip_preserves_nested_payload(self) -> None:
        original = _make_envelope(
            payload={
                "candidates": ["2026-05-26T14:00:00Z"],
                "duration_minutes": 45,
                "nested": {"k1": "v1", "k2": [1, 2, 3]},
            }
        )
        back = a2a_message_to_envelope(
            envelope_to_a2a_message(original, message_id="m")
        )
        assert back == original

    def test_missing_parts_raises(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        msg.ClearField("parts")
        with pytest.raises(WireFormatError, match="no Parts"):
            a2a_message_to_envelope(msg)

    def test_part_without_data_raises(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        msg.parts[0].ClearField("data")
        msg.parts[0].text = "not the right shape"
        with pytest.raises(WireFormatError, match="parts\\[0\\] does not carry .data"):
            a2a_message_to_envelope(msg)

    def test_missing_metadata_keys_raises(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        del msg.metadata.fields["mesherra.send_claim.signature"]
        with pytest.raises(WireFormatError, match="mesherra.send_claim.signature"):
            a2a_message_to_envelope(msg)

    def test_part_data_non_struct_raises(self) -> None:
        msg = envelope_to_a2a_message(_make_envelope(), message_id="m")
        msg.parts[0].data.CopyFrom(struct_pb2.Value(string_value="not a struct"))
        with pytest.raises(WireFormatError, match="struct_value"):
            a2a_message_to_envelope(msg)
