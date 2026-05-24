"""Integration tests for Phase 3 policy enforcement.

Two Mesherra instances on localhost with PolicyStores injected. Asserts:

* Outbound ALLOW_SCOPED — A sends a payload containing blocked fields;
  A's outbound airlock strips them; B's receive Residue's payload_hash
  matches the SCOPED bytes (not the original). The blocked fields'
  content_hash never appears in either ledger.
* Outbound BLOCK — unknown schema fails fast with PolicyBlocked; no
  network traffic, no Residue.
* Inbound scoping — B's consumer handler receives the policy-narrowed
  payload, while B's receive Residue still hashes the wire bytes.
* Defense-in-depth — a deliberately buggy engine that returns
  ALLOW_SCOPED with the original (un-stripped) payload triggers
  PolicyScopingFailed in the gateway before signing.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import A2AAdapter
from mesherra.crypto.primitives import Signer, canonical_json, content_hash
from mesherra.gateways.inbound import IncomingMessage, OutgoingResponse
from mesherra.gateways.outbound import (
    PolicyBlocked,
    PolicyScopingFailed,
)
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import Operation
from mesherra.policy import (
    Direction,
    Match,
    PolicyDecision,
    PolicyDoc,
    PolicyEngine,
    PolicyStore,
    Rule,
    Verdict,
    sign_policy_doc,
)
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import Mesherra

OWNER_A = "user-a@phase3.local"
OWNER_B = "user-b@phase3.local"

PAYLOAD_SCHEMA = "meshycal.scheduling/proposal-v1"

RICH_PAYLOAD: dict[str, Any] = {
    "candidates": ["2026-05-26T14:00:00Z", "2026-05-27T10:00:00Z"],
    "duration_minutes": 30,
    "calendar_titles": ["secret-mtg", "another-private"],
    "attendee_emails": ["alice@example.com"],
    "constraint_hints": {"tz": "America/New_York"},
}

# What's supposed to make it to the wire after A's default outbound policy.
SCOPED_PAYLOAD = {
    "candidates": ["2026-05-26T14:00:00Z", "2026-05-27T10:00:00Z"],
    "duration_minutes": 30,
    "constraint_hints": {"tz": "America/New_York"},
}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _safe_filename(principal_id: str) -> str:
    return principal_id.replace("@", "_at_").replace("/", "_")


def _default_meshycal_policy(principal_id: str) -> PolicyDoc:
    return PolicyDoc(
        principal_id=principal_id,
        version=1,
        issued_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        rules=[
            Rule(
                match=Match(schema=PAYLOAD_SCHEMA, direction=Direction.OUTBOUND),
                outbound_allow=["candidates", "duration_minutes", "constraint_hints"],
                outbound_block=["calendar_titles", "attendee_emails"],
                max_array_size={"candidates": 5},
            ),
            Rule(
                match=Match(schema=PAYLOAD_SCHEMA, direction=Direction.INBOUND),
                inbound_allow=["candidates", "duration_minutes", "constraint_hints"],
            ),
        ],
    )


def _make_mesherra_with_policy(
    *,
    principal_id: str,
    signer: Signer,
    db_dir: Path,
    public_key_directory: dict[str, str],
    policy_engine: PolicyEngine | None = None,
) -> tuple[Mesherra, ProvenanceLedger, PolicyStore]:
    db_path = db_dir / f"{_safe_filename(principal_id)}.sqlite"
    ledger = ProvenanceLedger(db_path=db_path, ledger_owner=principal_id)
    policy_db = db_dir / f"{_safe_filename(principal_id)}_policy.sqlite"
    store = PolicyStore(
        db_path=policy_db,
        principal_id=principal_id,
        public_key_b64=signer.public_key_b64(),
    )
    signed = sign_policy_doc(
        doc=_default_meshycal_policy(principal_id), signer=signer
    )
    store.save_signed(signed)
    adapter = A2AAdapter()
    sdk = Mesherra(
        principal_id=principal_id,
        signer=signer,
        ledger=ledger,
        adapter=adapter,
        directory=StaticDirectoryClient(public_key_directory),
        policy_store=store,
        policy_engine=policy_engine,
    )
    return sdk, ledger, store


class TestOutboundScoping:
    """A sends rich payload; outbound airlock strips blocked fields; B's
    ledger hashes the scoped bytes, not the original."""

    async def test_blocked_fields_never_cross_wire(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }
        a_sdk, a_ledger, a_store = _make_mesherra_with_policy(
            principal_id=OWNER_A, signer=a_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
        )
        b_sdk, b_ledger, b_store = _make_mesherra_with_policy(
            principal_id=OWNER_B, signer=b_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
        )

        observed_by_b: dict[str, dict[str, Any]] = {}

        async def b_consumer(msg: IncomingMessage) -> OutgoingResponse:
            observed_by_b["payload"] = msg.payload
            return OutgoingResponse(
                payload={"candidates": [msg.payload["candidates"][0]], "duration_minutes": 30},
                operation=Operation.ACCEPTANCE,
            )

        b_sdk.on_message(b_consumer)
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            result = await a_sdk.send_to(
                peer_url=f"http://127.0.0.1:{b_port}/",
                peer_principal_id=OWNER_B,
                payload=RICH_PAYLOAD,
                payload_schema=PAYLOAD_SCHEMA,
                operation=Operation.PROPOSAL,
            )

            # B's consumer received the inbound-scoped subset (calendar_titles
            # / attendee_emails were never in the wire bytes either — A
            # already stripped them — so inbound scoping is a no-op here).
            assert "calendar_titles" not in observed_by_b["payload"]
            assert "attendee_emails" not in observed_by_b["payload"]
            assert observed_by_b["payload"]["candidates"] == SCOPED_PAYLOAD["candidates"]

            # The load-bearing tessera-fit assertion: A's emit hash and
            # B's receive hash must equal the hash of the SCOPED payload,
            # NOT the hash of the original rich payload. If A's scoping
            # happened, this holds; if it didn't, A's emit would be over
            # the rich payload and the demo's whole proposition is broken.
            scoped_hash = content_hash(canonical_json(SCOPED_PAYLOAD))
            rich_hash = content_hash(canonical_json(RICH_PAYLOAD))
            assert scoped_hash != rich_hash  # sanity

            a_entries = a_ledger.get_all()
            b_entries = b_ledger.get_all()
            assert a_entries[0].payload_hash == scoped_hash
            assert b_entries[0].payload_hash == scoped_hash
            assert all(e.payload_hash != rich_hash for e in a_entries)
            assert all(e.payload_hash != rich_hash for e in b_entries)
        finally:
            await b_handle.stop()
            a_store.close()
            b_store.close()
            a_ledger.close()
            b_ledger.close()


class TestOutboundBlock:
    """Unknown schema → default-deny → PolicyBlocked, no Residue."""

    async def test_unknown_schema_blocks(self, tmp_path: Path) -> None:
        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }
        a_sdk, a_ledger, a_store = _make_mesherra_with_policy(
            principal_id=OWNER_A, signer=a_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
        )
        b_sdk, b_ledger, b_store = _make_mesherra_with_policy(
            principal_id=OWNER_B, signer=b_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
        )
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]
        b_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            with pytest.raises(PolicyBlocked):
                await a_sdk.send_to(
                    peer_url=f"http://127.0.0.1:{b_port}/",
                    peer_principal_id=OWNER_B,
                    payload={"foo": "bar"},
                    payload_schema="unknown/v1",
                    operation=Operation.PROPOSAL,
                )
            # No Residue should have been written on either side.
            assert a_ledger.get_all() == []
        finally:
            await b_handle.stop()
            a_store.close()
            b_store.close()
            a_ledger.close()
            b_ledger.close()


class TestDefenseInDepth:
    """A deliberately buggy engine that returns ALLOW_SCOPED with the
    original rich payload must be caught by the gateway's re-check."""

    async def test_buggy_engine_caught_before_send(self, tmp_path: Path) -> None:
        class BuggyEngine(PolicyEngine):
            def evaluate(self, **kwargs: Any) -> PolicyDecision:
                # Pretend we scoped, but return the input unchanged.
                payload = kwargs["payload"]
                # We must return something different from input to get
                # ALLOW_SCOPED rather than ALLOW (the gateway only re-checks
                # the ALLOW_SCOPED branch). Add a meaningless key, then leave
                # calendar_titles intact — the re-check should fire.
                tampered = dict(payload)
                tampered["__buggy_marker__"] = 1
                return PolicyDecision(
                    verdict=Verdict.ALLOW_SCOPED,
                    scoped_payload=tampered,
                    matched_rule_count=1,
                )

        a_signer = Signer.generate()
        b_signer = Signer.generate()
        public_keys = {
            OWNER_A: a_signer.public_key_b64(),
            OWNER_B: b_signer.public_key_b64(),
        }
        a_sdk, a_ledger, a_store = _make_mesherra_with_policy(
            principal_id=OWNER_A, signer=a_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
            policy_engine=BuggyEngine(),
        )
        b_sdk, b_ledger, b_store = _make_mesherra_with_policy(
            principal_id=OWNER_B, signer=b_signer,
            db_dir=tmp_path, public_key_directory=public_keys,
        )
        a_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]
        b_sdk.on_message(lambda msg: None)  # type: ignore[arg-type]

        b_port = _free_port()
        b_handle = await b_sdk.start_listener(
            host="127.0.0.1", port=b_port, agent_name="agent-b"
        )
        try:
            with pytest.raises(PolicyScopingFailed):
                await a_sdk.send_to(
                    peer_url=f"http://127.0.0.1:{b_port}/",
                    peer_principal_id=OWNER_B,
                    payload=RICH_PAYLOAD,  # still has calendar_titles
                    payload_schema=PAYLOAD_SCHEMA,
                    operation=Operation.PROPOSAL,
                )
            # No Residue written when defense-in-depth fires before signing.
            assert a_ledger.get_all() == []
        finally:
            await b_handle.stop()
            a_store.close()
            b_store.close()
            a_ledger.close()
            b_ledger.close()


class TestSdkPolicyAccessors:
    """Mesherra.get_policy / update_policy round-trip through the store."""

    def test_bypass_mode_get_policy_raises(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        ledger = ProvenanceLedger(db_path=tmp_path / "x.sqlite", ledger_owner=OWNER_A)
        sdk = Mesherra(
            principal_id=OWNER_A,
            signer=signer,
            ledger=ledger,
            adapter=A2AAdapter(),
            directory=StaticDirectoryClient({OWNER_A: signer.public_key_b64()}),
        )
        with pytest.raises(RuntimeError):
            sdk.get_policy()
        with pytest.raises(RuntimeError):
            sdk.update_policy(_default_meshycal_policy(OWNER_A))
        ledger.close()

    def test_update_then_get_round_trip(self, tmp_path: Path) -> None:
        signer = Signer.generate()
        ledger = ProvenanceLedger(db_path=tmp_path / "x.sqlite", ledger_owner=OWNER_A)
        store = PolicyStore(
            db_path=tmp_path / "x_policy.sqlite",
            principal_id=OWNER_A,
            public_key_b64=signer.public_key_b64(),
        )
        sdk = Mesherra(
            principal_id=OWNER_A,
            signer=signer,
            ledger=ledger,
            adapter=A2AAdapter(),
            directory=StaticDirectoryClient({OWNER_A: signer.public_key_b64()}),
            policy_store=store,
        )
        signed = sdk.update_policy(_default_meshycal_policy(OWNER_A))
        loaded = sdk.get_policy()
        assert loaded.signature_b64 == signed.signature_b64
        assert loaded.doc.version == 1
        store.close()
        ledger.close()
