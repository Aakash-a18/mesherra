"""Slice 2 step 12 — transient drop + recovery integration test.

Covers SLICE_2_SPEC §9 #15 (drop-and-fetch resume):

    Simulate a push failure (e.g., temporarily 503 on the receiver's
    listener), mutate the Object, restore the listener, mutate again.
    Receiver's callback fires for the post-restore mutation. Receiver,
    on detecting the gap, calls fetch_object(handle); the returned state
    equals the CURRENT scoped state. After reconciliation, subsequent
    pushes resume normally.

The full §9 #1-#16 + Slice 1 §9 #1-#17 dress rehearsal lands in step 13
(``test_live_promotion_roundtrip.py``). This file focuses tightly on
the §9 #15 invariant and the owner-driven §7.4 recovery loop:

* A failed push transitions Alice's owner-side subscription to
  ``disconnected``.
* The next mutation re-attempts the push (per §7.4 step 3) and, on
  success, transitions back to ``active`` while bumping
  ``last_pushed_object_version`` over the gap.
* Bob (the receiver) detects the version gap and can ``fetch_object``
  to get the CURRENT scoped state, not a stale frozen one (§6.2
  LIVE-fetch semantics).
"""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mesherra.a2a_adapter import A2AAdapter
from mesherra.crypto.primitives import Signer
from mesherra.identity import StaticDirectoryClient
from mesherra.models.primitives import (
    LayerKind,
    Mutability,
    PromotionHandle,
    SubscriptionRole,
    SubscriptionStatus,
)
from mesherra.object.store import ObjectStore
from mesherra.provenance.ledger import ProvenanceLedger
from mesherra.sdk import Mesherra

ALICE = "alice@phase4.local"
BOB = "bob@phase4.local"

CALENDAR_SCHEMA = "meshycal.scheduling/calendar-v1"

INITIAL_STATE: dict[str, Any] = {
    "candidates": ["2026-06-01T10:00Z"],
    "duration_minutes": 30,
    "private_note": "alice-out-of-scope",
}
V2_STATE: dict[str, Any] = {**INITIAL_STATE, "duration_minutes": 45}
V3_STATE: dict[str, Any] = {**INITIAL_STATE, "duration_minutes": 60}
V4_STATE: dict[str, Any] = {**INITIAL_STATE, "duration_minutes": 90}

SCOPE = {"fields": ["candidates", "duration_minutes"]}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _future_iso(hours: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _safe(name: str) -> str:
    return name.replace("@", "_at_").replace("/", "_")


def _make_sdk(
    *,
    principal: str,
    signer: Signer,
    db_dir: Path,
    public_keys: dict[str, str],
) -> tuple[Mesherra, ProvenanceLedger, ObjectStore]:
    ledger = ProvenanceLedger(
        db_path=db_dir / f"{_safe(principal)}.ledger.sqlite",
        ledger_owner=principal,
    )
    store = ObjectStore(
        db_path=db_dir / f"{_safe(principal)}.objects.sqlite",
        owner_principal_id=principal,
    )
    sdk = Mesherra(
        principal_id=principal,
        signer=signer,
        ledger=ledger,
        adapter=A2AAdapter(),
        directory=StaticDirectoryClient(public_keys),
        object_store=store,
    )
    return sdk, ledger, store


class TestDropAndFetchResume:
    """End-to-end: kill Bob's listener mid-flow, mutate, restart, mutate
    again. Verify the §9 #15 drop-and-fetch invariant + §7.4 owner-driven
    recovery."""

    @pytest.mark.asyncio
    async def test_resume_through_transient_drop(self, tmp_path: Path) -> None:
        alice_signer = Signer.generate()
        bob_signer = Signer.generate()
        public_keys = {
            ALICE: alice_signer.public_key_b64(),
            BOB: bob_signer.public_key_b64(),
        }
        alice_sdk, alice_ledger, alice_store = _make_sdk(
            principal=ALICE,
            signer=alice_signer,
            db_dir=tmp_path,
            public_keys=public_keys,
        )
        bob_sdk, bob_ledger, bob_store = _make_sdk(
            principal=BOB,
            signer=bob_signer,
            db_dir=tmp_path,
            public_keys=public_keys,
        )

        async def _noop(_msg):  # type: ignore[no-untyped-def]
            return None

        alice_sdk.on_message(_noop)
        bob_sdk.on_message(_noop)

        # Bob's callback collects every OBJECT_UPDATE the handler decodes.
        received: list[tuple[str, dict[str, Any], int]] = []

        async def bob_callback(
            handle: PromotionHandle, new_state: dict[str, Any], version: int
        ) -> None:
            received.append((handle.promotion_id, new_state, version))

        bob_sdk.on_object_update(bob_callback)

        alice_port = _free_port()
        bob_port = _free_port()
        alice_handle = await alice_sdk.start_listener(
            host="127.0.0.1", port=alice_port, agent_name="alice"
        )
        bob_handle = await bob_sdk.start_listener(
            host="127.0.0.1", port=bob_port, agent_name="bob"
        )
        alice_url = f"http://127.0.0.1:{alice_port}/"
        bob_url = f"http://127.0.0.1:{bob_port}/"

        try:
            # --- Setup: Alice creates LIVE Object, promotes to Bob ---

            obj = alice_sdk.create_object(
                state=INITIAL_STATE,
                home_layer=LayerKind.PERSONAL,
                mutability=Mutability.LIVE,
                schema_ref=CALENDAR_SCHEMA,
            )
            promotion, signed_handle = alice_sdk.promote(
                object_id=obj.object_id,
                receiver=BOB,
                scope=SCOPE,
                expiry=_future_iso(hours=2),
                mutability=Mutability.LIVE,
                fetch_endpoint_base=alice_url.rstrip("/"),
            )

            # Ship the handle via PROMOTE (real wire op).
            await alice_sdk.send_to(
                peer_url=bob_url,
                peer_principal_id=BOB,
                payload=signed_handle.model_dump(),
                payload_schema="mesherra.object/promotion-handle-v1",
                operation=__import__(
                    "mesherra.models.primitives", fromlist=["Operation"]
                ).Operation.PROMOTE,
            )

            # Bob subscribes — establishes the active row on Alice's side
            # via the §7.2 SUBSCRIBE matrix. Bob's URL flows in the
            # SubscribeRequest so Alice has a push target.
            await bob_sdk.subscribe_to_object(
                handle=signed_handle, peer_url=alice_url, my_url=bob_url
            )

            # --- v=2 push succeeds ---

            await alice_sdk.update_object(obj.object_id, V2_STATE)
            # Callback should have fired for v=2.
            assert len(received) == 1
            assert received[0][2] == 2
            sub_alice = alice_store.get_subscription(
                promotion_id=promotion.promotion_id, role=SubscriptionRole.OWNER
            )
            assert sub_alice.last_pushed_object_version == 2
            assert sub_alice.status is SubscriptionStatus.ACTIVE

            # --- Transient drop: stop Bob's listener ---

            await bob_handle.stop()

            # --- v=3 mutation: push must fail (Bob unreachable) ---

            await alice_sdk.update_object(obj.object_id, V3_STATE)
            # Alice's row should now be DISCONNECTED.
            sub_alice = alice_store.get_subscription(
                promotion_id=promotion.promotion_id, role=SubscriptionRole.OWNER
            )
            assert sub_alice.status is SubscriptionStatus.DISCONNECTED
            # last_pushed stays at 2 — v=3 push didn't succeed.
            assert sub_alice.last_pushed_object_version == 2
            # Bob's callback should NOT have fired (he was offline).
            assert len(received) == 1

            # --- Restore: bring Bob's listener back on the SAME port ---

            bob_handle = await bob_sdk.start_listener(
                host="127.0.0.1", port=bob_port, agent_name="bob"
            )

            # --- v=4 mutation: §7.4 owner-driven retry recovers ---

            await alice_sdk.update_object(obj.object_id, V4_STATE)
            # Alice's row transitions DISCONNECTED → ACTIVE; last_pushed=4.
            sub_alice = alice_store.get_subscription(
                promotion_id=promotion.promotion_id, role=SubscriptionRole.OWNER
            )
            assert sub_alice.status is SubscriptionStatus.ACTIVE
            assert sub_alice.last_pushed_object_version == 4

            # Bob's callback fires for v=4 — direct gap from v=2 to v=4
            # (skipping the never-delivered v=3). §8 gap-tolerant.
            assert len(received) == 2
            assert received[1][2] == 4
            # The state is the post-mutation V4 state, scoped (no
            # private_note leak).
            received_state = received[1][1]
            assert received_state == {
                "candidates": ["2026-06-01T10:00Z"],
                "duration_minutes": 90,
            }

            # --- Receiver-side: detect gap via fetch_object ---
            # Bob noticed his last_pushed jumped from 2 to 4 (a gap of 1).
            # The drop-and-fetch model has him call fetch_object to confirm
            # he's caught up to the owner's current state.
            current = await bob_sdk.fetch_object(
                handle=signed_handle, peer_url=alice_url, fetch_sequence=1
            )
            # The fetch returns the CURRENT scoped state at v=4. The
            # private_note out-of-scope field must NOT appear.
            assert current == {
                "candidates": ["2026-06-01T10:00Z"],
                "duration_minutes": 90,
            }
            assert "private_note" not in current

            # --- Final push v=5 should resume normally ---

            await alice_sdk.update_object(
                obj.object_id,
                {**V4_STATE, "duration_minutes": 120},
            )
            sub_alice = alice_store.get_subscription(
                promotion_id=promotion.promotion_id, role=SubscriptionRole.OWNER
            )
            assert sub_alice.status is SubscriptionStatus.ACTIVE
            assert sub_alice.last_pushed_object_version == 5
            assert len(received) == 3
            assert received[2][2] == 5

        finally:
            await bob_handle.stop()
            await alice_handle.stop()
            alice_store.close()
            bob_store.close()
            alice_ledger.close()
            bob_ledger.close()
