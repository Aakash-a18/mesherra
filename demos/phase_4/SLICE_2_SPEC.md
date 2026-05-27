# Phase 4 Slice 2 SPEC: Live Reference Promotion

This document is the implementable spec for Phase 4 Slice 2 — adding **live reference promotion** on top of the static-reference machinery shipped in Slice 1 (`demos/phase_4/SPEC.md` §0–13).

Slice 2 is **additive**. Every Slice 1 invariant (§9 #1–#17 of the main SPEC) must continue to hold for static-reference promotions; Slice 2 adds new invariants for the live case. Static and live promotions coexist in the same ObjectStore, distinguished by the `mutability` field on the Promotion row.

Read Slice 1's SPEC first. This document pins what's *different* and additive.

## 0. Goal

Prove that live reference promotion works mechanically end-to-end: an owner can create an Object whose `mutability == "live"`, scope a slice of it to a counterpart via a signed PromotionHandle, the counterpart subscribes to updates, and every owner-side mutation flows to the subscribed counterpart in real time as a signed `OBJECT_UPDATE` message, with paired Residue on both sides per push. Subscriptions close gracefully at expiry; transient transport drops are recoverable; no Slice 1 invariant breaks.

This is the mechanic MeshyCal's MeetingObject needs (`MeshyCal/docs/ARCHITECTURE.md` §3.2): two scheduling agents negotiating in real time, each seeing the other's counter-proposals as they happen, without either side polling. MeetingObject is **two-party** but each side owns its own Object (its half of the negotiation state) and issues a single live promotion to the counterpart — so Slice 2's one-receiver-per-promotion model is the right shape for MeshyCal; there is no multi-receiver fan-out requirement in Slice 2.

## 1. Scope

### In scope (Slice 2 must do these)

- `Object.mutability == Mutability.LIVE` supported end-to-end (the enum value already exists in Slice 1; Slice 2 makes it functional).
- `Promotion.mutability == Mutability.LIVE` is a valid configuration; co-exists with STATIC in the same ObjectStore.
- New wire schema `mesherra.object/object-update-v1` for push messages.
- New `Operation` enum values: `SUBSCRIBE`, `UNSUBSCRIBE`, `OBJECT_UPDATE`. (Acks reuse the request operation — same convention as Slice 1's PROMOTE → PROMOTE_ACK.)
- New ObjectStore table `active_subscriptions` (parallel to `received_handles`/`promotions`). Tracks who's subscribed to which live promotion + `last_pushed_object_version` for gap detection.
- New SDK methods: `Mesherra.subscribe_to_object(handle)`, `Mesherra.unsubscribe_from_object(handle)`, `Mesherra.on_object_update(callback)`.
- Extended `Mesherra.update_object()`: after persisting the new Object version, enumerates active subscriptions for live promotions of this `object_id` and pushes an OBJECT_UPDATE per active receiver.
- Live `Mesherra.fetch_object()` semantics: returns the *current* scoped Object state (not a frozen snapshot). The Promotion row's `snapshot_state` is `null` for live promotions; each fetch computes the scoped slice from the Object's current state.
- Push pipeline: outbound airlock for OBJECT_UPDATE; inbound airlock dispatches OBJECT_UPDATE to the ObjectInboundHandler, which validates against the receiver's stored handle, invokes the user callback, returns ack.
- Subscription auto-reconnect with bounded backoff: if owner's push fails transiently (peer offline, network blip), owner retries with exponential backoff up to a cap; persists subscription state across retries.
- Subscription graceful close at expiry: owner stops pushing after `promotion.expiry`; subscription row marked `status = "expired"`.
- Object version monotonicity: each OBJECT_UPDATE carries a strictly-greater `object_version` than the previous; receiver detects gaps and may FETCH to reconcile.
- Slice 1 invariants survive: static promotions still hash byte-equal across fetches (§9 #8 of the main SPEC); stolen-handle and scope-filter privacy invariants (§9 #15/#16) still hold for both modes.

### Out of scope for Slice 2 (deferred to Slice 3, Slice 4, or later)

| Out of scope | Why deferred |
|---|---|
| Bilateral per-push policy (ARCH §3.7 commitment) | Slice 2.5 / Slice 3. Closing the deferral note added in Slice 1 requires `inbound_accept` rule type in the Policy Engine, which is itself a separate piece of work. Slice 2 keeps the same trust-op bypass as Slice 1. |
| Catch-up replay on reconnect | Owner does NOT replay missed updates after a transient drop. Receiver detects the gap (via object_version) and may FETCH to reconcile. Persistent catch-up is Slice 3+. |
| True server-streaming wire (A2A `tasks/resubscribe`) | Slice 2 uses discrete request-response per push, reusing the Slice 1 wire. True streaming is an optimization for Slice 3+. The on-wire payload schema is forward-compatible (same `object-update-v1` shape can flow as stream chunks later). |
| Explicit revocation before expiry | Owner cannot tear down a subscription before expiry (other than waiting it out or terminating the Promotion itself, which is also Slice 3). |
| Push to multiple receivers with different scopes per `object_id` | Each Promotion is owner→single-receiver. A second receiver requires a separate Promotion (which is fine — the owner enumerates all live promotions for the object_id and pushes per promotion). |
| Receiver-initiated re-promotion / forwarding | Slice 1's forwarding-forbidden constraint (handler.py:124) continues to hold. |
| Copy mode (Slice 3 work) | Unaffected by Slice 2; remains stubbed. |
| Resuming a previously-unsubscribed subscription as if it had continuous state | After UNSUBSCRIBE, SUBSCRIBE creates a fresh active state (last_pushed_object_version resets to NULL — see §7.2 transition matrix). The receiver must FETCH explicitly if they need pre-push current state. Continuous-state resume (where last_pushed_object_version is preserved across an unsubscribe/re-subscribe cycle) is out of scope. |
| Multi-instance owner (one principal, multiple processes pushing) | Phase 5+. Slice 2 assumes one owner process per principal. |

If any out-of-scope item creeps in during Slice 2 work, stop and reconsider.

## 2. New Wire Schema: ObjectUpdate

**Schema ID:** `mesherra.object/object-update-v1`
**Owner:** Mesherra (trust layer)
**Phase 4 location:** authoritative Python type in `mesherra/src/mesherra/object/wire.py` (alongside `FetchResponse`, `FetchDenied`, etc.). No JSON Schema mirror in v0 — internal wire shape, no cross-language consumers yet. (Same call as the other Slice 1 wire payloads; only `Object` and `PromotionHandle` get mirrors because they cross identity boundaries.)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "mesherra.object/object-update-v1",
  "title": "Mesherra Object Update v1",
  "description": "Owner-initiated push of a new scoped snapshot to a subscribed receiver under a live reference promotion. Travels with operation = OBJECT_UPDATE.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version", "promotion_id", "object_version",
    "snapshot_state", "snapshot_content_hash"
  ],
  "properties": {
    "version": { "const": 1 },
    "promotion_id": {
      "description": "The live promotion this update belongs to.",
      "type": "string", "minLength": 1
    },
    "object_version": {
      "description": "The Object's version number at the time of this push. Strictly greater than any previously-pushed version for this subscription.",
      "type": "integer", "minimum": 1
    },
    "snapshot_state": {
      "description": "The scoped slice of the Object's CURRENT state (filtered through promotion.scope). Computed at push time from the just-mutated Object.",
      "type": "object"
    },
    "snapshot_content_hash": {
      "description": "SHA-256 (hex) of JCS(snapshot_state). The receiver validates this matches a recomputation locally.",
      "type": "string", "pattern": "^[0-9a-f]{64}$"
    }
  }
}
```

**Cross-field invariants (validators):**

- `object_version >= 1` (matches Object's monotonicity).
- `snapshot_content_hash` matches `SHA-256(JCS(snapshot_state))` — defense-in-depth recomputation on receive.

**Why no `fetch_sequence`-style counter:** OBJECT_UPDATE messages are owner-pushed (not receiver-pulled). Sequencing comes from `object_version` itself, which is monotonic on the Object. The A2A `task_id` provides per-push wire-level identity for residue dedup.

**Why no `previous_content_hash` chaining:** Slice 2 does not commit to chained-update integrity (a receiver can't prove "I have every update from v1 to vN"). Each push is independently signed by the owner's SendClaim. If chain integrity becomes a requirement, that's an additive Slice 2.5 schema bump.

## 3. Operation Enum Extension

`Operation` enum (currently 8 values after Slice 1) gains:

- `subscribe` — receiver requests subscription to a live promotion
- `unsubscribe` — receiver requests subscription teardown
- `object_update` — owner pushes a new scoped snapshot to a subscribed receiver

Ack responses reuse the request operation (same convention as Slice 1's PROMOTE → `promotion-ack-v1`). The payload schema distinguishes request from ack:

| Request op | Request schema | Response op | Response schema |
|---|---|---|---|
| `subscribe` | `mesherra.object/subscribe-v1` | `subscribe` | `mesherra.object/subscribe-ack-v1` |
| `unsubscribe` | `mesherra.object/unsubscribe-v1` | `unsubscribe` | `mesherra.object/unsubscribe-ack-v1` |
| `object_update` | `mesherra.object/object-update-v1` | `object_update` | `mesherra.object/object-update-ack-v1` |

**Wire-compat note:** identical to Slice 1's note on the Operation enum (`demos/phase_4/SPEC.md` §8.3): the SQLite `operation` column is plain TEXT with no CHECK, so adding values is additive. Existing Slice 1 ledger rows are unaffected; Slice 2 introduces three new wire identifiers.

**Add to InboundGateway dispatch:**

- `_INBOUND_TRUST_OPS` gains `SUBSCRIBE`, `UNSUBSCRIBE`, `OBJECT_UPDATE` — these route to the ObjectInboundHandler before the consumer.
- `_RESPONSE_ONLY_OPS` unchanged (acks reuse request ops; they're not separately enum'd).
- `_OUTBOUND_TRUST_OPS` (in `gateways/outbound.py`) gains the same three values, mirroring the policy-bypass discipline from Slice 1.

## 4. The Subscription Model

A live reference promotion has a lifecycle distinct from a static one:

```
[Owner creates Object (mutability=LIVE)]
            │
            ▼
[Owner.promote(receiver, scope, expiry, mutability=LIVE)]
            │
            ▼
[Owner ships PromotionHandle via PROMOTE]
            │
            ▼
[Receiver persists handle]    ─── Slice 1 ends here ───
            │
            ▼   ┌────────────────────────────────────────┐
[Receiver.subscribe_to_object(handle)]                   │
            │                                            │
            ▼                                            │
[Owner records active_subscription]                      │
            │                                            │
            ▼                                            │
[While now < expiry AND not unsubscribed:]               │  Slice 2
            │                                            │
        ┌───┴───────┐                                    │  body
        ▼           ▼                                    │
  [owner mutates  [receiver                              │
   Object]         receives OBJECT_UPDATE,              │
   ─push→           callback fires,                      │
                    ack returned]                        │
        │           │                                    │
        └─────┬─────┘                                    │
              │                                          │
              ▼                                          │
        [paired Residue both sides]                      │
            │                                            │
            ▼                                            │
[receiver.unsubscribe / now >= expiry]                   │
            │                                            │
            ▼                                            │
[Owner marks subscription closed; stops pushing]  ─── lifecycle end
```

**Subscription state (owner side):** Tracked in `active_subscriptions` table on owner's ObjectStore. One row per (promotion_id, receiver) tuple — initially `status = "active"`, `last_pushed_object_version = NULL`. Transitions: active → expired (at expiry); active → closed (on UNSUBSCRIBE).

**Subscription state (receiver side):** Tracked symmetrically in receiver's ObjectStore `active_subscriptions` table. One row per (promotion_id, owner). Receiver-side `status` reflects what the receiver believes: `active` (subscribed and expecting pushes); `disconnected` (transient; backoff retry in progress); `expired` (past promotion.expiry); `closed_by_receiver` (after explicit unsubscribe).

**Symmetry vs asymmetry:** The two sides' active_subscriptions tables can drift during transient drops (owner thinks subscription is active and is buffering; receiver hasn't yet retried). Reconciliation rule: owner is authoritative on whether pushes are happening; receiver is authoritative on whether the consumer is being notified. Both must agree on `status = "expired"` after the wall-clock crosses `promotion.expiry`.

## 5. ObjectStore Extensions

Add one table to the existing per-principal SQLite schema:

```sql
CREATE TABLE active_subscriptions (
    promotion_id TEXT NOT NULL,
    counterpart TEXT NOT NULL,          -- owner-side: receiver; receiver-side: owner
    role TEXT NOT NULL CHECK (role IN ('owner', 'receiver')),
    last_pushed_object_version INTEGER, -- NULL until first push observed/sent
    status TEXT NOT NULL CHECK (status IN ('active', 'disconnected', 'expired', 'closed_by_receiver')),
    subscribed_at TEXT NOT NULL,
    last_status_change_at TEXT NOT NULL,
    PRIMARY KEY (promotion_id, role)
);

CREATE INDEX idx_active_subscriptions_counterpart
    ON active_subscriptions(counterpart);
CREATE INDEX idx_active_subscriptions_status
    ON active_subscriptions(status);
```

**Storage rule:** `role` distinguishes owner-side from receiver-side rows. A single principal acting as both owner of some promotions and receiver of others will have rows of both roles in the same table. (Mirrors how `promotions` and `received_handles` coexist in one ObjectStore.)

**Why one table for both roles:** simpler than two parallel tables, and the role field keeps queries unambiguous. The alternative (separate `issued_subscriptions` / `received_subscriptions` tables) was rejected as overengineering for Slice 2's needs.

**API additions to `ObjectStore`:**

```python
def record_subscription(
    self,
    *,
    promotion_id: str,
    counterpart: str,
    role: Literal["owner", "receiver"],
) -> None: ...

def get_subscription(
    self, promotion_id: str, role: Literal["owner", "receiver"]
) -> ActiveSubscription: ...

def update_subscription_status(
    self,
    promotion_id: str,
    role: Literal["owner", "receiver"],
    status: SubscriptionStatus,
) -> None: ...

def update_subscription_pushed_version(
    self,
    promotion_id: str,
    role: Literal["owner", "receiver"],
    object_version: int,
) -> None: ...

def list_active_subscriptions_for_object(
    self, object_id: str
) -> list[ActiveSubscription]: ...
```

The `list_active_subscriptions_for_object` lookup is the owner-side hot path: `update_object` calls this to find every live receiver to push to.

`ActiveSubscription` is a frozen Pydantic model in `models/primitives.py`. Same discipline as `Promotion`.

**Append-and-update vs append-only:** Unlike Slice 1's `promotions` (append-only), `active_subscriptions` IS update-mutated (status changes, last_pushed_object_version advances). This matches its role: it's *state*, not *history*. The history of state changes is in the residue ledger (subscribe/unsubscribe/object_update entries).

## 6. SDK Surface

### 6.1 New methods

```python
class Mesherra:
    async def subscribe_to_object(
        self,
        *,
        handle: PromotionHandle,
        peer_url: str,
    ) -> None:
        """Open a live subscription against a received PromotionHandle.

        Only valid for handles with mutability == LIVE; otherwise raises
        ValueError. Records the subscription locally (receiver-side row)
        and sends a SUBSCRIBE request to the owner; the owner records
        their side (owner-side row) and acks.

        Idempotent within Slice 2: re-subscribing while already active
        is a no-op (returns without sending).
        """

    async def unsubscribe_from_object(
        self,
        *,
        handle: PromotionHandle,
        peer_url: str,
    ) -> None:
        """Close an active subscription. Sends UNSUBSCRIBE to the owner;
        owner marks subscription closed_by_receiver and stops pushing;
        local subscription row marked closed_by_receiver."""

    def on_object_update(self, callback: ObjectUpdateCallback) -> None:
        """Register the receiver-side callback for inbound OBJECT_UPDATE
        pushes.

        Signature: ``async (handle: PromotionHandle, new_state: dict,
        object_version: int) -> None``.

        Trust-layer concerns (signature verification, content_hash check,
        residue writing, gap detection) are handled by the InboundGateway
        and ObjectInboundHandler before the callback fires; the callback
        receives only the verified data.
        """
```

### 6.2 Modifications to existing methods

`Mesherra.update_object()` (existing Slice 1 method): after persisting the new Object version, queries `active_subscriptions` for every live promotion of `object_id`. For each, computes scoped snapshot from the new Object state, builds an `ObjectUpdate` payload, sends OBJECT_UPDATE to the receiver via the outbound airlock. If a push fails, marks the subscription `disconnected` and schedules a retry (§7).

`Mesherra.promote()` (existing Slice 1 method): now accepts `mutability=Mutability.LIVE`. When LIVE, the resulting Promotion row's `snapshot_state` is `null` (live promotions don't store a snapshot — pushes carry the snapshot, fetches compute it). The handle's `snapshot_content_hash` is computed at promotion-creation time over the scoped slice of the Object's current state — this gives the receiver an *initial* commitment they can verify against the first push.

**Initial-commitment verification is consumer-responsibility in Slice 2 v0.** The receiver's `on_object_update` callback gets both the handle (with its `snapshot_content_hash`) and the new `snapshot_state` — a consumer that cares about the initial-commitment binding can compute `SHA-256(JCS(new_state)) == handle.snapshot_content_hash` on the first push (where `last_pushed_object_version` was `None`) and reject if it diverges. The trust layer does not enforce this gate because the commitment is by design only meaningful for the first push (the owner is free to mutate before any push fires, in which case the first push legitimately diverges from the handle's hash). Building an "owner mutated between PROMOTE and first push" check into the trust layer would over-constrain the legitimate concurrent-mutation case; pushing the choice to the consumer keeps the trust layer's contract crisp.

`Mesherra.fetch_object()` (existing Slice 1 method): now branches on `handle.mutability`. STATIC: unchanged (returns frozen snapshot). LIVE: returns *current* scoped state (handler computes from current Object state, returns FetchResponse whose `snapshot_content_hash` equals the current scoped hash, NOT necessarily equal to handle.snapshot_content_hash since the Object may have mutated). On LIVE fetch, the SDK does NOT raise `FetchContentHashMismatch` — that check is STATIC-only.

### 6.3 New exceptions

```python
class SubscriptionExpired(Exception): ...
class SubscriptionNotActive(Exception): ...
class ObjectUpdateVersionRegression(Exception):
    """A push arrived with object_version <= previously-seen version.
    Either owner replayed (shouldn't happen) or version semantics broke.

    NOTE: not used by the Slice 2 v0 implementation. Step 6's
    handle_object_update returns ObjectUpdateDenied(version_regression)
    instead of raising — soft denial is recoverable (owner marks
    subscription disconnected and backs off) while a raise would
    propagate as an airlock failure with no graceful recovery path.
    The exception class is kept as documentation of the alternative
    posture; pre-Slice-3 wire compat assumes denial."""
```

## 7. Airlock Integration

### 7.1 Owner-side outbound: push pipeline

Triggered by `Mesherra.update_object(object_id, new_state)` when the Object's `mutability == LIVE`:

1. Persist the new Object version (existing Slice 1 path; same OwnershipError gate, version monotonicity, etc.).
2. Query `active_subscriptions` rows where `role = 'owner'` AND `promotion_id IN (live promotions for object_id)` AND `status = 'active'`.
3. For each active subscription:
   a. Load the Promotion row to get `scope`, `receiver`, `expiry`.
   b. If `now >= expiry`: mark subscription `status = 'expired'`, skip push.
   c. Compute `scoped_state = {k: v for k, v in new_state.items() if k in scope.fields}`.
   d. Compute `snapshot_content_hash = SHA-256(JCS(scoped_state))`.
   e. Build `ObjectUpdate(promotion_id, object_version, snapshot_state, snapshot_content_hash)`.
   f. Send via outbound airlock: `operation=OBJECT_UPDATE`, `payload_schema=object-update-v1`, `peer_principal_id=receiver`, `peer_url=<from active_subscription or directory>`.
   g. On success (ack received): bump `last_pushed_object_version` on the subscription row.
   h. On transient failure: mark `status = 'disconnected'`, schedule retry per §7.4.

**Push fan-out**: sequential within a single `update_object` call in Slice 2 v0. Parallel fan-out is a Slice 3 optimization.

### 7.2 Owner-side inbound: SUBSCRIBE / UNSUBSCRIBE handling

ObjectInboundHandler gains two new methods:

```python
async def handle_subscribe(self, payload, sender_principal_id) -> HandlerOutput:
    """Receiver requests subscription to a live promotion.

    Validate: promotion exists; promotion.receiver == sender; promotion.mutability == LIVE;
    now < promotion.expiry; (if subscription row exists) it's not in closed_by_receiver state.

    Effect: insert-or-update active_subscriptions row with role='owner',
    status='active'. Return SubscribeAck.
    """

async def handle_unsubscribe(self, payload, sender_principal_id) -> HandlerOutput:
    """Receiver requests subscription teardown.

    Validate: subscription exists; sender == promotion.receiver.
    Effect: mark active_subscriptions row status='closed_by_receiver'. Return UnsubscribeAck.
    """
```

**Failure modes:** Same shape as FETCH_DENIED — soft failures return a denial payload (e.g., `SubscribeDenied` with reasons `unknown_promotion`, `receiver_mismatch`, `not_live_promotion`, `expired`).

**SUBSCRIBE state-transition matrix (the explicit version of the docstring above):**

| Pre-state of owner-side row | Outcome |
|---|---|
| Row does NOT exist | Create row with `status='active'`, `last_pushed_object_version=NULL`. Return SubscribeAck. |
| Row exists, `status='active'` | No-op. Return SubscribeAck (idempotent within the active state). |
| Row exists, `status='disconnected'` | Transition to `status='active'`. Return SubscribeAck. (This is the recovery path after a transient drop where the receiver explicitly re-subscribes.) |
| Row exists, `status='closed_by_receiver'` | Treat as fresh subscription: transition to `status='active'`, reset `last_pushed_object_version=NULL`. Return SubscribeAck. (Receiver who unsubscribed and now wants back must SUBSCRIBE again; spec §1 obligates them to FETCH for current state before relying on the next push, but the protocol does not enforce that — it's the consumer's responsibility to call fetch first if they need pre-push state.) |
| Row exists, `status='expired'` | Return SubscribeDenied with reason `expired`. (Cannot revive past expiry.) |

**UNSUBSCRIBE state-transition matrix:**

| Pre-state of owner-side row | Outcome |
|---|---|
| Row does NOT exist | Return UnsubscribeDenied with reason `not_active`. |
| Row exists, `status='active'` or `'disconnected'` | Transition to `status='closed_by_receiver'`. Return UnsubscribeAck. |
| Row exists, `status='closed_by_receiver'` | No-op. Return UnsubscribeAck (idempotent). |
| Row exists, `status='expired'` | Return UnsubscribeDenied with reason `expired` (subscription already terminated by other means; ack would be misleading). |

### 7.3 Receiver-side inbound: OBJECT_UPDATE handling

ObjectInboundHandler gains:

```python
async def handle_object_update(self, payload, sender_principal_id) -> HandlerOutput:
    """Owner-pushed update to a live promotion we subscribed to.

    Validate:
    - handle exists in received_handles for this promotion_id
    - sender == handle.owner (Slice 2 forbids forwarded push paths, same as Slice 1 PROMOTE)
    - handle.mutability == LIVE
    - now < handle.expiry
    - object_version strictly greater than last_pushed_object_version (gap-tolerant: gaps OK, regressions NOT)
    - SHA-256(JCS(payload.snapshot_state)) == payload.snapshot_content_hash (defense-in-depth recomputation)

    Effect:
    - bump active_subscriptions.last_pushed_object_version
    - invoke registered on_object_update callback with (handle, new_state, object_version)
    - return ObjectUpdateAck

    Soft failures (denial returned, owner can recover) →
    ObjectUpdateDenied with reason:
    - ``expired``: handle past its expiry, OR no receiver-side
      ``active_subscriptions`` row exists (subscription was never opened
      or was already cleaned up). Slice 2 v0 collapses both into the
      single ``expired`` reason rather than expanding the
      ``ObjectUpdateDenialReason`` Literal — both indicate "the receiver
      can no longer process pushes under this handle." A dedicated
      ``no_subscription`` value is a Slice 2.5+ refinement if owners
      need to distinguish the two recovery paths.
    - ``version_regression``: ``object_version <= last_pushed_object_version``
      (see §7.4 and §8 for the strict-monotonic-forward rule).

    Hard failures (raise, gateway propagates as airlock failure):
    - No PromotionHandle for this promotion_id in the receiver's
      ``received_handles`` — no subscription relationship has ever
      existed; the owner is pushing without authority.
    - ``sender_principal_id != handle.owner`` — forwarded-push attack
      (same shape as Slice 1's PROMOTE no-forwarding rule).
    - ``handle.mutability != LIVE`` — owner pushing under a STATIC
      handle, which the protocol does not permit.
    - On-the-wire ``SHA-256(JCS(snapshot_state)) != snapshot_content_hash``
      after Pydantic decode (the model's construction-time check is the
      first line of defense; the handler recomputes from the raw payload
      dict as belt-and-braces against payloads that bypass model_validate).
    """
```

The receiver-side OBJECT_UPDATE handler does NOT mutate any Object — receivers never own Objects. The callback fires for consumer awareness; what the consumer does with the data is their concern.

### 7.4 Reconnect / resume model

Slice 2 v0 specifies the **drop-and-fetch** model: on a push failure, the owner does NOT buffer the failed update for later redelivery. Instead, the subscription is marked disconnected, the next mutation produces a new push (with a higher object_version), and the receiver — on observing the version gap — explicitly FETCHes to reconcile current state. Buffered ordered redelivery is a deferred Slice 2.5+ enhancement; the simpler model keeps Slice 2 small and exercises the receiver's gap-detection path that needs to work regardless.

Owner-side behavior on push failure:

1. Mark the subscription `status = 'disconnected'`.
2. Do NOT retry the specific failed push. The next `update_object` for this object_id will attempt a fresh push (carrying the new version, not the failed-and-skipped one).
3. On the next push attempt, if it succeeds, transition the subscription back to `status = 'active'`. If it fails again, leave it `disconnected`.
4. At `promotion.expiry`, mark the subscription `status = 'expired'` regardless of connectivity state.

**Per-receiver send ordering invariant:** the owner sends one OBJECT_UPDATE at a time per subscription and awaits its ack before initiating the next push (§7.1 step 3). This means out-of-order delivery is impossible at the wire — by the time v5's push starts, v4's push has either acked successfully (active) or failed (disconnected). The receiver therefore never observes `v5` before `v4`; gaps only ever appear monotonically forward. The handler's regression check (§8) is correct as a *soft* rejection for `v <= last`: it returns ObjectUpdateDenied(version_regression) rather than raising. Soft denial preserves the owner's recovery path (mark subscription disconnected, back off) where a hard raise would have to propagate as an unrecoverable airlock failure.

**Receiver-side reconnect:** If the receiver suspects it has missed updates (the connection's reachability state was lost, or it sees a gap in object_versions when a new push arrives), it can:

1. Call `fetch_object(handle, peer_url)` to get current state and reset `last_pushed_object_version` to the current Object's version. (Returns CURRENT state per §6.2 fetch semantics for LIVE.)
2. Continue subscribing for future pushes.

Receiver-side does NOT initiate a separate "resume" RPC. The subscription state is owner-driven; receiver actively observes and reconciles when needed.

### 7.5 Subscription closing at expiry

When `now >= promotion.expiry`:
- Owner: on the next `update_object` push attempt, marks `subscription.status = 'expired'`, skips the push, does not retry.
- Receiver: if a fetch attempt is made past expiry, the existing Slice 1 handler returns FETCH_DENIED with reason `expired`. If the receiver tries to SUBSCRIBE after expiry, returns SubscribeDenied with reason `expired`.
- Neither side actively notifies the other of expiry — both sides observe wall-clock independently. (Aligned with how SubscribeToTask works in A2A: implicit timeout, no explicit close signal.)

## 8. Reconnect / Resume Details

See §7.4 for the per-push retry policy and the explicit deferral of buffered redelivery.

**Receiver-side detection of missed updates:**

Each OBJECT_UPDATE handler invocation compares `payload.object_version` against `active_subscriptions.last_pushed_object_version`:

- `object_version == last + 1`: contiguous; normal case. Bump `last`.
- `object_version > last + 1`: gap (we missed updates). Bump `last` to the new version. The on_object_update callback fires with the new state, and the receiver SDK MAY also fire a separate `on_subscription_gap(handle, missed_count)` callback if registered. Slice 2 v0: this callback is OPTIONAL; integration test exercises the gap path via the basic on_object_update only.
- `object_version <= last`: regression. Return `ObjectUpdateDenied(reason="version_regression")` (soft denial — see §7.4 send-ordering invariant for the rationale). Do NOT process the push; do NOT advance `last_pushed_object_version`. The owner can react to the denial residue by marking its side disconnected and ceasing pushes.
- `object_version == 1` AND `last is None`: first push; normal initial case.

## 9. End-State Assertions (Slice 2)

After a successful Slice 2 run — owner creates a LIVE Object, promotes to receiver, receiver subscribes, owner mutates 3 times (each push delivered), receiver unsubscribes, owner mutates again (no push because unsubscribed) — the following must hold IN ADDITION to all Slice 1 §9 invariants (which Slice 2 must not break for static promotions running in the same process):

### Subscription state assertions

1. **Owner-side subscription row** exists with `role='owner'`, `status='closed_by_receiver'`, `last_pushed_object_version=3` (the third push, before unsubscribe).
2. **Receiver-side subscription row** exists with `role='receiver'`, `status='closed_by_receiver'`, `last_pushed_object_version=3`.

### Per-push residue assertions

3. **Three OBJECT_UPDATE residue pairs** on both ledgers (owner EMIT + receiver RECEIVE per push). Six entries total per side for the update phase.
4. **Object versions are monotonic** in the OBJECT_UPDATE residues' payload-decoded `object_version` field (1+initial mutation produces v2, v3, v4 in the three pushes; verify via the payload reconstruction).
5. **Each push's payload_hash byte-equal** between owner's EMIT and receiver's RECEIVE.

### Push ordering assertions

6. **Receiver's three OBJECT_UPDATE residues are sequentially ordered** in the ledger (residue.sequence monotonic, and payload object_versions also monotonic).
7. **Owner's three OBJECT_UPDATE EMIT residues** are likewise sequentially ordered.

### Subscribe / unsubscribe residue assertions

8. **One SUBSCRIBE residue pair** at the start (receiver EMIT → owner RECEIVE; owner EMIT ack → receiver RECEIVE ack — so two paired entries: subscribe and subscribe-ack).
9. **One UNSUBSCRIBE residue pair** at the end (same shape as #8).

### Slice 1 invariants survive

10. **All Slice 1 §9 #1–#17 assertions still hold** for any static-reference promotion in the same ObjectStore. (Tested by running a static promotion + fetch concurrently with the live promotion; their residues coexist; no cross-contamination.)

### Privacy invariants extend to LIVE mode

11. **§9 #15 (scope-filter)** for LIVE: each pushed `snapshot_state` and the third post-unsubscribe Object state's out-of-scope fields are NEVER present in any wire message, any receiver-side row, any payload_hash on the receiver's side. Same shape as Slice 1's §15 test, applied to OBJECT_UPDATE residues.
12. **§9 #16 (stolen-handle)** for LIVE: if Eve attempts to SUBSCRIBE with Bob's handle (sender != promotion.receiver), the owner's handler returns SubscribeDenied with reason `receiver_mismatch`. No subscription row created; no pushes sent to Eve. Paired denial residue on both Alice's and Eve's ledgers.

### Push-after-unsubscribe blocked

13. **Owner does NOT push after receiver UNSUBSCRIBE**. The mutation following the unsubscribe produces no OBJECT_UPDATE residue. The subscription row's `last_pushed_object_version` stays at 3 (the pre-unsubscribe push count).

### Expiry enforcement

14. **Owner does NOT push past expiry.** Construct a separate promotion with near-future expiry (5 seconds), subscribe, mutate just past expiry — the post-expiry mutation produces no push and the subscription row transitions to `status='expired'`.

### Drop-and-fetch resume

15. **Transient drop reconciliation.** Simulate a push failure (e.g., temporarily 503 on the receiver's listener), mutate the Object, restore the listener, mutate again. Receiver's callback fires for the post-restore mutation. Receiver, on detecting the gap, calls `fetch_object(handle)`; the returned state equals the CURRENT scoped state. After reconciliation, subsequent pushes resume normally.

### Cold reload

16. **Subscription state survives process restart.** Stop both processes mid-flow; restart; the `active_subscriptions` rows reload; subscription status is correctly resumed from disk.

If all 16 above hold AND all 17 Slice 1 §9 invariants hold concurrently, Slice 2 succeeds.

## 10. Build Sequence (Slice 2)

TDD discipline: tests first, then implementation. Each step ships as a green test suite before the next begins. Same play as Slice 1.

1. **ActiveSubscription model** (`models/primitives.py`)
   - Tests in `tests/unit/test_active_subscription_model.py`: field validation, role enum, status enum, status transitions (rejected transitions raise).

2. **ObjectUpdate wire schema** (`object/wire.py`)
   - Tests in `tests/unit/test_object_update_wire.py`: same discipline as `test_object_wire.py`; canonical encoding, content_hash recomputation invariant.

3. **SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE ack schemas** (`object/wire.py`)
   - Minimal Pydantic models (one `*_ack` per request op).

4. **Operation enum extension** (`models/primitives.py`)
   - Test in `tests/unit/test_operation_phase4.py` updated: enum has SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE; wire-compat with Slice 1 row formats.

5. **ObjectStore active_subscriptions table** (`object/store.py`)
   - Tests in `tests/unit/test_object_store_subscriptions.py`: record_subscription, get_subscription, status transitions, list_active_subscriptions_for_object.

6. **ObjectInboundHandler extensions** (`object/handler.py`)
   - Tests in `tests/unit/test_object_inbound_handler_live.py`: handle_subscribe (happy + denial cases), handle_unsubscribe, handle_object_update (happy + version regression + content_hash mismatch + expired).

7. **InboundGateway dispatch update** (`gateways/inbound.py`)
   - Tests in `tests/integration/test_gateway_phase4_live_dispatch.py`: SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE route to handler; consumer never invoked; existing Slice 1 dispatch unchanged.

8. **OutboundGateway bypass set update** (`gateways/outbound.py`)
   - Tests in `tests/integration/test_outbound_trust_op_bypass.py` updated: SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE also bypass policy.

9. **SDK live methods** (`sdk.py`)
   - Tests in `tests/unit/test_sdk_live_methods.py`: subscribe_to_object, unsubscribe_from_object, on_object_update registration. Mock adapter for happy + denial paths.

10. **SDK.update_object live-push extension** (`sdk.py`)
    - Tests in `tests/unit/test_sdk_update_object_pushes.py`: with active subscription, update_object triggers a push; without, it doesn't.

11. **SDK.fetch_object LIVE branch** (`sdk.py`)
    - Tests in `tests/unit/test_sdk_fetch_object_live.py`: LIVE handle's fetch returns current state, not frozen snapshot; no content_hash mismatch check for LIVE.

12. **Reconnect/resume integration** (`tests/integration/test_object_update_resume.py`)
    - Simulated transient failure + recovery via fetch.

13. **Slice 2 full roundtrip integration** (`tests/integration/test_live_promotion_roundtrip.py`)
    - The §9 assertion suite end-to-end. Two real Mesherra instances. Real A2A wire. Both static and live promotions in the same flow to prove no cross-contamination.

14. **Theory-aligner final audit**

Steps 1–6 are unit, no network. Steps 7–11 wire through the existing airlock. Steps 12–13 are integration with real listeners.

## 11. File Layout

```
mesherra/
├── src/mesherra/
│   ├── models/primitives.py            # +ActiveSubscription, +SubscriptionStatus enum
│   ├── object/
│   │   ├── store.py                    # +active_subscriptions table + 5 new methods
│   │   ├── handler.py                  # +handle_subscribe, +handle_unsubscribe, +handle_object_update
│   │   └── wire.py                     # +ObjectUpdate, +SubscribeAck, +UnsubscribeAck, +ObjectUpdateAck
│   ├── gateways/
│   │   ├── outbound.py                 # +SUBSCRIBE/UNSUBSCRIBE/OBJECT_UPDATE in _OUTBOUND_TRUST_OPS
│   │   └── inbound.py                  # +SUBSCRIBE/UNSUBSCRIBE/OBJECT_UPDATE in _INBOUND_TRUST_OPS
│   └── sdk.py                          # +subscribe_to_object, +unsubscribe, +on_object_update, extended update_object + fetch_object
├── tests/
│   ├── unit/
│   │   ├── test_active_subscription_model.py
│   │   ├── test_object_update_wire.py
│   │   ├── test_object_store_subscriptions.py
│   │   ├── test_object_inbound_handler_live.py
│   │   ├── test_sdk_live_methods.py
│   │   ├── test_sdk_update_object_pushes.py
│   │   └── test_sdk_fetch_object_live.py
│   └── integration/
│       ├── test_gateway_phase4_live_dispatch.py
│       ├── test_object_update_resume.py
│       └── test_live_promotion_roundtrip.py
└── demos/phase_4/
    ├── SPEC.md                         # main Slice 1 SPEC (unchanged; §14 points here)
    └── SLICE_2_SPEC.md                 # this file
```

## 12. What This Spec Deliberately Does Not Commit To

- **A2A `tasks/resubscribe` integration** for true server-side streaming. Slice 2 uses discrete request-response per push, reusing the Slice 1 wire surface. The implementer's choice between this and switching to streaming is deferred to Slice 3+; the `object-update-v1` schema is forward-compatible with either transport.
- **Buffered redelivery on disconnect.** §7.4 specifies the simpler drop-and-fetch model. Buffered ordered delivery is Slice 2.5+.
- **Per-push policy gate (bilateral fetch policy ARCH §3.7).** Same bypass as Slice 1. The deferral note in ARCH §3.7:164 continues to apply through Slice 2.
- **Multiple owner processes for one principal.** Slice 2 assumes one owner process per principal. Distributed-owner pushes (where multiple processes share active_subscriptions state) is Phase 5+.
- **Explicit unsubscribe before subscribe is idempotent / no-op.** Slice 2 spec rejects out-of-order UNSUBSCRIBE (unsubscribe with no active subscription returns SubscribeDenied with reason `not_active`).
- **Catch-up replay log.** Receiver does NOT get a replay of missed updates after reconnect. They get the current state via FETCH and continue forward. Replay is a future addition.
- **Pluggable subscription persistence** (Redis, etc.). SQLite v0; same future pluggability story as the rest of ObjectStore.
- **Exact retry backoff numbers in code.** §7.4 specifies `2s, 4s, 8s, 16s, 32s, 64s` cap; implementer's call on tuning constants. Spec pins the SHAPE (exponential, capped, retry-until-expiry).
- **Subscription persistence across re-promotion.** Slice 2 assumes the Promotion row is immutable (Slice 1 invariant). Re-promotion = new promotion_id = new subscription. Not a Slice 2 concern.
- **Bounded delivery between UNSUBSCRIBE ack and owner-side push cessation.** There is a narrow window where, between the owner emitting the UNSUBSCRIBE-ack and the receiver receiving it, the owner may emit one further OBJECT_UPDATE for a concurrent mutation. The receiver, by then, has discarded the subscription locally and the push will be NACK'd (or the receiver's handler will see the in-flight push and process it before learning about the unsubscribe). Slice 2 v0 accepts this race: at most one straggler push per unsubscribe. Bounded delivery (a fence that guarantees zero straggler pushes after UNSUBSCRIBE-ack returns) is a Slice 2.5+ enhancement.

## 13. Slice 2 Done Condition

Slice 2 is complete when:

- All Slice 1 done conditions still hold (`demos/phase_4/SPEC.md` §13).
- `pytest tests/unit/test_active_subscription_model.py` passes
- `pytest tests/unit/test_object_update_wire.py` passes
- `pytest tests/unit/test_object_store_subscriptions.py` passes
- `pytest tests/unit/test_object_inbound_handler_live.py` passes
- `pytest tests/unit/test_sdk_live_methods.py` passes
- `pytest tests/unit/test_sdk_update_object_pushes.py` passes
- `pytest tests/unit/test_sdk_fetch_object_live.py` passes
- `pytest tests/integration/test_gateway_phase4_live_dispatch.py` passes
- `pytest tests/integration/test_object_update_resume.py` passes
- `pytest tests/integration/test_live_promotion_roundtrip.py` passes — all 16 §9 assertions in this document hold
- Existing Slice 1 tests (all 503) still pass
- Final theory-aligner audit returns ALIGNED
- ARCH `§3.7`, `§13.3`, `§13.13` amended with Slice 2 deltas:
  - Live reference push pipeline documented
  - OBJECT_UPDATE inbound dispatch documented
  - active_subscriptions component documented (could be §13.14 or folded into §13.12 ObjectStore)
  - ARCH §3.7:164 deferral note updated: bilateral fetch policy commitment becomes "Slice 3+" (Slice 2 retains the same trust-op bypass as Slice 1; per §1 out-of-scope and §12)
  - ARCH §3.7:183 amended: the "live reference wire pattern is `SubscribeToTask` push" sentence updated to note Slice 2 uses per-push request-response messages over the existing wire; true server-streaming via `SubscribeToTask` / `tasks/resubscribe` is a Slice 3 optimization. The wire schema (`object-update-v1`) is forward-compatible with either transport.
- MeshyCal's MeetingObject is now buildable against this Mesherra surface (no MeshyCal code required for Slice 2 to ship; this is the Mesherra capability the MeetingObject will rely on)
