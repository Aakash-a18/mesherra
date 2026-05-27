# Phase 4 SPEC: Object Promotion Lifecycle

This document is the bridge between Mesherra's architecture (the *what* and *why*) and Phase 4 code (the *how*). It pins down the four artifacts the architecture defines but the code stubs only name:

1. The exact shape of `Object`, `Layer`, `Promotion`, and `PromotionHandle` Pydantic models
2. The exact wire shape of a `PromotionHandle` traveling across the boundary
3. The per-principal `ObjectStore` SQLite schema (parallel to `ProvenanceLedger`)
4. The end-state assertions for a static-reference promotion roundtrip

Phase 4 code is written *against* this spec. If the spec is wrong, the code is wrong; fix the spec first.

The work is partitioned into three slices, each independently shippable and verifiable:

| Slice | What ships | Why first |
|---|---|---|
| **1 — Static reference promotion** | Object + Layer + Promotion + PromotionHandle with static reference mode end-to-end. Counterpart receives a signed handle, fetches scoped data on demand, paired residue on both sides. | Smallest end-to-end demonstration. No subscription, no push, no irrevocable bytes. Proves the model. |
| **2 — Live reference promotion** | A2A `SubscribeToTask` integration. Owner pushes new content_hash on every update; counterpart receives signed envelopes; paired residue per update. | The actual mechanic MeshyCal's MeetingObject needs (§3.2 of MeshyCal/docs/ARCHITECTURE.md). |
| **3 — Copy promotion** | One-shot transfer of scoped bytes; no fetch endpoint; honor-system forward conditions; residue records the irrevocability. | Closes the architecture commitment from Mesherra §3.7. Smaller wire surface than live. |

This SPEC covers all three slices, with Slice 1 specified in full and Slices 2/3 specified as additive done-conditions at the end. **Start by reading sections 0–13 (Slice 1). Sections 14 (Slice 2) and 15 (Slice 3) are additive.**

## 0. Goal

Prove that Mesherra's Object/Layer/Promotion primitives work mechanically: an owner can create an Object in their Personal layer, scope a snapshot of it to a counterpart via a signed static reference Promotion, the counterpart can fetch the scoped data through the resulting PromotionHandle, and both ledgers record matching paired Residue entries for the promotion event and for every subsequent fetch. Without either party trusting the other in advance.

This is the smallest possible end-to-end demonstration of the Object/Layer model. It establishes the **owner-is-canonical** invariant (ARCH §3.7) in working code: only the owner can mutate, every observer reads through a scoped, signed, auditable handle, and the airlock remains the single boundary gate.

## 1. Scope

### In scope (Slice 1 must do these)

- Pydantic models for `Object`, `Layer`, `Promotion`, `PromotionHandle` (replacing the four `NotImplementedError` stubs in `mesherra/src/mesherra/models/primitives.py`)
- JSON Schema mirrors for `Object` (`object_v1.json`) and `PromotionHandle` (`promotion_handle_v1.json`) — the two that cross identity or wire boundaries
- Per-principal `ObjectStore` SQLite-backed persistence (parallels `ProvenanceLedger`)
- Snapshot-at-promotion semantics for static references (the content_hash in the handle is the snapshot's hash; later owner mutations do not affect what the counterpart sees through this handle)
- Scope-spec enforcement on every fetch (only allowed fields are returned)
- Owner-signed `PromotionHandle` (Ed25519 over canonical JCS bytes)
- Promotion → paired Residue entries (owner EMIT, counterpart RECEIVE) tied by `promotion_id`
- Fetch → paired Residue entries (one per fetch call, on both sides) tied by `promotion_id` + monotonic `fetch_sequence`
- Owner-is-canonical enforcement: counterpart cannot mutate the Object through any API path
- Expiry: handle includes an ISO-8601 expiry; fetch after expiry returns 410 Gone and writes a paired residue rejection
- SDK surface: `Mesherra.create_object()`, `Mesherra.promote()`, `Mesherra.fetch_object()`, `Mesherra.get_object()`, `Mesherra.list_promotions()`

### Out of scope for Slice 1 (deferred to Slice 2, Slice 3, or later phases)

| Out of scope | Why deferred |
|---|---|
| Live reference mode (A2A `SubscribeToTask` push) | Slice 2; static is the simpler case and exercises the same invariants |
| Copy mode (bytes on the wire, irrevocable) | Slice 3 |
| Revocation before expiry | Slice 1 ships expiry-based auto-revocation only; explicit revocation is Slice 2+ |
| Per-viewer field visibility on Promotion (more elaborate than scope spec) | Slice 2 (MeetingObject pressures this) |
| Re-promotion / chain of promotions | Not yet specified |
| Pluggable storage backend (Postgres, distributed) | SQLite v0 matches ProvenanceLedger; future per ARCH §13.8 |
| Per-fetch policy override (vs. promotion-time scope) | Slice 2+; Slice 1 uses promotion-time scope verbatim |
| Object schema validation against published payload schemas | Schema Registry is currently a stub; Slice 1 trusts the `schema_ref` field; full validation lands when Schema Registry ships |
| Cross-machine deployment | Single process, in-memory directory; matches Phase 1 pattern |

If any of the above creeps in during Slice 1 work, stop and reconsider.

## 2. The Object Schema

**Schema ID:** `mesherra.object/object-v1`
**Owner:** Mesherra (the trust layer)
**Phase 4 location:** authoritative Python type in `mesherra/src/mesherra/models/primitives.py` (the `Object` class gets a real body in Slice 1). JSON Schema mirror in `mesherra/src/mesherra/object/object_v1.json` for runtime validation.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "mesherra.object/object-v1",
  "title": "Mesherra Object v1",
  "description": "A passive resource (calendar, document, meeting agreement, etc.) owned by a single principal. The owner's stack holds canonical state; every observer reads through a scoped Promotion.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version", "object_id", "owner", "home_layer", "mutability",
    "schema_ref", "state", "object_version", "content_hash",
    "created_at", "updated_at"
  ],
  "properties": {
    "version": { "const": 1, "description": "Schema version of this entry." },
    "object_id": {
      "description": "Stable Object identifier, UUID4. Assigned at create. Never changes.",
      "type": "string",
      "minLength": 1
    },
    "owner": {
      "description": "Principal that canonically owns this Object. Mutations are owner-only.",
      "type": "string",
      "minLength": 1
    },
    "home_layer": {
      "description": "Default visibility layer when no active Promotion grants a viewer access.",
      "type": "string",
      "enum": ["personal", "shared", "public"]
    },
    "mutability": {
      "description": "static: snapshot at promotion time. live: continuously updated reference (Slice 2).",
      "type": "string",
      "enum": ["static", "live"]
    },
    "schema_ref": {
      "description": "Schema ID for the state payload (e.g., meshycal.scheduling/calendar-v1).",
      "type": "string",
      "minLength": 1
    },
    "state": {
      "description": "The actual Object content. Free-form object; structure governed by schema_ref.",
      "type": "object"
    },
    "object_version": {
      "description": "Monotonic per-Object version. Starts at 1; bumps on every mutation.",
      "type": "integer",
      "minimum": 1
    },
    "content_hash": {
      "description": "SHA-256 (hex) of JCS(state). Recomputed on every mutation.",
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "created_at": {
      "description": "ISO 8601 UTC timestamp of creation.",
      "type": "string",
      "format": "date-time"
    },
    "updated_at": {
      "description": "ISO 8601 UTC timestamp of last mutation (== created_at at create).",
      "type": "string",
      "format": "date-time"
    }
  }
}
```

**Construction invariants:**

- `object_id` is generated by the ObjectStore at create; not caller-supplied.
- `created_at == updated_at` at create.
- `object_version == 1` at create.
- `content_hash` is computed by the model itself (validator), not by the caller. Passing a wrong `content_hash` raises ValidationError.

**Mutation semantics (Slice 1):**

- Only `mesherra.sdk.Mesherra.update_object(object_id, new_state)` mutates. It bumps `object_version`, recomputes `content_hash`, updates `updated_at`, and persists.
- The Object is Pydantic-frozen at the model level; mutation produces a new Object instance (functional update), persisted via ObjectStore.put.
- The SDK call enforces `requesting_principal == owner` and raises `OwnershipError` otherwise. **This is the owner-is-canonical gate.**

## 3. The Layer Type

**Schema ID:** not separately mirrored — `Layer` is a value type, not a stored entity in Slice 1.
**Phase 4 location:** `mesherra/src/mesherra/models/primitives.py` `Layer` class.

Layer is a frozen Pydantic model describing "who can see an Object right now." Constructed on demand by the SDK to answer `is_visible_to(viewer)` queries; not persisted as its own row.

```python
class Layer(BaseModel):
    kind: LayerKind                       # personal | shared | public
    members: frozenset[str]               # principal_ids with visibility (empty for public)

    def is_visible_to(self, principal: str) -> bool: ...
```

Visibility rules:

| kind | members | visible to |
|---|---|---|
| `personal` | `{owner}` | only the owner |
| `shared` | `{owner, *counterparts_with_active_promotion}` | listed members |
| `public` | `frozenset()` | any authenticated principal |

**Why Layer isn't its own SQLite table in Slice 1:** ARCH §3.3 says "Layer-membership is per-viewer and per-context… a *relation* between Object and viewer, not a property of the Object." The persistent state of the relation lives on the Object (its `home_layer`) plus the active Promotions (which grant additional visibility). Layer is the *computed answer* to a visibility query, not a stored entity. Slice 2 may revisit if multi-Object layer groupings become useful.

## 4. The Promotion Type

**Schema ID:** not separately mirrored — `Promotion` is the *local event* of issuing a handle. Its persisted form lives in `ObjectStore`'s `promotions` table.
**Phase 4 location:** `mesherra/src/mesherra/models/primitives.py` `Promotion` class.

A Promotion is the signed event that records "owner authorized counterpart to perceive Object Z under scope S with mode M, expiring at T." It produces:

1. A `PromotionHandle` (the wire artifact — see §5) for transmission to the counterpart
2. A pair of paired Residue entries (owner's EMIT, counterpart's RECEIVE) with `operation = "promote"`
3. A row in the owner's `promotions` table tying `promotion_id` to `(object_id, snapshot_content_hash, scope, mode, expiry, receiver)`

```python
class Promotion(BaseModel):
    promotion_id: str                          # stable UUID, assigned at create
    object_id: str
    owner: str
    receiver: str
    mode: PromotionMode                        # reference | copy
    mutability: Mutability                     # static | live
    scope: dict[str, Any]                      # field allow-list / slice
    expiry: str                                # ISO 8601 UTC
    snapshot_content_hash: str                 # the content_hash at promotion-creation time
    snapshot_state: dict[str, Any] | None      # static: stored snapshot; live: None
    fetch_endpoint: str | None                 # reference: owner's airlock URL; copy: None
    created_at: str
```

**Slice 1 constraints:**

- `mode == PromotionMode.REFERENCE` only. Copy is Slice 3.
- `mutability == Mutability.STATIC` only. Live is Slice 2.
- `snapshot_state` is populated at promotion-create with the scoped slice of the Object's current `state` (other fields filtered per `scope`). Stored once, returned on every fetch.
- `fetch_endpoint` is the owner's airlock URL: `{owner_endpoint}/mesherra/objects/fetch/{promotion_id}`.
- `expiry` is required; missing or past-dated expiry raises ValidationError at construct.

### 4.1 The `scope` field

The `scope` spec is a JSON object whose semantics in Slice 1 is **field allow-list only**:

```json
{ "fields": ["candidates", "duration_minutes"] }
```

The promotion-create step computes `snapshot_state = {k: v for k, v in object.state.items() if k in scope["fields"]}` and stores it on the Promotion row.

Future slices may extend `scope` with slice predicates (e.g., date range), per-viewer field visibility, or schema-aware projection. Slice 1 stays minimal.

## 5. The PromotionHandle Schema (wire-format)

**Schema ID:** `mesherra.object/promotion-handle-v1`
**Owner:** Mesherra (the trust layer)
**Phase 4 location:** authoritative Python type in `mesherra/src/mesherra/models/primitives.py` (the `PromotionHandle` class gets a real body in Slice 1). JSON Schema mirror in `mesherra/src/mesherra/object/promotion_handle_v1.json`.

The PromotionHandle is the **only** artifact that crosses the boundary at promotion time. It is signed by the owner; the receiver verifies the signature against the owner's public key (resolved through the Identity Directory). The full Object state never crosses at promotion time in reference mode — only the handle does.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "mesherra.object/promotion-handle-v1",
  "title": "Mesherra PromotionHandle v1",
  "description": "The signed wire artifact for an Object promotion. Travels in the A2A Message metadata. Carries enough for the receiver to fetch scoped data and verify its authenticity, never enough for them to know the full Object.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version", "promotion_id", "object_id", "owner", "receiver",
    "schema_ref", "mode", "mutability",
    "scope", "snapshot_content_hash", "expiry", "issued_at",
    "owner_signature"
  ],
  "properties": {
    "version": { "const": 1 },
    "promotion_id": {
      "description": "Stable promotion ID, UUID4. Distinct from object_id.",
      "type": "string", "minLength": 1
    },
    "object_id": {
      "description": "The Object being promoted. Stable for the lifetime of the Object.",
      "type": "string", "minLength": 1
    },
    "owner": {
      "description": "Principal who owns the Object and authorized this promotion.",
      "type": "string", "minLength": 1
    },
    "receiver": {
      "description": "Principal authorized to perceive this Object via this handle.",
      "type": "string", "minLength": 1
    },
    "schema_ref": {
      "description": "Schema ID of the Object state (e.g., meshycal.scheduling/calendar-v1).",
      "type": "string", "minLength": 1
    },
    "mode": {
      "description": "reference: fetch on demand. copy: bytes in scoped_payload (Slice 3).",
      "type": "string", "enum": ["reference", "copy"]
    },
    "mutability": {
      "description": "static: snapshot at promotion time. live: streaming updates (Slice 2).",
      "type": "string", "enum": ["static", "live"]
    },
    "scope": {
      "description": "Field allow-list (Slice 1) governing what the receiver may perceive.",
      "type": "object"
    },
    "snapshot_content_hash": {
      "description": "SHA-256 (hex) of JCS(scoped snapshot at promotion-creation time). The receiver verifies every fetch returns bytes whose canonical hash matches this.",
      "type": "string", "pattern": "^[0-9a-f]{64}$"
    },
    "fetch_endpoint": {
      "description": "Reference mode only: owner's airlock URL where scoped data can be fetched. Absent for copy mode.",
      "type": "string"
    },
    "scoped_payload": {
      "description": "Copy mode (Slice 3) only: the bytes themselves, canonical-encoded. Absent for reference mode.",
      "type": "string"
    },
    "expiry": {
      "description": "ISO 8601 UTC timestamp when this handle ceases to be valid.",
      "type": "string", "format": "date-time"
    },
    "issued_at": {
      "description": "ISO 8601 UTC timestamp when this handle was signed by the owner.",
      "type": "string", "format": "date-time"
    },
    "owner_signature": {
      "description": "Ed25519 signature (base64) over the canonical JSON of this handle with owner_signature omitted. Verified against owner's public key resolved through the Identity Directory.",
      "type": "string", "minLength": 1
    }
  }
}
```

**Cross-field invariants (validators):**

- `mode == "reference"` → `fetch_endpoint` required; `scoped_payload` absent
- `mode == "copy"` → `scoped_payload` required; `fetch_endpoint` absent (Slice 3 only)
- `expiry > issued_at` (validator)
- `owner != receiver` (a principal cannot promote to themselves)
- Canonical signing rule: signature is over `canonical_json(handle.to_signing_payload())` where `to_signing_payload()` returns the dict with `owner_signature` *omitted* (same rule as Residue per Phase 1 SPEC §4)

## 6. Canonicalization Commitment

Same as Phase 1 SPEC §4. Reproduced here for the new types:

- **Algorithm:** JSON Canonicalization Scheme — RFC 8785 (JCS)
- **Library:** `jcs` (already in `pyproject.toml`)
- **Hash function:** SHA-256
- **Signature scheme:** Ed25519 (`cryptography` library)
- **Canonicalization rule for signed objects:** when computing signature input, encode with the signature field *omitted* (not blanked — removed). Same rule applies to `Residue` (Phase 1) and `PromotionHandle` (Phase 4).
- **Object `content_hash`:** SHA-256(JCS(state)) — the canonical bytes of the `state` dict only (not the whole Object). This means changing only metadata like `updated_at` does NOT change `content_hash`; only changes to `state` do.

## 7. Storage: ObjectStore

**Location:** `mesherra/src/mesherra/object/store.py`

Parallel to `ProvenanceLedger` (`mesherra/src/mesherra/provenance/ledger.py`):

- One SQLite file per principal
- Self-describing: `object_meta` table records the owning principal — pointing the wrong DB at a Store fails loudly
- Two tables:

```sql
CREATE TABLE object_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE objects (
    object_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,            -- denormalized for indexed lookup (also asserts ownership invariant at storage layer)
    home_layer TEXT NOT NULL,       -- denormalized for indexed lookup
    object_version INTEGER NOT NULL CHECK (object_version >= 1),
    object_json TEXT NOT NULL,      -- the full Object as canonical JSON; source of truth
    content_hash TEXT NOT NULL,     -- denormalized for indexed lookup
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_objects_owner ON objects(owner);
CREATE INDEX idx_objects_content_hash ON objects(content_hash);

-- Storage rule: every column outside object_json is denormalized for query.
-- object_json remains the source of truth; on a row read, the SPEC requires
-- the loader to reconstruct the Object from object_json and assert the
-- denormalized columns match. Drift between the two is a corruption signal.

CREATE TABLE promotions (
    promotion_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    receiver TEXT NOT NULL,
    mode TEXT NOT NULL,
    mutability TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    snapshot_state_json TEXT,        -- static reference: stored snapshot; null otherwise
    snapshot_content_hash TEXT NOT NULL,
    expiry TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_promotions_object ON promotions(object_id);
CREATE INDEX idx_promotions_receiver ON promotions(receiver);
```

**API surface (Slice 1):**

```python
class ObjectStore:
    def __init__(self, db_path: Path, owner_principal_id: str) -> None: ...
    def put(self, obj: Object) -> None: ...           # insert or update by object_id
    def get(self, object_id: str) -> Object: ...      # raises ObjectNotFound
    def list(self) -> list[Object]: ...
    def record_promotion(self, promotion: Promotion) -> None: ...
    def get_promotion(self, promotion_id: str) -> Promotion: ...
    def list_promotions_for_object(self, object_id: str) -> list[Promotion]: ...
    def list_promotions_for_receiver(self, receiver: str) -> list[Promotion]: ...
```

Counterpart side: the same ObjectStore class is used to store **received** PromotionHandles in a separate database file (different `owner_principal_id` in meta). Slice 1 simplification: handles received from others land in the counterpart's ObjectStore via `record_handle()` (TBD; may need a second table `received_handles`). Implementer's call; the constraint is that handles persist across process restart so a fetch days later still works.

## 8. Airlock Integration

The airlock (`mesherra/src/mesherra/gateways/`) is the single boundary gate (ARCH §6). Phase 4 adds two new flows through it:

### 8.1 Outbound: promotion send

`Mesherra.promote(object_id, receiver, scope, expiry)`:

1. Load Object from ObjectStore; assert `requesting_principal == owner` → else `OwnershipError`
2. Compute scoped snapshot per `scope.fields`
3. Construct Promotion, sign PromotionHandle (Ed25519 over canonical JCS bytes with `owner_signature` omitted)
4. Persist Promotion in ObjectStore
5. Hand to outbound gateway as a SendClaim with `operation = "promote"` and `payload = canonical(handle)`; gateway runs PolicyEngine (block-list check), writes EMIT Residue with `operation = "promote"`, sends via A2A
6. Counterpart's inbound gateway receives, verifies owner's signature on the handle (via Directory), verifies SendClaim signature, runs PolicyEngine (inbound accept rule), writes RECEIVE Residue with `operation = "promote"`, persists handle in counterpart's ObjectStore (received_handles table)

### 8.2 Outbound: fetch request

`Mesherra.fetch_object(handle)` (counterpart side):

1. Load handle from counterpart's ObjectStore (or accept as argument)
2. Construct SendClaim with `operation = "fetch"`, `payload = {promotion_id, fetch_sequence: <monotonic per-handle>}`
3. Outbound gateway signs, writes EMIT Residue with `operation = "fetch"`, sends to owner's `fetch_endpoint`
4. Owner's inbound gateway verifies, looks up promotion by `promotion_id`, checks `now < expiry`, returns `snapshot_state` (static) as the response payload, writes EMIT Residue with `operation = "fetch_response"`
5. Counterpart's inbound gateway receives, verifies, validates `SHA-256(JCS(snapshot_state)) == handle.snapshot_content_hash` → else `IntegrityError`, writes RECEIVE Residue with `operation = "fetch_response"`, returns the snapshot to caller

### 8.3 Two new Operation enum values

`Operation` enum (currently `proposal | counter | acceptance | rejection`) gains:

- `promote` — issuing a PromotionHandle
- `fetch` — counterpart requesting scoped data
- `fetch_response` — owner responding with scoped data
- `fetch_denied` — owner rejecting (expired, revoked, scope violation)

Residue uniqueness backstop (ARCH §11.1) currently uses `UNIQUE(task_id, action_type, operation)`. Phase 4 needs to add a dedup dimension for repeated fetches under the same handle: the new index is `UNIQUE(task_id, action_type, operation)` (unchanged — each fetch is a distinct A2A Task with its own task_id; the SendClaim nonce + clock-skew handle replay).

**Wire compatibility note:** existing ledgers contain rows where `operation IN ('proposal','counter','acceptance','rejection')`. Adding `promote`, `fetch`, `fetch_response`, `fetch_denied` is **additive** — the SQLite `operation` column is plain TEXT with no CHECK constraint, so old rows are unaffected and new rows simply use the new values. A future strict-enum migration would need to be aware of the Phase 4 additions; this SPEC pins them as v1 of the extended set.

## 9. End-State Assertions (Slice 1)

After a successful Slice 1 run — owner creates Object, promotes (static reference) to counterpart, counterpart fetches twice (once immediately, once after the owner mutates) — the following must hold:

### Per-store structural assertions

For owner's ObjectStore:

1. **The Object exists** with `object_version == 2` (post-mutation).
2. **The Promotion exists** with `mode == "reference"`, `mutability == "static"`, `snapshot_content_hash` equal to the content_hash of the Object at the moment of promotion (NOT the post-mutation hash).
3. **`snapshot_state` is the scoped subset** of the Object's state at promotion time.

For counterpart's ObjectStore:

4. **The received handle exists** with `owner_signature` verifying against owner's public key.
5. **No Object exists in counterpart's store with `owner == counterpart`** for this `object_id` — the receiver has the handle, not the canonical Object.

### Per-ledger structural assertions (each side)

6. **Promotion residue pair:** owner has an EMIT entry with `operation == "promote"`; counterpart has a RECEIVE entry with `operation == "promote"`. Both reference the same `promotion_id` in their payload_hash chain (via the canonical PromotionHandle hash).
7. **First-fetch residue pair:** owner has an EMIT `fetch_response` entry; counterpart has matching emit+receive entries for the fetch and the response. `payload_hash` of the fetch_response equals `SHA-256(JCS(snapshot_state))`.
8. **Second-fetch residue pair:** identical structure as #7, with monotonically-increasing sequence numbers. The `payload_hash` is **identical to the first fetch's response** (static reference → snapshot unchanged despite owner mutation).
9. **Hash chain integrity** preserved on both ledgers (Phase 1 SPEC §5 assertion #2 still holds with Phase 4 entries).
10. **All signatures verify** (Phase 1 SPEC §5 assertion #3 holds for new operations).

### Cross-ledger paired assertions

11. **`payload_hash` byte-equal** between owner's EMIT promote entry and counterpart's RECEIVE promote entry.
12. **`payload_hash` byte-equal** between owner's EMIT fetch_response and counterpart's RECEIVE fetch_response (for both fetches).
13. **Counterpart cannot mutate:** invoking `Mesherra.update_object(object_id, new_state)` on the counterpart's SDK raises `OwnershipError` and writes nothing to either ledger.
14. **Expiry enforcement:** after `expiry`, a third fetch returns `fetch_denied`; counterpart receives signed denial; both ledgers record paired `fetch_denied` residue.

### Privacy invariants (the load-bearing scope assertions)

15. **Scope filter actually filters.** The fixture Object's `state` includes a field `not_in_scope_field` whose key is NOT listed in the promotion's `scope.fields`. After every fetch in the run:
    - the counterpart's fetched payload does NOT contain `not_in_scope_field`
    - the counterpart's RECEIVE `fetch_response` Residue `payload_hash` matches `SHA-256(JCS(scoped_payload))` where scoped_payload omits `not_in_scope_field`
    - the owner's EMIT `fetch_response` Residue carries the same `payload_hash`
    The field never appears in any wire payload, any handle, or any counterpart-side store. Without this assertion an implementation that silently ignores `scope.fields` would still pass §9 #1–#14.
16. **Stolen handle rejected.** A third principal `eve` (not owner, not receiver) attempts `Mesherra.fetch_object(receiver_handle)` carrying the handle in some out-of-band way. The owner's inbound gateway rejects the fetch because `sender_principal_id != handle.receiver` (the handle binds to a specific receiver). Both ledgers record a paired `fetch_denied` Residue with a `reason = "receiver_mismatch"` field. No scoped data leaves the owner's stack. This pins the handle-to-receiver binding as a real invariant, not an honor-system field.

### Overall assertion

17. The two ObjectStore SQLite files plus the two ledger files can be re-loaded after the demo terminates, all signatures re-verified, all hash chains re-verified, and all 16 above assertions re-evaluated, without the running process.

If all 17 assertions hold, Slice 1 succeeds.

## 10. Build Sequence (Slice 1)

TDD discipline: tests first, then implementation. Each step ships as a green test suite before the next begins.

1. **Models — Object** (`mesherra/src/mesherra/models/primitives.py`)
   - Tests in `tests/unit/test_object_model.py`: construction, field validation, content_hash determinism, frozen-ness, JSON-schema mirror agreement.
   - Replace `NotImplementedError` stub at line 336 with real Pydantic model.
   - Add `mesherra/src/mesherra/object/object_v1.json` (JSON Schema mirror).
2. **Models — Layer**
   - Tests in `tests/unit/test_layer_model.py`: kind constraints, member-set semantics, is_visible_to.
   - Replace stub at line 353. No JSON mirror (value type only).
3. **Models — Promotion + PromotionHandle**
   - Tests in `tests/unit/test_promotion_model.py` and `tests/unit/test_promotion_handle_model.py`.
   - Replace stubs at lines 394 and 420.
   - Add `mesherra/src/mesherra/object/promotion_handle_v1.json` mirror.
   - Tests cover: cross-field validators (mode + fetch_endpoint vs scoped_payload), expiry > issued_at, owner != receiver, signing payload omission.
4. **ObjectStore** (`mesherra/src/mesherra/object/store.py`)
   - Tests in `tests/unit/test_object_store.py`: put/get round-trip, list, record_promotion, lookup helpers, self-describing meta, wrong-principal rejection.
   - Implement SQLite schema + API per §7.
5. **Crypto extension** (no code change expected; `Signer.sign(canonical_bytes)` and `Verifier.verify(canonical_bytes, sig)` already work; verify with a Phase 4 signing test).
6. **SDK surface** (`mesherra/src/mesherra/sdk.py`)
   - Replace deferred-helper `NotImplementedError`s at lines 254 and 261 (the `create_object` / `promote` helpers) with implementations.
   - Add `update_object`, `fetch_object`, `get_object`, `list_promotions`.
   - Owner-is-canonical gate: `update_object` raises `OwnershipError` if requester != owner.
7. **Gateway integration** (`mesherra/src/mesherra/gateways/outbound.py` and `inbound.py`)
   - Wire the four new operations (`promote`, `fetch`, `fetch_response`, `fetch_denied`) through the airlock.
   - Tests in `tests/integration/test_promotion_gateway.py`: outbound signs handle, writes EMIT residue; inbound verifies, persists, writes RECEIVE residue.
8. **Fetch endpoint** (FastAPI handler in the existing identity server pattern, or a small new module)
   - Tests prove fetch returns scoped snapshot, fetch after expiry returns 410, paired residue on both sides.
9. **Integration test** (`tests/integration/test_object_promotion_roundtrip.py`)
   - The end-state assertion script. Runs the full Slice 1 flow and evaluates all 15 assertions.

Steps 1–4 are pure-Mesherra and can run as unit tests with zero network. Step 5 is a sanity-check. Step 6 introduces the SDK surface. Steps 7–9 are integration through the existing airlock + A2A SDK.

## 11. File Layout

```
mesherra/
├── src/mesherra/
│   ├── models/primitives.py            # Object, Layer, Promotion, PromotionHandle get bodies
│   ├── object/                         # NEW module
│   │   ├── __init__.py
│   │   ├── store.py                    # ObjectStore (parallels provenance/ledger.py)
│   │   ├── object_v1.json              # JSON Schema mirror for Object
│   │   └── promotion_handle_v1.json    # JSON Schema mirror for PromotionHandle
│   ├── gateways/
│   │   ├── outbound.py                 # +promote, +fetch operations
│   │   └── inbound.py                  # +promote, +fetch, +fetch_response handling
│   └── sdk.py                          # +create_object, +promote, +fetch_object, +update_object
├── tests/
│   ├── unit/
│   │   ├── test_object_model.py        # NEW
│   │   ├── test_layer_model.py         # NEW
│   │   ├── test_promotion_model.py     # NEW
│   │   ├── test_promotion_handle_model.py  # NEW
│   │   └── test_object_store.py        # NEW
│   └── integration/
│       ├── test_promotion_gateway.py   # NEW
│       └── test_object_promotion_roundtrip.py  # NEW (the §9 assertions)
└── demos/phase_4/
    └── SPEC.md                         # this file
```

## 12. What this spec deliberately does not commit to

- **Wire format for the fetch request/response in transit.** Whether the fetch travels as a plain A2A Message with a `mesherra/object-fetch-v1` payload schema, or via an HTTP sidecar on the same `fetch_endpoint` — implementer's call. Constraint: the fetch must produce paired residue on both sides exactly like a Phase 1 message exchange.
- **Exact SQLite DDL.** The §7 schema is illustrative; column-name details are implementer's call. Constraints: append-only-style behavior on `promotions` (no update/delete in Slice 1), self-describing meta, indexed lookup.
- **Snapshot storage for live promotions.** Slice 2 will need a different shape; Slice 1 just stores the snapshot inline on the `promotions` row.
- **Authorization beyond owner-is-canonical.** Slice 1 says "only owner can mutate." Multi-agent delegation (the owner's butler authorizing a sub-agent to act for them) is Phase 5+.
- **Error model.** Custom exception classes (`OwnershipError`, `IntegrityError`, `PromotionExpired`, `ObjectNotFound`) are introduced as needed; type hierarchy can stabilize across slices.
- **Performance.** Two Objects, a handful of promotions, two ledgers per process is trivial. Indexing strategy beyond the explicit indices in §7 is implementer's call.

## 13. Slice 1 Done Condition

Slice 1 is complete when:

- `pytest tests/unit/test_object_model.py` passes
- `pytest tests/unit/test_layer_model.py` passes
- `pytest tests/unit/test_promotion_model.py` passes
- `pytest tests/unit/test_promotion_handle_model.py` passes
- `pytest tests/unit/test_object_store.py` passes
- `pytest tests/integration/test_promotion_gateway.py` passes
- `pytest tests/integration/test_object_promotion_roundtrip.py` passes — all 17 assertions in §9 hold (including #15 scope-filter and #16 stolen-handle privacy invariants)
- Existing Phase 1/2/3 tests (200+ test functions) still pass
- `delegation.json`, MeshyCal's MeetingObject, and Schema Registry wiring remain out of scope (separate downstream work)
- ARCHITECTURE.md §13 has been amended with a §13.12 entry for the new `ObjectStore` component (parallel to §13.7 Directory Store and §13.8 Provenance Ledger)

## 14. Slice 2 (live reference, additive) — see SLICE_2_SPEC.md

Slice 2 is the additive build on top of Slice 1 for **live reference promotion**: the owner pushes updates to subscribed receivers as the Object mutates, rather than the receiver pulling a frozen snapshot.

The full implementable spec for Slice 2 — wire schemas, ObjectStore extensions, SDK surface, airlock pipeline, end-state assertions, build sequence — lives in `demos/phase_4/SLICE_2_SPEC.md`. That file is to Slice 2 what §0–13 of this file are to Slice 1.

High-level done condition (the headline; full breakdown in `SLICE_2_SPEC.md` §13):

- All Slice 1 done conditions still hold
- `Object.mutability == "live"` supported end-to-end with paired Residue per push
- Subscription lifecycle (subscribe → updates → unsubscribe / expiry) works on both sides
- Subscription state survives process restart
- Transient transport drops recoverable via receiver-initiated FETCH reconciliation
- MeshyCal's MeetingObject buildable against this Mesherra surface

## 15. Slice 3 Done Condition (copy mode, additive)

Slice 3 is complete when Slices 1 and 2 conditions still hold AND:

- `PromotionMode.COPY` is supported: scoped bytes travel in `PromotionHandle.scoped_payload` (canonical JCS, signed); no `fetch_endpoint`
- Residue on both sides records `copy` mode explicitly; the entry includes any owner-attached terms (honor-system forward conditions)
- Owner has no API path to revoke a copy promotion (the architecture commitment per ARCH §3.7)
- Tests prove: receiver gets bytes immediately at promotion time; later owner mutations do not affect what the receiver holds; an attempt to revoke fails with `RevocationNotPermittedOnCopy`
