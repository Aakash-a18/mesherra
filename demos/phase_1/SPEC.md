# Phase 1 Demo Spec

This document is the bridge between Tesherra's architecture (the *what* and *why*) and Phase 1 code (the *how*). It pins down four artifacts the reviewer flagged as hand-waved in the architecture:

1. The exact JSON for `meshycal.scheduling/proposal-v1`
2. The exact JSON for the residue entry (`tesherra.provenance/entry-v1`)
3. The canonicalization commitment (JCS, the `jcs` Python library, SHA-256)
4. The end-state assertion (both sides hold byte-equal, signature-verifying entries)

Phase 1 code is written *against* this spec. If the spec is wrong, the code is wrong; fix the spec first.

## 0. Goal

Prove that Tesherra's provenance layer works mechanically: two principals on the same host can exchange a structured payload, sign it independently, write matching entries into their own append-only ledgers, and verify after the fact that both ledgers agree on what happened — without trusting each other's claims.

This is the smallest possible end-to-end demonstration of the trust layer. Nothing else from the architecture is exercised. No identity verification, no scoped disclosure, no policy engine, no schema registry, no guest principals, no UI, no LLM.

## 1. Scope

### In scope (Phase 1 must do these)

- Define and use the `meshycal.scheduling/proposal-v1` schema (locally; no Schema Registry lookup)
- Define and use the `tesherra.provenance/entry-v1` schema (the residue entry format)
- Canonical JSON encoding per RFC 8785 (JCS)
- SHA-256 content hashing of canonical bytes
- Ed25519 signing and verification of residue entries
- Append-only SQLite-backed Provenance Ledger with hash-chain integrity
- Minimal Tesherra SDK surface: `attest()`, `get_residue_chain()`, message send/receive plumbing
- Minimal A2A SDK Adapter wired to send/receive Messages over localhost
- Two deterministic Python scheduling agents (Agent A and Agent B) exercising the round-trip
- An end-state assertion script that verifies the demo succeeded

### Explicitly out of scope (Phase 1 must NOT do these)

| Out of scope | Why deferred |
|---|---|
| LLM in the scheduling logic | Adds debugging surface, contributes nothing to the trust-layer demo |
| Real calendar integration (Google, Apple, Microsoft) | OAuth and rate limits add friction; build-discipline #9 forbids real user data anyway |
| Identity Directory / AgentCard verification | Phase 2 |
| Policy Engine and scoped disclosure | Phase 3 |
| Schema Registry (signed, remote schemas) | Phase 3; for Phase 1, schemas are hardcoded locally |
| Guest principal lifecycle | Phase 1.5 |
| Mobile / web UI | Not needed for a mechanical demo; CLI output suffices |
| Cross-machine deployment | Single process, two ports on localhost |
| Network resilience (retries, timeouts) | Localhost is reliable |

If any of the above creeps in during Phase 1 work, stop and reconsider.

## 2. The Proposal Schema

**Schema ID:** `meshycal.scheduling/proposal-v1`
**Owner:** MeshyCal (the consumer Delegation)
**Phase 1 location:** hardcoded in `MeshyCal/demos/phase_1/schemas/proposal_v1.json`. Schema Registry registration happens in Phase 3.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "meshycal.scheduling/proposal-v1",
  "title": "MeshyCal Scheduling Proposal v1",
  "description": "Candidate meeting time slots proposed by one MeshyCal scheduling agent to another. Carries only candidate timestamps and duration; never carries calendar contents, titles, or attendee identities.",
  "type": "object",
  "additionalProperties": false,
  "required": ["candidates", "duration_minutes"],
  "properties": {
    "candidates": {
      "description": "Proposed meeting start times in UTC (ISO 8601). Ordered by sender preference.",
      "type": "array",
      "items": { "type": "string", "format": "date-time" },
      "minItems": 1,
      "maxItems": 10,
      "uniqueItems": true
    },
    "duration_minutes": {
      "description": "Desired meeting duration in whole minutes.",
      "type": "integer",
      "minimum": 5,
      "maximum": 480
    }
  }
}
```

**Example payload:**

```json
{
  "candidates": [
    "2026-05-26T14:00:00Z",
    "2026-05-27T10:00:00Z",
    "2026-05-28T16:30:00Z"
  ],
  "duration_minutes": 30
}
```

A counter-proposal uses the same schema. An acceptance is a proposal with `candidates.length == 1` (the chosen slot). This collapses three message types into one for Phase 1; Phase 2+ will likely split them.

## 3. The Residue Entry Schema

**Schema ID:** `tesherra.provenance/entry-v1`
**Owner:** Tesherra (the trust layer)
**Phase 1 location:** authoritative Python type in `tesherra/src/tesherra/models/primitives.py` (the Residue model gets a real body in Phase 1). JSON Schema mirror in `tesherra/src/tesherra/provenance/entry_v1.json` for runtime validation.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "tesherra.provenance/entry-v1",
  "title": "Tesherra Provenance Ledger Entry v1",
  "description": "An append-only, signed entry in a single principal's residue ledger. Each entry records one action this principal took or observed.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "ledger_owner",
    "task_id",
    "context_id",
    "sequence",
    "previous_hash",
    "timestamp",
    "actor",
    "counterpart",
    "action_type",
    "operation",
    "payload_hash",
    "payload_schema",
    "signature"
  ],
  "properties": {
    "version": {
      "description": "Schema version of this entry.",
      "const": 1
    },
    "ledger_owner": {
      "description": "Principal that owns this ledger shard. All entries in this ledger belong to this principal.",
      "type": "string"
    },
    "task_id": {
      "description": "The A2A task.id this entry pertains to.",
      "type": "string"
    },
    "context_id": {
      "description": "The A2A context_id tying multi-turn interactions together.",
      "type": "string"
    },
    "sequence": {
      "description": "Monotonic per-ledger entry index, starting at 0.",
      "type": "integer",
      "minimum": 0
    },
    "previous_hash": {
      "description": "SHA-256 content hash of the previous entry in this ledger (hex). Empty string for sequence=0.",
      "type": "string",
      "pattern": "^([0-9a-f]{64}|)$"
    },
    "timestamp": {
      "description": "ISO 8601 UTC timestamp of when this entry was recorded.",
      "type": "string",
      "format": "date-time"
    },
    "actor": {
      "description": "Principal that performed the action. For emit entries this equals ledger_owner; for receive entries it is the remote principal.",
      "type": "string"
    },
    "counterpart": {
      "description": "Principal on the other side of the interaction.",
      "type": "string"
    },
    "action_type": {
      "description": "Direction of the action from this ledger's perspective.",
      "type": "string",
      "enum": ["emit", "receive"]
    },
    "operation": {
      "description": "What kind of action it was.",
      "type": "string",
      "enum": ["proposal", "counter", "acceptance", "rejection"]
    },
    "payload_hash": {
      "description": "SHA-256 (hex) of the canonical JSON encoding (JCS) of the payload referenced by this entry.",
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "payload_schema": {
      "description": "Schema ID of the payload that was hashed.",
      "type": "string"
    },
    "signature": {
      "description": "Ed25519 signature (base64) over the canonical JSON encoding of this entry with the signature field omitted. Verified against actor's public key.",
      "type": "string"
    }
  }
}
```

**Example matched pair of entries (Agent A proposes to Agent B):**

Agent A's ledger:

```json
{
  "version": 1,
  "ledger_owner": "user-a@phase1.local",
  "task_id": "task-7f3a",
  "context_id": "ctx-1b2c",
  "sequence": 0,
  "previous_hash": "",
  "timestamp": "2026-05-23T15:30:00Z",
  "actor": "user-a@phase1.local",
  "counterpart": "user-b@phase1.local",
  "action_type": "emit",
  "operation": "proposal",
  "payload_hash": "a3f0...64hex",
  "payload_schema": "meshycal.scheduling/proposal-v1",
  "signature": "base64..."
}
```

Agent B's ledger:

```json
{
  "version": 1,
  "ledger_owner": "user-b@phase1.local",
  "task_id": "task-7f3a",
  "context_id": "ctx-1b2c",
  "sequence": 0,
  "previous_hash": "",
  "timestamp": "2026-05-23T15:30:01Z",
  "actor": "user-a@phase1.local",
  "counterpart": "user-b@phase1.local",
  "action_type": "receive",
  "operation": "proposal",
  "payload_hash": "a3f0...64hex",
  "payload_schema": "meshycal.scheduling/proposal-v1",
  "signature": "base64..."
}
```

**The link between the two:** `task_id`, `context_id`, `payload_hash`, and `payload_schema` are identical across the two ledgers. `ledger_owner`, `action_type`, `timestamp`, and `signature` differ (each ledger owner signs their own entry; receivers may sign as an acknowledgment of receipt; this is per-side accountability, not a joint signature).

## 4. Canonicalization Commitment

**Algorithm:** JSON Canonicalization Scheme — RFC 8785 (JCS).
**Library:** `jcs` (Python; declared in `pyproject.toml`).
**Hash function:** SHA-256.
**Encoding for transport:** UTF-8.
**Signature scheme:** Ed25519 (via the `cryptography` library, also already in `pyproject.toml`).

**Canonicalization rule for the entry itself:** when computing the signature input or the previous_hash chain link, encode the entry with the `signature` field *removed* (not set to empty string — removed). Sign / hash the canonical bytes of the rest.

**Why this matters in practice:** if two implementations canonicalize differently (e.g., one preserves key order, the other sorts keys), the hashes diverge and the demo fails. JCS specifies a single canonical form. Use the `jcs` library; do not roll your own.

## 5. End-State Assertions

After a successful demo run with one proposal from A and one acceptance from B, the following must hold:

### Per-ledger structural assertions

For each of Agent A's ledger and Agent B's ledger:

1. **Two entries** exist (sequence 0 and 1).
2. **Hash chain valid:** entry 1's `previous_hash` equals the SHA-256 (JCS-canonical) of entry 0.
3. **Every signature verifies** against its `actor`'s public key.
4. **Sequence ordering:** sequence 0 entry's `timestamp` ≤ sequence 1 entry's `timestamp`.

### Cross-ledger paired assertions

For the proposal interaction (Agent A emits, Agent B receives):

5. A's entry 0 has `action_type = "emit"`, `operation = "proposal"`, `actor = A`, `counterpart = B`.
6. B's entry 0 has `action_type = "receive"`, `operation = "proposal"`, `actor = A`, `counterpart = B`.
7. **`payload_hash` is byte-equal** between A's entry 0 and B's entry 0.
8. **`task_id` is equal** between A's entry 0 and B's entry 0.
9. **`context_id` is equal** between A's entry 0 and B's entry 0.

For the acceptance interaction (Agent B emits, Agent A receives):

10. B's entry 1 has `action_type = "emit"`, `operation = "acceptance"`, `actor = B`, `counterpart = A`.
11. A's entry 1 has `action_type = "receive"`, `operation = "acceptance"`, `actor = B`, `counterpart = A`.
12. **`payload_hash` is byte-equal** between B's entry 1 and A's entry 1.
13. The acceptance payload's single candidate slot is one of the candidates A proposed in entry 0.

### Overall assertion

14. The two ledger files (or rows, if SQLite) can be re-loaded after the demo terminates, the chain reverified, and all signatures re-verified, without the running process.

If all 14 assertions hold, Phase 1 succeeds.

## 6. Demo Flow

Two processes on the same host:

| Process | Port | Identity | Synthetic calendar |
|---|---|---|---|
| Agent A | 8001 | `user-a@phase1.local` | `agent_a_calendar.json` |
| Agent B | 8002 | `user-b@phase1.local` | `agent_b_calendar.json` |

A third process (`run_demo.py`) orchestrates: starts A and B, triggers A to initiate, waits for completion, runs the end-state assertions.

**Step-by-step:**

```
[orchestrator] start Agent A and Agent B on their ports
[orchestrator] trigger: "Agent A, schedule 30 min with Agent B this week"

[Agent A]
  1. Read agent_a_calendar.json (synthetic).
  2. Compute 3 candidate open slots in the next 7 days (deterministic, no LLM).
  3. Build proposal payload conforming to meshycal.scheduling/proposal-v1.
  4. Compute payload_hash = SHA-256(JCS(payload)).
  5. Build residue entry (sequence=0, action_type=emit, operation=proposal,
     payload_hash, ...).
  6. Sign entry with A's Ed25519 key.
  7. Append signed entry to A's SQLite ledger.
  8. Open A2A Task targeting Agent B:
     - context_id: new UUID
     - Message Parts: [Part.data containing the proposal payload]
     - Artifact.metadata: { "tesherra.provenance.entry_hash": SHA-256(JCS(entry)) }
  9. Wait for response.

[Agent B] (via A2A SDK Adapter receiving the Task message)
  1. Receive A's Message.
  2. Extract proposal payload.
  3. Validate against meshycal.scheduling/proposal-v1 schema.
  4. Verify A's signature on the entry-hash claim against A's known public key
     (Phase 1: public keys are hardcoded in agent config).
  5. Build a "receive" entry mirroring A's (sequence=0, action_type=receive,
     operation=proposal, payload_hash=same, ...).
  6. Sign and append to B's SQLite ledger.
  7. Pick one slot from candidates (deterministic: first available).
  8. Build acceptance payload (proposal-v1 with candidates.length == 1).
  9. Compute payload_hash for acceptance.
  10. Build residue entry (sequence=1, action_type=emit, operation=acceptance,
      previous_hash = SHA-256(JCS(entry 0)), ...).
  11. Sign and append to B's SQLite ledger.
  12. Send acceptance back via A2A SendMessage on the same context_id.

[Agent A]
  10. Receive B's acceptance.
  11. Validate, verify B's signature.
  12. Build receive entry (sequence=1, action_type=receive, operation=acceptance,
      previous_hash = SHA-256(JCS(entry 0)), ...).
  13. Sign and append.
  14. Mark Task COMPLETED in A2A; emit final Artifact with both signed entries
      embedded in Artifact.metadata.

[orchestrator]
  After both processes signal done:
  - Load each ledger from SQLite (cold, not from running process memory).
  - Run all 14 assertions from section 5.
  - Print PASS or FAIL with details on any assertion that fails.
```

## 7. Build Sequence

What gets coded first, second, etc. (matches `ARCHITECTURE.md` section 12 build-order rule):

1. **Models** (`tesherra/src/tesherra/models/primitives.py`)
   - Flesh out `Residue` as a real Pydantic model matching the entry schema.
   - JSON Schema mirror in `tesherra/src/tesherra/provenance/entry_v1.json`.
2. **Crypto** (`tesherra/src/tesherra/crypto/primitives.py`)
   - Implement `Signer.sign()`, `Verifier.verify()`, `content_hash()`.
   - Add `canonical_json()` wrapper around the `jcs` library.
   - Skip `mint_guest_credential` (Phase 1.5).
3. **Provenance Ledger** (`tesherra/src/tesherra/provenance/ledger.py`)
   - SQLite-backed append-only table with hash-chain integrity.
   - Implement `append()`, `get_by_task()`, `get_by_context()`, `verify_chain()`.
4. **A2A SDK Adapter** (`tesherra/src/tesherra/a2a_adapter/adapter.py`)
   - Wire `SendMessage` and a receive callback against `a2a-sdk`.
   - Implement `envelope_to_a2a()` and `a2a_to_envelope()` for the minimal shapes.
   - Skip `SubscribeToTask` (Phase 2/3).
5. **SDK** (`tesherra/src/tesherra/sdk.py`)
   - Implement `attest(task_id)`, `get_residue(task_id)`, `get_residue_chain(context_id)`, and the send/receive plumbing that calls into the adapter and ledger.
   - Leave `verify`, `update_policy`, `register_principal` as `NotImplementedError` (Phase 2/3).
6. **MeshyCal scheduling agents** (`MeshyCal/demos/phase_1/`)
   - `agent_a.py`, `agent_b.py`: deterministic candidate generation, validation, accept/counter logic.
   - `synthetic_calendar.py`: generates ICS-like synthetic data.
   - `schemas/proposal_v1.json`: the schema hardcoded for Phase 1.
7. **Orchestrator + assertions** (`MeshyCal/demos/phase_1/run_demo.py`)
   - Starts both agents, triggers the negotiation, runs the 14 assertions.

Steps 1–3 are pure-Tesherra and can run as unit tests before any A2A wire exists. Step 4 introduces the wire. Steps 5–7 are integration. The pre-flight check (section 9) gates everything: if JCS round-tripping isn't byte-equal, fix that before writing any of the above.

## 8. File Layout

```
tesherra/
├── src/tesherra/
│   ├── models/primitives.py            # Residue model gets a body
│   ├── crypto/primitives.py            # Signer/Verifier/content_hash/canonical_json
│   ├── provenance/
│   │   ├── ledger.py                   # ProvenanceLedger with body
│   │   └── entry_v1.json               # JSON Schema mirror
│   ├── a2a_adapter/adapter.py          # SendMessage + receive callback
│   └── sdk.py                          # attest / get_residue_chain implemented
├── tests/integration/
│   └── test_provenance_roundtrip.py    # In-process round-trip test
└── demos/phase_1/
    └── SPEC.md                         # This file

MeshyCal/
└── demos/phase_1/
    ├── README.md                       # How to run the demo
    ├── schemas/proposal_v1.json        # Hardcoded for Phase 1
    ├── synthetic_calendar.py
    ├── agent_a.py
    ├── agent_b.py
    └── run_demo.py                     # Orchestrator + assertions
```

## 9. Pre-Flight Check (do this before writing other code)

Cheapest test that catches the most expensive bug:

```python
import json
from jcs import canonicalize
from hashlib import sha256

payload_1 = {"candidates": ["2026-05-26T14:00:00Z"], "duration_minutes": 30}
payload_2 = {"duration_minutes": 30, "candidates": ["2026-05-26T14:00:00Z"]}

c1 = canonicalize(payload_1)
c2 = canonicalize(payload_2)

assert c1 == c2, "JCS canonicalization is not order-independent — broken"
assert sha256(c1).hexdigest() == sha256(c2).hexdigest()
print("JCS round-trip OK, hash:", sha256(c1).hexdigest())
```

If this assertion fails, no further code is worth writing — the canonicalization library is broken and every downstream assumption falls apart. Run this in a Python REPL with `pip install jcs` before doing anything else.

## 10. What this spec deliberately does not commit to

- **Wire format for the entry in transit.** Whether the entry travels in `Artifact.metadata` as embedded JSON, or as a separate Part, or in a sidecar — TBD by the implementer; the spec only requires that both sides end up with byte-equal entries in their ledgers.
- **The SQLite schema exact DDL.** Implementer's call. The constraint is "append-only with hash-chain integrity," not a specific table layout.
- **Logging or observability.** Phase 1 demo can log to stdout; structured logging is Phase 2+.
- **Error handling beyond "fail loudly with a clear message."** Phase 1 demos a happy path. Retry/idempotency is Phase 2+.
- **Performance.** Two ledger entries per process is trivial.

These omissions are intentional. Phase 1 proves the mechanic; subsequent phases harden everything.

## 11. Done condition

Phase 1 is complete when:

- `python -m MeshyCal.demos.phase_1.run_demo` (or equivalent) exits 0
- All 14 assertions in section 5 PASS
- The ledgers persist after the demo terminates and can be re-verified cold
- `pytest tests/integration/test_provenance_roundtrip.py` passes

Anything beyond that is Phase 2.
