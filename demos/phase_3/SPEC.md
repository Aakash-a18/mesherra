# Phase 3 Demo Spec — Scoped Disclosure

This document is the bridge between Mesherra's architecture (the *what* and *why*) and Phase 3 code (the *how*). It pins down the artifacts the architecture hand-waves about field-level policy:

1. The exact JSON shape of a signed policy document (`mesherra.policy/doc-v1`).
2. The exact JSON shape of the proposal payload after additive Phase 3 fields (`meshycal.scheduling/proposal-v1`, minor extension).
3. The Policy Engine's verdict contract (input, output, and what `ALLOW_SCOPED` literally returns).
4. The PolicyStore SQLite schema and signing canonicalization.
5. The Outbound and Inbound Gateway pipeline insertion points.
6. The new end-state assertions (extending Phase 1's SPEC §5).

Phase 3 code is written *against* this spec. If the spec is wrong, the code is wrong; fix the spec first.

## 0. Goal

Prove Mesherra's scoped-disclosure layer works mechanically: A's agent holds rich calendar data internally (titles, attendee emails, etc.), A's user-signed policy strips the blocked fields before the message leaves A's airlock, and B's ledger contains zero references to the blocked fields. Plus the symmetric inbound check: B's own user-signed policy refuses any payload whose schema or fields exceed B's `inbound_allow`.

This is the third primitive from ARCH §4: **scoped disclosure**. Phase 1 shipped provenance; Phase 2 shipped identity verification; Phase 3 closes the trust-layer triangle.

## 1. Scope

### In scope (Phase 3 must do these)

- Define and use the `mesherra.policy/doc-v1` schema for the user-signed policy.
- Build a real, stateless `PolicyEngine` implementing the four verdicts from ARCH §13.4.
- Build a real `PolicyStore` (SQLite-backed, schema-versioned, append-only, signature-verifying) per ARCH §13.6.
- Sign and verify policy documents via Ed25519 + JCS, reusing the existing `crypto/primitives.py` surface.
- Wire the engine into both the Outbound Gateway (pre-send) and the Inbound Gateway (post-verify).
- Extend `meshycal.scheduling/proposal-v1` with additive optional fields (`calendar_titles`, `attendee_emails`, `constraint_hints`) — additive per ARCH §8.5, so no URI bump.
- Ship a MeshyCal default policy template that blocks `calendar_titles` and `attendee_emails` outbound and allows the rest.
- Extend `MeshyCal/demos/phase_1/run_demo.py` to mint signed policies for both agents at boot, load them into per-agent `PolicyStore`s, and exercise the scoped pipeline end-to-end.
- Add new SPEC §5 assertions (#15, #16, #17) that fail loudly if scoping is not actually happening.
- Add a force-injection regression test: if the orchestrator deliberately tries to send a payload containing a blocked field, the gateway must refuse rather than silently send.

### Explicitly out of scope (Phase 3 must NOT do these)

| Out of scope | Why deferred |
|---|---|
| `ESCALATE` verdict actually surfacing to a user via A2A `INPUT_REQUIRED` | Phase 3 returns `ESCALATE` as a typed verdict and treats it as a strict refusal for the v0 demo. Wiring it through the A2A task state machine is a later phase once a real UI exists. |
| Reference-promotion vs copy-promotion of Objects (ARCH §4.2) | Object-layer mechanics; Phase 3 only handles the field-scoping case. |
| Conditional policy rules (e.g., "block titles unless counterpart is on this allow-list") | Phase 3 supports allow / block / max-array-size only. Conditional rules are a Phase 3.5 add-on. |
| User-facing policy editor UI | Policy is authored as Python/JSON in the demo. UI is a renderer concern that lives in MeshyCal's frontend (Phase 4+). |
| Schema Registry (signed, remote schemas) | Still hardcoded locally; Phase 3 only adds policy infrastructure. |
| Inbound policy enforcement on text payloads (`Part.text`) | ARCH §8.7: text payloads do not get field-level scoping. Inbound text can still be blocked by source/principal rules later. |
| Cross-agent policy negotiation | Each agent's policy is its own; no policy is shared across the wire. |

If any of the above creeps in during Phase 3 work, stop and reconsider.

## 2. The Policy Document Schema

**Schema ID:** `mesherra.policy/doc-v1`
**Owner:** Mesherra (trust-layer-owned schema)
**Storage:** locally hardcoded under `src/mesherra/policy/schemas/policy_doc_v1.json` for Phase 3 (same convention as Phase 1's proposal schema; Schema Registry is still deferred).

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "mesherra.policy/doc-v1",
  "title": "Mesherra Policy Document v1",
  "description": "The user's signed constitution. One document per principal. Each document is a list of rules, each rule scoping how a specific payload schema may cross this principal's airlock.",
  "type": "object",
  "additionalProperties": false,
  "required": ["principal_id", "version", "issued_at", "rules"],
  "properties": {
    "principal_id": {
      "description": "The principal this policy belongs to. Must match the principal whose signing key signed the doc.",
      "type": "string",
      "minLength": 1
    },
    "version": {
      "description": "Monotonically increasing integer. v1 is the first signed policy for a principal; every update increments.",
      "type": "integer",
      "minimum": 1
    },
    "issued_at": {
      "description": "RFC 3339 UTC timestamp the policy was signed.",
      "type": "string",
      "format": "date-time"
    },
    "rules": {
      "type": "array",
      "minItems": 0,
      "items": { "$ref": "#/$defs/Rule" }
    }
  },
  "$defs": {
    "Rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["match"],
      "properties": {
        "match": {
          "type": "object",
          "additionalProperties": false,
          "required": ["schema"],
          "properties": {
            "schema": {
              "description": "Payload schema URI this rule applies to.",
              "type": "string",
              "minLength": 1
            },
            "direction": {
              "description": "If omitted, the rule applies to both directions.",
              "type": "string",
              "enum": ["outbound", "inbound", "both"]
            }
          }
        },
        "outbound_allow": {
          "type": "array",
          "items": { "$ref": "#/$defs/FieldPath" }
        },
        "outbound_block": {
          "type": "array",
          "items": { "$ref": "#/$defs/FieldPath" }
        },
        "inbound_allow": {
          "type": "array",
          "items": { "$ref": "#/$defs/FieldPath" }
        },
        "inbound_block": {
          "type": "array",
          "items": { "$ref": "#/$defs/FieldPath" }
        },
        "max_array_size": {
          "type": "object",
          "additionalProperties": { "type": "integer", "minimum": 0 }
        }
      }
    },
    "FieldPath": {
      "description": "Dotted-path reference to a field. Top-level keys (`candidates`) or nested keys (`constraint_hints.tz`). Array indexing is NOT supported in v1 — rules apply to fields, not specific elements.",
      "type": "string",
      "pattern": "^[a-z][a-zA-Z0-9_]*(\\.[a-z][a-zA-Z0-9_]*)*$"
    }
  }
}
```

### 2.1 Signing canonicalization

A signed policy is a tuple `(doc, signature)` where:
- `doc` is a `mesherra.policy/doc-v1` JSON object.
- `signature` is `Ed25519_sign(privkey=principal.signing_key, message=JCS(doc))`, base64-encoded.

JCS = the same RFC 8785 canonicalization Phase 1 uses for residue and Phase 2 uses for directory records. `crypto/primitives.py` already exposes `canonical_json` and `content_hash`; signing reuses `Signer.sign(bytes)`.

**Cross-language signing note (Phase 3.5+):** Python's `PolicyDoc.to_signing_payload()` emits unset optional fields as JSON `null` (e.g., `"inbound_allow":null`). The JSON schema mirror at `policy_doc_v1.json` declares those fields optional under `additionalProperties: false`. A correct second-language implementation that follows the JSON schema literally would *omit* unset keys instead of emitting nulls, producing different JCS bytes and a signature the Python store would reject. **For the v0 single-language demo this is a non-issue.** When a second-language signer enters scope, either pass `exclude_none=True` in `to_signing_payload` (and update this note) or change the schema mirror to require explicit nulls.

A `SignedPolicyDoc` is the wire shape persisted in the PolicyStore:

```python
@dataclass(frozen=True)
class SignedPolicyDoc:
    doc: PolicyDoc       # parsed Pydantic model
    signature_b64: str   # Ed25519 signature over JCS(doc)
```

### 2.2 Rule evaluation semantics

Given a `(payload, payload_schema, direction)` and a policy doc, the engine:

1. **Selects matching rules**: every rule whose `match.schema == payload_schema` AND whose `match.direction` is the requested direction or `"both"` (or absent).
2. **No matching rule → BLOCK.** A schema not named in policy is, by default, refused. This is the "withhold by default" stance of ARCH §4.2.
3. **For each matched rule**, in document order:
   - If `outbound_block` (for outbound) or `inbound_block` (for inbound) names a field present in the payload, that field is dropped from a working copy. Nested paths drop only the leaf — `constraint_hints.tz` blocked does not drop `constraint_hints.priority`.
   - If `outbound_allow` (resp. `inbound_allow`) is present and non-empty, any field NOT in the allow-list is dropped. Allow-lists are stronger than block-lists: an empty allow-list means "nothing crosses." A missing allow-list means "everything except blocks crosses."
   - `max_array_size` truncates listed arrays to the specified max.
4. **Verdict resolution after all matched rules applied**:
   - "Byte-equal" in this step means `JCS(working) == JCS(input)` — JCS-canonical equality, since key ordering is canonicalized at hash time anyway.
   - If the working payload is JCS-equal to the input → `ALLOW`.
   - If the working payload is empty (all fields dropped) → `BLOCK`.
   - Otherwise → `ALLOW_SCOPED`, with the working payload as the scoped payload.
   - `ESCALATE` is not produced by any rule type in v1; it is reserved for future conditional rules. The engine never returns it in this slice. The gateways still handle it defensively to guard against future engines.
5. **Defense-in-depth (gateway-side)**: after the engine returns `ALLOW_SCOPED`, the Outbound Gateway re-checks that no `outbound_block` field-path is present in the scoped payload before signing the SendClaim. A non-empty re-check failure is a `PolicyScopingFailed` exception, not a silent send. This guards against engine bugs.

## 3. The Extended Proposal Payload

**Schema ID:** `meshycal.scheduling/proposal-v1` (unchanged URI; additive optional fields per ARCH §8.5).
**Phase 3 location:** `MeshyCal/demos/phase_1/schemas/proposal_v1.json` (already exists from Phase 1; this slice rewrites it with additive fields).

New optional fields added in Phase 3:

```json
{
  "calendar_titles": {
    "description": "Sender's own calendar entry titles in the candidate windows. ALWAYS blocked outbound by default policy; present here only so internal agents can pass it through their own scoping check.",
    "type": "array",
    "items": { "type": "string" }
  },
  "attendee_emails": {
    "description": "Email addresses of the sender's existing attendees in the candidate windows. ALWAYS blocked outbound by default policy.",
    "type": "array",
    "items": { "type": "string", "format": "email" }
  },
  "constraint_hints": {
    "description": "Soft scheduling constraints the sender is willing to share. Allowed outbound by default.",
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "tz": { "type": "string" },
      "preferred_window": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "start_hour": { "type": "integer", "minimum": 0, "maximum": 23 },
          "end_hour":   { "type": "integer", "minimum": 0, "maximum": 23 }
        }
      }
    }
  }
}
```

Existing required fields (`candidates`, `duration_minutes`) are unchanged. Receivers that ignore unknown fields (per ARCH §8.5) handle the new fields gracefully.

## 4. The MeshyCal Default Policy Template

Phase 3 ships exactly one MeshyCal default policy template, used for both A and B in the demo:

```python
DEFAULT_MESHYCAL_POLICY_TEMPLATE = {
    "rules": [
        {
            "match": {"schema": "meshycal.scheduling/proposal-v1", "direction": "outbound"},
            "outbound_allow": ["candidates", "duration_minutes", "constraint_hints"],
            "outbound_block": ["calendar_titles", "attendee_emails"],
            "max_array_size": {"candidates": 5},
        },
        {
            "match": {"schema": "meshycal.scheduling/proposal-v1", "direction": "inbound"},
            "inbound_allow": ["candidates", "duration_minutes", "constraint_hints"],
        },
    ],
}
```

The orchestrator wraps this template per principal at boot:
1. Fills in `principal_id`, `version=1`, `issued_at=now`.
2. Signs with that principal's Ed25519 key over JCS bytes.
3. Persists the `SignedPolicyDoc` to that principal's PolicyStore.

## 5. The PolicyStore SQLite Schema

One SQLite file per principal (e.g., `user-a_phase3_policy.sqlite`). Mirrors the conventions of `ProvenanceLedger` and `DirectoryStore`:

```sql
CREATE TABLE IF NOT EXISTS policy_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    principal_id    TEXT NOT NULL,
    version         INTEGER NOT NULL,
    issued_at       TEXT NOT NULL,
    doc_json        TEXT NOT NULL,
    signature_b64   TEXT NOT NULL,
    saved_at        TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (principal_id, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_latest
    ON policy_versions (principal_id, version DESC);
```

- `policy_meta` row `('schema_version', '1')` enables fail-fast on mismatch (matches Phase 2's `DirectoryStore.directory_meta` per-store naming convention).
- `PolicyStore` is constructed per-principal and bound to that principal's Ed25519 public key at construction (passed in by the SDK from `signer.public_key_b64()`). One store serves one principal's policies; sharing a store across principals is not supported in v0.
- `PolicyStore.get_current()` returns the highest-version row for the bound principal, verifies the signature against the bound public key, raises `PolicyVerificationFailed` if invalid, raises `PolicyNotFound` if no rows exist, returns the `SignedPolicyDoc` on success.
- `PolicyStore.save_signed(signed_doc)` inserts a new row. The doc's `principal_id` must match the bound principal (raises `PolicyPrincipalMismatch` if not). PK enforces version uniqueness; non-monotonic insert raises `NonMonotonicPolicyVersion`.

## 6. Gateway Pipeline Insertion

### 6.1 Outbound (modifies ARCH §13.2 pipeline step 1)

```
PRE-SEND:
  1. Policy decision   ← consult PolicyEngine(policy, payload, schema, "outbound")
     - BLOCK         → raise PolicyBlocked; no SendClaim, no Residue
     - ESCALATE      → raise PolicyEscalationRequired (Phase 3: same effect as BLOCK)
     - ALLOW         → continue with original payload
     - ALLOW_SCOPED  → replace payload with scoped payload; defense-in-depth re-check
  2. Peer resolution    (unchanged)
  3. SendClaim signing  (unchanged; signs the post-scoping payload)
  4. Hand to adapter    (unchanged)

POST-RESPONSE:
  5–8. (unchanged)
```

### 6.2 Inbound (modifies ARCH §13.3 pipeline)

After signature verification (existing step 3), and before consumer dispatch:

```
  3a. Policy decision   ← consult PolicyEngine(policy, payload, schema, "inbound")
     - BLOCK         → raise PolicyBlocked; record a rejection Residue if Phase 4+ adds one; for Phase 3, raise and skip handler
     - ALLOW         → dispatch full payload
     - ALLOW_SCOPED  → dispatch scoped payload (drops fields the recipient's own policy refuses)
     - ESCALATE      → same as BLOCK in Phase 3
```

The Inbound Gateway acquires a `PolicyEngine` and a `PolicyStore` via the same constructor-injection pattern Phase 2 used for `DirectoryClient`.

## 7. SDK Surface

`Mesherra.__init__` gains two optional kwargs:

```python
def __init__(
    self,
    *,
    principal_id: str,
    signer: Signer,
    ledger: ProvenanceLedger,
    adapter: A2AAdapter,
    directory: DirectoryClient,
    policy_store: PolicyStore | None = None,
    policy_engine: PolicyEngine | None = None,
    replay_protector: ReplayProtector | None = None,
) -> None: ...
```

If `policy_store` is None, the gateways operate in **bypass mode** — no engine call, all messages pass. This preserves Phase 1/2 backward compatibility for tests that don't care about policy and is explicit: bypass is not "no rules"; it is "no enforcement at all." Once a `policy_store` is provided, the default-deny stance from §2.2 step 2 kicks in (an unmatched schema is `BLOCK`, not silently allowed). This distinction matters: tests in Phase 3 that supply a PolicyStore but no rules for a given schema will see BLOCK, which is the correct behavior. If `policy_store` is provided but `policy_engine` is None, the SDK constructs a default `PolicyEngine()` (stateless; no config).

`Mesherra.get_policy()` and `update_policy()` (currently `NotImplementedError`) are filled in:
- `get_policy()` → returns the current `SignedPolicyDoc` from the store.
- `update_policy(new_doc, signer)` → signs and persists a new version.

## 8. End-State Assertions (extends Phase 1 SPEC §5)

Phase 1 ships 14 assertions. Phase 3 adds three more:

- **#15 — Outbound scoping happened.** A's ledger entry for the proposal carries `payload_hash = SHA-256(JCS(scoped_payload))`, where `scoped_payload` is the original payload with `calendar_titles` and `attendee_emails` stripped. The orchestrator constructs both the pre-scope and post-scope canonical bytes and asserts A's residue references the post-scope hash. Equivalently: hashing the input payload yields a hash that does NOT appear anywhere in either ledger.
- **#16 — B genuinely never saw the blocked fields.** B's ledger entries reference the same scoped payload's hash as A. If B had received the un-scoped payload, A's emit hash and B's receive hash would diverge (because B's residue is built from the bytes B received). Byte-equality of the two `payload_hash` values is the proof.
- **#17 — Force-injection defense holds.** A regression test bypasses the engine and tries to push a payload containing `calendar_titles` directly into the gateway's SendClaim path. The gateway raises `PolicyScopingFailed` before signing. (This is the SPEC §5 #13-style "load-bearing" check for Phase 3, mirroring how Phase 1 #13 catches the invented-slot attack.)

## 9. Failure modes the demo must surface

| Failure | What the orchestrator should print | Why |
|---|---|---|
| Policy doc signature invalid on load | `PolicyVerificationFailed` with the principal id | Tamper-evidence: a corrupted policy file must not silently load |
| Outbound `BLOCK` | `PolicyBlocked: schema={schema} fields={blocked_fields}` | Operator visibility — knowing why a send was refused matters |
| Outbound `ESCALATE` (Phase 3 treats as BLOCK) | `PolicyEscalationRequired` with rule context | Surfaces the rule that escalated; Phase 4 will route to UI |
| Defense-in-depth re-check fail | `PolicyScopingFailed: scoped payload still contained {field}` | Internal-bug class; visible failure beats silent leak |
| Inbound `BLOCK` | `PolicyBlocked` from the receive path | Symmetric to outbound; receiver knows why it refused |

## 10. Done-condition

Phase 3 is done when:

1. All Phase 1 assertions (#1–#14) continue to pass on the cold-reload demo.
2. New assertions #15, #16, #17 pass.
3. mesherra test suite ≥ Phase 2's 193 tests + new tests for `PolicyEngine`, `PolicyStore`, signing canonicalization, gateway integration.
4. MeshyCal 45 tests still green; new tests for policy boot, default-template signing, force-injection regression.
5. Theory-aligner verdict "Aligned, ship" after every sub-step.
6. mesherra `CLAUDE.md` and `AGENTS.md` build-order section updated to show Phase 3 shipped.
7. MeshyCal `CLAUDE.md` build-order section updated to show Phase 3 shipped.
8. ARCH.md §13.4 and §13.6 reconciled with the as-built (replace "scaffolding only" with the real implementation).
9. Both repos pushed to origin/main with green CI.
