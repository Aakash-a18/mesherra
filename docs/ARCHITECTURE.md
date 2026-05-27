# Mesherra Architecture

## 1. Problem

Agents (Claude, ChatGPT, custom assistants) can now reach other agents across personal and organizational boundaries via Google's Agent2Agent (A2A) protocol. A2A is explicitly transport and communication. It is not security, not disclosure control, not accountability.

Documented gaps in the A2A specification:

- **AgentCards self-declare identity and authentication schemes.** A2A does not specify how cards are verified for authenticity. Agent impersonation, card tampering, and replay attacks are real risks.
- **The wire format carries whatever `Part`s the sender includes.** A2A has no concept of "minimum disclosure" or scoped sharing.
- **Task completion produces an `Artifact` with optional `metadata`.** A2A provides no provenance schema, signature mechanism, or liability-grade record beyond basic logs.

Without these, autonomous agents cannot transact safely, coordinate across organizations, or operate in regulated contexts. Mesherra is the layer that fills the gap.

## 2. Relationship to A2A

### What A2A provides (we consume, do not rebuild)

| Concept | A2A primitive |
|---|---|
| Discovery | `AgentCard` at `/.well-known/agent-card.json` |
| Stateful unit of work | `Task` with `id`, `context_id`, `status`, `artifacts`, `history` |
| Lifecycle | `TaskState` enum (`SUBMITTED`, `WORKING`, `INPUT_REQUIRED`, `AUTH_REQUIRED`, `COMPLETED`, `FAILED`, `CANCELED`, `REJECTED`) |
| Multi-turn context | `Message.context_id` |
| Cross-task references | `Message.reference_task_ids` |
| Transport | JSON-RPC / gRPC / HTTP+REST, SSE streaming |
| Wire format | `Message` containing `Part`s (`text`, `raw`, `url`, `data`) |
| Task output | `Artifact` with `parts` and `metadata` |
| Transport security | mTLS, OAuth2, OIDC, API key (declared in AgentCard) |

### What Mesherra adds

| Piece | Description |
|---|---|
| **0. Policy capture** | Structures the user's authorizations so layers 1 and 3 have something to verify and attest against |
| **1. Identity verification** | Confirms an AgentCard genuinely represents the claimed principal, beyond self-declaration |
| **2. Scoped disclosure** | Enforces user policy on what data may cross the boundary in any outgoing `Part` |
| **3. Provenance / attestation** | Produces a tamper-evident signed record of every agent interaction, embedded in `Artifact.metadata` and stored append-only |

Layers 1–3 are the product surface. Layer 0 develops alongside the others.

## 3. Core concepts

### 3.1 Agent

A principal. Has:

- **Identity** — cryptographically verifiable through the Mesherra directory.
- **Intent** — delegated from the user via Policy.
- **Authority scope** — the set of actions the principal may take, the boundaries it may cross, the Objects it may promote.
- **Zone standing** — which trust zones the agent has been granted to operate in.

Agents act. They cross boundaries. They are categorically distinct from Objects.

### 3.2 Object

A passive resource: a calendar, a document, a 3D model, a meeting agreement, a contract draft. Properties:

- **Owner** — whose principal it belongs to. Stable. Root of all authority over the Object.
- **Home layer** — where the Object lives at rest.
- **Type**
  - *Mutability*: static (snapshot) vs live (continuously updated reference)
  - *Share mode*: copy (counterpart gets bytes, irrevocable) vs reference (counterpart gets a view, owner retains control, revocable)
  - *Multiplicity*: singular (one owner). Co-ownership is deferred to v1+ (see section 14).
- **Per-viewer layer-membership** — the live, contextual answer to "who can presently perceive this." A *relation* between Object and viewer, not a property of the Object.
- **Residue** — append-only cryptographic trace of every agent that has touched the Object.

> **Important:** Objects are *not* A2A `Artifact`s. An A2A Artifact is the output of a Task. An Object is any shareable resource that may flow through or be referenced by a Task. When an Object is delivered as the result of a Task, it may be wrapped in an A2A Artifact (as Parts plus signed Mesherra metadata), but the Object's identity, lifecycle, and residue are independent of any single Task.

### 3.3 Layer

A visibility zone. Default layers:

- **Personal** — visible only to the owner's own agents.
- **Shared** — visible to specific authorized counterparts, scoped per-relationship.
- **Public** — discoverable by any authenticated agent.

Layer-membership is per-viewer and per-context. The same Object can be in personal layer for the world and transiently in shared layer for one specific counterpart, for a bounded duration, then revert.

### 3.4 Handshake

A continuous, stateful trust negotiation between agents. Spans one or more A2A `Task`s, tied together by `context_id`. Maintains live state:

- Verified identity of each party
- Authorization scope granted on each side
- Active Object promotions and their expiry windows
- Accumulated residue across the conversation

### 3.5 Policy

The user-authored constitution governing their agent's behavior at the boundary. Specifies:

- **Standing authorizations** — who may interact with the user's agent, in what role.
- **Disclosure rules** — what Objects may be promoted, to whom, under what conditions, in what mode (reference vs copy), for how long.
- **Acceptance rules** — what counterparts and claims to trust; what to refuse.
- **Escalation rules** — when to surface to the human (via A2A's `INPUT_REQUIRED` state).

Policy is **user-owned**. The platform cannot write into it. The butler executes only policy the user authored.

### 3.6 Residue

Cryptographically signed, append-only trace. Each agent that acts on an Object appends a signed entry containing:

- Acting agent's verified identity
- Action taken (created, promoted, modified, attested, revoked)
- Authorization chain — which policy clause permitted this *(Phase 3+; not present in `entry-v1` since Phase 1 has no Policy Engine to reference)*
- Timestamp
- Reference to A2A `task.id` and `context_id`

Residue is the foundation of any liability/recourse layer. It is *descriptive* (history), not *executive* (does not gate). Agents read residue to make judgment calls; the Object does not enforce anything itself.

**Forensic in v0, preventive in v1+.** In the initial system, residue is primarily forensic — a tamper-evident record used for audit and dispute resolution after the fact, not for preventing actions in the moment. Preventive uses (reputation scoring, automatic re-trust based on residue history, conditional acceptance based on past behavior) emerge in v1+ as the trust graph accretes through real interactions. We are honest about this rather than claiming compounding trust we have not yet earned.

**Important property:** sharing transfers practical control. A signature on an Object is a fingerprint, not a key. Contribution alone does not confer perpetual standing over the Object. The only legitimate gates on downstream propagation are:

1. The **share mode** at original disclosure (reference vs copy)
2. An **explicit term** the owner attached at share time

**Two signed objects per exchange (not one):** Mesherra signs at two layers with two distinct objects. See §13.10 for the full rationale, but in brief:

* **SendClaim** — signed pre-send, lives on the A2A wire, attests "the sender really sent this payload, with this semantic operation, in this context at this time." Verifiable by the receiver from wire fields alone.
* **Residue** — signed post-response by each ledger owner, lives in their ledger, attests "this is my view of what happened." Contains ledger-relative fields (`sequence`, `previous_hash`, post-response `task_id`) that the wire cannot carry.

Both are signed by the same actor (the sender, for their outbound). They are not the same signature: same key, different objects, different purposes. The cross-ledger linkage between A's emit entry and B's receive entry is via shared fields (`payload_hash`, `task_id`, `context_id`, `payload_schema`); each side independently signs their own Residue with their own key.

### 3.7 Object data flow across boundaries

This subsection extends 3.2 (Object) with the data-flow semantics that govern how Objects move between agents and across trust boundaries. It is a foundational architectural commitment: every Object has exactly one canonical source of truth, and every observer sees a derivative.

**Canonical source of truth: the owner**

The Object's owner is canonical. Specifically:

- The Object lives in the owner's home layer, on the owner's stack.
- The owner's Mesherra instance holds the authoritative state.
- Any other agent that "sees" the Object sees it through a **promotion** — a scoped, time-bounded, possibly revocable view authorized by the owner's policy.

This single rule is what makes scoped disclosure tractable. If everyone agrees the owner is the source, then "what is the receiver allowed to see" is a question the owner's policy answers, and enforcement happens at one well-defined point: the owner's airlock.

Architectural consequence: Mesherra is explicitly *not* a CRDT, shared-state, or multi-writer system. We do not solve eventual consistency, multi-writer conflict resolution, or "whose copy is canonical." In our model there is one canonical state per Object on the owner's stack; every viewer sees a derivative.

**Reference promotion (default, preferred)**

The receiver gets a *handle*, not data. The handle contains:

- **Object ID** — stable promotion identifier (UUID-style), assigned once at promotion time and stable across the entire lifetime of the promotion (including across live updates). Distinct from the content hash.
- **Content hash** — hash of the canonical representation at the current state. Static Objects have one content hash for the lifetime of the promotion; live Objects emit a new content hash per update (see Mutability below).
- **Schema reference** — pointer to the published schema in the Schema Registry
- **Scope spec** — which fields or slice the receiver may see
- **Mode flag** — `reference`
- **Expiry** — when the promotion auto-revokes
- **Fetch endpoint** — the owner's airlock URL where scoped data can be requested
- **Owner's signature** — proving the owner authorized this view

The receiver does NOT receive:

- The Object's full state
- The Object's internal home-layer location
- Other promotions of the same Object to other parties
- The owner's full policy

When the receiver's agent needs to read the Object, it queries the owner's airlock through the handle. Each fetch is policy-checked at the owner's side *before release* and policy-checked at the receiver's side *on arrival* against acceptance rules. The symmetry matters: the owner enforces what they release; the receiver enforces what they accept. Each fetch is logged in both sides' residue.

> **Slice 1+2 deferral (Phase 4):** the Phase 4 Slice 1 and Slice 2 implementations do *not* run the Policy Engine on the trust-layer wire traffic — PROMOTE / FETCH / FETCH_RESPONSE / FETCH_DENIED (Slice 1) plus SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE (Slice 2) — all of which are wired straight to the Object handler (§13.13) on the inbound side and bypass the outbound policy gate. The Policy Engine v1 has no `inbound_accept` rule type yet, and its default-deny stance on unmatched schemas would otherwise block every promotion or live push the moment a real PolicyStore is wired. Bilateral fetch policy (per-message owner-release rules + receiver acceptance rules) is the Slice 3+ work that closes this gap and restores the architectural commitment above. Until then, scope enforcement remains *at promotion creation time* (the snapshot is captured against `scope.fields` once for static; the live push fan-out re-applies the same scope filter on every mutation) rather than per-message via policy.

**Copy promotion (explicit, warned, irrevocable)**

The receiver gets *bytes*:

- The same handle fields as reference promotion
- The actual scoped content (canonical JSON, signed)
- A `copy` flag in the residue entry

After copy promotion, the owner cannot revoke. The bytes are on the receiver's side. Forward-conditions the owner attaches ("do not re-share") are honor-system: recorded as terms in the residue, enforceable after the fact (as evidence of breach) but not prevented before the fact.

Architectural principle: **prevention requires reference; conditions require copy.** Anything the owner truly cannot afford to have propagate must use reference promotion. Copy with a condition gives accountability, not prevention.

**Mutability: static vs live (and the wire pattern that follows)**

Cross-cutting with share mode is the Object's mutability (from 3.2 Type properties), and the wire pattern differs by combination:

- **Static reference** — the Object does not change after promotion. The receiver sees one snapshot. Wire pattern is on-demand **pull**: the receiver hits the owner's fetch endpoint when they need data, each call policy-checked on both sides. The Object ID and content hash are both stable across the lifetime of the promotion.
- **Live reference** — the receiver sees ongoing updates. Wire pattern is **push**: the receiver subscribes once, the owner pushes a new signed envelope per update. Slice 2 ships this as discrete request-response messages over the existing wire (SUBSCRIBE → owner records subscription → owner's `update_object` mutation fans out OBJECT_UPDATE messages to every active subscriber, each carrying the Object's monotonic `object_version` and the SHA-256/JCS hash of the scoped state). True server-streaming via A2A's `SubscribeToTask` / `tasks/resubscribe` is a Slice 3+ optimisation; the `object-update-v1` schema is forward-compatible with either transport. Each envelope carries the stable promotion_id, the scoped state, a per-push content hash, and is policy-checked at the receiver's inbound gateway before delivery to the consumer agent (the policy gate is itself Slice 3+; see the deferral note in §3.7 above).
- **Copy mode** is always a one-time transfer regardless of source mutability. If the source mutates after copy, the receiver still holds only the original snapshot. There is no "live copy."

Live promotion is more powerful and more dangerous. It permits a long-running stream that the owner may have authorized once and forgotten about. Default policy should require explicit opt-in to live mode and bounded expiry.

**Residue: both sides record, symmetrically**

Every promotion produces matching signed residue entries on both ledgers, each describing the entry-holder's own role:

- **Owner's entry**: "I, owner X, authorized counterpart Y to perceive scope Z of Object [Object ID], mode = reference, expiry T, under policy clause P." Signed by owner.
- **Receiver's entry**: "I, receiver Y, was granted a reference handle to Object [Object ID] by owner X, scope Z, mode = reference, expiry T." Signed by receiver.

Both entries are needed in disputes: the owner can prove what they authorized; the receiver can prove they lawfully held a view. Matching Object IDs and timestamps link the two entries across ledgers.

For fetches under a reference promotion, each fetch generates a smaller paired entry: owner's "released slice Q at time t" and receiver's "received slice Q at time t." For live promotions, each pushed update generates a paired entry on both sides.

**What stays behind, always**

Regardless of promotion mode or mutability, the following never crosses the boundary:

- The full Object state (in reference mode); the non-promoted slices (in copy mode)
- The owner's policy governing the Object
- The owner's complete residue chain — only entries relevant to a specific promotion are visible to the counterpart who has standing
- The Object's internal home-layer location

**Summary table**

| Item | Reference promotion | Copy promotion |
|---|---|---|
| Object ID | Crosses | Crosses |
| Schema reference | Crosses | Crosses |
| Scope spec | Crosses | Crosses |
| Expiry | Crosses | Crosses |
| Fetch endpoint | Crosses | Not applicable |
| Actual scoped bytes | Stays (fetched on demand, scoped per call) | Crosses (one-time, irrevocable) |
| Owner's signature | Crosses | Crosses |
| Residue entry | Recorded in both ledgers | Recorded in both ledgers |
| Owner's policy | Stays | Stays |
| Full Object state | Stays | Stays (only scoped slice crossed) |

**Bearing on the build**

In Phase 1 (provenance-only), this Object data flow is not fully exercised — Phase 1 ships signed structured payloads (canonical proposals), not Objects with promotion lifecycles. The Object data-flow model lights up in Phase 2/3 when an actual document or calendar gets reference-promoted across a boundary.

The owner-is-canonical commitment, however, must be encoded from day one. Every component built (the gateways, the Policy Engine, the Provenance Ledger) should assume the owner is the source and never accidentally introduce a shared-state pathway.

## 4. The three pieces

### 4.1 Identity verification

A2A's AgentCard at `/.well-known/agent-card.json` declares identity and supported auth schemes (mTLS, OAuth2, OIDC). It does **not** prove that the agent at that URL genuinely represents the human or organization it claims.

Mesherra provides a **verified directory**: when an agent encounters a remote AgentCard, Mesherra can answer "yes, this URL belongs to the principal named X, here is the cryptographic proof."

**Phase 2 (shipped):** SQLite-backed HTTP directory service plus a `DirectoryClient` consumer interface (`StaticDirectoryClient` for tests, `HTTPDirectoryClient` for production). Every record returned by the directory is signed by the directory's Ed25519 root key over the canonical JSON of `{principal_id, public_key_b64, issued_at, expires_at}`. Clients pin the directory's public key out-of-band and verify on every resolve. The Outbound and Inbound Gateways consume the `DirectoryClient` interface; no other path from gateway to public key exists. See §13.5 for the full surface.

**Implementation strategy:**

- **Initial centralized trust root.** Mesherra hosts the directory. Similar to Plaid's initial approach to bank trust.
- **Decentralized-ready data structures.** The `DirectoryClient` Protocol is the migration seam — a federated or web-of-trust implementation drops in without touching the gateways or the SDK.
- **Wraps incoming AgentCard reads.** Every time a gateway resolves a peer, the client does a directory lookup + signature check before returning.

### 4.2 Scoped disclosure

A2A's `SendMessage` will transmit whatever Parts the sender provides. Mesherra wraps the send path with a **policy enforcement gateway**:

- Inspects every outgoing Part against the user's policy.
- Blocks, scrubs, or scopes Parts that exceed authorized disclosure.
- For Object promotions, enforces **withhold by default**: data does not cross the boundary unless policy or explicit user gesture authorizes it.
- Defaults to **reference-promotion** where possible (counterpart gets a view, owner retains control, revocable). Copy-promotion is explicit and warned.
- Promotes **extent**, not just yes/no: a calendar share might promote *this week's view*, not *the whole calendar object*. The classifier decides both whether to share and what extent.

**Two intent-classification failure modes to defend against:**

- **False share** — the gateway misreads ambiguous context as a grant and over-shares. Default: when uncertain, withhold. Explicit gesture or policy clause is required to promote.
- **False withhold** — the gateway refuses a legitimate share, breaking the user experience. Acceptable. Better than the leak.

**Sovereignty vs. operation.** The user is sovereign over their Objects' layer state — only they can decide that a calendar moves from personal to shared with a specific counterpart. But in practice, the user *delegates the operation* of layer-state changes to their agent: gestures, intent signals, and standing policy rules drive the layer transitions, with the agent acting on the user's behalf within signed policy bounds. Sovereignty stays with the user (the policy authorizing the agent is user-signed; the user can always override or revoke). Operation is delegated (otherwise every share would require a manual permission grant, which is the exact friction we exist to remove). This distinction is what lets the system feel automatic without the user losing authority — the user's role becomes authoring policy and providing intent, not toggling permissions per interaction.

### 4.3 Provenance / attestation

At Task completion, Mesherra produces a **structured provenance record**:

- Both parties' verified identities (resolved through the directory)
- The authorization chain on each side (which policy clauses permitted what)
- A hash of the Task's relevant input and output
- A signature from each party's Mesherra principal

**Storage:**

- Embedded in A2A `Artifact.metadata` so it travels with the result.
- Mirrored to an append-only Mesherra-side log keyed by `task.id` and `context_id`.

**Compounding trust:** future Tasks can reference prior provenance via A2A's `Message.reference_task_ids`. This is how the trust graph accretes without us building a separate social network — every interaction's provenance becomes a node in the implicit graph. Note: in v0, provenance is primarily forensic (audit and dispute resolution); compounding-trust uses such as reputation scoring and conditional acceptance based on history emerge in v1+ as the graph fills out (see 3.6 for the full framing).

### 4.4 Policy capture (zeroth piece)

Layers 1–3 require structured policy to verify against. Mesherra provides:

- A **policy schema** — machine-readable, signed by the user.
- A **capture flow** — translates user intent into structured policy (UI lives in consumers; the schema lives here).
- **Authorization grants** — per-task or per-relationship, referencing the user's standing policy.

## 5. Zone model

Three trust zones, hard-separated by design and by code.

### 5.1 Internal (within the user's trust boundary)

The user's own agents (butler, domain agents, leaf agents) talk to each other freely. Trust by construction. No handshake required. Mesherra is mostly **absent** here — it is a *boundary* layer.

### 5.2 Known external

Counterparts the user has pre-authorized: a friend's agent, a known vendor's agent, an institution like a bank. Mesherra mediates:

- Identity verified against the directory on every interaction
- Disclosure scoped per policy
- Provenance recorded
- Handshake re-verifies each time (no implicit standing trust beyond the policy grant)

### 5.3 Open mesh

Strangers on the public A2A network with no prior relationship. Mesherra mediates with maximum verification, minimum disclosure, and reputation lookup. Some interactions may be policy-forbidden in this zone (e.g., no transactions above a threshold with unverified counterparts).

## 6. The airlock pattern

The user's butler (the apex agent, or a designated coordinator) is the **single gate** between internal and external zones.

- **Internal agents push scoped data outward** to boundary envoys.
- **Boundary envoys never read inward** into internal agents.
- **The butler decides what payload crosses**, on a per-interaction basis.
- The same gate **screens inbound contact** and curates what reaches the user.

The same component enforces outbound privacy (scoped disclosure) and inbound attention protection (the dial). Loyalty to the user and control of what crosses are anchored to the same principal — by design, not by policy.

**Implementation consequence:** the boundary envoy is intentionally "dumb." It holds only its scoped task. If it needs more context mid-negotiation, it returns to the butler via A2A's `INPUT_REQUIRED` state and the butler decides whether to grant additional scope. This trades fluidity for security.

## 7. A2A Task as the unit of Mesherra interaction

A single negotiation between two parties is modeled as one A2A `Task`:

- `context_id` ties multi-turn exchanges together.
- `Message.role` (`USER` / `AGENT`) tracks turn-taking; Mesherra also attaches its own verified principal identity.
- `Part` carries the actual proposal (candidate slot, scoped document view, contract clause).
- `TaskState.INPUT_REQUIRED` maps onto the airlock pattern: envoy needs more scope from butler, or human needs to make a judgment call the agent isn't authorized for.
- `TaskState.AUTH_REQUIRED` maps onto re-verification: identity needs to be re-asserted before proceeding.
- `TaskState.COMPLETED` triggers Mesherra's attestation: provenance record signed and embedded in the final `Artifact.metadata`.

**Object-mediated interaction.** Every Mesherra interaction is *about* an Object: a calendar being scheduled against, a contract being negotiated, a procurement order being formed, a document being reviewed. The Object is both the **topic** (what the interaction concerns) and the **context anchor** (what carries policy attachment, scope spec, schema reference, and residue target). A pure agent-to-agent conversation with no Object reference has no policy attachment point and no provenance target; such interactions are out of scope for Mesherra. In practice, every A2A `Task` initiated through Mesherra carries an Object reference (an existing Object being acted upon, or a new Object being constructed by the negotiation itself), and the payload schema names which Object class is being acted on. Agents do not negotiate in the abstract; they negotiate *over Objects*.

## 8. Payload structure and schema-based messaging

Mesherra interactions carry structured, schema-defined payloads by default. Free-form text is a fallback, not the norm. This decision shapes Policy Engine design, Provenance Ledger design, and the Schema Registry component (see section 13.11).

### 8.1 Default: `Part.data`, not `Part.text`

For every defined interaction (scheduling proposal, contract clause, transaction terms, document promotion), consumers use A2A's `Part.data` (JSON) carrying a payload that references a published schema. `Part.text` is reserved for genuinely human-facing content where rendering as language is the point — escalation messages, error explanations, free-form chat.

Three reasons:

- **Policy Engine operates on fields, not prose.** A rule like "never include `calendar_titles`" is enforceable on structured JSON, not on free text.
- **Provenance is hashable.** Canonical JSON encoding gives deterministic bytes for signing; free text does not.
- **Residue is auditable.** A future dispute over what was agreed reads as `{"slot": "2026-05-26T14:00Z"}`, not as a paragraph.

### 8.2 Schema identity and ownership

Schemas live under the publisher's namespace:

```
<publisher>.<domain>/<message_type>-v<major>
```

Examples:

- `meshycal.scheduling/proposal-v1`
- `meshycal.scheduling/counter-v1`
- `meshycal.scheduling/accepted-v1`

Publishers are principals verified through the Identity Directory. A schema is signed by its publisher's key; any receiver can verify the schema is genuinely from the claimed source before accepting payloads against it.

**Mesherra does not define schemas.** Consumers do. Mesherra provides the registry and the verification mechanism.

### 8.3 Canonical encoding

Structured payloads use JSON Canonicalization Scheme (RFC 8785, JCS) or equivalent so the same logical JSON always produces the same bytes. This determinism matters for:

- **Provenance hashing** — the same agreement must hash identically on both sides.
- **Signature input** — signatures over canonical bytes are stable across parties.
- **Replay detection** — content-addressed deduplication requires deterministic encoding.

### 8.4 Schema Registry

A Mesherra service, sibling to the Identity Directory. See section 13.11 for the component-level spec. Functionally:

- Consumers publish schemas, signed by their publisher principal.
- Other consumers resolve schemas by ID and version.
- Trust is rooted in the publisher's verified principal, not in Mesherra-the-company.

v0 centralized, future federated; same trust migration path as the Identity Directory.

### 8.5 Versioning rules

- **Major version in URI.** Breaking changes mean a new schema (`-v2`), not a mutation of v1.
- **Minor additions allowed without URI bump** — new optional fields only. Receivers ignore unknown fields.
- **Receivers declare accepted versions in their AgentCard** as a Mesherra extension field, so senders can negotiate.
- **Schemas are content-addressed at publication.** Each published version has a stable hash; the registry can confirm "this is the schema I published" without depending on URI alone.

### 8.6 Field-level policy

Policy rules reference schema fields directly:

```yaml
- match:
    schema: meshycal.scheduling/proposal-v1
  outbound_allow:
    - candidates
    - constraint_hints.tz
  outbound_block:
    - calendar_titles
    - attendee_emails
  max_array_size:
    candidates: 5
```

The Policy Engine validates structured payloads against rules before the Outbound Gateway releases them. The same mechanism applies inbound: only accept payloads whose schemas appear in policy's `inbound_allow`.

This is materially more enforceable than text-based policies. We trade flexibility (free-form prose) for verifiability (structured fields with named scoping).

### 8.7 Text fallback

`Part.text` is allowed when no schema exists for the interaction or when human-facing content is the point. Policy can restrict its use: "never accept `Part.text` from unverified principals," "text only allowed in human-escalation paths."

Text payloads still get hashed (over UTF-8 bytes) and signed; they just do not get field-level scoping. Residue records the text content verbatim.

### 8.8 Binary encoding (optional, deferred)

Default to JSON for debuggability and tooling. Protobuf or msgpack permitted when size or speed matters, declared via content-type in the schema registration. The Schema Registry stores both JSON Schema and any binary schema (e.g., `.proto`) together so receivers can choose.

v0 ships JSON-only. Binary is a v0.5 optimization, not a v0 requirement.

## 9. Origin metaphor: Tessera

In Roman antiquity, two parties would break a *tessera* — a small clay or bone tile — into two halves. Each kept one. Centuries later, descendants who had never met could meet, fit the halves together, and prove the original bond by the precision of the fit.

The trust layer's identity primitive is the digital analogue: each principal carries a cryptographic half-token that fits only the bond it was minted with. Verification is not "do I trust you" but "do these halves fit." The truth holds without anyone trusting anyone in advance.

The metaphor extends through the product:

- **Identity verification** — the two halves fit.
- **Scoped disclosure** — neither side shows what wasn't part of the original bond.
- **Provenance** — each fitting leaves a witnessed mark in the residue.

## 10. First consumer: MeshyCal

A scheduling product where two users' agents negotiate a meeting time. Each agent holds its user's calendar privately; only candidate slots cross the boundary; the final agreed time is recorded with attested provenance. Demonstrates all three Mesherra pieces in the smallest possible use case.

**MeshyCal is a Delegation, not a primitive.** It is a published package — the agent-era equivalent of an application — that uses Mesherra primitives to deliver an end-user experience for the scheduling domain. The Delegation packages four things, each of which slots into a different primitive in the user's stack at install time:

- **Object class definitions** — Calendar, Meeting, and `meshycal.scheduling/proposal-v1` (and successors), registered in the Schema Registry.
- **A scheduling Agent** — a domain agent that runs under each user's butler, carrying the domain logic for reading calendars and proposing slots.
- **Policy templates** — defaults like "share candidate slots, never share titles" merged into the user's signed policy on install.
- **A mobile/web UI** — the user-facing renderer for set-points, exceptions, and confirmations; disposable as ambient/voice/AR surfaces emerge.

**The four-component shape is the Delegation integration contract.** It is not specific to MeshyCal — it is the contract Mesherra defines for *any* Delegation. Every Delegation conforms to this shape; the components themselves are bespoke per domain. A Contract Delegation has contract-clause schemas and a negotiation Agent; a Procurement Delegation has purchase-order schemas and a procurement Agent; both still package the same four kinds of components. This uniformity is what makes Delegations interchangeable plug-ins at the Mesherra level — the user's butler-equivalent can host any conforming Delegation without knowing anything about its domain.

When two MeshyCal users meet, what actually happens: each user's butler dispatches to its MeshyCal scheduling Agent; the agents negotiate over the shared Object class (proposal payloads against the registered schema); the result is an agreed time recorded with attested provenance on both sides. The "MeshyCal app" the users see is one of the four pieces (the UI); the other three are the Delegation's contributions to each user's primitive layer.

**MeshyCal is our test rig, not our market.** The market for Mesherra is contracts, transactions, regulated B2B coordination — domains where being wrong is expensive and trust is materially valued. Scheduling is low-stakes by comparison and only weakly exercises identity and provenance. MeshyCal proves Mesherra works mechanically, but it does not prove Mesherra is necessary; the necessity story lives in the higher-stakes verticals. We build MeshyCal because it gives us the fastest feedback loop on the layer, not because it is the largest addressable customer.

**Sibling repo.** Not part of Mesherra. The dependency arrow runs one way: `MeshyCal → Mesherra`. Never reverse.

**Why it's the right first consumer:**

- Calendar provides one-click context to fund a fresh agent (universal, permissioned via OAuth, rich).
- Scheduling is a coordination pain everyone understands.
- The privacy asymmetry is real (neither side wants to expose their calendar).
- The smallest negotiation that exercises all three Mesherra layers.

**The hard part for MeshyCal specifically:** the invitee experience. To beat Calendly's one-sided-link cold-start advantage, the invited counterpart needs a near-zero-friction guest agent. Designing this flow is MeshyCal's problem, not Mesherra's — but Mesherra must support short-lived, scoped guest principals as a primitive.

## 11. Threat model

Mesherra makes specific security guarantees and explicitly does not make others. This section names both, so design decisions stay scoped and marketing stays honest.

### 11.1 What Mesherra defends against (in scope)

| Attack | Defense |
|---|---|
| Agent impersonation (someone claims to be User1's agent) | Identity Directory + signed AgentCards verified on every interaction |
| AgentCard tampering | Signed cards; signature verified through Directory |
| Replay attacks | Phase 1: weak — signed SendClaim with timestamp catches large clock skew only. **Phase 2 (shipped):** (a) signed `nonce` on every SendClaim, (b) clock-skew tolerance window (`MESHERRA_CLOCK_SKEW_SECONDS`, default 300) + per-sender `(principal_id, nonce)` seen-set in the Inbound Gateway, and (c) Provenance Ledger UNIQUE constraint on `(task_id, action_type, operation)` raising `DuplicateEntry` — storage-layer backstop if the seen-set misses across restarts. Residual risk: the seen-set is in-process, so an attacker holding a captured envelope within the skew window of a process restart can replay once before the ledger constraint catches it. Bounded and acceptable for v0. |
| Over-disclosure by the sender's own agent | Outbound Gateway scopes against Policy Engine before send |
| Acceptance from unverified senders | Inbound Gateway requires verified identity before any delivery |
| Tampering with agreed terms post-hoc | Signed Artifact with provenance hash; both sides hold matching signatures |
| Repudiation ("I never agreed to that") | Provenance Ledger + counter-signed Artifacts |
| MITM on the A2A wire | A2A-mandated mTLS plus Mesherra message-level signing (defense in depth) |
| Cross-user privilege escalation | Zone separation; airlock pattern; no path from one user's external traffic to another user's internal agents |
| Schema spoofing | Schemas signed by verified publisher principal; receivers verify before accepting payloads |
| Fetch endpoint abuse under reference promotion (DoS via repeated fetches, resource exhaustion) | Per-principal rate limiting on the owner's airlock; configurable fetch quotas in policy; circuit breakers; receiver-side caching of handle data to minimize fetches |

**Note on tracking via fetch timing:** the reference promotion model has an inherent property that the owner sees every read by the receiver (because each read is a fetch to the owner's airlock). This is the cost of revocability and policy enforcement at the owner's side. It is a tradeoff of the model, not a defendable attack. Receivers concerned about tracking should request copy promotion where appropriate; owners concerned about leaking activity metadata to receivers should be aware that the reverse property does not hold (the receiver does not see the owner's reads).

### 11.2 What Mesherra does NOT defend against (out of scope)

| Attack | Why out of scope | Where the defense lives |
|---|---|---|
| Compromised user device (rootkit, key extraction) | Hardware/OS security problem | Platform vendor, hardware enclaves, key-store best practices |
| Compromised LLM (prompt injection, jailbreak) | Mesherra verifies identity, not alignment | Consumer-side LLM safety, sandboxing, constrained tool use |
| Social engineering of the human | Mesherra enforces the user's authorization; cannot second-guess them | User-side: clear policy UI, friction on dangerous authorizations |
| Network-level attacks (BGP hijack, DNS poison) | Below the protocol | Standard internet security: HSTS, DNSSEC, cert pinning |
| Quantum cryptanalysis | v0 uses standard PKI vulnerable to sufficient quantum computers | Migrate to post-quantum schemes as standards mature; tracked as design question |
| Covert channels in policy-allowed fields | Cannot inspect semantics, only structure | Consumer-side schema design; minimize free-form fields |
| Denial of service | Mostly an ops problem | Rate limiting at the Gateway; infrastructure-level DDoS protection |
| Long-term key compromise | Inevitable eventually | Key rotation (lifecycle); short-lived session keys; eventual threshold schemes |
| Insider attack on Mesherra itself | v0 trust root is us, by design | Mitigated by future decentralized directory migration |

### 11.3 Trust assumptions

For Mesherra's guarantees to hold, the following must be true:

1. The user's signing key is genuinely controlled by the user.
2. The user's device running their butler is not fully compromised at the OS level.
3. The user's LLM agent is reasonably aligned and not jailbroken.
4. A2A's transport security (mTLS / HTTPS) is properly configured by both parties.
5. In v0, the Mesherra service itself (operating the Directory, Schema Registry, and Ledger) is not adversarial.

If any of these is false, Mesherra's guarantees degrade or fail. We are explicit about this rather than claiming otherwise.

### 11.4 Defense in depth

Even where Mesherra cannot fully defend, the layered design limits blast radius:

- A compromised LLM agent still cannot exceed the user's signed policy bounds (Policy Engine still enforces).
- A compromised counterpart still cannot extract more than was scoped (Outbound Gateway still scopes outbound disclosure).
- A compromised Mesherra service in v0 still cannot forge user signatures (the user's signing key is local to their device).
- A future migration to a decentralized directory removes Mesherra-the-company from the trust root entirely, so even a fully-compromised Mesherra becomes survivable.

The architecture is intentionally designed so that no single failure compromises everything.

## 12. Build discipline

1. **The trust layer must not import from any consumer.** No MeshyCal-specific code in Mesherra. Ever.
2. **Domain-specific logic lives in consumer agents**, not in Mesherra.
3. **The renderer is disposable.** Build the principal model as the source of truth. Mobile, web, voice, future AR are all renderers over the same core.
4. **Use the A2A SDK as the foundation.** Do not reimplement transport, discovery, or task lifecycle. `a2a-sdk` (Python) or `@a2a-js/sdk` (JS/TS) are the starting points.
5. **Centralized identity directory first, decentralized-ready schemas.** Ship faster, design to migrate later.
6. **Provenance ships first** (recording, least invasive). **Identity verification second** (off-the-shelf PKI). **Scoped disclosure last** (hardest, most differentiated).
7. **Policy capture co-develops** with the others; the schema firms up as the layers reveal what they need.
8. **No hardcoded environment-specific values.** All of the following must be injected via environment variables, never literal in code:
   - File system paths (storage roots, log paths, key locations)
   - Hostnames and URLs (the identity directory endpoint, webhook destinations, A2A peer URLs)
   - Database and storage connection strings
   - Signing keys, API keys, and any other secrets
   - Port numbers
   - Feature flags and environment selectors
   - Default policy values and developer test identities

   The codebase must be deployable to dev, staging, or production without code changes. Local development uses `.env` (gitignored); required variables are documented in `.env.example` (committed). The application fails fast at startup if any required variable is missing — no silent defaults that pretend to work and break later.

9. **No real user data anywhere in the repository.** No real names, emails, calendar entries, organization names, phone numbers, or any other identifying information in fixtures, tests, seed data, examples, or documentation. Use generated synthetic data only. This is a hard rule from day one — once real data lands in git history, it is effectively permanent. When in doubt, generate.

10. **Don't abstract MeshyCal prematurely.** MeshyCal is the first Delegation, hand-crafted against Mesherra's raw SDK. Resist the urge to extract reusable Delegation-authoring helpers from MeshyCal before a second Delegation exists. Two examples is the minimum from which useful templates can be derived; one is just a special case in disguise. A "Delegation Authoring SDK" (a `mesherra create-delegation` CLI, a base Delegation class, standard project layout) should emerge from real comparison between Delegation #1 and Delegation #2, not from speculation inside MeshyCal. Resisting this temptation is what keeps MeshyCal honest as a domain-specific product and Mesherra honest as a domain-agnostic substrate.

## 13. Component inventory

The three pieces from section 4 (identity verification, scoped disclosure, provenance) are implemented as eleven distinct modules. This section enumerates them so the build map is unambiguous.

See `docs/DIAGRAMS.md` for the visual reference (internal architecture, outbound flow, inbound flow).

### 13.1 SDK / Public API

The only surface consumers (MeshyCal, future apps) interact with. Everything else in Mesherra is internal.

Core operations:

- `init(user_id, config)` — initialize Mesherra for a user
- `register_principal()` — create or refresh this user's principal record in the directory
- `send_to(peer, parts, opts)` — route an outgoing message through the outbound gateway
- `on_message(handler)` — register a callback for inbound messages
- `verify(agent_card)` — explicitly verify a peer's claimed identity
- `attest(task_id)` — produce signed provenance for a completed task
- `get_policy()` / `update_policy(policy)` — read or write the user's signed constitution
- `get_residue(task_id)` / `get_residue_chain(context_id)` — retrieve provenance

Ships in Python first (matches `a2a-sdk` Python SDK), JS/TS second (for browser and mobile consumers like MeshyCal).

### 13.2 Outbound Gateway

Intercepts every outgoing message before it reaches A2A, and lands the matching residue entry once the A2A roundtrip completes.

#### Concrete outbound pipeline (ordered)

The pipeline splits across the A2A roundtrip — some work happens pre-send, the rest happens post-response.

**Pre-send (before the A2A wire):**

1. **Policy decision.** Consult the Policy Engine (§13.4) for `allow / allow_scoped / block / escalate` on the outbound payload. For `allow_scoped`, narrow the payload to permitted fields.
2. **Peer resolution.** Consult the Identity Directory (§13.5) to resolve the peer principal to a verified URL.
3. **SendClaim signing.** Compute `payload_hash = SHA-256(JCS(payload))`. Build a `SendClaim` (payload_hash, payload_schema, operation, sender_principal_id, context_id, timestamp, nonce — see §11.1 for the nonce's replay-defense role). Sign the canonical JCS bytes via Crypto Primitives (§13.9). Place the signature in the envelope's `send_claim_signature` field.
4. **Hand to A2A SDK Adapter.** Adapter sends; awaits response.

**Post-response (after A2A returns with the assigned `task_id`):**

5. **Verify peer's SendClaim** on the response. The gateway reconstructs the canonical SendClaim from the response envelope's fields and verifies the signature against the peer's published public key. Failed verification raises and aborts the post-response pipeline — no residue entries are written. (Phase 1 chose this strict ordering over the looser "log-and-continue" stance: if we can't authenticate the response, there's nothing to record. Phase 2+ may add a `rejected` Residue operation that captures verification failures forensically.)
6. **Build and sign emit Residue.** With the now-known `task_id` (obtained from `adapter.send_envelope()`'s returned response envelope's `task_id` field), build the outbound emit Residue (sequence = ledger.next_sequence, previous_hash = ledger.head_hash, payload_hash matches the SendClaim's). Sign the canonical Residue bytes with this user's key.
7. **Append emit Residue to Provenance Ledger** (§13.8). Validation in `ledger.append()` enforces sequence monotonicity and chain integrity; raises if anything is off.
8. **Build, sign, and append receive Residue** for the response (sequence = ledger.next_sequence, previous_hash = the just-appended emit's hash).

Why the split: A2A 1.0 assigns `task_id` only after the server-side roundtrip. The signed Residue needs `task_id`, so Residue construction cannot happen pre-send. The SendClaim (which is signable pre-send because it has no `task_id` field) carries the cross-side trust commitment on the wire; the Residue carries per-side accountability in the ledger. See §3.6 and §13.10 for the trust model.

#### Hard rule

There is no path from consumer code to the A2A wire that bypasses the Outbound Gateway. All outbound traffic goes through here.

#### Phase 4 trust-layer ops (bypass step 1)

Outbound `PROMOTE / FETCH / FETCH_RESPONSE / FETCH_DENIED` operations carry Mesherra's own promotion-lifecycle wire schemas (`mesherra.object/*`). The Policy Engine has no rules for these schemas — they are protocol-level, not user-policy-level — and the engine's default-deny stance on unmatched schemas would otherwise reject every `Mesherra.promote()` / `fetch_object()` call as soon as a real PolicyStore is wired. Step 1 (policy decision) is therefore *skipped* for these four operations; steps 2–8 (peer resolution, SendClaim signing, residue) run unchanged. Symmetric with the inbound bypass in §13.3.

### 13.3 Inbound Gateway

Sits between the A2A SDK Adapter (§13.10) and the consumer's agent handler. Owns every trust decision on incoming messages. No consumer code ever receives raw envelopes.

#### Concrete inbound pipeline (ordered)

When the adapter delivers a `MesherraEnvelope` via the registered `InboundHandler`, the gateway runs this pipeline:

1. **Schema check.** Resolve `envelope.payload_schema` against the Schema Registry (§13.11). If unknown or `envelope.payload` does not validate, reject. → A2A `InvalidParamsError` response; agent handler is NOT invoked.
2. **Sender resolution.** Look up `envelope.sender_principal_id` in the Identity Directory (§13.5). If unknown/unverified, reject. → A2A `InvalidAgentResponseError`.
3. **SendClaim verification.** Construct a `Verifier` from the resolved principal's public key. Reconstruct the canonical `SendClaim` bytes from the envelope: `{payload_hash = SHA-256(JCS(envelope.payload)), payload_schema, operation, sender_principal_id, context_id, timestamp, nonce}`. Verify `envelope.send_claim_signature` against those canonical bytes. If verification fails, reject. → A2A authentication error.
3a. **Clock-skew window check** (Phase 2 hardening per §11.1). Reject if `envelope.timestamp` is outside `now ± MESHERRA_CLOCK_SKEW_SECONDS`. → `TimestampOutsideWindowError`.
3b. **Nonce replay check** (Phase 2 hardening per §11.1). The gateway maintains a TTL-pruned `(sender_principal_id, nonce)` seen-set with lifetime `2 × clock_skew_seconds` (the longest a replay could still pass the timestamp check). If the pair has already been observed within the window, reject. → `ReplayedNonceError`. Order matters: this check runs AFTER signature verification so the seen-set is only populated by verified envelopes from known senders; an attacker cannot fill it with unverified traffic.
4. **Policy decision.** Ask the Policy Engine (§13.4) for an `allow / allow_scoped / block / escalate` verdict against the user's signed policy version. Apply the verdict — for `allow_scoped`, narrow the payload to the policy-permitted fields.
4a. **Phase 4 trust-op dispatch.** Before step 4 runs, the gateway inspects `envelope.operation`. If the operation is one of `PROMOTE / FETCH` (Slice 1 inbound trust-layer ops) or `SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE` (Slice 2 inbound trust-layer ops), the gateway *skips step 4* and dispatches the verified envelope to the Object handler (§13.13) instead of the consumer. Step 5 (residue write) still records the wire bytes; step 6 (consumer invocation) is replaced by the Object handler's `HandlerOutput → OutgoingResponse` translation. If the operation is one of `FETCH_RESPONSE / FETCH_DENIED` — response-only operations that should only ever arrive as the response to our own outbound FETCH — the gateway raises `UnsolicitedTrustOperation` and aborts (no residue, no dispatch). This pin is what keeps consumer code from intercepting trust-layer ops and violating the scope-filter (§9 #15 in `demos/phase_4/SPEC.md`) and stolen-handle (§9 #16) invariants. The Slice 2 ops extend these invariants to live promotions: SUBSCRIBE / OBJECT_UPDATE both check `sender_principal_id == promotion.receiver` (or `handle.owner` for the receiver-side OBJECT_UPDATE) before any state mutation, preventing stolen-handle subscribes and forwarded pushes.
5. **Residue write.** Build a `receive` Residue entry for this exchange (the A2A-assigned `task_id` is now known — it's on `envelope.task_id`). Sign with this user's key. Append to the per-user Provenance Ledger (§13.8). This happens *after* all verification steps so the ledger only contains observations the gateway has accepted as trustworthy. The ledger's duplicate-rejecting constraint (§13.8) raises `DuplicateEntry` if the same `(task_id, action_type, operation)` has already been recorded — this only happens if the seen-set in step 3b missed (e.g., across a process restart), and surfacing it as a hard error is the right behavior because a ledger that silently accepts duplicate writes has lost integrity.
6. **Agent invocation.** Call the registered consumer handler with the verified (and possibly scoped) envelope. The handler's return envelope flows back through the gateway, which:
   - Builds and signs the gateway's `emit` Residue for the response.
   - Wraps the response in a new SendClaim signed by this user.
   - Returns the new envelope through the adapter as the A2A response.

Rejected messages produce an A2A-level error response. The agent handler is not invoked for rejected messages. Phase 2+ may additionally record `rejected`-operation entries in the ledger for forensic purposes; Phase 1 only records successful interactions per SPEC §1.

#### Registration topology

```
Consumer agent     ──registers──▶  Inbound Gateway  ──registers──▶  A2AAdapter
                                                                      │
                                                                      ▼
                                                                    A2A wire
```

The consumer never sees the adapter; the gateway never appears in adapter signatures. This keeps trust enforcement uncircumventable: the only way for a consumer to receive A2A traffic is through the gateway.

#### Hard rule

No consumer code receives raw A2A messages. Everything inbound passes through the gateway first.

### 13.4 Policy Engine

Stateless decision-maker. Given `(payload, payload_schema, direction, policy)`, returns a `PolicyDecision` carrying a verdict plus, for `ALLOW_SCOPED`, the post-scoping payload that should actually cross the airlock.

Verdicts:

- `ALLOW` — pass the full payload
- `ALLOW_SCOPED` — pass the engine-specified scoped subset
- `BLOCK` — refuse the interaction (default-deny on unmatched schema, empty allow-list, or all fields removed)
- `ESCALATE` — reserved for future conditional rules; never produced in v1, but the gateways still handle it defensively (treating it as `BLOCK`) so a future engine returning it fails closed

**Phase 3 (shipped):** `mesherra.policy.PolicyEngine`. Stateless, no I/O, no clock — every dependency comes in via `evaluate()`. Rule semantics per `demos/phase_3/SPEC.md` §2.2: match on `(schema, direction)`; default-deny on no match; outbound/inbound allow-lists narrow what crosses; outbound/inbound block-lists drop named paths; `max_array_size` truncates arrays. Verdict is computed by JCS-canonical equality between input and post-rule payload.

Policy-version-aware: the engine validates against the version of policy the user signed (the doc's `version` field). The `PolicyStore` (§13.6) hands the latest signed version to the gateways on each evaluation; mismatches force re-signing rather than silent acceptance.

### 13.5 Identity Directory

The verified registry of principals.

**Phase 2 (shipped):** HTTP service backed by SQLite, fronted by a `DirectoryClient` consumer interface in `mesherra.identity`. The Outbound and Inbound Gateways resolve every peer through that client; the raw `dict[str, str]` of Phase 1 is gone.

Server endpoints (`mesherra.identity.server.create_app`):

- `GET /healthz` → liveness probe.
- `GET /.well-known/directory-public-key` → the directory's Ed25519 public key (base64). Operators publish this so clients can pin it out-of-band.
- `POST /principals` → register a principal. Once-only per principal id (re-register raises 409). **No write auth in v0 — must run behind a network policy or reverse proxy that gates POST traffic to trusted operators.**
- `GET /principals/{id}` → resolve a principal. Returns a record signed by the directory's root key over the canonical JSON of `{principal_id, public_key_b64, issued_at, expires_at}`. Each resolve mints a fresh signature with a fresh validity window (sign-on-read, not sign-once-at-register).

Consumer-side client interface (`mesherra.identity.client`):

- `DirectoryClient` Protocol with `async resolve(principal_id) → ResolvedPrincipal`.
- `StaticDirectoryClient` — in-memory dict-backed, for tests and unit scenarios.
- `HTTPDirectoryClient` — talks to a running directory; verifies every record against an operator-pinned public key before returning it. Raises `DirectorySignatureVerificationFailed` on mismatch, `UnknownPrincipalError` on 404, `DirectoryUnavailableError` on network failure.

**Deferred to a later phase:**

- `attest(principal_a, principal_b)` → "these two are verified peers" assertion.
- Write authentication on `POST /principals`.
- Signed key-rotation flow (v0 has no rotate API; operator delete + re-add).

v0: centralized, Mesherra-hosted. Trust root is the directory's organizational signing key (pinned out-of-band by every client).

Future: pluggable backend designed to swap to decentralized (PKI, web-of-trust, transparency log) without rewriting consumers — the `DirectoryClient` Protocol is the migration seam.

### 13.6 Policy Store

Backing storage for the user's signed constitution. Per-user.

Properties:

- **User-owned**: only the user's signing key can produce a valid update
- **Versioned**: every change is a new signed version with a monotonically increasing version number
- **Local-first**: stored on the user's device, replicated to Mesherra-hosted backup with end-to-end encryption
- **Schema-validated**: every version must match the policy schema for the Mesherra version it was signed against

**Phase 3 (shipped):** SQLite-backed `mesherra.policy.PolicyStore`. Per-principal: one store serves one principal's policies, bound at construction to that principal's `(principal_id, public_key_b64)`. Every read verifies the stored signature against the bound key — `PolicyVerificationFailed` on mismatch, treat as tampering. Versions are append-only and strictly monotonic; non-monotonic insert raises `NonMonotonicPolicyVersion`. Cross-principal save attempts raise `PolicyPrincipalMismatch`. Schema-versioned via a `policy_meta` row with fail-fast on mismatch (mirrors `DirectoryStore.directory_meta`). End-to-end-encrypted backup replication ships later.

### 13.7 Directory Store

Backing storage for the Identity Directory.

**Phase 2 (shipped):** SQLite-backed, `mesherra.identity.store.DirectoryStore`. One row per principal: `principal_id` (PK), `public_key_b64`, `registered_at`. Mirrors the lifecycle conventions of `ProvenanceLedger` (§13.8): context-manager wrapped, schema-versioned, fail-fast on mismatch. The store enforces register-once: a second registration for the same principal raises `PrincipalAlreadyRegistered`. Phase 3+ will add a signed key-rotation flow that chains a new row to the previous.

v0: SQLite (recommended for local + small deployments). Future: pluggable backend for Postgres or decentralized models.

Future: pluggable backend for decentralized models.

### 13.8 Provenance Ledger

The append-only signed log of every Mesherra interaction.

Properties:

- **Append-only**: entries cannot be modified or deleted, only appended
- **Tamper-evident**: each entry references the hash of the previous (hash-chain or Merkle-tree)
- **Per-user shard**: a user can retrieve their full residue without exposing other users'
- **Indexed**: by A2A `task.id` and `context_id` for fast lookup
- **Duplicate-rejecting**: refuses a second entry with the same `(task_id, action_type, operation)` — Phase 2 defense-in-depth replay backstop per §11.1 (raises `DuplicateEntry`)
- **Referenceable**: future tasks can cite prior residue via A2A's `Message.reference_task_ids`, compounding trust across interactions

v0: append-only Postgres table with hash-chain integrity. Future: pluggable for distributed ledger or cryptographic transparency systems.

### 13.9 Crypto Primitives

Shared utility module. No invention; off-the-shelf libraries only.

Provides:

- Signing and signature verification (Ed25519 or equivalent modern scheme)
- Key management (per-principal keys, per-session ephemeral keys)
- Content addressing (SHA-256 hashing)
- Short-lived scoped credentials for guest principals (the cold-start primitive MeshyCal needs for frictionless invitees; the lifecycle — minting, expiry, conversion to standing — is deferred to Phase 1.5 and tracked in section 14)

### 13.10 A2A SDK Adapter

The only module in Mesherra that imports `a2a-sdk`. Strict isolation: if A2A changes, only this module changes.

#### What a2a-sdk gives us (we consume, do not re-shape)

Google's A2A SDK ships protobuf-defined wire types (`a2a.types`) plus async client and server frameworks (`a2a.client.Client`, `a2a.server.agent_execution.AgentExecutor`). Wire types are **protobuf messages, not Pydantic models** — they are constructed imperatively (e.g. `Message(message_id=..., parts=[...])`) and serialized via `.SerializeToString()` / `.FromString()`. Any contributor coming from steps 1–3 of this codebase will expect Pydantic; the adapter is the layer where that expectation breaks.

The Mesherra core depends on the following `a2a-sdk` extras (declared as `a2a-sdk[http-server,sqlite,signing]` in `pyproject.toml`):

- `http-server` — pulls in `starlette` and `sse-starlette`. Required by the per-agent listener (see §13.10 "Server location").
- `sqlite` — pulls in `sqlalchemy[aiosqlite]`. Required by the SDK's internal task tracking on the server side (independent of Mesherra's own Provenance Ledger).
- `signing` — pulls in `pyjwt`. Required by the server's AgentCard signature path; Phase 1 does not exercise it but the dep is needed for the server to construct.

These are **core** Mesherra dependencies, not optional. Every concrete deployment either sends messages, receives messages, or both, and the install footprint is acceptable. We do not split into `mesherra[server]` extras because every running Delegation ends up needing the full set.

#### Two signed objects, two purposes

Mesherra signs at two layers, with two distinct signed objects:

* **SendClaim** — signed *pre-send* by the sender. Lives on the A2A wire. Attests "I really sent this payload, with this semantic operation, in this context at this time, with this single-use nonce." Verifiable by the receiver using only fields available on the wire. Defined in `mesherra.models.primitives.SendClaim`. Schema: `{payload_hash, payload_schema, operation, sender_principal_id, context_id, timestamp, nonce}`. The `nonce` field is the Phase 2 replay defense (added per §11.1): a sender-generated UUID4 the inbound gateway tracks in a per-sender seen-set so a captured envelope cannot be re-delivered within the clock-skew window.
* **Residue** — signed *post-response* by each ledger owner over their own ledger entry. Anchors per-side accountability. Contains ledger-relative fields (`sequence`, `previous_hash`) that the wire cannot carry. Defined in `mesherra.models.primitives.Residue`.

Both signatures are by the same actor on the sender side (A signs both A's SendClaim and A's emit Residue), but the two objects serve different purposes and live in different places. The receiver verifies the SendClaim signature inline at receive time (gateway pipeline step 3); the Residue signature exists purely for post-hoc audit of each ledger.

Why the split: A2A 1.0 assigns `task_id` only after the server-side roundtrip. A Residue is signed with `task_id` *inside* its canonical bytes, so the sender cannot sign a Residue before sending. The SendClaim is the largest signable object that has no dependency on `task_id`. See SPEC §2a (SendClaim schema) and the Phase 1 design decision notes.

#### MesherraEnvelope: the boundary type

The adapter exposes a single Pydantic model — `MesherraEnvelope` — that all upstream Mesherra code uses. No other module in Mesherra ever touches a protobuf message.

```python
class MesherraEnvelope(BaseModel):
    task_id: str = ""           # empty on first send; A2A assigns and returns on response
    context_id: str
    sender_principal_id: str
    payload: dict[str, Any]
    payload_schema: str
    operation: Operation        # PROPOSAL/COUNTER/ACCEPTANCE/REJECTION; signed as part of the SendClaim
    timestamp: str              # ISO-8601 UTC when sender prepared the send
    nonce: str                  # sender-generated UUID4 for inbound replay defense (§11.1); signed
    send_claim_signature: str   # base64 Ed25519 over canonical(SendClaim)
```

This is the boundary shape. The adapter is the single translator between this and the A2A wire format.

#### Wire format mapping

| MesherraEnvelope field | A2A Message location |
|---|---|
| `task_id` | `Message.task_id` |
| `context_id` | `Message.context_id` |
| `payload` (dict) | `Message.parts[0]` as `Part.data` (Value wrapping a Struct) |
| `payload_schema` | `Message.metadata["mesherra.send_claim.payload_schema"]` |
| `sender_principal_id` | `Message.metadata["mesherra.send_claim.sender_principal_id"]` |
| `timestamp` | `Message.metadata["mesherra.send_claim.timestamp"]` |
| `send_claim_signature` | `Message.metadata["mesherra.send_claim.signature"]` |
| `operation` | `Message.metadata["mesherra.send_claim.operation"]` |
| `nonce` | `Message.metadata["mesherra.send_claim.nonce"]` |
| (implicit) | `Message.role = ROLE_AGENT` |

Single sub-namespace under `mesherra.*`:

* **`mesherra.send_claim.*`** — every Mesherra-namespaced metadata key lives here in Phase 1, because every wire-side trust-relevant field is signed as part of the SendClaim. Receiver verifies these against the sender's published public key. `operation` was promoted into this namespace during Phase 1 review: under the older `mesherra.payload.operation` layout an in-transit attacker could flip PROPOSAL↔ACCEPTANCE without invalidating the signature, then the receiver (which branches on `operation`) would honor it. Signing `operation` closes that gap.

The `mesherra.*` namespace on metadata keys is reserved. Consumers MUST NOT use this prefix for their own metadata.

The Residue does NOT travel on the wire. Each ledger owner constructs their own Residue post-response and signs it with their own key (per the Outbound Gateway and Inbound Gateway pipelines in §13.2 and §13.3). The receiver does not need the sender's Residue bytes for any Phase 1 trust property — the cross-ledger linkage is via shared fields (`payload_hash`, `task_id`, `context_id`, `payload_schema`) and the wire-level SendClaim signature.

**Known unsigned wire field — `task_id`.** Every Mesherra-namespaced wire field is part of the signed SendClaim *except* `task_id`, which travels on the envelope but is not in the SendClaim. This is forced by A2A 1.0: `task_id` is assigned by the receiver's server post-roundtrip, so the sender cannot sign it pre-send. The threat profile is bounded — unlike the (now-closed) unsigned-`operation` case, a flipped `task_id` cannot coerce either party into appearing to agree to anything they didn't. It can only corrupt the cross-ledger linkage invariant (the two ledgers' entries for the same exchange would no longer share `task_id` and could not be paired in an audit). Phase 1 accepts this as a known limitation. Phase 2+ may add a post-roundtrip second signature (over the now-known `task_id`) if cross-ledger linkage integrity needs to be enforceable on each side rather than only mutually agreed.

#### Adapter API surface (Phase 1)

```python
class A2AAdapter:
    """The single bridge between Mesherra and a2a-sdk."""

    # Outbound (client side). Always available.
    async def send_envelope(
        self,
        peer_url: str,
        envelope: MesherraEnvelope,
    ) -> MesherraEnvelope:
        """Send envelope to peer; await peer's response envelope."""

    # Inbound (server side). Started by the per-agent process.
    def register_handler(self, handler: InboundHandler) -> None:
        """Register the callback that receives RAW envelopes from the wire."""

    async def start_listener(self, host: str, port: int) -> ListenerHandle:
        """Start the per-agent A2A HTTP listener. Returns a graceful-shutdown handle."""

    # Phase 2/3 surface (NotImplementedError in Phase 1)
    async def subscribe_to_task(self, task_id: str) -> AsyncIterator[StateUpdate]: ...
```

The `InboundHandler` Protocol:

```python
class InboundHandler(Protocol):
    async def __call__(self, envelope: MesherraEnvelope) -> MesherraEnvelope | None:
        """Process inbound envelope; optionally return response envelope.

        The adapter delivers RAW envelopes — no trust decisions are made at this
        layer. The Inbound Gateway (§13.3) is the next layer up; IT owns
        verification, ledger writes, and policy. Consumers register with the
        Gateway; the Gateway registers with the adapter.

        Return None for fire-and-forget. Return an envelope to send back as
        the A2A response on the same task.
        """
```

#### Server location: per-agent process

Each running agent process (e.g., a MeshyCal scheduling agent on `localhost:8001`) calls `start_listener(host, port)` to serve its own A2A endpoint. There is no central Mesherra-managed listener — the SDK supports such a layout, but Phase 1 does not require it. This decision matches:

- The Google A2A reference examples' deployment model
- The SPEC §6 two-process demo flow (Agent A on 8001, Agent B on 8002)
- Build discipline #4 (ride the SDK — don't add an extra Mesherra router)

If a future deployment wants a fan-out router, it can be added as a new component without changing the adapter API.

#### Strict isolation (enforced)

- `a2a-sdk` may be imported only by files under `src/mesherra/a2a_adapter/`.
- `MesherraEnvelope` is the *only* type that crosses out of this module to other Mesherra code.
- No other Mesherra module references `a2a.types.*`, `a2a.client.*`, or `a2a.server.*`.
- A test asserts this (Phase 1.5+) via grep on the source tree.

### 13.11 Schema Registry

Verified registry of payload schemas published by consumers. Sibling to the Identity Directory, with parallel mechanics.

Operations:

- `resolve_schema(id, version)` → schema definition + publisher signature
- `publish_schema(schema, publisher)` → signed registration (requires verified principal)
- `list_versions(id)` → version history for compatibility checking
- `verify_publisher(schema, publisher_principal)` → confirms the schema is genuinely from the claimed publisher

Trust model: schemas are signed by their publisher's principal (verified through Identity Directory). Receivers verify a schema is authentic before accepting payloads against it.

v0: centralized, Mesherra-hosted. Same migration path to federated/decentralized as the Identity Directory.

See section 8 for the broader schema-based messaging model that this component supports.

### 13.12 Object Store

Per-principal append-and-update persistence for Mesherra `Object`s (§3.2) and the `Promotion` records derived from them (§3.7). Parallel to §13.8 Provenance Ledger in shape and discipline: one SQLite file per principal, self-describing meta row, denormalized indexed columns plus a canonical-JSON source-of-truth column.

Operations:

- `put(object)` — insert-or-update an Object (owner-only at the SDK gate; ObjectStore itself trusts caller)
- `get(object_id)` → the canonical Object, reconstructed from the source-of-truth JSON column
- `list()` → all Objects in this principal's store
- `record_promotion(promotion)` — append a Promotion row tying `promotion_id` to `(object_id, snapshot_state, scope, expiry, receiver)`
- `get_promotion(promotion_id)`, `list_promotions_for_object(object_id)`, `list_promotions_for_receiver(receiver)`
- **Slice 2 active-subscriptions table** (`active_subscriptions`): one row per (promotion_id, role) tracking the live-subscription state. Role distinguishes owner-side rows (one per receiver who has subscribed) from receiver-side rows (one per active subscription this principal holds against an owner). Operations: `record_subscription`, `get_subscription`, `update_subscription_status`, `update_subscription_pushed_version`, `reset_subscription_pushed_version`, `update_subscription_peer_url`, `list_active_subscriptions_for_object`. Unlike `promotions`, this table is update-mutated: status and `last_pushed_object_version` advance over time (the history of changes lives in the residue ledger).

Storage rule: every column outside the canonical JSON column is denormalized for query. The canonical JSON column is the source of truth; on row read, the loader reconstructs the model and asserts denormalized columns match. Drift between the two is a corruption signal.

Trust model: ObjectStore enforces append-only semantics on `promotions` (no update/delete). Promotion-time `snapshot_state` is stored inline for static reference promotions and returned verbatim on every fetch — the snapshot's content_hash is the cryptographic anchor that links the wire PromotionHandle to what the counterpart actually sees, regardless of whether the owner mutates the Object afterwards. For live promotions, `snapshot_state` is `null` on the Promotion row (pushes carry the snapshot; fetches compute it from the Object's current state); the handle's `snapshot_content_hash` commits to the *initial* scoped state at promotion-creation time, which the consumer may use to verify the first push (per `demos/phase_4/SLICE_2_SPEC.md` §6.2).

v0: SQLite, parallel to §13.8. Same future pluggability story.

See `demos/phase_4/SPEC.md` for the Slice 1 schema and end-state assertions, and `demos/phase_4/SLICE_2_SPEC.md` for the Slice 2 additions (the `active_subscriptions` table and live-reference push lifecycle).

### 13.13 Object Handler

Trust-layer routine the Inbound Gateway (§13.3) dispatches to for Phase 4 trust-layer operations. The handler sits between the gateway and the Object Store (§13.12), enforcing the invariants that the consumer is not allowed to violate.

**Slice 1 responsibilities (PROMOTE / FETCH):**

- **PROMOTE inbound.** Verify `handle.owner_signature` against `handle.owner`'s directory-resolved public key (a second signature check on top of the gateway's SendClaim verification — the gateway proves the envelope is from the sender, the handler proves the handle's *contents* are owner-authored). Slice 1 forbids forwarded handles: `sender_principal_id == handle.owner` is required; relaxation is Slice 3+. On success, persist via `ObjectStore.record_received_handle` (which itself enforces `handle.receiver == this principal`, the second line of defense behind the airlock) and return a `PromotionAck`.
- **FETCH inbound.** Look up the promotion in our own ObjectStore. Three soft failures return a `FetchDenied` (with a pinned `DenialReason` Literal — `expired`, `revoked`, `receiver_mismatch`, `unknown_promotion`, `scope_violation`): unknown promotion id, sender not the promotion's receiver (the §9 #16 stolen-handle invariant), or current time past `promotion.expiry`. On success, build a `FetchResponse` — STATIC promotions return the pre-stored snapshot verbatim (Slice 1 byte-equality across fetches); LIVE promotions compute the scoped state fresh from the Object's current state (Slice 2 §6.2 LIVE-fetch semantics).

**Slice 2 responsibilities (SUBSCRIBE / UNSUBSCRIBE / OBJECT_UPDATE):**

- **SUBSCRIBE inbound (owner-side).** Per the §7.2 SUBSCRIBE matrix in `demos/phase_4/SLICE_2_SPEC.md`: branches on pre-state via `get_subscription` BEFORE any store mutation, so an EXPIRED row produces `SubscribeDenied(expired)` on the wire rather than the internal `InvalidSubscriptionTransition`. Soft denials cover `unknown_promotion`, `receiver_mismatch` (stolen-handle invariant extended to LIVE), `not_live_promotion`, and `expired`. On success, inserts or transitions the owner-side `active_subscriptions` row to ACTIVE (with the receiver's listener URL captured for the push path), resets `last_pushed_object_version` on the CLOSED_BY_RECEIVER → ACTIVE re-subscribe path, and refreshes `peer_url` on both CLOSED_BY_RECEIVER → ACTIVE and DISCONNECTED → ACTIVE recovery paths.
- **UNSUBSCRIBE inbound (owner-side).** Per the §7.2 UNSUBSCRIBE matrix: marks the row CLOSED_BY_RECEIVER. Soft denials `not_active` (no row, or sender != receiver — collapsed to the same reason to avoid leaking row existence to Eve) and `expired`.
- **OBJECT_UPDATE inbound (receiver-side).** Per §7.3: hard failures (unknown received handle, sender != handle.owner, mutability != LIVE, on-the-wire snapshot_content_hash mismatch after defense-in-depth recomputation) raise `InvalidObjectUpdatePayload`. Soft failures (expired handle, no subscription row, `object_version <= last_pushed_object_version` regression) return `ObjectUpdateDenied` with a structured reason. On success, bumps `last_pushed_object_version` on the receiver-side row and invokes the SDK-registered `on_object_update` callback with verified data only.

Why a separate handler (not the consumer): these operations are part of Mesherra's trust contract. Letting domain code intercept them would let a consumer return the wrong snapshot (violating §9 #15), accept fetches or pushes from non-receivers (violating §9 #16), or forward live pushes without owner authority. The Inbound Gateway dispatches these operations to the handler *before* the consumer ever sees them.

Construction: one handler per Mesherra instance, built by the SDK whenever an `object_store` is provided. The handler holds an optional `_object_update_callback` (set via `register_object_update_callback`) that the SDK wires from `Mesherra.on_object_update`. Stateless across calls beyond that one slot — all persistent state lives in the store. The SDK wires the handler into the Inbound Gateway as the `object_handler` parameter; gateways constructed without one raise `TrustLayerHandlerNotWired` on any inbound trust-layer op so a misconfiguration fails loudly rather than silently dispatching to the consumer.

See `demos/phase_4/SPEC.md` §8 for the Slice 1 wire-protocol details and §9 #15/#16 for the privacy invariants; see `demos/phase_4/SLICE_2_SPEC.md` §§2, 7.2-7.3, 9 #11-#13 for the Slice 2 extensions.

### Build order, mapped to components

The pieces from section 4 map onto these components as follows:

| Section 4 piece | Primary components built |
|---|---|
| Provenance / attestation (ships first) | 13.8 Provenance Ledger, 13.9 Crypto Primitives |
| Identity verification (ships second) | 13.5 Identity Directory, 13.7 Directory Store |
| Scoped disclosure (ships third) | 13.4 Policy Engine, 13.2 Outbound Gateway, 13.3 Inbound Gateway, 13.11 Schema Registry |
| Object promotion lifecycle (ships fourth) | 13.12 Object Store, 13.13 Object Handler, plus extensions to 13.2 / 13.3 for `promote` and `fetch` operations |
| Policy capture (co-develops throughout) | 13.6 Policy Store, plus schema work in 13.4 |

The SDK (13.1) and A2A SDK Adapter (13.10) are foundational: both develop continuously from day one because every piece depends on them.

## 14. Open design questions

These are unresolved and will be answered through implementation in MeshyCal and subsequent consumers.

- **Conflict-resolution policy when two butlers' policies disagree.** Strictest-wins, human-escalation, or negotiated-middle? Test cases will force this decision.
- **Promotion extent classifier accuracy.** How does the system decide *what slice* of an Object a gesture authorized? Probably starts policy-driven, learns over time.
- **Open-mesh reputation layer.** How does a boundary agent trust a stranger agent with no prior history? Out of scope for v0, in scope before any consumer touches the open mesh.
- **Guest principal lifecycle.** How short-lived, scoped guest identities are minted, used, and either expire or convert to standing principals. MeshyCal will force the first answer here.
- **Decentralized trust migration path.** When and how the centralized directory transitions to a federated or PKI-based model.
- **Object co-ownership governance.** Dropped from v0 to avoid a half-defined primitive. v1+ design likely uses multi-signature consent (N-of-M owner principals must co-sign any change to the Object's policy or any new promotion), with provenance recording each signer's consent. Specifics deferred until a real co-owned use case forces the design.
- **Economic model.** Not strictly an architecture concern, but who pays — consumers per-call, users by subscription, organizations per-seat — drives which components get hardened first and how the Directory and Schema Registry should be priced. Open question to carry alongside the technical ones.
