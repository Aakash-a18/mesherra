# Concept note — Circles, shared Delegations, and the group-chat analogy

> **Status: concept, not committed architecture.** This note captures a design
> thread ahead of any implementation phase. Nothing here overrides
> `ARCHITECTURE.md`; where the two disagree, `ARCHITECTURE.md` wins until this
> note graduates. Vocabulary follows `CLAUDE.md`.

## 1. The analogy (front door, not blueprint)

Mesherra can be introduced as **a group chat for applications**: Discord-style
servers — two-person or ten-person — where roles determine what each member can
see, do, and interact with inside the application layer.

The mapping onto existing vocabulary:

| Group-chat concept | Mesherra concept |
|---|---|
| Server / group chat | The interaction context between principals |
| Role | Per-viewer layer-membership + policy-derived authority |
| Channel visible only to a role | An Object promoted to some members, not others |
| Installing a bot into a server | Installing a Delegation into a context |

The analogy is a good front door and a bad blueprint, because the places it
*breaks* are the actual pitch:

1. **Discord has an admin; Mesherra doesn't.** A server owner defines roles and
   everyone submits to that authority (and to the platform above it). In
   Mesherra every participant brings their own user-owned Policy. Roles are not
   assigned — they are **negotiated at the door**, which is what the Handshake
   being continuous and stateful means. No platform can rewrite your
   permissions, because Policy is user-authored by construction.
2. **Discord roles are static; Mesherra scopes are contextual.** A Discord role
   is looked up; a disclosure scope is *computed per interaction* by the
   PolicyEngine (ALLOW / ALLOW_SCOPED / BLOCK). Same counterpart, different
   context → different effective role. Interactions are curated on the spot.
3. **Servers persist; most Mesherra interactions dissolve into residue.** The
   default interaction is transient — the "server" exists for the negotiation,
   and what persists is the signed, tamper-evident record on both sides.

One-liner: *every interaction is an ad-hoc server where each member is their
own admin, roles are negotiated rather than assigned, and when the server
dissolves both sides keep a signed receipt of what happened inside it.*

Why this matters now: application creation itself has collapsed to near-zero
cost. When anyone can generate an app instantly, the app stops being the
scarce thing; **the interaction context becomes the product**. What you
install is not software but authority over a domain plus rules for who sees
what inside it — i.e., a Delegation. In the analogy's terms: the server *is*
the application now.

## 2. New primitives the analogy surfaces

Everything in `ARCHITECTURE.md` today is essentially **bilateral**: two
butlers, a handshake, promotions between counterparts, residue on both sides.
The analogy — pushed through a concrete multi-party example (a household) —
surfaces three primitives the current model does not yet have.

### 2.1 Circle — a standing multi-party context with a role lattice

A **Circle** is a persistent group context: membership, a role lattice, and a
co-signed context constitution. Example shape (synthetic): a household Circle
where two guardian-role members are co-equal with each other and hold superior
authority to two member-role members, all inside the same layer.

This is different in kind from the current Layer definition ("a visibility
zone"). A Layer answers *who can perceive*; a Circle additionally carries
*membership, roles, and a role → authority mapping*. A Circle is not a
transient handshake — it is a standing context that Objects and Delegations
can live inside.

Discipline note: **"family" is a domain; Circles are not.** Mesherra ships the
generic primitives — standing multi-party context, role lattice, co-signed
constitution, role-scoped promotions. Guardian/member/chore-chart semantics
belong in a Delegation's policy templates and Object class definitions, the
same way MeshyCal owns meeting semantics. Mesherra knows *roles exist and
scope capabilities*; it never knows what a parent is.

### 2.2 Shared Delegation instances

Today a Delegation installs under **one** user's butler, governed by that
user's policy. A shared calendar, chore list, or door-passkey Object implies a
Delegation whose *instance* is shared: one canonical Object set, multiple
principals with different authority over it.

This composes with existing promotion mechanics: the canonical Objects live in
one home layer (or a Circle-designated store), and each member holds a
**reference-mode promotion** scoped to their role. Owner retains canonical
state; handles are revocable; every promotion is signed into residue.

### 2.3 Constitution composition (context ∩ personal, restrict-only)

In the bilateral model each party's policy governs their own boundary. A
Circle introduces a second document: the **context constitution** — authored
by some members (e.g., the guardians), co-signed by every member's agent on
joining.

Proposed composition rule:

> The context constitution defines the role table and the **maximum**
> authority each role can hold. A member's personal policy can further
> restrict, never expand. An agent operating inside a Circle is bound by the
> intersection.

This keeps the hard rule intact — the platform never writes policy, and no
member writes another member's policy. The context constitution does not
reach inside anyone's boundary; it defines what the *context will honor* from
each role.

### 2.4 Capability-scoped handles: unexpressible, not blocked

Two enforcement models for "a member-role agent must not delete the shared
chore chart":

- **Policy-as-gate** — the agent attempts the delete, the request hits the
  boundary, the PolicyEngine returns BLOCK. The verb exists; it is refused.
- **Capability-scoped handle** — the promotion the agent holds simply does not
  contain a delete verb. Deletion is not forbidden; it is **unexpressible**.
  There is nothing to block because there is nothing to attempt.

The second is strictly stronger (nothing to bypass; no reliance on the
counterpart's gateway behaving) and falls naturally out of promotion
mechanics: a reference-mode promotion already carries "owner retains canonical
state"; it additionally carries a **verb set derived from the holder's role in
the context constitution**. Read-and-check-off for one role, full CRUD for
another. Gate-style policy evaluation remains as defense in depth at the
boundary.

## 3. Worked example — ambient meal-memory (synthetic)

*All data in this example is synthetic. The scenario illustrates the
primitives; the domain logic described belongs entirely in a hypothetical
consumer Delegation, never in Mesherra.*

**The problem.** A household's tastes cycle: a dish gets cooked repeatedly for
weeks, fatigue sets in, it vanishes — and months later nobody remembers it
existed. An app that resurfaces forgotten favorites ("you ate variations of
this three times a week last spring and nothing similar since") is useful but
dies twice in today's app model:

1. **Input friction** — every member must manually log every meal, forever.
2. **Multiplayer cold start** — the app is worthless unless the whole
   household adopts it on day one. One holdout and it collapses.

Today's app must build both the data pipeline and the social graph from zero.

**The Delegation version.** One member finds the meal-memory Delegation and
installs it. Their agent carries a **proposal into the household Circle**;
each member's butler evaluates it against that member's personal policy plus
the Circle constitution. A guardian-role member might see a one-tap approval;
a member-role agent might auto-consent because the constitution already
delegates that class of decision. Adoption is not N app downloads — it is
**ratifying a proposal in an existing context**. The Delegation inherits both
the membership and the data streams the Circle's members already have.

**Why ambient capture is acceptable here and nowhere else.** The Delegation's
value depends on background ingestion — grocery receipts today, ambient
observation (AR overlays) eventually. In the app model, "an app that reads all
receipts" is a privacy horror: receipts carry pharmacy items, prices,
locations, payment details. Here, the friction removal and the privacy
guarantee are the same mechanism:

- Raw receipts never leave each member's personal layer.
- The Delegation's domain agent runs **under each member's own butler**,
  inside the boundary. The Delegation author never sees anyone's data.
- What crosses into the Circle is a **derived Object** (dish, ingredient
  class, date — per the Delegation's registered schema), promoted in reference
  mode, revocable, signed into residue.
- The promotion's verb set is role-scoped and the field set is
  schema-scoped: the Delegation cannot express a request for the pharmacy
  line. Not refused — **unexpressible** (§2.4).
- A member who leaves the Circle or revokes stops contributing from that
  moment; residue records exactly what was ever shared.

**What the "app" decomposes into.** Exactly the four-piece Delegation package:
an Object class (food-consumption event schema), Agent code (the pattern
detector that notices a dish cycled out and nothing similar has appeared
since), Policy templates (which source fields are food-relevant; what the
derived Object may contain; role → verb defaults), and a UI manifest (the
surface that nudges "you haven't had anything like this in eight months").
The nudge a member sees is **their own agent talking to them**, informed by
Circle-shared derived Objects — not a third-party service that harvested the
household's data.

## 4. Delegations are applications for agents

The example above still assumed a store: a member *finds* the Delegation. With
agentic coding the marginal cost of authoring the four-piece package (Object
class, Agent code, Policy templates, UI manifest) approaches zero, and the
concept sharpens into its final form:

> **A Delegation is an application whose primary user is an agent.** Humans
> supply intent and receive outcomes. The UI is a projection, generated on
> demand — possibly never.

Three consequences:

**Market-of-one software.** A Delegation custom-tuned to a single Circle is
economically viable. A member's agent does not find the meal-memory
Delegation — it *writes* it, proposes it to the Circle, actively uses it,
monitors it, and reports back. If a human ever wants to look, their agent
projects a visual layer on the spot (screen, AR overlay — whatever the
current era renders to). If they never ask, no UI ever exists. This is build
discipline #3 ("principal model first, renderer second; the UI is disposable")
taken to its endpoint: the renderer is not merely disposable but **lazily
generated**.

**Distribution inverts.** The "store" stops being a shelf of binaries and
becomes, at most, a library of proven schemas and authority patterns that
agents draw on when synthesizing. The four-piece package remains portable —
a Delegation authored for one Circle can still be published — but publication
is an option, not the pipeline.

**Trust relocates from author to container.** Agent-authored, on-the-spot
software running inside a shared context is untenable in the current model,
which locates trust in the *author* (app review, brand, code audit). When the
author is an ephemeral agent, that anchor is gone. Mesherra relocates trust to
the **container**: the synthesized Delegation runs under each member's butler,
holds only capability-scoped handles minted from the Circle constitution, and
every action lands in residue. Nobody trusts the code, because the code
cannot express actions outside its grant (§2.4). Review changes shape
accordingly: nothing reviews the implementation; the butler — or the human,
for high-stakes grants — reviews the **authority manifest**: which schemas,
which verbs, which scopes. That is a small, structured, policy-checkable
object, so consent to agent-authored software can itself be largely automated
under the constitution.

A closing symmetry: "the agent monitors the application and gives the user
feedback on its usage" requires no telemetry system. Residue *is* the usage
record — the agent reports by reading the signed trace, and there is nothing
for the Delegation's author (an agent) to exfiltrate.

## 5. Open questions

- **Circle schema.** Membership lifecycle (join, leave, eviction), role
  lattice representation, constitution amendment and re-signing.
- **Canonical residence of shared Objects.** Which member's stack (or what
  neutral store) holds canonical state for a shared Delegation instance, and
  what happens when that member leaves.
- **Verb-set minting.** How a promotion's capability set is derived from the
  role table and represented on the wire; interaction with copy-mode
  promotions (where conditions are honor-system).
- **Restrict-only composition edge cases.** What happens when a member's
  personal policy restricts below the minimum a role needs to function in the
  Circle (graceful degradation vs. refusal to join).
- **Multi-party residue.** Bilateral residue is well-defined; what does the
  append-only trace look like when N members hold handles to one Object?
- **Authority manifest.** Concrete shape of the reviewable grant object for an
  agent-authored Delegation (schemas + verbs + scopes), and how much of its
  approval a constitution can safely automate versus escalate to a human.
- **Sequencing.** None of this blocks Phases 1–4. Circles look like a
  post-Phase-4 layer that reuses promotions, policy, and residue as-is and
  adds the standing-context, role, and constitution-composition machinery on
  top.
