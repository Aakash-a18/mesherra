# Mesherra Visual Reference

Six diagrams covering the architecture from outside-in:

1. **The Layer Stack** — where Mesherra sits in the larger system
2. **Two Users, Mirrored Stacks** — A2A in the middle, internal zones on each side
3. **One Full Meeting Negotiation, Step by Step** — end-to-end flow between two users
4. **Mesherra Internal Architecture** — what's inside the trust layer
5. **Outbound Message Flow** — what happens when a consumer sends
6. **Inbound Message Flow** — what happens when a message arrives

Read them in order for the cleanest mental model. See `docs/ARCHITECTURE.md` for the corresponding prose.

---

## Diagram 1: The Layer Stack

What sits on what.

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│   MeshyCal App  (mobile/web UI)                            │
│   ─ User-facing surface, disposable, swap per era          │
│                                                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│   MeshyCal Scheduling Agent  (domain logic)                │
│   ─ Reads private calendar                                 │
│   ─ Proposes / evaluates candidate slots                   │
│   ─ Domain-specific to scheduling                          │
│                                                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│       ◆◆◆◆◆  MESHTES (trust layer)  ◆◆◆◆◆                 │
│                                                            │
│   ─ Butler (apex agent, airlock gate)                      │
│   ─ Identity verification (who's really there)             │
│   ─ Scoped disclosure (only minimum crosses)               │
│   ─ Provenance / attestation (signed record)               │
│   ─ Policy enforcement (user-owned rules)                  │
│                                                            │
│       ↑ THIS IS WHAT WE BUILD AND SELL                     │
│                                                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│   A2A Protocol SDK  (Google's, open standard)              │
│   ─ Discovery (AgentCard at well-known URL)                │
│   ─ Task lifecycle (multi-turn conversation state)         │
│   ─ Message transport (text, data, files)                  │
│   ─ Streaming, push notifications                          │
│                                                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│   HTTPS / mTLS / OAuth  (off-the-shelf internet plumbing)  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Read top to bottom.** The consumer app is what the user sees. Under it sits the consumer's domain logic. Under that, Mesherra. Under us, Google's A2A protocol. Under that, the regular internet.

Mesherra is the layer between any consumer app and the wire. The app calls into us. We call into A2A.

---

## Diagram 2: Two Users, Mirrored Stacks

The A2A wire in the middle, internal trust zones on each side.

```
   ┌──────────────────────────┐         ┌──────────────────────────┐
   │       USER 1's SIDE      │         │       USER 2's SIDE      │
   │                          │         │                          │
   │   ┌──────────────────┐   │         │   ┌──────────────────┐   │
   │   │     User 1       │   │         │   │     User 2       │   │
   │   │     (human)      │   │         │   │     (human)      │   │
   │   └────────┬─────────┘   │         │   └────────▲─────────┘   │
   │            │             │         │            │             │
   │            ▼             │         │            │             │
   │   ┌──────────────────┐   │         │   ┌────────┴─────────┐   │
   │   │  MeshyCal App    │   │         │   │  MeshyCal App    │   │
   │   │    (UI)          │   │         │   │    (UI)          │   │
   │   └────────┬─────────┘   │         │   └────────▲─────────┘   │
   │            │             │         │            │             │
   │            ▼             │         │            │             │
   │   ┌──────────────────┐   │         │   ┌────────┴─────────┐   │
   │   │     BUTLER       │   │         │   │     BUTLER       │   │
   │   │  (apex agent)    │   │         │   │  (apex agent)    │   │
   │   │  Loyal to U1     │   │         │   │  Loyal to U2     │   │
   │   └────────┬─────────┘   │         │   └────────▲─────────┘   │
   │            │             │         │            │             │
   │            ▼             │         │            │             │
   │   ┌──────────────────┐   │         │   ┌────────┴─────────┐   │
   │   │ MeshyCal         │   │         │   │ MeshyCal         │   │
   │   │ scheduling agent │   │         │   │ scheduling agent │   │
   │   │ (sees U1's cal)  │   │         │   │ (sees U2's cal)  │   │
   │   └────────┬─────────┘   │         │   └────────▲─────────┘   │
   │            │             │         │            │             │
   │  ═════════════════════   │         │   ═════════════════════  │
   │  INTERNAL ZONE BOUNDARY  │         │   INTERNAL ZONE BOUNDARY │
   │  (everything inbound or  │         │   (same on this side)    │
   │   outbound goes through  │         │                          │
   │   the airlock below)     │         │                          │
   │            │             │         │            │             │
   │            ▼             │         │            │             │
   │   ┌──────────────────┐   │         │   ┌────────┴─────────┐   │
   │   │  ◆ MESHTES ◆     │   │         │   │  ◆ MESHTES ◆     │   │
   │   │    AIRLOCK       │   │         │   │    AIRLOCK       │   │
   │   │                  │   │         │   │                  │   │
   │   │  Verify sender   │   │         │   │  Verify sender   │   │
   │   │  Scope payload   │   │         │   │  Scope payload   │   │
   │   │  Sign provenance │   │         │   │  Sign provenance │   │
   │   └────────┬─────────┘   │         │   └────────▲─────────┘   │
   │            │             │         │            │             │
   └────────────┼─────────────┘         └────────────┼─────────────┘
                │                                    │
                ▼                                    │
            ┌───────────────────────────────────────────┐
            │       A2A PROTOCOL WIRE                   │
            │   (Google's protocol, the open rails)     │
            │   Carries signed, scoped messages         │
            │   Both directions                         │
            └───────────────────────────────────────────┘
```

**Read left to right.** Each user has the same five-layer stack. The only thing that crosses between them is messages through the Mesherra airlock onto the A2A wire. Nothing inside one user's internal zone is ever directly reachable from the other side.

The diagram shows the request direction (User 1 → User 2). The response flows the same way in reverse.

---

## Diagram 3: One Full Meeting Negotiation, Step by Step

```
                      USER 1                                      USER 2
                        │                                            │
            ┌───────────┴───────────┐                    ┌───────────┴───────────┐
            │                       │                    │                       │
            ▼                       │                    │                       ▼

  [1] "Schedule 30min               │                    │       [12] "Meeting set:
       with User 2"                 │                    │             Tuesday 2pm" ✓
            │                       │                    │                       ▲
            ▼                       │                    │                       │
  ┌──────────────────┐              │                    │              ┌────────┴─────────┐
  │ MeshyCal App     │              │                    │              │ MeshyCal App     │
  └────────┬─────────┘              │                    │              └────────▲─────────┘
           │                        │                    │                       │
           ▼                        │                    │                       │
  ┌──────────────────┐              │                    │              ┌────────┴─────────┐
  │ Butler           │              │                    │              │ Butler           │
  │ ─ checks policy  │              │                    │              │ ─ checks policy  │
  └────────┬─────────┘              │                    │              └────────▲─────────┘
           │                        │                    │                       │
           ▼                        │                    │                       │
  ┌──────────────────┐              │                    │              ┌────────┴─────────┐
  │ Scheduling Agent │              │                    │              │ Scheduling Agent │
  │ ─ reads U1's cal │              │                    │              │ ─ reads U2's cal │
  │ ─ picks candidate│              │                    │              │ ─ accepts/picks  │
  │   slots          │              │                    │              │   one slot       │
  └────────┬─────────┘              │                    │              └────────▲─────────┘
           │                        │                    │                       │
           ▼  [2] proposal          │                    │                       │ [9] choice
  ╔═════════════════════════╗       │                    │       ╔═════════════════════════╗
  ║   MESHTES AIRLOCK       ║       │                    │       ║   MESHTES AIRLOCK       ║
  ║                         ║       │                    │       ║                         ║
  ║ [3] Verify policy says  ║       │                    │       ║ [7] Verify sender is    ║
  ║     "U2 OK to contact"  ║       │                    │       ║     genuinely U1 ✓      ║
  ║ [4] Scope: candidate    ║       │                    │       ║ [8] Check policy says   ║
  ║     slots only, no full ║       │                    │       ║     "accept from U1" ✓  ║
  ║     calendar leaves     ║       │                    │       ║     Log residue         ║
  ║ [5] Sign U1's identity  ║       │                    │       ║                         ║
  ╚════════════╤════════════╝       │                    │       ╚════════════▲════════════╝
               │                    │                    │                    │
               │   [6] over A2A wire ──────────────────────────────▶          │
               │                                                              │
               │   ◀────────────────────── over A2A wire [10] response ───────┤
               │                                                              │
               │     [11] Both airlocks attach signed provenance to result    │
               │           Both MeshyCal apps then write the event into       │
               │           each user's real calendar via OAuth                │
```

**Read as a journey.**

- Steps **1–5** happen inside User 1's stack.
- Step **6** is the moment the message crosses the internet via A2A.
- Steps **7–9** happen inside User 2's stack.
- Step **10** is the response crossing back.
- Step **11** is both sides signing the final agreement, writing it to each user's actual calendar, and notifying the apps.
- Step **12** is what User 2 sees on their phone.

---

## Diagram 4: Mesherra Internal Architecture

What's actually inside the trust layer.

```
                    CONSUMER (e.g., MeshyCal scheduling agent)
                    Calls into Mesherra through the SDK
                                  │
                                  ▼
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                       M E S H T E S                               ║
║                                                                   ║
║  ┌─────────────────────────────────────────────────────────────┐  ║
║  │             SDK / Public API                                 │ ║
║  │  send_to(peer, parts)  ·  on_message(handler)                │ ║
║  │  verify(agent_card)    ·  attest(task)                       │ ║
║  │  update_policy(policy) ·  get_residue(task_id)               │ ║
║  └────────────────────────────┬─────────────────────────────────┘ ║
║                               │                                   ║
║              ┌────────────────┴────────────────┐                  ║
║              ▼                                 ▼                  ║
║  ┌──────────────────────┐         ┌──────────────────────┐        ║
║  │  OUTBOUND GATEWAY    │         │  INBOUND GATEWAY     │        ║
║  │  (airlock, outgoing) │         │  (airlock, incoming) │        ║
║  │                      │         │                      │        ║
║  │  ─ Scope payload     │         │  ─ Verify sender ID  │        ║
║  │  ─ Sign sender ID    │         │  ─ Check scope OK    │        ║ 
║  │  ─ Tag residue       │         │  ─ Apply policy      │        ║
║  └──────┬───────────────┘         └───────────┬──────────┘        ║
║         │                                     │                   ║
║         │      ┌──── consults ────┐           │                   ║
║         └──────┤                  ├───────────┘                   ║
║                ▼                  ▼                               ║
║  ┌──────────────────────────────────────────────────────────┐     ║
║  │              DECISION SERVICES                           │     ║
║  │                                                          │     ║
║  │   ┌────────────────────┐   ┌────────────────────┐        │     ║
║  │   │  POLICY ENGINE     │   │ IDENTITY DIRECTORY │        │     ║
║  │   │                    │   │                    │        │     ║
║  │   │ ─ Reads policy     │   │ ─ Resolves agent   │        │     ║
║  │   │ ─ Decides:         │   │   names → verified │        │     ║
║  │   │   allow / scope /  │   │   AgentCards       │        │     ║ 
║  │   │   block / escalate │   │ ─ Cryptographic    │        │     ║
║  │   │ ─ Selects extent   │   │   proof of "is     │        │     ║
║  │   │   of disclosure    │   │   really X"        │        │     ║
║  │   └─────────┬──────────┘   └─────────┬──────────┘        │     ║
║  └─────────────┼─────────────────────────┼──────────────────┘     ║
║                │                         │                        ║
║                ▼                         ▼                        ║
║  ┌──────────────────────────────────────────────────────────┐     ║
║  │              PERSISTENT STORES                           │     ║
║  │                                                          │     ║
║  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │     ║
║  │   │   POLICY    │  │  DIRECTORY  │  │ PROVENANCE  │      │     ║
║  │   │    STORE    │  │    STORE    │  │   LEDGER    │      │     ║
║  │   │             │  │             │  │             │      │     ║
║  │   │ The user's  │  │ Centralized │  │ Append-only │      │     ║
║  │   │ signed      │  │ registry of │  │ signed log  │      │     ║
║  │   │ constitution│  │ verified    │  │ of every    │      │     ║
║  │   │             │  │ principals  │  │ interaction │      │     ║
║  │   │ (user-      │  │ (Mesherra-   │  │ (per task)  │      │     ║
║  │   │  owned)     │  │  hosted v0) │  │             │      │     ║
║  │   └─────────────┘  └─────────────┘  └─────────────┘      │     ║
║  └──────────────────────────────────────────────────────────┘     ║
║                                                                   ║
║  ┌──────────────────────────────────────────────────────────┐     ║
║  │              CRYPTO PRIMITIVES (shared service)          │     ║
║  │                                                          │.    ║
║  │   ─ Signing & signature verification                     │     ║
║  │   ─ Key management (per principal, per session)          │     ║
║  │   ─ Hashing for content addressing                       │     ║
║  │   ─ Off-the-shelf (PKI, mTLS, standard libs)             │     ║
║  └──────────────────────────────────────────────────────────┘.    ║
║                                                                   ║
║  ┌──────────────────────────────────────────────────────────┐     ║
║  │              A2A SDK ADAPTER                             │     ║
║  │                                                          │     ║
║  │   Thin wrapper over Google's a2a-sdk / @a2a-js/sdk       │     ║
║  │   Translates Mesherra messages ↔ A2A SendMessage,         │     ║
║  │   GetTask, SubscribeToTask, etc.                         │     ║
║  └──────────────────────────────────────────────────────────┘     ║
║                                                                   ║
╚══════════════════════════════╤════════════════════════════════════╝
                               │
                               ▼
                ┌──────────────────────────────┐
                │   A2A PROTOCOL (the wire)    │
                └──────────────────────────────┘
```

### Component legend

| Component | What it does |
|---|---|
| **SDK / Public API** | The set of calls consumers (MeshyCal, future apps) make. The whole product surface. |
| **Outbound Gateway** | Wraps every outgoing message. Before anything leaves, this is the last stop: scope, sign, tag. |
| **Inbound Gateway** | Wraps every incoming message. Before anything reaches the consumer's agent, this is the first stop: verify, check, log. |
| **Policy Engine** | The decision-maker. Given a request, reads the user's policy and decides allow / scope / block / escalate. |
| **Identity Directory** | The "is this really who they claim to be" service. Resolves agent names to verified cryptographic identities. |
| **Policy Store** | Where the user's constitution lives. Signed by the user. Cannot be written by the platform. |
| **Directory Store** | The verified registry of principals. Initially Mesherra-hosted; designed for later decentralization. |
| **Provenance Ledger** | The permanent, append-only, signed log of every interaction. Foundation for any liability claim. |
| **Crypto Primitives** | Shared utility: signing, verification, keys, hashing. Off-the-shelf libraries, no inventing. |
| **A2A SDK Adapter** | The translator between Mesherra's world and Google's a2a-sdk. The only place that touches A2A. |

See `docs/ARCHITECTURE.md` section 11 for the full component inventory with operations and v0 implementation notes.

---

## Diagram 5: Outbound Message Flow

What happens when a consumer's agent says "send this to that other agent."

```
CONSUMER calls:
  mesherra.send_to(
    peer = User2's agent,
    parts = ["proposal: Tuesday 2pm"]
  )
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 1: SDK receives the call                           │
│  Forwards to Outbound Gateway with consumer context.     │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 2: Outbound Gateway asks Policy Engine             │
│  "User wants to send X to Y. Policy: allowed?            │
│   What scope is permitted? What needs to be stripped?"   │
│                                                          │
│  Policy Engine reads Policy Store, returns decision:     │
│  ✓ allowed                                               │
│  ✓ scope = [proposal slots only, no calendar contents]   │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 3: Outbound Gateway asks Identity Directory        │
│  "Resolve 'User2's agent' to a verified endpoint."       │
│                                                          │
│  Directory returns:                                      │
│  ✓ verified URL + public key + AgentCard hash            │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 4: Outbound Gateway asks Crypto Primitives         │
│  "Sign the scoped payload with User1's key."             │
│                                                          │
│  Returns signed envelope.                                │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 5: Outbound Gateway writes to Provenance Ledger    │
│  "User1's agent sent [scoped proposal] to User2's agent  │
│   at time T under policy clause P. Hash = H."            │
│                                                          │
│  Append-only. Signed. Permanent.                         │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 6: A2A SDK Adapter calls a2a-sdk.SendMessage()     │
│  Message goes onto the wire toward User2.                │
└──────────────────────────────────────────────────────────┘
```

---

## Diagram 6: Inbound Message Flow

What happens when an A2A message arrives from somewhere.

```
[a message arrives over the A2A wire]
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 1: A2A SDK Adapter receives via a2a-sdk callbacks  │
│  Hands raw envelope to Inbound Gateway.                  │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 2: Inbound Gateway asks Crypto Primitives          │
│  "Verify this signature claims sender is X. Valid?"      │
│                                                          │
│  Crypto returns: ✓ signature valid                       │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 3: Inbound Gateway asks Identity Directory         │
│  "Is the entity that signed this genuinely 'User1's      │
│   agent'? Cross-check against the directory."            │
│                                                          │
│  Directory returns: ✓ verified                           │
│  (If ✗ → reject and log as unverified attempt)           │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 4: Inbound Gateway asks Policy Engine              │
│  "User1's agent is sending us [parts]. Policy: accept?   │
│   Route to which internal agent? Or escalate to user?"   │
│                                                          │
│  Policy Engine reads Policy Store, returns:              │
│  ✓ accept                                                │
│  → route to MeshyCal scheduling agent                    │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 5: Inbound Gateway writes to Provenance Ledger     │
│  "Received from User1's agent at time T. Verified ✓.     │
│   Accepted under policy clause P. Hash = H."             │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│  STEP 6: SDK delivers the scoped, verified message to    │
│  the consumer's registered handler (the MeshyCal         │
│  scheduling agent in this case).                         │
│                                                          │
│  The consumer agent never sees raw A2A messages or       │
│  unverified senders. By the time anything reaches it,    │
│  it has already been through every check.                │
└──────────────────────────────────────────────────────────┘
```

---

## The Big Picture

**Mesherra is, mechanically, two gateways with a shared brain.**

- The Outbound Gateway is the airlock for things leaving the user's trust zone. Nothing exits without being scoped, signed, and recorded.
- The Inbound Gateway is the airlock for things entering. Nothing reaches the user's agents without being verified, policy-checked, and logged.
- Both gateways consult the same Decision Services (Policy Engine, Identity Directory), which in turn read the same Persistent Stores (Policy, Directory, Provenance) and use the same Crypto Primitives.
- The A2A SDK Adapter is the only place in the whole system that knows about A2A. Everything above it is in Mesherra's own model. Everything below it is Google's protocol.

That last property is what makes Mesherra durable: if A2A changes, only the adapter changes. If a new protocol emerges later, we add another adapter without touching the Decision Services, Stores, or Gateways. The trust model is independent of the wire format.
