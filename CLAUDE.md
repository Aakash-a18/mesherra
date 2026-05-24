# Mesherra

Trust layer for agent-to-agent (A2A) interaction. Built on top of Google's A2A protocol. Not a competing protocol.

## What Mesherra is

A scoped-disclosure and provenance layer that sits between an agent and the A2A wire. When two parties' agents interact, Mesherra ensures:

1. **Identity is verified** — you know who you're talking to, beyond the self-declared AgentCard.
2. **Disclosure is scoped** — only the minimum policy-authorized data crosses the boundary.
3. **The outcome is attested** — a tamper-evident signed record of what was agreed, by whom, under whose authority.

A2A handles transport, discovery, task lifecycle, and streaming. Mesherra adds the governance A2A explicitly leaves to implementers ("communication, not security").

## What Mesherra is not

- Not a competing protocol to A2A. We build on the official `a2a-sdk`.
- Not an agent framework. Agents (LangGraph, Claude, GPT, custom) consume Mesherra as a library.
- Not a scheduling app. The first consumer built on Mesherra is **MeshyCal** (sibling repo), but Mesherra itself is domain-agnostic.

## Vocabulary (read this before writing code)

We use specific terms to avoid collision with A2A and to keep the model precise:

- **Agent** — a principal. Has identity, intent, authority. Acts. Crosses boundaries.
- **Object** — a passive resource (calendar, document, 3D model, agreement). Lives in a layer. Per-viewer visibility. **NOT the same as A2A's `Artifact`.**
- **Artifact** (A2A term) — reserved for A2A's narrow definition: the output of a Task. Do not overload.
- **Layer** — a visibility zone (personal, shared, public). Determines who can perceive an Object.
- **Promotion** — the act by which an owner changes an Object's layer-membership for a specific counterpart (e.g., from personal to a shared view), in either *reference mode* (revocable handle, owner retains canonical state) or *copy mode* (irrevocable bytes, conditions honor-system). Every promotion is signed and recorded in residue on both sides.
- **Handshake** — a continuous, stateful trust negotiation between agents. Not a stateless request.
- **Policy** — the user-authored constitution that governs what their agent may disclose, accept, or commit to. User-owned. Cannot be written by the platform.
- **Residue** — cryptographically signed, append-only trace of every agent that touched an Object.
- **Butler / Airlock** — the apex agent that owns the user's intent and is the single gate between internal and external zones.
- **Delegation** (capitalized for the noun; lowercase for the verb/act) — the agent-era unit of application. A published package that uses Mesherra primitives to deliver an end-user experience for a domain. Contains: one or more Object class definitions, Agent code (the domain agents that run under the user's butler), Policy templates, and a UI manifest. Installing a Delegation grants it authority over a domain of the user's life — schemas register in the Schema Registry, agents spawn under the butler, policy templates merge into the user's signed policy, the UI loads. *Application : Delegation* names the paradigm shift from the pre-agent to the agent web. MeshyCal is the first Delegation.

## Architecture

See `docs/ARCHITECTURE.md` for the full design.

## Build discipline

1. **Domain-agnostic.** Trust layer code must not contain scheduling, document, or any single use-case logic. Use cases live in consumers (MeshyCal, etc.).
2. **Dependency direction.** Consumers depend on Mesherra. Mesherra never depends on a consumer.
3. **Principal model first, renderer second.** Build the agent/object/handshake model in code as the source of truth. The mobile/web UI is a current-era renderer and is disposable.
4. **Ride the A2A SDK.** Do not reimplement transport, discovery, task lifecycle, or streaming.
5. **Hard boundary between trust zones.** Internal agents push scoped data outward through the airlock. Boundary envoys never read inward.
6. **Start centralized for identity, design for decentralized.** Initial trust directory is Mesherra-hosted. Schemas must allow later migration to PKI / web-of-trust without rewrite.
7. **Configuration via environment, never hardcoded.** No literal file paths, hostnames, URLs, ports, keys, secrets, or environment selectors in code. All injected via env vars. Local dev uses `.env` (gitignored); required vars documented in `.env.example`. Fail fast at startup if a required var is missing.
8. **No real user data in the repo, ever.** No real names, emails, calendar entries, or identifying info in fixtures, tests, seeds, examples, or docs. Synthetic data only. Hard rule from day one — git history is forever.

## Build order

Layers ship in order of difficulty, easiest first:

1. **Provenance** ✅ shipped (Phase 1). Record and sign. Least invasive. Demonstrates the layer is real.
2. **Identity verification** ✅ shipped (Phase 2: replay-defense hardening + live signed Directory). Integration of Ed25519-signed records via a per-agent `HTTPDirectoryClient` over a small FastAPI Directory service.
3. **Scoped disclosure** ✅ shipped (Phase 3). User-signed policy doc in a per-principal SQLite `PolicyStore`; stateless `PolicyEngine` returns ALLOW / ALLOW_SCOPED / BLOCK; gateways enforce on every outbound and inbound message. MeshyCal demo proves blocked fields never cross the wire.
4. **Policy capture (zeroth piece)** — develops alongside all three; the schema firms up as the others reveal what they need. Phase 3 ships the doc schema (`mesherra.policy/doc-v1`); the user-facing capture UI lives in consumers (MeshyCal Phase 4+).

## First consumer

**MeshyCal**: the first Delegation. Packages Calendar/Meeting/Proposal Object class definitions, a scheduling Agent (the domain agent that runs under each user's butler), default Policy templates, and a mobile/web UI. When two MeshyCal users meet, their butlers dispatch to their respective MeshyCal scheduling agents, which negotiate a meeting time without exposing either calendar and produce a signed attested record. Sibling repo. Use it as the relentless feedback loop on Mesherra's public API.

## Origin metaphor

In Roman antiquity, two parties would break a *tessera* (small clay or bone tile) into two halves. Each kept one. Centuries later, descendants who had never met could fit the halves together and prove the original bond by the precision of the fit.

Mesherra is the digital tessera. The trust holds without anyone trusting anyone in advance — the two halves either fit, or they don't.
