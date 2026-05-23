# Mesherra

> Trust layer for agent-to-agent (A2A) interaction. Identity verification, scoped disclosure, and provenance — on top of Google's A2A protocol.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status--honest-expectations)

---

## The shape of the thing

Google's Agent2Agent (A2A) protocol gives AI agents a way to find each other and talk. It does **not** give them:

1. A way to know who they're really talking to (beyond a self-declared identity card)
2. Control over what data crosses the boundary (the wire ships whatever the sender includes)
3. A verifiable record of what was agreed (no signed provenance beyond basic logs)

A2A is, in its own words, "communication, not security." The gap is explicit and intentional.

**Mesherra fills it.**

| Piece | What it does |
|---|---|
| **Identity verification** | Confirms an agent is who it claims to be, beyond self-declaration. Backed by a verified directory of principals. |
| **Scoped disclosure** | Enforces user policy on what data crosses the boundary. Default: withhold. Sharing is a deliberate, signed act. |
| **Provenance / attestation** | Tamper-evident signed record of every interaction. Both parties hold matching, verifiable entries. |

Plus a zeroth piece — **policy capture** — translating user intent into structured rules the runtime can verify.

## Why this matters

The agentic web is forming now. The companies that own the trust primitives for it will look back on this moment the way Plaid, Stripe, and DocuSign look back on the early commercial web: boring infrastructure that captured enormous value because everything had to route through it.

Mesherra is one of those primitives. It sits between any AI agent and the A2A wire — invisible to end users, essential to anyone whose agent does anything consequential.

## The origin metaphor

In Roman antiquity, two parties making a long-term agreement would break a *tessera* — a small clay or bone tile — into two halves. Each kept one. Centuries later, descendants who had never met could meet, fit the halves together, and prove the original bond by the precision of the fit.

Mesherra is the digital tessera. The trust holds without anyone trusting anyone in advance — the two halves either fit, or they don't.

## What you should read

In order of "where to start":

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system spec. 14 sections covering core concepts (Agent, Object, Layer, Promotion, Handshake, Policy, Residue), Object data flow, the three pieces, schema-based messaging, threat model, the 11-component inventory.
- [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md) — visual reference. 6 ASCII diagrams: layer stack, two-user mirrored stacks, full negotiation flow, internal architecture, outbound/inbound message paths.
- [`docs/STRATEGY.md`](docs/STRATEGY.md) — longer-arc strategic direction. The Application → Delegation paradigm shift; three-product framing (Mesherra / Butler / first Delegation); marketplace path through a Delegation Registry; open strategic questions.
- [`demos/phase_1/SPEC.md`](demos/phase_1/SPEC.md) — the Phase 1 demo specification. Pins the proposal schema, residue entry schema, canonicalization commitment (JCS / SHA-256 / Ed25519), and 14 end-state assertions.
- [`CLAUDE.md`](CLAUDE.md) — orientation for any AI coding session entering this repo. Vocabulary, build discipline, build order.

## The first Delegation

Mesherra is the substrate. **Delegations** are the agent-era equivalent of applications — published packages that use Mesherra primitives to deliver an end-user experience for a specific domain.

**[MeshyCal](https://github.com/Aakash-a18/meshycal)** is the first Delegation. Two users' AI agents negotiate a meeting time without exposing either calendar, producing a signed attested record.

MeshyCal is our **test rig** — it proves Mesherra works mechanically across all three pieces in the smallest possible negotiation. It is **not our market**. The market for Mesherra is contracts, transactions, regulated B2B coordination — domains where being wrong is expensive and trust is materially valued. Scheduling exercises the layer; high-stakes commerce justifies it.

## The Application → Delegation paradigm

In the pre-agent web, the unit was an **Application** — a monolith bundling data, logic, UI, and integrations behind a fixed interface that the user navigates *to* and *operates*.

In the agentic web, the unit is a **Delegation** — a published package that the user *grants authority to* for a domain of their life, and which then operates on the user's behalf through their butler agent.

A Delegation packages four things:

1. **Object class definitions** — schemas registered in the Schema Registry
2. **Agent code** — domain agents that run under the user's butler
3. **Policy templates** — sensible defaults merged into the user's signed policy
4. **A renderer/UI** — the user-facing surface (optional, disposable as ambient/voice/AR surfaces emerge)

The four-component shape is the Delegation integration contract. MeshyCal is the first; the same hosting mechanism accepts the second, third, and Nth without modification.

## Project structure

```
mesherra/
├── docs/
│   ├── ARCHITECTURE.md         # System spec (14 sections)
│   ├── DIAGRAMS.md             # 6 ASCII visual references
│   └── STRATEGY.md             # Longer-arc strategic direction
├── demos/
│   └── phase_1/
│       └── SPEC.md             # Provenance round-trip demo spec
├── src/mesherra/               # 11 component modules — all NotImplementedError today
│   ├── sdk.py                  # 13.1  Public API surface
│   ├── gateways/               # 13.2, 13.3  Outbound + inbound airlock
│   ├── policy/                 # 13.4, 13.6  Engine + signed user policy store
│   ├── identity/               # 13.5, 13.7  Verified directory + backing store
│   ├── provenance/             # 13.8  Append-only signed ledger
│   ├── crypto/                 # 13.9  Signing, verification, canonicalization
│   ├── a2a_adapter/            # 13.10  The only module that imports a2a-sdk
│   ├── schemas/                # 13.11  Schema Registry
│   └── models/                 # Agent, Object, Layer, Promotion, etc.
├── tests/
│   ├── unit/                   # Pure logic, no I/O
│   ├── integration/            # Real crypto + SQLite round-trips
│   └── e2e/                    # Two-agent localhost demos
├── pyproject.toml              # Python 3.11+, a2a-sdk + cryptography + pydantic + fastapi + jcs
├── .env.example                # Required configuration (no hardcoded values anywhere)
├── LICENSE                     # Apache-2.0
└── CLAUDE.md                   # AI coding session orientation
```

## Roadmap

| Phase | What ships | Status |
|---|---|---|
| **Phase 1** | Provenance vertical slice: signed entries, hash-chained ledger, two-process localhost demo with 14 end-state assertions | Spec'd; build next |
| **Phase 1.5** | Guest principal lifecycle (driven by MeshyCal invitee flow) | Open question |
| **Phase 2** | Identity verification: verified directory, signed AgentCard resolution | Architecture complete |
| **Phase 3** | Scoped disclosure: field-level policy enforcement, Schema Registry | Architecture complete |
| **Beyond** | Decentralized directory migration; Delegation Authoring SDK; Class Registry → marketplace | Open strategic questions |

The build order is enforced by discipline (`CLAUDE.md`): provenance first (recording is least invasive), identity second (off-the-shelf PKI), scoped disclosure last (the hardest, most differentiated piece). Each phase ships independently and demonstrably.

## Build discipline (the rules we don't break)

1. The trust layer must not import from any consumer (Delegation). Ever.
2. Domain-specific logic lives in consumer Delegations, not in Mesherra.
3. The renderer is disposable; the principal model is the source of truth.
4. Ride the A2A SDK. Don't reimplement transport, discovery, or task lifecycle.
5. Hard zone separation; the airlock is the single boundary gate.
6. Centralized identity directory first, decentralized-ready schemas. Migrate later without rewrite.
7. Configuration via environment, never hardcoded. Fail fast on missing required vars.
8. No real user data in the repo, ever. Synthetic only. Git history is forever.
9. Don't abstract MeshyCal prematurely. The Delegation Authoring SDK emerges from Delegation #2, not from speculation inside #1.

## Setup (once Phase 1 code lands)

```bash
git clone https://github.com/Aakash-a18/mesherra.git
cd mesherra
cp .env.example .env
# Edit .env with your local values
pip install -e ".[dev]"
```

All configuration is environmental. The application fails fast at startup if a required env var is missing — no silent defaults that pretend to work and break later in production.

## Status & honest expectations

This is **pre-alpha**. Nothing runs yet. The repo contains:

- Comprehensive documentation (architecture, strategy, diagrams)
- A Python source skeleton matching the architecture (every module currently `raise NotImplementedError`)
- A Phase 1 demo specification ready to be implemented against

If you're looking for code that does something today, this isn't it — yet. If you're looking for disciplined infrastructure thinking with a coherent architecture, an explicit threat model, and a clear build path, you're in the right place.

## Contributing

Pre-alpha. The architecture is being shaped in public; expect rapid iteration. Contribution guidelines will come once Phase 1 ships. For now: questions and issues welcome; PRs probably premature until the layer is real.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

Copyright © 2026 Aakash Agrawal.
