# Tesherra

Trust layer for agent-to-agent (A2A) interaction. Built on top of Google's A2A protocol. Not a competing protocol.

**Status:** pre-alpha. Documentation-first. No production code yet; source tree is component skeleton matching the architecture.

## What this is

Tesherra adds three things to A2A that the protocol explicitly leaves to implementers:

1. **Identity verification** — verifying an agent is who its AgentCard claims, beyond self-declaration
2. **Scoped disclosure** — enforcing user policy on what data crosses the boundary
3. **Provenance / attestation** — tamper-evident signed records of every interaction

Plus a zeroth piece: **policy capture** (structuring the user's authorizations).

## Read first

- `CLAUDE.md` — orientation for any AI coding session entering this repo (vocabulary, build discipline, build order)
- `docs/ARCHITECTURE.md` — the full system spec (14 sections)
- `docs/DIAGRAMS.md` — visual reference (6 diagrams)
- `docs/STRATEGY.md` — longer-arc strategic direction

## Source tree

The `src/tesherra/` skeleton matches `ARCHITECTURE.md` section 13 (Component inventory):

```
src/tesherra/
├── sdk.py                  # 13.1  SDK / Public API
├── gateways/
│   ├── outbound.py         # 13.2  Outbound Gateway
│   └── inbound.py          # 13.3  Inbound Gateway
├── policy/
│   ├── engine.py           # 13.4  Policy Engine
│   └── store.py            # 13.6  Policy Store
├── identity/
│   ├── directory.py        # 13.5  Identity Directory
│   └── store.py            # 13.7  Directory Store
├── provenance/
│   └── ledger.py           # 13.8  Provenance Ledger
├── crypto/
│   └── primitives.py       # 13.9  Crypto Primitives
├── a2a_adapter/
│   └── adapter.py          # 13.10 A2A SDK Adapter
├── schemas/
│   └── registry.py         # 13.11 Schema Registry
└── models/
    └── primitives.py       # Agent, Object, Layer, Handshake, Policy, Residue, Promotion
```

Every module currently raises `NotImplementedError` on use. Phase 1 (provenance vertical slice) fills in `provenance/`, `crypto/`, `models/`, and the relevant parts of `sdk.py` and `a2a_adapter/`.

## First consumer

**MeshyCal** (sibling repo) — the first Delegation built on top of Tesherra. See `docs/ARCHITECTURE.md` section 10 and `docs/STRATEGY.md` section 5.

## Setup (once Phase 1 code lands)

```bash
cp .env.example .env
# Fill required values
pip install -e ".[dev]"
```

All configuration is environmental. No hardcoded values. Application fails fast on missing required env vars.

## License

TBD.
