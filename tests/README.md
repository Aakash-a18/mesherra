# Mesherra tests

Tests live alongside the code they exercise. Phase 1 (provenance vertical slice) is the first round; Phase 2 (identity verification) and Phase 3 (scoped disclosure) follow per `docs/ARCHITECTURE.md` section 12.

## Conventions

- **Synthetic data only.** No real names, emails, or calendar contents. See `CLAUDE.md` build discipline.
- **All configuration via env.** Tests read from `.env.test` (gitignored) when set; fall back to defaults defined in fixtures. No hardcoded paths.
- **Integration over mock for the trust path.** Provenance signing and verification must round-trip against the real `cryptography` library, not mocks. Mocks are for external HTTP (Directory, Registry) only.

## Layout (as it lands)

```
tests/
├── unit/           # Pure unit tests, no I/O
├── integration/    # Round-trip tests against real crypto + SQLite
└── e2e/            # Two-agent localhost demos (Phase 1+)
```

Phase 1 priority: `integration/test_provenance_roundtrip.py` proves a signed entry from one principal can be verified by the other and that the residue chain is byte-equal on both sides.
