"""Guardrail: enforce A2A wire-type isolation (ARCHITECTURE.md §13.10).

Per ARCH §13.10: ``a2a-sdk`` (including ``a2a.types``) may only be imported
by files under ``src/mesherra/a2a_adapter/``. Every other Mesherra module —
gateways, SDK, models, consumers — operates on ``MesherraEnvelope`` and never
touches a protobuf wire type.

This invariant is load-bearing: it keeps the protobuf wire shape from leaking
into the rest of Mesherra, and it is what lets us swap A2A SDK versions
without ripple across the codebase. If any file outside ``src/mesherra/
a2a_adapter/`` ever imports ``a2a.types`` (in any syntactic form), this test
must fail loudly and name the offender(s).

Approach: pure text scan of every ``*.py`` under ``src/mesherra/``. For each
file, we look at non-blank, non-comment lines whose first token (after
stripping leading whitespace) is ``import`` or ``from``, and flag any that
reference the ``a2a.types`` namespace or the ``types`` submodule of the ``a2a``
package. This is deliberately a syntactic scan (not AST) — overkill is not
warranted, and it must remain immune to prose / docstring mentions of the
string ``a2a.types`` (wire.py's own docstring talks about it at length).
"""

from __future__ import annotations

import re
from pathlib import Path

# Resolve src/mesherra/ relative to this test file: tests/unit/ -> repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MESHERRA_SRC = _REPO_ROOT / "src" / "mesherra"

# Per ARCH §13.10, files under src/mesherra/a2a_adapter/ are the legitimate
# importers of a2a.types (wire.py owns the conversion functions; adapter.py
# owns the Client / HTTP-server lifecycle and must touch Message, Task,
# AgentCard, etc. directly). Everything outside this directory must operate
# on MesherraEnvelope.
_ALLOWED_DIR = _MESHERRA_SRC / "a2a_adapter"

# Match an import line that pulls in the a2a.types namespace, in any of:
#   from a2a.types import X
#   from a2a.types import (X, Y)
#   import a2a.types
#   import a2a.types as t
#   from a2a import types
#   from a2a import types as t
# We anchor on ``import`` / ``from`` as the first token of the line so that
# prose / docstrings / comments that merely mention the string ``a2a.types``
# (as wire.py's own docstring does) do not trigger the guardrail.
_IMPORT_PATTERN = re.compile(
    r"""^\s*
        (?:
            from\s+a2a\.types(?:\s|$)            # from a2a.types ...
          | from\s+a2a\s+import\s+(?:[^#\n]*\b)?types\b   # from a2a import ..., types, ...
          | import\s+a2a\.types(?:\s|,|$)        # import a2a.types[, ...]
        )
    """,
    re.VERBOSE,
)


def test_only_a2a_adapter_imports_a2a_types() -> None:
    """Only files under ``src/mesherra/a2a_adapter/`` may import ``a2a.types``.

    Enforces ARCHITECTURE.md §13.10. If this test fails, do NOT extend the
    allowlist — refactor so the offending module uses ``MesherraEnvelope``
    (defined in ``a2a_adapter/envelope.py``) instead of protobuf wire types.
    """
    assert _MESHERRA_SRC.is_dir(), f"expected mesherra source tree at {_MESHERRA_SRC}"

    offenders: list[tuple[Path, int, str]] = []
    for py_file in sorted(_MESHERRA_SRC.rglob("*.py")):
        if _ALLOWED_DIR in py_file.parents:
            continue
        text = py_file.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _IMPORT_PATTERN.match(line):
                offenders.append((py_file, lineno, line.strip()))

    if offenders:
        rel = lambda p: p.relative_to(_REPO_ROOT)  # noqa: E731
        details = "\n".join(
            f"  - {rel(path)}:{lineno}: {line}" for path, lineno, line in offenders
        )
        raise AssertionError(
            "ARCH §13.10 violation: `a2a.types` may only be imported by files "
            f"under {rel(_ALLOWED_DIR)}/, but found {len(offenders)} import(s) "
            f"outside that directory:\n"
            f"{details}\n"
            "Refactor the offending module to operate on MesherraEnvelope "
            "(see src/mesherra/a2a_adapter/envelope.py) instead of protobuf "
            "wire types. Do NOT extend the allowlist."
        )


# The syntactic import scan above can't catch re-exports through the
# a2a_adapter package's public surface. If anyone ever adds `Message` or
# `Task` (or any other a2a.types symbol) to `a2a_adapter.__all__`, the
# protobuf shape leaks transparently — every downstream `from mesherra.a2a_adapter
# import Message` succeeds without ever triggering the line-scan above.
# Lock the public surface to known-clean names; a contributor adding a new
# export must update this set deliberately.
_ALLOWED_PUBLIC_EXPORTS = frozenset(
    {
        "A2AAdapter",
        "InboundHandler",
        "ListenerHandle",
        "MesherraEnvelope",
        "WireFormatError",
    }
)


def test_a2a_adapter_public_surface_does_not_leak_protobuf_types() -> None:
    """The ``a2a_adapter`` package's ``__all__`` must not re-export ``a2a.types``.

    Closes a gap the syntactic import scan would miss: a re-export via
    ``__all__`` would let downstream code reach protobuf wire types through
    Mesherra's own namespace, defeating the isolation guarantee without ever
    typing the string ``a2a.types`` outside ``a2a_adapter/``.
    """
    from mesherra import a2a_adapter

    actual = set(a2a_adapter.__all__)
    leaked = actual - _ALLOWED_PUBLIC_EXPORTS
    assert not leaked, (
        f"`mesherra.a2a_adapter.__all__` re-exports {sorted(leaked)}, which "
        "are not on the known-clean public surface. If you intend to add a "
        "new export, audit that the symbol is not a protobuf wire type "
        "(anything from `a2a.types`) and then extend `_ALLOWED_PUBLIC_EXPORTS` "
        "in this test deliberately. Do NOT re-export `Message`, `Task`, "
        "`AgentCard`, or other `a2a.types` symbols — downstream callers must "
        "operate on `MesherraEnvelope` per ARCH §13.10."
    )
