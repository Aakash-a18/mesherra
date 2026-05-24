"""Mesherra policy primitive models.

Per ARCHITECTURE.md §13.4 / §13.6 and demos/phase_3/SPEC.md §2.

Defines the wire/at-rest shape of a user-signed policy document. One
``PolicyDoc`` per principal; the principal's Ed25519 key signs the canonical
JSON encoding of the doc, producing a ``SignedPolicyDoc`` that the
``PolicyStore`` persists and the ``PolicyEngine`` consumes.

The five Pydantic types here:

* :class:`Direction` — enum for outbound/inbound/both.
* :class:`Match`     — which (schema, direction) a rule applies to.
* :class:`Rule`      — one allow/block/cap clause for matched payloads.
* :class:`PolicyDoc` — the signed document: principal_id, version, rules.
* :class:`SignedPolicyDoc` — frozen pair of doc + base64 Ed25519 signature.

A field-path string (``constraint_hints.tz``) is enforced via regex on the
``Rule`` fields so an invalid path is rejected at construction time, not at
evaluation time.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Dotted field-path: a leading lowercase-starting segment, optional more
# segments. Matches SPEC §2 pattern. Top-level keys are valid one-segment
# paths.
_FIELD_PATH_PATTERN = re.compile(r"^[a-z][a-zA-Z0-9_]*(\.[a-z][a-zA-Z0-9_]*)*$")


def _validate_field_path(v: str) -> str:
    if not _FIELD_PATH_PATTERN.match(v):
        raise ValueError(
            f"Invalid field path {v!r}. Field paths are dotted lowercase "
            "identifiers (e.g., 'candidates' or 'constraint_hints.tz')."
        )
    return v


class Direction(str, Enum):
    """Direction a rule applies to.

    ``BOTH`` is the default when a rule omits ``direction``; the engine
    treats it as matching either outbound or inbound evaluation.
    """

    OUTBOUND = "outbound"
    INBOUND = "inbound"
    BOTH = "both"


class Match(BaseModel):
    """Which (schema, direction) a rule applies to.

    JSON wire field is ``schema`` (per SPEC §2 / JSON-schema mirror), but
    pydantic v2's ``BaseModel.schema()`` method makes that name shadow a
    base attribute. We use the Python attribute ``schema_uri`` internally
    and alias to ``schema`` for serialization. ``populate_by_name=True``
    keeps the constructor convenient: ``Match(schema=...)`` still works.
    """

    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True
    )

    schema_uri: str = Field(min_length=1, alias="schema")
    direction: Direction = Direction.BOTH


class Rule(BaseModel):
    """One allow/block/cap clause for a (schema, direction).

    All allow/block lists are optional. Semantics (per SPEC §2.2):

    * Block-list (``outbound_block`` / ``inbound_block``): listed field paths
      are removed from the payload.
    * Allow-list (``outbound_allow`` / ``inbound_allow``): if present and
      non-empty, every field NOT in the list is removed. Stronger than
      block-list.
    * ``max_array_size``: per-field cap. Listed arrays are truncated.

    An "allow_list present and empty" means "nothing crosses" (the engine
    will produce ``BLOCK`` for that rule's direction). An allow_list absent
    means "everything except blocks crosses."
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    match: Match
    outbound_allow: list[str] | None = None
    outbound_block: list[str] | None = None
    inbound_allow: list[str] | None = None
    inbound_block: list[str] | None = None
    max_array_size: dict[str, int] | None = None

    @field_validator(
        "outbound_allow", "outbound_block", "inbound_allow", "inbound_block"
    )
    @classmethod
    def _validate_path_list(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return [_validate_field_path(p) for p in v]

    @field_validator("max_array_size")
    @classmethod
    def _validate_max_array_size(
        cls, v: dict[str, int] | None
    ) -> dict[str, int] | None:
        if v is None:
            return v
        validated: dict[str, int] = {}
        for path, size in v.items():
            if size < 0:
                raise ValueError(
                    f"max_array_size[{path!r}] = {size}; must be >= 0"
                )
            validated[_validate_field_path(path)] = size
        return validated


class PolicyDoc(BaseModel):
    """The user-signed policy document.

    Schema ID: ``mesherra.policy/doc-v1``.

    ``principal_id`` must match the principal whose Ed25519 key signed the
    enclosing ``SignedPolicyDoc``. The ``PolicyStore`` enforces that
    invariant; verification at parse time is intentionally not done here so
    the model can be constructed before signing.

    ``version`` is monotonically increasing. v1 is the first signed policy;
    every update increments. The ``PolicyStore`` enforces monotonicity on
    insert.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": "mesherra.policy/doc-v1",
            "title": "Mesherra Policy Document v1",
        },
    )

    principal_id: str = Field(min_length=1)
    version: int = Field(ge=1)
    issued_at: str = Field(min_length=1)
    rules: list[Rule] = Field(default_factory=list)

    def to_signing_payload(self) -> dict[str, Any]:
        """Return the dict form for canonical encoding by the signer.

        The signed bytes are ``canonical_json(this_dict)``. Matches the
        convention used by :class:`Residue.to_signing_payload`: signature
        lives separately in the wrapping :class:`SignedPolicyDoc`, so the
        signed bytes never contain the signature being computed.

        ``by_alias=True`` is load-bearing: ``Match.schema_uri`` serializes
        as ``schema`` per the SPEC §2 wire shape, and signed bytes must
        match the wire shape exactly or the JSON schema mirror would fail
        to validate.
        """
        return self.model_dump(mode="json", by_alias=True)


class SignedPolicyDoc(BaseModel):
    """A policy document paired with the principal's Ed25519 signature.

    Wire/at-rest shape. ``signature_b64`` is the base64 string produced by
    ``Signer.sign(canonical_json(doc.to_signing_payload()))``.

    Verification (caller's responsibility): reconstruct the canonical bytes
    of ``doc`` and run ``Verifier.verify(bytes, signature_b64)``. The
    :class:`PolicyStore` does this on every read.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    doc: PolicyDoc
    signature_b64: str = Field(min_length=1)
