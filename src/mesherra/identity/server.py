"""Identity Directory HTTP service.

Implements ARCHITECTURE.md §13.5 over FastAPI. Phase 2 sub-step 3 endpoints:

* ``GET  /.well-known/directory-public-key`` — the directory's own Ed25519
  public key (base64). Clients pin this out-of-band before their first
  resolve — it's the trust root for every signed record the directory
  returns.
* ``POST /principals``         — register a principal (idempotent only on
  the no-op case; re-register with a different key is rejected). Sub-step
  2 had no auth on this endpoint; that's still the v0 posture — see the
  deployment guidance below.
* ``GET  /principals/{id}``    — resolve a principal. Returns a signed
  record the client verifies against the directory's published public key.
* ``GET  /healthz``            — liveness probe.

**Deployment guidance — v0 has no write auth.** Anyone who can reach
``POST /principals`` can register a principal. This is intentional for
v0 (it ships sub-step 2 fast and lets the MeshyCal demo orchestrator
self-register at boot) but **a v0 deployment MUST run the directory
behind a network policy or reverse proxy that gates POST traffic** to
trusted operators. Read traffic (``GET /principals/{id}``) is safe to
expose because every response is signed and re-register-with-different-key
is rejected at the store level.

What gets signed on every resolve: the canonical JSON of
``{principal_id, public_key_b64, issued_at, expires_at}``. The directory
does not sign per-record at registration time — that would lock the
``expires_at`` to a static value far in the future. Instead, each resolve
mints a fresh signature with a fresh validity window, so consumers can
treat the record as authoritative for the window's duration.

Out of scope for sub-step 3:
* The full §13.5 ``attest`` operation.
* Write authentication on ``POST /principals``.
* Listing / enumeration endpoints.
* Key rotation (delete + re-add only).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from mesherra.crypto.primitives import Signer, canonical_json

from .store import (
    DirectoryStore,
    PrincipalAlreadyRegistered,
    PrincipalNotFound,
    StoredPrincipal,
)

# The four fields the directory's signature covers. Order doesn't matter
# (JCS canonicalizes), but listing them here makes the signed-payload
# contract auditable in one place.
SIGNED_RECORD_FIELDS = ("principal_id", "public_key_b64", "issued_at", "expires_at")

DEFAULT_RECORD_TTL_SECONDS = 3600


# -- Wire types ---------------------------------------------------------


class RegisterRequest(BaseModel):
    """Body of ``POST /principals``."""

    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(min_length=1)
    public_key_b64: str = Field(min_length=1)


class RegistrationConfirmation(BaseModel):
    """Returned by ``POST /principals`` — confirms what was stored.

    Distinct from a resolved record (which is signed) because registration
    is an operator-facing confirmation, not a verifiable claim. The
    ``GET /principals/{id}`` flow is where the cryptographic guarantee
    lives.
    """

    model_config = ConfigDict(extra="forbid")

    principal_id: str
    public_key_b64: str
    registered_at: str


class SignedPrincipalRecord(BaseModel):
    """Returned by ``GET /principals/{id}``.

    The signature covers the canonical JSON of the four fields named in
    ``SIGNED_RECORD_FIELDS`` (NOT including the signature itself). Clients
    reconstruct those bytes and verify against the directory's published
    public key before trusting ``public_key_b64``.
    """

    model_config = ConfigDict(extra="forbid")

    principal_id: str
    public_key_b64: str
    issued_at: str
    expires_at: str
    directory_signature: str


class DirectoryPublicKey(BaseModel):
    """Returned by ``GET /.well-known/directory-public-key``."""

    model_config = ConfigDict(extra="forbid")

    public_key_b64: str


# -- App factory --------------------------------------------------------


def create_app(
    *,
    store: DirectoryStore,
    signer: Signer,
    record_ttl_seconds: int = DEFAULT_RECORD_TTL_SECONDS,
) -> FastAPI:
    """Construct the FastAPI app bound to a store + signing key.

    Args:
        store: The persistent registry of principals. Caller owns lifecycle.
        signer: The directory's own Ed25519 signing key. Its public key is
            what clients pin out-of-band. Each resolve response is signed
            with this key over the canonical JSON of the record's four
            non-signature fields.
        record_ttl_seconds: How long each resolved record stays valid.
            Defaults to 1 hour. Production deployments tune this via
            ``MESHERRA_DIRECTORY_RECORD_TTL_SECONDS`` env at the wiring
            layer.
    """
    if record_ttl_seconds <= 0:
        raise ValueError(
            f"record_ttl_seconds must be positive, got {record_ttl_seconds}"
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="Mesherra Identity Directory",
        version="0.2.0",  # bumped: signed records
        lifespan=lifespan,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/directory-public-key", response_model=DirectoryPublicKey)
    async def public_key() -> dict[str, str]:
        return {"public_key_b64": signer.public_key_b64()}

    @app.post(
        "/principals",
        status_code=status.HTTP_201_CREATED,
        response_model=RegistrationConfirmation,
    )
    async def register(body: RegisterRequest) -> dict[str, Any]:
        registered_at = _utc_now_iso()
        try:
            store.register(
                principal_id=body.principal_id,
                public_key_b64=body.public_key_b64,
                registered_at=registered_at,
            )
        except PrincipalAlreadyRegistered as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            ) from e
        return {
            "principal_id": body.principal_id,
            "public_key_b64": body.public_key_b64,
            "registered_at": registered_at,
        }

    @app.get(
        "/principals/{principal_id}",
        response_model=SignedPrincipalRecord,
    )
    async def resolve(principal_id: str) -> dict[str, Any]:
        try:
            record = store.get_record(principal_id)
        except PrincipalNotFound as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            ) from e
        return _sign_resolve_response(
            record=record, signer=signer, ttl_seconds=record_ttl_seconds
        )

    return app


def _sign_resolve_response(
    *,
    record: StoredPrincipal,
    signer: Signer,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Mint a freshly-signed record from a persisted row.

    The signature covers the canonical JSON of the four non-signature
    fields. ``issued_at`` is "now" at sign time; ``expires_at`` is
    ``issued_at + ttl_seconds``.
    """
    issued_at = _utc_now_iso()
    expires_at = _utc_iso(datetime.now(UTC) + timedelta(seconds=ttl_seconds))
    fields = {
        "principal_id": record.principal_id,
        "public_key_b64": record.public_key_b64,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    signature = signer.sign(canonical_json(fields))
    return {**fields, "directory_signature": signature}


def _utc_now_iso() -> str:
    return _utc_iso(datetime.now(UTC))


def _utc_iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")
