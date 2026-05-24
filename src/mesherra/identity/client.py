"""DirectoryClient — consumer-side interface to the Identity Directory.

Per ARCHITECTURE.md §13.5. The DirectoryClient is the seam between Mesherra's
gateways and whatever backs the Identity Directory:

* :class:`StaticDirectoryClient` — wraps an in-memory ``dict[str, str]`` of
  principal_id → public_key_b64. Used by Phase 1 demos and tests that don't
  need a live directory.
* (Phase 2 sub-step 2) ``HTTPDirectoryClient`` — talks to a running Directory
  service over HTTP. Lands when the FastAPI service is in place.
* (Future) federated / decentralized variants — multiple directories, web of
  trust, DID resolution. The Protocol is intentionally narrow so adding them
  is implementation, not interface, work.

The gateways consume this interface, never the underlying dict / HTTP client
directly. That keeps the trust-layer code domain-agnostic to *how* identity
resolution is implemented — exactly the structural promise ARCH §4.1 makes
about "wraps incoming AgentCard reads" without committing to a backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx

from mesherra.crypto.primitives import Verifier, canonical_json


class UnknownPrincipalError(Exception):
    """The Directory does not have a record for the requested principal_id.

    Distinct from a transient lookup failure (network error, directory down).
    This means "we asked, and the directory said no such principal." The
    gateways translate this to an A2A-level rejection.
    """


class DirectoryUnavailableError(Exception):
    """The Directory could not be reached.

    Raised by network-backed implementations (Phase 2 ``HTTPDirectoryClient``)
    when the directory service is down or the lookup times out. Distinct from
    :class:`UnknownPrincipalError` because the right operational response is
    different — for "unknown principal" the right move is reject and surface;
    for "directory unreachable" the right move is back off and retry.
    Static / in-memory implementations never raise this.
    """


class DirectorySignatureVerificationFailed(Exception):
    """The Directory's signature on a resolved record did not verify.

    Either the Directory server is impersonated (returning records signed
    with a key the client doesn't pin), the response was tampered with in
    transit, or the client was configured with the wrong pinned public
    key. In every case the right operational response is the same: reject
    the record, do NOT trust the public_key_b64 inside it, and surface
    the failure. This is the Phase 2 sub-step 3 tessera-fit guarantee
    extending out to identity itself: the directory's halves of every
    issued record either fit, or they don't.
    """


@dataclass(frozen=True)
class ResolvedPrincipal:
    """The verified record the Directory returns for a principal lookup.

    Phase 2 sub-step 1: ``principal_id`` and ``public_key_b64`` only — enough
    for the gateways' existing signature-verification path. Sub-step 3 adds:

    * ``directory_signature``: Ed25519 signature by the Directory's root key
      over the canonical encoding of this record. Receivers verify against
      the Directory's published public key before trusting ``public_key_b64``.
    * ``issued_at`` / ``expires_at``: validity window so a stale resolved
      record can be detected without a fresh lookup.

    Kept as a dataclass (not a Pydantic model) because nothing crosses the
    A2A wire — the Directory record is local-only between client and
    gateway. If we later wire-format this (e.g., bundle it into the
    SendClaim so the verifier doesn't need its own directory lookup),
    it'll graduate to a Pydantic model in ``models/primitives.py``.
    """

    principal_id: str
    public_key_b64: str


@runtime_checkable
class DirectoryClient(Protocol):
    """Async lookup interface the gateways consume.

    Async because real implementations do HTTP I/O. ``StaticDirectoryClient``
    is also async-shaped even though its lookup is in-memory, so the gateway
    code path is uniform across implementations.

    Implementations MUST:

    * Raise :class:`UnknownPrincipalError` when the principal does not exist
      in the directory.
    * Raise :class:`DirectoryUnavailableError` when the directory cannot be
      reached. Static implementations never raise this.
    * Return a :class:`ResolvedPrincipal` whose ``public_key_b64`` is the
      genuine, verified public key for the requested principal. Sub-step 3
      adds Directory-signature verification *inside* the client so the
      gateway can trust the returned key without doing its own
      signature dance.
    """

    async def resolve(self, principal_id: str) -> ResolvedPrincipal: ...


class StaticDirectoryClient:
    """In-memory ``dict[str, str]`` backed directory for tests and demos.

    Phase 1's hardcoded ``public_key_directory: dict[str, str]`` is preserved
    by wrapping it in this client. No behavioral change — the gateways still
    see the same principal → public_key mapping, just through the
    :class:`DirectoryClient` interface. The Phase 2 sub-step 2
    ``HTTPDirectoryClient`` will drop in here without touching any consumer.

    Construct with a dict of ``{principal_id: public_key_b64}``. Defensive
    copy: mutating the source dict after construction does not affect the
    client (matches the Phase 1 SDK behavior of ``dict(public_key_directory)``).
    """

    def __init__(self, principal_to_public_key: dict[str, str]) -> None:
        self._directory = dict(principal_to_public_key)

    async def resolve(self, principal_id: str) -> ResolvedPrincipal:
        if principal_id not in self._directory:
            raise UnknownPrincipalError(
                f"Principal {principal_id!r} not in directory; "
                f"known: {sorted(self._directory)}"
            )
        return ResolvedPrincipal(
            principal_id=principal_id,
            public_key_b64=self._directory[principal_id],
        )

    def known_principals(self) -> list[str]:
        """Sorted list of principal ids this static directory has records for.

        Provided for tests and demos that want to surface "who's registered"
        without going through resolve() for every one. Not part of the
        :class:`DirectoryClient` Protocol — real network-backed directories
        don't enumerate.
        """
        return sorted(self._directory)


class HTTPDirectoryClient:
    """DirectoryClient implementation that talks to a remote Directory service.

    Phase 2 sub-step 3: HTTP round-trip + Directory-signature verification.
    Every record returned by ``GET /principals/{id}`` is signed by the
    Directory over the canonical JSON of
    ``{principal_id, public_key_b64, issued_at, expires_at}``. This client
    verifies that signature against the operator-pinned Directory public
    key before returning a :class:`ResolvedPrincipal`. A record whose
    signature does not verify raises
    :class:`DirectorySignatureVerificationFailed`; the gateway never sees
    an unverified key.

    Trust root: the ``directory_public_key_b64`` argument. The operator
    pins this out-of-band (from the Directory's
    ``/.well-known/directory-public-key`` endpoint, but pinned *separately*
    so a man-in-the-middle can't substitute both the pubkey and the
    records signed with their own key — that's the classic TOFU
    vulnerability we avoid by requiring out-of-band pinning).

    The client owns its own ``httpx.AsyncClient`` by default. Construct one
    per agent process; do NOT share a single client across processes.
    Sharing inside one process is fine and recommended (httpx pools
    connections).

    Args:
        base_url: Root URL of the Directory service (no trailing slash).
        directory_public_key_b64: The Directory's Ed25519 public key
            (base64), pinned out-of-band. Required — sub-step 3 has no
            "trust on first use" mode.
        timeout: Per-request timeout in seconds. Defaults to 10.
        http_client: Optional pre-constructed ``httpx.AsyncClient`` for
            tests that want to inject an ASGI transport (no real network).
            Production callers should let the client build its own.
    """

    def __init__(
        self,
        *,
        base_url: str,
        directory_public_key_b64: str,
        timeout: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must be a non-empty URL")
        if not directory_public_key_b64:
            raise ValueError(
                "directory_public_key_b64 must be a non-empty pinned key"
            )
        self._base_url = base_url.rstrip("/")
        self._verifier = Verifier.from_b64(directory_public_key_b64)
        self._owned_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)

    async def resolve(self, principal_id: str) -> ResolvedPrincipal:
        url = f"{self._base_url}/principals/{principal_id}"
        try:
            response = await self._http.get(url)
        except httpx.HTTPError as e:
            raise DirectoryUnavailableError(
                f"Could not reach Directory at {self._base_url!r}: {e}"
            ) from e

        if response.status_code == 404:
            raise UnknownPrincipalError(
                f"Directory at {self._base_url!r} has no record for "
                f"principal {principal_id!r}."
            )
        if response.status_code != 200:
            raise DirectoryUnavailableError(
                f"Directory at {self._base_url!r} returned HTTP "
                f"{response.status_code} for principal {principal_id!r}: "
                f"{response.text[:200]!r}"
            )

        data = response.json()
        # Reconstruct the canonical bytes the Directory signed and verify.
        # The four fields the directory signs (mirroring server.py's
        # SIGNED_RECORD_FIELDS) — extracted here rather than imported to
        # keep the client independent of the server module.
        signed_fields = {
            "principal_id": data["principal_id"],
            "public_key_b64": data["public_key_b64"],
            "issued_at": data["issued_at"],
            "expires_at": data["expires_at"],
        }
        canonical_bytes = canonical_json(signed_fields)
        if not self._verifier.verify(canonical_bytes, data["directory_signature"]):
            raise DirectorySignatureVerificationFailed(
                f"Directory signature on record for {principal_id!r} did "
                f"not verify under the pinned public key. The record will "
                "NOT be trusted; check that the pinned key matches the "
                "Directory's /.well-known/directory-public-key, or treat "
                "this as evidence of tampering / impersonation."
            )

        return ResolvedPrincipal(
            principal_id=data["principal_id"],
            public_key_b64=data["public_key_b64"],
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance owns it."""
        if self._owned_client:
            await self._http.aclose()

