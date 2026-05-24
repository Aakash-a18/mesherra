"""End-to-end test: HTTPDirectoryClient ↔ FastAPI Directory service.

Boots the FastAPI app in-process with an ASGI transport (no real network
socket — faster, no port allocation, deterministic). The client and server
talk over the standard httpx + ASGITransport machinery, exactly the same
codepath the production HTTPDirectoryClient uses against a real uvicorn
server — only the transport layer differs.

If these tests pass, the Phase 2 sub-step 2 promise holds: a remote
directory backed by SQLite resolves principals through the same
DirectoryClient interface the gateways consume.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from mesherra.crypto.primitives import Signer
from mesherra.identity import (
    DirectorySignatureVerificationFailed,
    DirectoryStore,
    DirectoryUnavailableError,
    HTTPDirectoryClient,
    UnknownPrincipalError,
    create_app,
)

PRINCIPAL_A = "user-a@phase1.local"
PRINCIPAL_B = "user-b@phase1.local"
KEY_A = "A" * 44
KEY_B = "B" * 44


@pytest.fixture
async def directory_client(tmp_path: Path):
    """Spin up a Directory service on an ASGI transport and yield a client.

    The store lives in a temp SQLite file (not in-memory) so tests that
    care about persistence work the same as the production code path.
    The Directory's signing key is generated fresh per test; the client
    pins the matching public key.
    """
    db = tmp_path / "directory.sqlite"
    store = DirectoryStore(db_path=db)
    directory_signer = Signer.generate()
    app = create_app(store=store, signer=directory_signer)
    transport = httpx.ASGITransport(app=app)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    client = HTTPDirectoryClient(
        base_url="http://testserver",
        directory_public_key_b64=directory_signer.public_key_b64(),
        http_client=http_client,
    )
    try:
        yield client, http_client, directory_signer
    finally:
        await client.aclose()
        await http_client.aclose()
        store.close()


class TestRegisterAndResolve:
    async def test_register_then_resolve_round_trip(self, directory_client) -> None:
        client, http, _ = directory_client
        # Register via raw HTTP (we don't expose register on the client yet
        # — Phase 2 sub-step 4 will add a registration helper that the
        # MeshyCal orchestrator uses at boot).
        r = await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["principal_id"] == PRINCIPAL_A
        assert body["public_key_b64"] == KEY_A

        resolved = await client.resolve(PRINCIPAL_A)
        assert resolved.principal_id == PRINCIPAL_A
        assert resolved.public_key_b64 == KEY_A

    async def test_resolve_unknown_principal_raises(self, directory_client) -> None:
        client, _, _ = directory_client
        with pytest.raises(UnknownPrincipalError, match="no record"):
            await client.resolve("ghost@phase1.local")

    async def test_double_register_returns_409(self, directory_client) -> None:
        _, http, _ = directory_client
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )
        r = await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": "different"},
        )
        assert r.status_code == 409

    async def test_two_principals_coexist(self, directory_client) -> None:
        client, http, _ = directory_client
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_B, "public_key_b64": KEY_B},
        )
        a = await client.resolve(PRINCIPAL_A)
        b = await client.resolve(PRINCIPAL_B)
        assert a.public_key_b64 == KEY_A
        assert b.public_key_b64 == KEY_B


class TestErrorPaths:
    async def test_unreachable_directory_raises_unavailable(self) -> None:
        """If the Directory URL points at nothing, resolve() must surface
        a clear DirectoryUnavailableError, NOT an UnknownPrincipalError —
        the operational response is different (back off vs reject)."""
        client = HTTPDirectoryClient(
            base_url="http://127.0.0.1:1",  # nothing listens here
            directory_public_key_b64=Signer.generate().public_key_b64(),
            timeout=0.5,
        )
        try:
            with pytest.raises(DirectoryUnavailableError, match="Could not reach"):
                await client.resolve(PRINCIPAL_A)
        finally:
            await client.aclose()


class TestSignedRecords:
    async def test_record_signature_verifies_under_directory_key(
        self, directory_client
    ) -> None:
        client, http, signer = directory_client
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )
        # The client verifies internally; getting back a valid
        # ResolvedPrincipal is evidence the signature checked out.
        resolved = await client.resolve(PRINCIPAL_A)
        assert resolved.public_key_b64 == KEY_A

    async def test_pinned_wrong_key_rejects_records(
        self, directory_client, tmp_path: Path
    ) -> None:
        """A client that pins a DIFFERENT public key than the directory
        actually signs with must reject every record. This is the
        impersonation defense: a malicious directory that re-signs records
        with its own key cannot fool a client whose pinned key was
        published by the real directory operator."""
        _, http, _ = directory_client  # real directory signing with real key
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )

        # Build a SECOND client that points at the same directory URL
        # but pins a wrong public key (an attacker's, or just a typo).
        attacker_signer = Signer.generate()
        bad_client = HTTPDirectoryClient(
            base_url="http://testserver",
            directory_public_key_b64=attacker_signer.public_key_b64(),
            http_client=http,
        )
        with pytest.raises(
            DirectorySignatureVerificationFailed, match="did not verify"
        ):
            await bad_client.resolve(PRINCIPAL_A)

    async def test_well_known_public_key_endpoint(self, directory_client) -> None:
        _, http, signer = directory_client
        r = await http.get("/.well-known/directory-public-key")
        assert r.status_code == 200
        assert r.json() == {"public_key_b64": signer.public_key_b64()}

    async def test_resolved_records_carry_issued_and_expires(
        self, directory_client
    ) -> None:
        _, http, _ = directory_client
        await http.post(
            "/principals",
            json={"principal_id": PRINCIPAL_A, "public_key_b64": KEY_A},
        )
        r = await http.get(f"/principals/{PRINCIPAL_A}")
        body = r.json()
        assert body["issued_at"]  # non-empty
        assert body["expires_at"]  # non-empty
        assert body["expires_at"] > body["issued_at"]
        assert body["directory_signature"]  # non-empty


class TestHealth:
    async def test_healthz_returns_ok(self, directory_client) -> None:
        _, http, _ = directory_client
        r = await http.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
