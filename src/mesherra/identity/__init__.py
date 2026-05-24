"""Mesherra identity: verified directory of principals.

Per ARCHITECTURE.md sections 4.1, 13.5, 13.7.
"""

from .client import (
    DirectoryClient,
    DirectorySignatureVerificationFailed,
    DirectoryUnavailableError,
    HTTPDirectoryClient,
    ResolvedPrincipal,
    StaticDirectoryClient,
    UnknownPrincipalError,
)
from .runtime import DirectoryListenerHandle, start_directory_listener
from .server import create_app
from .store import (
    DirectoryStore,
    DirectoryStoreError,
    PrincipalAlreadyRegistered,
    PrincipalNotFound,
    StoredPrincipal,
)

__all__ = [
    "DirectoryClient",
    "DirectoryListenerHandle",
    "DirectorySignatureVerificationFailed",
    "DirectoryStore",
    "DirectoryStoreError",
    "DirectoryUnavailableError",
    "HTTPDirectoryClient",
    "PrincipalAlreadyRegistered",
    "PrincipalNotFound",
    "ResolvedPrincipal",
    "StaticDirectoryClient",
    "StoredPrincipal",
    "UnknownPrincipalError",
    "create_app",
    "start_directory_listener",
]
