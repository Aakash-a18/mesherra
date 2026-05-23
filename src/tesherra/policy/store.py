"""Policy Store.

Implements ARCHITECTURE.md section 13.6.

Backing storage for the user's signed constitution. Per-user.

Properties (per architecture):
- User-owned: only the user's signing key can produce a valid update
- Versioned: every change is a new signed version with a monotonically
  increasing version number
- Local-first: stored on the user's device, replicated to Tesherra-hosted
  backup with end-to-end encryption
- Schema-validated: every version matches the policy schema for the Tesherra
  version it was signed against

Status: scaffolding only.
"""

from __future__ import annotations

from typing import Any


class PolicyStore:
    """User-owned, versioned, schema-validated policy storage."""

    def __init__(self) -> None:
        raise NotImplementedError

    def get_current(self, user_id: str) -> Any:
        raise NotImplementedError

    def get_version(self, user_id: str, version: int) -> Any:
        raise NotImplementedError

    def save_signed(self, user_id: str, policy: Any, signature: bytes) -> int:
        """Save a new signed policy version. Returns the new version number."""
        raise NotImplementedError
