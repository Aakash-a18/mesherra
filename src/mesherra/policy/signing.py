"""Policy doc signing and verification helpers.

Per demos/phase_3/SPEC.md §2.1. Thin wrappers around
``mesherra.crypto.primitives`` that pin the canonical-encoding convention
for policy docs in one place, so callers don't re-derive it.

The signed bytes for a policy doc are always:

    canonical_json(doc.to_signing_payload())

i.e. the JCS encoding of the doc's dict form, excluding any signature. The
signature is held in the wrapping :class:`SignedPolicyDoc` so it never
contributes to its own input bytes.
"""

from __future__ import annotations

from mesherra.crypto.primitives import Signer, Verifier, canonical_json

from .models import PolicyDoc, SignedPolicyDoc


def sign_policy_doc(*, doc: PolicyDoc, signer: Signer) -> SignedPolicyDoc:
    """Sign ``doc`` with ``signer``, return a :class:`SignedPolicyDoc`.

    Caller is responsible for ensuring ``signer`` matches ``doc.principal_id``
    — the helper itself does not look up the principal's published key, so
    a mis-paired signer here only surfaces at verification time
    (:func:`verify_policy_doc`).
    """
    payload = canonical_json(doc.to_signing_payload())
    signature_b64 = signer.sign(payload)
    return SignedPolicyDoc(doc=doc, signature_b64=signature_b64)


def verify_policy_doc(
    *,
    signed: SignedPolicyDoc,
    public_key_b64: str,
) -> bool:
    """Verify ``signed.signature_b64`` over ``signed.doc``.

    Returns True on a valid signature, False otherwise. Mirrors
    :meth:`Verifier.verify`'s boolean contract so callers can write
    ``if not verify_policy_doc(...): raise`` without a try/except.
    """
    payload = canonical_json(signed.doc.to_signing_payload())
    verifier = Verifier.from_b64(public_key_b64)
    return verifier.verify(payload, signed.signature_b64)
