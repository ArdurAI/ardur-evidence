"""Content-addressed public-key identifiers shared by Ardur's signed surfaces.

Ardur names a public key by hashing its SubjectPublicKeyInfo (SPKI) DER
encoding and formatting the result as ``sha256:<hex>``. The identifier is
*content-addressed*: anyone holding the public key can recompute it
independently, so it is a checkable binding rather than an operator-chosen
label that a verifier would have to resolve through a registry it may not be
able to reach offline.

This module exists so the derivation has exactly one implementation. It
previously lived only in :func:`vibap.offline_verification.public_key_fingerprint`,
where it names trust roots in verification reports. :mod:`vibap.receipt` needs
the same value for the JWS ``kid`` header, and ``offline_verification`` already
imports ``receipt``, so ``receipt`` cannot import it back. Both now import this
leaf module, which deliberately has no intra-package imports.

Not to be confused with :func:`vibap.transparency._note_key_id`, which is a
4-byte truncation mandated by the signed-note wire format of the transparency
log. That value is fixed by an external format and is not interchangeable with
the identifiers here.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives import serialization

__all__ = [
    "KEY_FINGERPRINT_PREFIX",
    "KeyFingerprintError",
    "public_key_fingerprint",
    "public_key_spki",
]

KEY_FINGERPRINT_PREFIX = "sha256:"


class KeyFingerprintError(ValueError):
    """A public key could not be encoded as SPKI DER, so it cannot be named."""


def public_key_spki(public_key: Any) -> bytes:
    """Return the DER-encoded SubjectPublicKeyInfo for ``public_key``.

    DER is a distinguished encoding, so for a given key object this byte string
    is stable across processes and library versions — which is what makes the
    derived fingerprint safe to compare for equality.
    """

    try:
        return public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise KeyFingerprintError("public key cannot be encoded as SPKI") from exc


def public_key_fingerprint(public_key: Any) -> str:
    """Return the stable ``sha256:<hex>`` SPKI fingerprint of ``public_key``.

    Raises :class:`KeyFingerprintError` when the key cannot be encoded. Callers
    that already have a domain-specific error taxonomy are expected to catch it
    and re-raise in their own terms rather than let it escape untranslated.
    """

    digest = hashlib.sha256(public_key_spki(public_key)).hexdigest()
    return f"{KEY_FINGERPRINT_PREFIX}{digest}"
