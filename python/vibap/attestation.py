"""Behavioral attestation helpers for governed VIBAP sessions."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .canonical_json import RFC8785JSONEncoder, canonical_json_bytes
from .passport import ALGORITHM, DEFAULT_IAT_FUTURE_SKEW_S, DEFAULT_IAT_PAST_SKEW_S


ATTESTATION_SCHEMA_VERSION = "ardur.behavioral_attestation.v0.2"


def compute_log_digest(events: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json_bytes(events)).hexdigest()


ATTESTATION_TTL_S = 90 * 24 * 3600  # 90 days; archive separately for long-term retention


def issue_attestation(
    passport_jti: str,
    agent_id: str,
    mission: str,
    events: list[dict[str, Any]],
    permits: int,
    denials: int,
    elapsed_s: float,
    private_key: ec.EllipticCurvePrivateKey,
    issuer: str = "vibap-governance-proxy",
    ttl_s: int = ATTESTATION_TTL_S,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "iss": issuer,
        "sub": agent_id,
        "aud": "vibap-attestation-verifier",
        "iat": now,
        "exp": now + ttl_s,
        "jti": str(uuid.uuid4()),
        "type": "behavioral_attestation",
        "passport_jti": passport_jti,
        "mission": mission,
        "total_events": len(events),
        "permits": permits,
        "denials": denials,
        "elapsed_s": round(elapsed_s, 3),
        "scope_compliance": "full" if denials == 0 else "violated",
        "log_digest_sha256": compute_log_digest(events),
    }
    if extra_claims:
        collisions = sorted(set(claims) & set(extra_claims))
        if collisions:
            raise ValueError(
                f"extra attestation claims cannot override reserved claims: {collisions}"
            )
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        json_encoder=RFC8785JSONEncoder,
    )


def verify_attestation(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
    *,
    verify_expiry: bool = True,
    iat_future_skew_s: int | None = DEFAULT_IAT_FUTURE_SKEW_S,
    iat_past_skew_s: int | None = DEFAULT_IAT_PAST_SKEW_S,
) -> dict[str, Any]:
    """Verify a Phase-3.3 attestation JWT and return its claims.

    Round-4 hardening (FIX-R4-3, 2026-04-28): the attestation verifier
    now applies the same bounded-iat-skew gate every other JWT loader
    runs, defending against a briefly-compromised attestation issuer
    minting tokens with iat far in the future. Defaults to ±300s future
    / 30 days past — same envelope as the rest of the JWT surface.

    Offline archival verification passes ``verify_expiry=False`` and ``None``
    skews, matching how it verifies receipts, so an old attestation can still
    seal the journal it was issued for.
    """
    # Local import keeps attestation.py free of a cyclic dep on passport
    # at module load time.
    from .passport import assert_iat_in_window

    claims = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        audience="vibap-attestation-verifier",
        options={
            "require": ["iss", "sub", "aud", "iat", "exp", "jti", "passport_jti"],
            "verify_exp": verify_expiry,
            # Use the explicit window helper below; PyJWT's default check
            # uses zero leeway and clashes with cross-node clock drift.
            "verify_iat": False,
        },
    )
    assert_iat_in_window(
        claims.get("iat"),
        future_skew_s=iat_future_skew_s,
        past_skew_s=iat_past_skew_s,
        field_name="attestation iat",
    )
    schema_version = claims.get("schema_version")
    if schema_version not in {None, ATTESTATION_SCHEMA_VERSION}:
        raise jwt.InvalidTokenError(
            f"unsupported attestation schema_version {schema_version!r}"
        )
    return claims
