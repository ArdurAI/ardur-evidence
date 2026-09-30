"""Protected-header ``kid`` on Execution Receipts.

``docs/specs/execution-receipt-v0.1.md`` §9.1 has always said the receipt's
protected header SHOULD include a ``kid``, but the implementation emitted only
``typ`` and ``alg`` and never inspected the header at all. These tests pin the
three properties that make the header field worth having:

1. it is emitted, and it is *content-addressed* — a verifier recomputes it from
   the public key it already holds, so the binding is checkable offline rather
   than being an opaque label;
2. its absence is not an error, so receipts issued before this change verify
   exactly as they did before; and
3. its presence with the wrong value fails closed, per the fail-closed rule in
   ``docs/security-model.md``.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from jwt.utils import base64url_encode

from vibap.canonical_json import RFC8785JSONEncoder, canonical_json_bytes
from vibap.key_fingerprint import public_key_fingerprint
from vibap.offline_verification import (
    public_key_fingerprint as trust_root_fingerprint,
)
from vibap.passport import ALGORITHM
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import (
    RECEIPT_JWT_TYPE,
    ReceiptChainError,
    ReceiptKeyIdMismatchError,
    build_receipt,
    receipt_key_id,
    sign_receipt,
    verify_chain,
    verify_receipt,
)


def _event(step_id: str = "step-kid") -> PolicyEvent:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return PolicyEvent(
        timestamp=timestamp,
        step_id=step_id,
        actor="spiffe://example.test/agent",
        verifier_id="vibap-governance-proxy",
        tool_name="read_file",
        arguments={"path": "README.md"},
        action_class="read",
        target="README.md",
        resource_family="file",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="within scope",
        passport_jti="grant-kid",
        trace_id="trace-kid",
        run_nonce="kid-run-nonce-0001",
    )


def _claims() -> dict:
    return build_receipt(Decision.PERMIT, _event()).to_dict()


def _mint(private_key, headers: dict) -> str:
    """Sign a well-formed receipt payload under a caller-chosen header.

    Uses the same canonical-JSON encoder as ``sign_receipt`` so the payload
    still passes the RFC 8785 gate and the *header* is the only variable.
    """

    return jwt.encode(
        _claims(),
        private_key,
        algorithm=ALGORITHM,
        headers=headers,
        json_encoder=RFC8785JSONEncoder,
    )


def _mint_raw(private_key, header: dict) -> str:
    """Assemble and sign a JWS under a header ``jwt.encode`` refuses to emit.

    Needed only for headers PyJWT rejects at encode time (a non-string
    ``kid``). The signature is real, so the token gets as far into
    verification as its header allows.
    """

    segments = [
        base64url_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ),
        base64url_encode(canonical_json_bytes(_claims())),
    ]
    signature = ECAlgorithm(ECAlgorithm.SHA256).sign(b".".join(segments), private_key)
    segments.append(base64url_encode(signature))
    return b".".join(segments).decode("ascii")


# ---------------------------------------------------------------------------
# 1. Emitted, and content-addressed
# ---------------------------------------------------------------------------


def test_signed_receipt_carries_a_kid_a_verifier_can_recompute(
    private_key, public_key
) -> None:
    """The emitted kid equals what a holder of the public key derives itself."""

    token = sign_receipt(build_receipt(Decision.PERMIT, _event()), private_key)
    header = jwt.get_unverified_header(token)

    assert header["typ"] == RECEIPT_JWT_TYPE
    assert header["alg"] == ALGORITHM
    # Recomputed independently from the public key, exactly as an offline
    # verifier would, with no registry lookup and no issuer-supplied label.
    assert header["kid"] == public_key_fingerprint(public_key)
    assert header["kid"] == receipt_key_id(public_key)
    assert header["kid"].startswith("sha256:")


def test_kid_reuses_the_offline_verifier_trust_root_scheme(public_key) -> None:
    """One derivation, not a third scheme invented for receipts.

    ``offline_verification.public_key_fingerprint`` is what the verification
    report prints as ``spki_fingerprint``; a reader must be able to match that
    against a receipt's kid by eye.
    """

    assert receipt_key_id(public_key) == trust_root_fingerprint(public_key)


def test_kid_is_not_in_the_payload(private_key, public_key) -> None:
    """Scope guard: the header carries the kid, the claim set is untouched.

    The v0.2 claim schema is ``additionalProperties: false``, so a payload
    ``kid`` would be a format migration rather than a drop-in.
    """

    claims = verify_receipt(
        sign_receipt(build_receipt(Decision.PERMIT, _event()), private_key),
        public_key,
    )

    assert "kid" not in claims


def test_distinct_keys_get_distinct_kids(private_key, public_key) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())

    assert receipt_key_id(other_key.public_key()) != receipt_key_id(public_key)


# ---------------------------------------------------------------------------
# 2. Absent kid must still verify (no migration)
# ---------------------------------------------------------------------------


def test_receipt_without_kid_still_verifies(private_key, public_key) -> None:
    """Pre-change receipts carry no kid. Their behaviour must be unchanged.

    §9.1 makes the header a SHOULD, so absence is silence rather than a
    contradicted claim, and must not escalate to an error.
    """

    legacy_token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE})
    header = jwt.get_unverified_header(legacy_token)
    assert "kid" not in header

    claims = verify_receipt(legacy_token, public_key)

    assert claims["verdict"] == "compliant"


def test_chain_of_kidless_receipts_still_verifies(private_key, public_key) -> None:
    legacy_token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE})

    verified = verify_chain([legacy_token], public_key)

    assert len(verified) == 1


# ---------------------------------------------------------------------------
# 3. Present-and-mismatched must fail closed
# ---------------------------------------------------------------------------


def test_mismatched_kid_fails_closed_even_with_a_valid_signature(
    private_key, public_key
) -> None:
    """The whole point of the check.

    The token below is signed by the *real* key, so the signature verifies and
    every claim is well-formed. Only the header names someone else's key. A
    verifier that shrugged this off would be accepting a binding the issuer
    never asserted.
    """

    impostor_kid = receipt_key_id(ec.generate_private_key(ec.SECP256R1()).public_key())
    token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE, "kid": impostor_kid})

    # Signature really is valid — prove the test is not just a broken token.
    jwt.decode(token, public_key, algorithms=[ALGORITHM], options={"verify_exp": False})

    with pytest.raises(ReceiptKeyIdMismatchError) as excinfo:
        verify_receipt(token, public_key)

    assert excinfo.value.code == "receipt_kid_mismatch"
    assert "names a different signing key" in str(excinfo.value)


def test_mismatched_kid_is_catchable_as_a_pyjwt_error(private_key, public_key) -> None:
    """Existing fail-closed callers catch ``jwt.PyJWTError``; keep them working.

    A verifier trialling candidate keys also depends on this: it must be able
    to move on to the next key rather than crash.
    """

    impostor_kid = receipt_key_id(ec.generate_private_key(ec.SECP256R1()).public_key())
    token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE, "kid": impostor_kid})

    with pytest.raises(jwt.PyJWTError):
        verify_receipt(token, public_key)


def test_mismatched_kid_fails_the_chain_verifier(private_key, public_key) -> None:
    """The offline path funnels through ``verify_chain``; it must fail there too."""

    impostor_kid = receipt_key_id(ec.generate_private_key(ec.SECP256R1()).public_key())
    token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE, "kid": impostor_kid})

    with pytest.raises(ReceiptChainError, match="receipt signature/schema invalid"):
        verify_chain([token], public_key)


@pytest.mark.parametrize(
    "bad_kid",
    ["", "sha256:not-a-digest", "vibap-primary", "SHA256:UPPERCASE"],
)
def test_malformed_kid_strings_fail_closed(private_key, public_key, bad_kid) -> None:
    """Anything present but not equal to the recomputed id is a mismatch.

    An empty string is included on purpose: a stated-but-empty binding is not
    the same as omitting the header field, so it must not be read as absence.
    ``vibap-primary`` is the opaque label the JWKS endpoint advertises — a kid
    that is not content-addressed is exactly the kind of unverifiable claim
    this check is meant to reject.
    """

    token = _mint(private_key, {"typ": RECEIPT_JWT_TYPE, "kid": bad_kid})

    with pytest.raises(ReceiptKeyIdMismatchError):
        verify_receipt(token, public_key)


@pytest.mark.parametrize("bad_kid", [1234, None, ["sha256:x"]])
def test_non_string_kid_fails_closed(private_key, public_key, bad_kid) -> None:
    """A non-string kid is rejected before the binding check even runs.

    PyJWT's own header validation rejects these during ``decode``, so this
    records where the guarantee actually comes from rather than crediting it
    to Ardur's check. The receipt-level ``isinstance`` guard behind it is
    belt-and-braces for callers that reach the helper another way.

    These tokens must be hand-assembled: ``jwt.encode`` refuses to emit a
    non-string kid, so they cannot be produced by the normal signing path.
    """

    token = _mint_raw(
        private_key, {"alg": ALGORITHM, "typ": RECEIPT_JWT_TYPE, "kid": bad_kid}
    )

    with pytest.raises(jwt.InvalidTokenError, match="Key ID header parameter"):
        verify_receipt(token, public_key)


def test_rewriting_kid_in_place_breaks_the_signature(private_key, public_key) -> None:
    """Why this is defence in depth rather than the primary control.

    The protected header is inside the JWS signing input, so an attacker who
    edits ``kid`` on a signed receipt invalidates the signature and never
    reaches the mismatch check. The mismatch check exists for the case the
    signature cannot catch: a producer that signs with one key while naming
    another.
    """

    token = sign_receipt(build_receipt(Decision.PERMIT, _event()), private_key)
    impostor_kid = receipt_key_id(ec.generate_private_key(ec.SECP256R1()).public_key())
    forged_header = base64url_encode(
        json.dumps(
            {"alg": ALGORITHM, "kid": impostor_kid, "typ": RECEIPT_JWT_TYPE},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).decode("ascii")
    _, payload, signature = token.split(".")
    spliced = f"{forged_header}.{payload}.{signature}"

    with pytest.raises(jwt.InvalidSignatureError):
        verify_receipt(spliced, public_key)
