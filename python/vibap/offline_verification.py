"""Self-contained offline verification and receipt-explorer reports."""

from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, ValidationError

from ._specs import (
    offline_verification_bundle_v01_schema,
    offline_verification_report_v01_schema,
)
from .key_fingerprint import KeyFingerprintError
from .key_fingerprint import public_key_fingerprint as _public_key_fingerprint
from .receipt import ReceiptChainError, verify_chain
from .receiver_attestation import (
    ASSURANCE_RECEIVER_ATTESTED,
    ReceiverAttestationError,
    verify_receiver_envelope,
)
from .transparency import AnchorVerificationError, verify_anchor_bundle


BUNDLE_SCHEMA_VERSION = "ardur.offline_verification_bundle.v0.1"
REPORT_SCHEMA_VERSION = "ardur.offline_verification_report.v0.1"
FULL_EVIDENCE_PROFILE = "full-evidence"
CHAIN_ONLY_PROFILE = "chain-only"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 2048
MAX_JWS_BYTES = 2 * 1024 * 1024
REDACTION_MARKER = "[REDACTED]"

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|authorization)"
    r"(\s*[:=]\s*)([^\s&,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_GITHUB_TOKEN_RE = re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_SERVICE_TOKEN_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{24,}|npm_[A-Za-z0-9]{20,})\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_BIDI_CONTROL_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


class OfflineVerificationError(ValueError):
    """A portable journal or one of its evidence bindings failed closed."""

    def __init__(self, code: str, message: str, *, index: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.index = index


@dataclass(frozen=True, slots=True)
class OfflineInput:
    kind: str
    entries: tuple[dict[str, Any], ...]
    source_sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OfflineVerificationError(
                "duplicate_json_key", f"JSON object repeats key {key!r}"
            )
        value[key] = item
    return value


def _strict_json(raw: str, *, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except OfflineVerificationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        line = getattr(exc, "lineno", 1)
        column = getattr(exc, "colno", 1)
        raise OfflineVerificationError(
            "malformed_json",
            f"{label} is not valid bounded JSON at line {line}, column {column}",
        ) from exc


def _read_bounded_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise OfflineVerificationError(
            "input_symlink", "offline verification input must not be a symlink"
        )
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise OfflineVerificationError(
            "input_missing", "offline verification input was not found"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise OfflineVerificationError(
            "input_not_file", "offline verification input must be a regular file"
        )
    if metadata.st_size <= 0 or metadata.st_size > MAX_INPUT_BYTES:
        raise OfflineVerificationError(
            "input_size_invalid",
            f"offline verification input must be 1..{MAX_INPUT_BYTES} bytes",
        )
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise OfflineVerificationError(
            "input_too_large", "offline verification input exceeds the size limit"
        )
    return raw


def _journal_token(value: Any, *, line_number: int) -> str:
    if isinstance(value, str):
        token = value
    elif isinstance(value, dict) and isinstance(value.get("jwt"), str):
        token = value["jwt"]
    else:
        raise OfflineVerificationError(
            "journal_entry_invalid",
            f"journal line {line_number} must be a compact JWS or an object with a jwt field",
            index=line_number - 1,
        )
    if len(token.encode("utf-8")) > MAX_JWS_BYTES or token.count(".") != 2:
        raise OfflineVerificationError(
            "journal_token_invalid",
            f"journal line {line_number} is not a bounded compact JWS",
            index=line_number - 1,
        )
    return token


def _load_jsonl_journal(text: str, source_sha256: str) -> OfflineInput:
    entries: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parsed: Any = line
        if line.startswith("{") or line.startswith('"'):
            parsed = _strict_json(line, label=f"journal line {line_number}")
        entries.append({"receipt_jwt": _journal_token(parsed, line_number=line_number)})
        if len(entries) > MAX_JOURNAL_ENTRIES:
            raise OfflineVerificationError(
                "journal_too_large",
                f"journal exceeds {MAX_JOURNAL_ENTRIES} receipts",
            )
    if not entries:
        raise OfflineVerificationError(
            "journal_empty", "receipt journal contains no receipts"
        )
    return OfflineInput("journal", tuple(entries), source_sha256)


def _validate_bundle(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, dict):
        raise OfflineVerificationError(
            "bundle_not_object", "offline verification bundle must be a JSON object"
        )
    try:
        Draft202012Validator(offline_verification_bundle_v01_schema()).validate(value)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "root"
        raise OfflineVerificationError(
            "bundle_schema_invalid",
            f"offline bundle schema violation at {location}: {exc.message}",
        ) from exc
    return tuple(copy.deepcopy(value["journal"]))


def _validate_report(value: dict[str, Any]) -> dict[str, Any]:
    """Fail closed if the explorer report drifts from its published schema.

    The report is the artifact an external evaluator actually reads, so a
    silently reshaped report is an honesty defect, not a cosmetic one. This
    only ever converts a malformed report into a loud failure: on the success
    path the value is returned unchanged.
    """

    try:
        Draft202012Validator(offline_verification_report_v01_schema()).validate(value)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "root"
        raise OfflineVerificationError(
            "report_schema_invalid",
            f"offline verification report schema violation at {location}: {exc.message}",
        ) from exc
    return value


def load_offline_input(path: str | Path) -> OfflineInput:
    """Load a bounded full bundle or legacy JSONL receipt journal."""

    input_path = Path(path).expanduser()
    raw = _read_bounded_regular_file(input_path)
    source_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OfflineVerificationError(
            "input_not_utf8", "offline verification input must be UTF-8"
        ) from exc
    if text.lstrip().startswith("{"):
        try:
            value = _strict_json(text, label="offline verification bundle")
        except OfflineVerificationError as exc:
            if exc.code != "malformed_json" or len(text.splitlines()) <= 1:
                raise
        else:
            if (
                isinstance(value, dict)
                and value.get("schema_version") == BUNDLE_SCHEMA_VERSION
            ):
                return OfflineInput("bundle", _validate_bundle(value), source_sha256)
            if (
                isinstance(value, dict)
                and "schema_version" in value
                and "jwt" not in value
            ):
                raise OfflineVerificationError(
                    "unsupported_bundle_schema",
                    f"unsupported offline bundle schema {value.get('schema_version')!r}",
                )
    return _load_jsonl_journal(text, source_sha256)


def public_key_fingerprint(public_key: Any) -> str:
    """Return a stable SHA-256 SPKI fingerprint for an out-of-band trust root.

    The derivation itself lives in :mod:`vibap.key_fingerprint` so that the
    receipt ``kid`` header and these report fingerprints are the same value by
    construction rather than by coincidence. This wrapper only re-raises in the
    offline verifier's own error taxonomy.
    """

    try:
        return _public_key_fingerprint(public_key)
    except KeyFingerprintError as exc:
        raise OfflineVerificationError(
            "trust_root_invalid", "trust root cannot be encoded as SPKI"
        ) from exc


def redact_text(value: str) -> str:
    """Redact common credential shapes from a human-facing evidence string."""

    redacted = _PRIVATE_KEY_RE.sub(REDACTION_MARKER, value)
    redacted = _BEARER_RE.sub(f"Bearer {REDACTION_MARKER}", redacted)
    redacted = _GITHUB_TOKEN_RE.sub(REDACTION_MARKER, redacted)
    redacted = _AWS_ACCESS_KEY_RE.sub(REDACTION_MARKER, redacted)
    redacted = _SERVICE_TOKEN_RE.sub(REDACTION_MARKER, redacted)
    return _SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        redacted,
    )


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return value


def _verdict_label(verdict: str) -> str:
    return {
        "compliant": "PERMIT",
        "violation": "DENY",
        "insufficient_evidence": "ERROR",
        "unknown": "UNKNOWN",
    }[verdict]


def _default_reason_code(verdict: str) -> str:
    """Return a verdict-appropriate reason code when no explicit code is set."""
    if verdict == "compliant":
        return "policy_permit"
    if verdict == "unknown":
        return "observation_gap"
    if verdict == "violation":
        return "policy_denied"
    # insufficient_evidence or any future verdict
    return "insufficient_evidence"


def _budget_narrowing(
    claims: Mapping[str, Any], previous: Mapping[str, Any] | None
) -> dict[str, Any]:
    current_budget = dict(claims.get("budget_remaining", {}))
    previous_budget = dict(previous.get("budget_remaining", {})) if previous else {}
    decreased = sorted(
        key
        for key, value in current_budget.items()
        if key in previous_budget
        and isinstance(value, int)
        and value < previous_budget[key]
    )
    expanded = sorted(
        key
        for key, value in current_budget.items()
        if previous is not None
        and isinstance(value, int)
        and (
            (key in previous_budget and value > previous_budget[key])
            or (key not in previous_budget and value > 0)
        )
    )
    delta = claims.get("budget_delta")
    signed_delta_narrows = False
    delta_inconsistent = False
    why: list[str] = []
    if isinstance(delta, dict):
        operation = delta.get("operation")
        amount = delta.get("amount", delta.get("delta", 0))
        resource = delta.get("resource")
        remaining_after = delta.get("remaining_after")
        signed_delta_narrows = (
            operation in {"consume", "reserve"}
            and isinstance(amount, int)
            and not isinstance(amount, bool)
            and amount > 0
        )
        if signed_delta_narrows:
            why.append(f"signed budget delta {operation or 'consume'} {amount}")
        if (
            isinstance(resource, str)
            and resource in current_budget
            and isinstance(remaining_after, int)
            and not isinstance(remaining_after, bool)
            and current_budget[resource] != remaining_after
        ):
            delta_inconsistent = True
            why.append(
                f"signed budget delta remaining_after contradicts budget_remaining for {resource}"
            )
    if decreased:
        why.append(f"remaining budget decreased in {', '.join(decreased)}")
    grant_changed = previous is not None and claims.get("grant_id") != previous.get(
        "grant_id"
    )
    if grant_changed:
        why.append("signed grant identifier changed; scope containment is not inferred")
    if expanded:
        why.append(
            f"remaining budget increased in {', '.join(expanded)}; narrowing is not proven"
        )
    narrowing_proven = (
        bool(signed_delta_narrows or decreased)
        and not expanded
        and not delta_inconsistent
    )
    return {
        "grant_changed": grant_changed,
        "budget_narrowed": narrowing_proven,
        "narrowing_proven": narrowing_proven,
        "why": why or ["no signed budget narrowing at this step"],
        "budget_delta": copy.deepcopy(delta),
        "budget_remaining": current_budget,
    }


def _cost_projection(claims: Mapping[str, Any]) -> dict[str, int | float]:
    measurements = claims.get("measurements")
    if not isinstance(measurements, dict):
        return {}
    return {
        str(key): value
        for key, value in measurements.items()
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and any(marker in str(key).lower() for marker in ("cost", "usd", "token"))
    }


def _timeline_item(
    index: int,
    claims: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
    anchor_report: Mapping[str, Any] | None,
    receiver_report: Mapping[str, Any] | None,
) -> dict[str, Any]:
    policy_outcomes = [
        {
            "backend": item.get("backend"),
            "decision": item.get("decision"),
            "reason": item.get("reason"),
            "rule_id": item.get("rule_id"),
        }
        for item in claims.get("policy_decisions", [])
        if isinstance(item, dict)
    ]
    receiver_evidence = (
        receiver_report.get("receiver_attestation", {}) if receiver_report else {}
    )
    return {
        "index": index,
        "timestamp": claims["timestamp"],
        "receipt_id": claims["receipt_id"],
        "parent_receipt_hash": claims["parent_receipt_hash"],
        "step_id": claims["step_id"],
        "verdict": claims["verdict"],
        "decision": _verdict_label(str(claims["verdict"])),
        "reason_code": claims.get("internal_denial_code")
        or _default_reason_code(claims["verdict"]),
        "actor": claims["actor"],
        "verifier_id": claims["verifier_id"],
        "grant_id": claims["grant_id"],
        "tool": claims["tool"],
        "action_class": claims["action_class"],
        "target": claims["target"],
        "resource_family": claims["resource_family"],
        "side_effect_class": claims["side_effect_class"],
        "sensitivity": claims.get("sensitivity"),
        "instruction_bearing": claims.get("instruction_bearing"),
        "content_class": claims.get("content_class"),
        "content_provenance": claims.get("content_provenance"),
        "invocation_digest": copy.deepcopy(claims["invocation_digest"]),
        "evidence_level": claims["evidence_level"],
        "reason": claims["reason"],
        "policy_outcomes": policy_outcomes,
        "cost_outcomes": _cost_projection(claims),
        "authority": _budget_narrowing(claims, previous),
        "evidence": {
            "receipt_signature_valid": True,
            "chain_link_valid": True,
            "transparency": (
                {
                    "present": True,
                    "valid": True,
                    "anchor_id": anchor_report.get("anchor_id"),
                    "log_id": anchor_report.get("log_id"),
                    "log_index": anchor_report.get("log_index"),
                    "tree_size": anchor_report.get("tree_size"),
                }
                if anchor_report
                else {"present": False, "valid": False}
            ),
            "receiver": (
                {
                    "present": bool(receiver_evidence.get("present")),
                    "valid": bool(receiver_evidence.get("signature_valid")),
                    "assurance_tier": receiver_report.get("assurance_tier"),
                    "status": (
                        "verified"
                        if receiver_evidence.get("signature_valid")
                        else "not-dispatched"
                    ),
                    "attestation_id": receiver_evidence.get("attestation_id"),
                    "receiver_id": receiver_evidence.get("receiver_id"),
                }
                if receiver_report
                else {"present": False, "valid": False, "status": "absent"}
            ),
        },
    }


def _validate_claim_sequence(claims: list[dict[str, Any]]) -> None:
    receipt_ids: set[str] = set()
    jtis: set[str] = set()
    trace_id = claims[0]["trace_id"]
    run_nonce = claims[0]["run_nonce"]
    for index, item in enumerate(claims):
        receipt_id = str(item["receipt_id"])
        jti = str(item["jti"])
        if receipt_id in receipt_ids or jti in jtis:
            raise OfflineVerificationError(
                "duplicate_receipt",
                f"receipt or JTI repeats at index {index}",
                index=index,
            )
        receipt_ids.add(receipt_id)
        jtis.add(jti)
        if item["trace_id"] != trace_id or item["run_nonce"] != run_nonce:
            raise OfflineVerificationError(
                "journal_lineage_mismatch",
                f"receipt at index {index} belongs to a different trace or run nonce",
                index=index,
            )
        if index and item["iat"] < claims[index - 1]["iat"]:
            raise OfflineVerificationError(
                "timestamp_regression",
                f"receipt issuance time regresses at index {index}",
                index=index,
            )
        try:
            observed = datetime.fromisoformat(
                str(item["timestamp"]).replace("Z", "+00:00")
            )
            previous = (
                datetime.fromisoformat(
                    str(claims[index - 1]["timestamp"]).replace("Z", "+00:00")
                )
                if index
                else None
            )
        except ValueError as exc:
            raise OfflineVerificationError(
                "timestamp_invalid",
                f"receipt timestamp is invalid at index {index}",
                index=index,
            ) from exc
        if observed.utcoffset() is None or (
            previous is not None and previous.utcoffset() is None
        ):
            raise OfflineVerificationError(
                "timestamp_invalid",
                f"receipt timestamp must include a UTC offset at index {index}",
                index=index,
            )
        if previous is not None and observed < previous:
            raise OfflineVerificationError(
                "timestamp_regression",
                f"receipt observation time regresses at index {index}",
                index=index,
            )


def _bundle_freshness_report(
    claims: list[dict[str, Any]],
    *,
    verified_at: int,
    max_bundle_age_s: int | None,
    freshness_clock_skew_s: int | None,
) -> dict[str, Any]:
    if max_bundle_age_s is not None and (
        isinstance(max_bundle_age_s, bool)
        or not isinstance(max_bundle_age_s, int)
        or max_bundle_age_s < 0
    ):
        raise OfflineVerificationError(
            "freshness_policy_invalid",
            "max bundle age must be a non-negative integer or omitted",
        )

    latest_iat = int(claims[-1]["iat"])
    if max_bundle_age_s is None:
        if freshness_clock_skew_s is not None:
            raise OfflineVerificationError(
                "freshness_policy_invalid",
                "freshness clock skew requires a maximum bundle age",
            )
        return {
            "age_checked": False,
            "max_age_s": None,
            "allowed_future_skew_s": None,
            "latest_receipt_iat": latest_iat,
            "age_s": None,
            "one_time_replay_checked": False,
        }

    allowed_future_skew_s = (
        60 if freshness_clock_skew_s is None else freshness_clock_skew_s
    )
    if (
        isinstance(allowed_future_skew_s, bool)
        or not isinstance(allowed_future_skew_s, int)
        or allowed_future_skew_s < 0
    ):
        raise OfflineVerificationError(
            "freshness_policy_invalid",
            "freshness clock skew must be a non-negative integer",
        )

    last_index = len(claims) - 1
    if latest_iat > verified_at + allowed_future_skew_s:
        raise OfflineVerificationError(
            "bundle_freshness_future",
            "latest receipt issuance time exceeds the verifier freshness clock-skew allowance",
            index=last_index,
        )
    age_s = max(0, verified_at - latest_iat)
    if age_s > max_bundle_age_s:
        raise OfflineVerificationError(
            "bundle_freshness_stale",
            "latest receipt exceeds the verifier-supplied maximum bundle age",
            index=last_index,
        )
    return {
        "age_checked": True,
        "max_age_s": max_bundle_age_s,
        "allowed_future_skew_s": allowed_future_skew_s,
        "latest_receipt_iat": latest_iat,
        "age_s": age_s,
        "one_time_replay_checked": False,
    }


def verify_offline_input(
    offline_input: OfflineInput,
    *,
    receipt_public_key: ec.EllipticCurvePublicKey,
    log_public_key: Any | None = None,
    receiver_public_key: ec.EllipticCurvePublicKey | None = None,
    chain_only: bool = False,
    verify_expiry: bool = False,
    max_registration_delay_s: int | None = 86_400,
    max_attestation_delay_s: int = 300,
    receiver_clock_skew_s: int = 60,
    max_bundle_age_s: int | None = None,
    freshness_clock_skew_s: int | None = None,
    redact: bool = True,
    include_correlation_fields: bool = False,
) -> dict[str, Any]:
    """Verify a loaded bundle without network access and return an explorer report.

    The default is retrospective audit verification: receipt age and one-time
    replay are not enforced. Set ``max_bundle_age_s`` to reject a latest signed
    receipt outside a verifier-clock age/skew window. That age bound does not
    prevent repeated presentation inside the accepted window.
    """

    if offline_input.kind == "journal" and not chain_only:
        raise OfflineVerificationError(
            "full_evidence_required",
            "raw receipt journals require --chain-only; full verification requires a versioned bundle",
        )
    if not isinstance(receipt_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        receipt_public_key.curve, ec.SECP256R1
    ):
        raise OfflineVerificationError(
            "receipt_key_invalid", "receipt trust root must be an ES256 P-256 key"
        )
    full_evidence = offline_input.kind == "bundle" and not chain_only
    if full_evidence and log_public_key is None:
        raise OfflineVerificationError(
            "log_key_required",
            "full verification requires a transparency-log public key",
        )
    if full_evidence and receiver_public_key is None:
        raise OfflineVerificationError(
            "receiver_key_required", "full verification requires a receiver public key"
        )
    if full_evidence:
        trust_fingerprints = {
            public_key_fingerprint(receipt_public_key),
            public_key_fingerprint(log_public_key),
            public_key_fingerprint(receiver_public_key),
        }
        if len(trust_fingerprints) != 3:
            raise OfflineVerificationError(
                "trust_roots_not_independent",
                "receipt issuer, transparency log, and receiver must use distinct trust roots",
            )

    tokens = [str(entry["receipt_jwt"]) for entry in offline_input.entries]
    try:
        claims = verify_chain(
            tokens,
            receipt_public_key,
            verify_expiry=verify_expiry,
            iat_future_skew_s=None,
            iat_past_skew_s=None,
        )
    except (ReceiptChainError, TypeError, ValueError) as exc:
        raise OfflineVerificationError("receipt_chain_invalid", str(exc)) from exc
    _validate_claim_sequence(claims)

    timeline: list[dict[str, Any]] = []
    for index, (entry, item) in enumerate(
        zip(offline_input.entries, claims, strict=True)
    ):
        anchor_report: Mapping[str, Any] | None = None
        receiver_report: Mapping[str, Any] | None = None
        if full_evidence:
            anchor = entry["transparency_anchor"]
            receiver = entry["receiver_attestation"]
            if anchor.get("receipt_jwt") != tokens[index]:
                raise OfflineVerificationError(
                    "anchor_receipt_mismatch",
                    f"transparency anchor does not bind journal receipt at index {index}",
                    index=index,
                )
            if receiver.get("receipt_jwt") != tokens[index]:
                raise OfflineVerificationError(
                    "receiver_receipt_mismatch",
                    f"receiver envelope does not bind journal receipt at index {index}",
                    index=index,
                )
            try:
                anchor_report = verify_anchor_bundle(
                    anchor,
                    receipt_public_key=receipt_public_key,
                    log_public_key=log_public_key,
                    max_registration_delay_s=max_registration_delay_s,
                )
            except (AnchorVerificationError, TypeError, ValueError) as exc:
                raise OfflineVerificationError(
                    "anchor_verification_failed",
                    f"anchor failed at index {index}: {exc}",
                    index=index,
                ) from exc
            try:
                receiver_report = verify_receiver_envelope(
                    receiver,
                    receipt_public_key=receipt_public_key,
                    receiver_public_key=receiver_public_key,
                    max_attestation_delay_s=max_attestation_delay_s,
                    receiver_clock_skew_s=receiver_clock_skew_s,
                )
            except (ReceiverAttestationError, TypeError, ValueError) as exc:
                raise OfflineVerificationError(
                    "receiver_verification_failed",
                    f"receiver attestation failed at index {index}: {exc}",
                    index=index,
                ) from exc
            assurance_tier = receiver_report.get("assurance_tier")
            if (
                item["verdict"] == "compliant"
                and assurance_tier != ASSURANCE_RECEIVER_ATTESTED
            ):
                raise OfflineVerificationError(
                    "receiver_attestation_required",
                    f"a compliant receipt requires receiver-attested evidence at index {index}",
                    index=index,
                )
            if (
                item["verdict"] != "compliant"
                and assurance_tier == ASSURANCE_RECEIVER_ATTESTED
            ):
                raise OfflineVerificationError(
                    "receiver_attestation_unexpected",
                    f"a non-compliant receipt must record blocked dispatch at index {index}",
                    index=index,
                )
        timeline_item = _timeline_item(
            index,
            item,
            claims[index - 1] if index else None,
            anchor_report,
            receiver_report,
        )
        if include_correlation_fields:
            timeline_item.update(
                {
                    "trace_id": item["trace_id"],
                    "arguments_hash": item["arguments_hash"],
                }
            )
        timeline.append(timeline_item)

    verified_at = int(time.time())
    freshness = _bundle_freshness_report(
        claims,
        verified_at=verified_at,
        max_bundle_age_s=max_bundle_age_s,
        freshness_clock_skew_s=freshness_clock_skew_s,
    )
    result = "verified" if full_evidence else "verified_chain_only"
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "valid": True,
        "result": result,
        "verification_mode": "offline",
        "revocation_checked": False,
        "freshness": freshness,
        "assurance_profile": FULL_EVIDENCE_PROFILE
        if full_evidence
        else CHAIN_ONLY_PROFILE,
        "redaction": {"enabled": redact, "marker": REDACTION_MARKER},
        "source": {
            "kind": offline_input.kind,
            "sha256": offline_input.source_sha256,
        },
        "trust_roots": [
            {
                "role": "receipt-issuer",
                "spki_fingerprint": public_key_fingerprint(receipt_public_key),
            },
            *(
                [
                    {
                        "role": "transparency-log",
                        "spki_fingerprint": public_key_fingerprint(log_public_key),
                    }
                ]
                if full_evidence
                else []
            ),
            *(
                [
                    {
                        "role": "receiver",
                        "spki_fingerprint": public_key_fingerprint(receiver_public_key),
                    }
                ]
                if full_evidence
                else []
            ),
        ],
        "summary": {
            "receipt_count": len(timeline),
            "permit_count": sum(item["decision"] == "PERMIT" for item in timeline),
            "deny_count": sum(item["decision"] == "DENY" for item in timeline),
            "error_count": sum(item["decision"] == "ERROR" for item in timeline),
            "unknown_count": sum(item["decision"] == "UNKNOWN" for item in timeline),
            "anchored_count": sum(
                item["evidence"]["transparency"]["valid"] for item in timeline
            ),
            "receiver_attested_count": sum(
                item["evidence"]["receiver"]["valid"] for item in timeline
            ),
            "authority_narrowing_steps": [
                item["index"]
                for item in timeline
                if item["authority"]["narrowing_proven"]
            ],
        },
        "timeline": timeline,
        "limitations": [
            "offline verification did not query a revocation registry",
            "a receipt revoked after signing may remain cryptographically valid offline",
            (
                "age-bounded freshness does not prevent repeated presentation inside the accepted window"
                if freshness["age_checked"]
                else "offline verification did not enforce receipt age or one-time replay"
            ),
            "valid signatures do not prove receiver correctness, action-set completeness, or non-collusion",
            "grant changes alone do not prove scope containment without the signed grant artifacts",
        ],
        "verified_at": verified_at,
    }
    return _validate_report(_redact_value(report) if redact else report)


def verify_offline_path(
    path: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Load and verify an offline journal or bundle."""

    return verify_offline_input(load_offline_input(path), **kwargs)


def _display(value: Any) -> str:
    rendered = _CONTROL_RE.sub(" ", str(value))
    rendered = _BIDI_CONTROL_RE.sub("", rendered)
    return " ".join(rendered.split())


def render_cli_report(report: Mapping[str, Any]) -> str:
    """Render the bounded chronological explorer as plain text."""

    summary = report["summary"]
    freshness = report["freshness"]
    lines = [
        f"Ardur offline verification: {str(report['result']).upper()}",
        (
            f"Mode: offline | revocation checked: false | assurance: "
            f"{report['assurance_profile']} | redacted: {str(report['redaction']['enabled']).lower()}"
        ),
        (
            f"Freshness age checked: {str(freshness['age_checked']).lower()} | "
            "one-time replay checked: false"
        ),
        (
            f"Receipts: {summary['receipt_count']} | PERMIT: {summary['permit_count']} | "
            f"DENY: {summary['deny_count']} | ERROR: {summary['error_count']}"
            + (
                f" | UNKNOWN: {summary['unknown_count']}"
                if summary.get("unknown_count", 0)
                else ""
            )
        ),
        f"Source SHA-256: {_display(report['source']['sha256'])}",
        "Trust roots:",
        *(
            f"  {_display(root['role'])}: {_display(root['spki_fingerprint'])}"
            for root in report["trust_roots"]
        ),
        "Timeline:",
    ]
    if freshness["age_checked"]:
        lines.insert(
            3,
            (
                f"Freshness age: {freshness['age_s']}s | maximum: "
                f"{freshness['max_age_s']}s | allowed future skew: "
                f"{freshness['allowed_future_skew_s']}s"
            ),
        )
    for item in report["timeline"]:
        authority = item["authority"]
        lines.append(
            f"  [{item['index']}] {_display(item['timestamp'])} {item['decision']} "
            f"{_display(item['tool'])} -> {_display(item['target'])}"
        )
        lines.append(
            f"      grant={_display(item['grant_id'])} reason={_display(item['reason'])}"
        )
        lines.append(
            f"      authority_narrowed={str(authority['narrowing_proven']).lower()} "
            f"why={_display('; '.join(authority['why']))}"
        )
        evidence = item["evidence"]
        lines.append(
            f"      receipt=valid chain=valid anchor={str(evidence['transparency']['valid']).lower()} "
            f"receiver={_display(evidence['receiver']['status'])}"
        )
        for outcome in item["policy_outcomes"]:
            lines.append(
                f"      policy[{_display(outcome['backend'])}]={_display(outcome['decision'])}: "
                f"{_display(outcome.get('reason') or 'no signed reason')}"
            )
        if item["cost_outcomes"]:
            costs = ", ".join(
                f"{_display(key)}={_display(value)}"
                for key, value in sorted(item["cost_outcomes"].items())
            )
            lines.append(f"      signed_cost={costs}")
        transparency = evidence["transparency"]
        receiver = evidence["receiver"]
        if transparency.get("anchor_id"):
            lines.append(
                f"      anchor_ref={_display(transparency['anchor_id'])} "
                f"log={_display(transparency.get('log_id'))} "
                f"index={_display(transparency.get('log_index'))}"
            )
        lines.append(
            f"      receiver_ref={_display(receiver.get('attestation_id') or receiver['status'])} "
            f"receiver_id={_display(receiver.get('receiver_id') or 'none')}"
        )
    lines.append("Limitations:")
    lines.extend(f"  - {_display(item)}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def render_html_report(report: Mapping[str, Any]) -> str:
    """Render a static no-JavaScript report with sink-level HTML escaping."""

    def esc(value: Any) -> str:
        return html.escape(_display(value), quote=True)

    summary = report["summary"]
    freshness = report["freshness"]
    freshness_notice = (
        f"Signed receipt age was checked: {freshness['age_s']}s against a "
        f"{freshness['max_age_s']}s maximum with "
        f"{freshness['allowed_future_skew_s']}s allowed future clock skew. "
        if freshness["age_checked"]
        else "Signed receipt age was not checked. "
    )
    rows: list[str] = []
    for item in report["timeline"]:
        authority = item["authority"]
        evidence = item["evidence"]
        policy = "; ".join(
            f"{outcome.get('backend')}: {outcome.get('decision')} ({outcome.get('reason') or 'no signed reason'})"
            for outcome in item["policy_outcomes"]
        )
        costs = ", ".join(
            f"{key}={value}" for key, value in sorted(item["cost_outcomes"].items())
        )
        transparency = evidence["transparency"]
        receiver = evidence["receiver"]
        rows.append(
            "<tr>"
            f"<td>{item['index']}</td>"
            f"<td>{esc(item['timestamp'])}</td>"
            f"<td><strong>{esc(item['decision'])}</strong><br>{esc(item['reason'])}</td>"
            f"<td>{esc(item['tool'])}<br><code>{esc(item['target'])}</code></td>"
            f"<td><code>{esc(item['grant_id'])}</code><br>{esc('; '.join(authority['why']))}</td>"
            f"<td>{esc(policy or 'no signed policy outcomes')}</td>"
            f"<td>{esc(costs or 'no signed cost outcomes')}</td>"
            f"<td>receipt: valid<br>chain: valid<br>anchor: {str(evidence['transparency']['valid']).lower()}"
            f"<br>anchor ref: <code>{esc(transparency.get('anchor_id') or 'none')}</code>"
            f"<br>log: {esc(transparency.get('log_id') or 'none')} [{esc(transparency.get('log_index'))}]"
            f"<br>receiver: {esc(receiver['status'])}"
            f"<br>receiver ref: <code>{esc(receiver.get('attestation_id') or receiver['status'])}</code>"
            f"<br>receiver id: {esc(receiver.get('receiver_id') or 'none')}</td>"
            "</tr>"
        )
    limitations = "".join(f"<li>{esc(item)}</li>" for item in report["limitations"])
    trust_roots = "".join(
        f"<li>{esc(root['role'])}: <code>{esc(root['spki_fingerprint'])}</code></li>"
        for root in report["trust_roots"]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Ardur Offline Verification Report</title>
  <style>
    :root {{ color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; color: #172022; background: #f4f6f5; }}
    header {{ padding: 28px max(24px, 5vw); color: #fff; background: #173d36; }}
    main {{ padding: 24px max(24px, 5vw) 48px; }}
    h1, h2 {{ letter-spacing: 0; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1px; background: #c9d2cf; border: 1px solid #c9d2cf; }}
    .metric {{ padding: 14px; background: #fff; }}
    table {{ width: 100%; margin-top: 20px; border-collapse: collapse; background: #fff; }}
    th, td {{ padding: 10px; border: 1px solid #d8dfdc; text-align: left; vertical-align: top; }}
    th {{ background: #e7ecea; }}
    code {{ overflow-wrap: anywhere; }}
    .notice {{ padding: 12px; border-left: 4px solid #b46a13; background: #fff7e8; }}
    @media (max-width: 800px) {{ table {{ display: block; overflow-x: auto; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Ardur Offline Verification</h1>
    <p>{esc(str(report["result"]).upper())} | {esc(report["assurance_profile"])}</p>
  </header>
  <main>
    <p class="notice">Offline mode. Revocation was not checked. {esc(freshness_notice)} One-time replay was not checked. Evidence-derived values are redacted by default and HTML-escaped at this rendering sink.</p>
    <section class="summary" aria-label="Verification summary">
      <div class="metric"><strong>{summary["receipt_count"]}</strong><br>Receipts</div>
      <div class="metric"><strong>{summary["permit_count"]}</strong><br>PERMIT</div>
      <div class="metric"><strong>{summary["deny_count"]}</strong><br>DENY</div>
      <div class="metric"><strong>{summary["error_count"]}</strong><br>ERROR</div>
      <div class="metric"><strong>{summary["anchored_count"]}</strong><br>Anchored</div>
      <div class="metric"><strong>{summary["receiver_attested_count"]}</strong><br>Receiver-attested</div>
    </section>
    <h2>Verification Material</h2>
    <p>Source SHA-256: <code>{esc(report["source"]["sha256"])}</code></p>
    <ul>{trust_roots}</ul>
    <h2>Chronological Timeline</h2>
    <table>
      <thead><tr><th>#</th><th>Time</th><th>Decision</th><th>Action</th><th>Authority</th><th>Policy</th><th>Cost</th><th>Evidence</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
    <h2>Limitations</h2>
    <ul>{limitations}</ul>
  </main>
</body>
</html>
"""


def write_html_report(path: str | Path, report: Mapping[str, Any]) -> None:
    """Atomically write a private static HTML report."""

    output = Path(path).expanduser()
    if output.is_symlink():
        raise OfflineVerificationError(
            "html_output_symlink", "HTML report output must not be a symlink"
        )
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise OfflineVerificationError(
            "html_output_parent_invalid", "HTML report parent must be a real directory"
        )
    temporary = output.with_name(f".{output.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd: int | None = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(render_html_report(report))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        output.chmod(0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            # The atomic replace already consumed the temporary path.
            pass
