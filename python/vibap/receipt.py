"""Execution Receipt issuance and verification for per-hop governance evidence.

Receipt *n* carries ``parent_receipt_hash`` — the hex SHA-256 of receipt
*n-1*'s full signed JWT string (``header.payload.signature``), not merely an
opaque identifier. ``parent_receipt_id`` remains for one release cycle as a
deprecated compatibility shim populated from ``parent_receipt_hash[:16]`` for
downstream log readers. ``verify_receipt()`` still enforces the current Phase 3
signed schema.
"""

from __future__ import annotations

import hashlib
import time
import base64
import re
from collections import OrderedDict
from collections.abc import Iterator, MutableSet
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .canonical_json import (
    RFC8785JSONEncoder,
    canonical_json_bytes,
    canonical_json_text,
)

from .key_fingerprint import KeyFingerprintError
from .key_fingerprint import public_key_fingerprint as _public_key_fingerprint

from .passport import (
    ALGORITHM,
    DEFAULT_IAT_FUTURE_SKEW_S,
    DEFAULT_IAT_PAST_SKEW_S,
    DEFAULT_ISSUER,
    assert_iat_in_window,
)

if TYPE_CHECKING:
    from .proxy import PolicyEvent


RECEIPT_JWT_TYPE = "application/ardur.er+jwt"
RECEIPT_SCHEMA_VERSION = "ardur.execution_receipt.v0.2"
RECEIPT_CANONICALIZATION = "jcs-rfc8785"
RECEIPT_KIND_ACTION = "action"
DEFAULT_RECEIPT_TTL_S = 300
DEFAULT_EVIDENCE_LEVEL = "self_signed"
DEFAULT_REPLAY_CACHE_MAX_ENTRIES = 4096

# Round 3 (2026-04-28) lifted the bounded-iat-skew implementation into
# :func:`vibap.passport.assert_iat_in_window` so AAT/MD/passport/status-list
# verifiers all share the same gate. ``_IAT_FUTURE_SKEW_S`` /
# ``_IAT_PAST_SKEW_S`` remain here as backwards-compatible aliases for
# external callers that imported them by name. New code should import
# DEFAULT_IAT_FUTURE_SKEW_S / DEFAULT_IAT_PAST_SKEW_S from vibap.passport.
_IAT_FUTURE_SKEW_S = DEFAULT_IAT_FUTURE_SKEW_S
_IAT_PAST_SKEW_S = DEFAULT_IAT_PAST_SKEW_S

_REQUIRED_CLAIMS = [
    "receipt_id",
    "grant_id",
    "parent_receipt_hash",
    "parent_receipt_id",
    "actor",
    "verifier_id",
    "step_id",
    "tool",
    "action_class",
    "target",
    "resource_family",
    "side_effect_class",
    "verdict",
    "evidence_level",
    "reason",
    "policy_decisions",
    "arguments_hash",
    "trace_id",
    "run_nonce",
    "invocation_digest",
    "budget_remaining",
    "timestamp",
    "iss",
    "iat",
    "exp",
    "jti",
]
_PYJWT_REQUIRED_CLAIMS = [
    claim
    for claim in _REQUIRED_CLAIMS
    if claim not in {"parent_receipt_hash", "parent_receipt_id"}
]
_OPTIONAL_CLAIMS = {
    "content_class",
    "content_provenance",
    "sensitivity",
    "instruction_bearing",
    "budget_delta",
    "result_hash",
    "public_denial_reason",
    "internal_denial_code",
    "evidence_proof_ref",
    "measurements",
}
_V02_REQUIRED_CLAIMS = {
    "schema_version",
    "canonicalization",
    "receipt_kind",
}
_LEGACY_ALLOWED_CLAIMS = set(_REQUIRED_CLAIMS) | _OPTIONAL_CLAIMS
_ALLOWED_CLAIMS = _LEGACY_ALLOWED_CLAIMS | _V02_REQUIRED_CLAIMS
_ACTION_CLASSES = {
    "search",
    "read",
    "write",
    "query",
    "delegate",
    "send",
    "summarize",
    "observe",
    # Claude Code hook adapter extensions — tool-execution semantics not covered
    # by the original proxy-centric schema:
    "execute",  # Bash / shell execution
    "dispatch",  # Task / subagent dispatch
    "fetch",  # WebFetch / HTTP read
    "invoke",  # LS, TodoRead, TodoWrite, other passive invocations
}
_SIDE_EFFECT_CLASSES = {
    "none",
    "internal_write",
    "external_send",
    "state_change",
    # Claude Code hook adapter extensions:
    "filesystem_write",  # Write/Edit to local filesystem
    "process_launch",  # Bash spawns a subprocess
    "network_read",  # WebFetch/WebSearch makes an outbound read request
    "subagent_launch",  # Task spawns a sub-agent
}
_VERDICTS = {"compliant", "violation", "insufficient_evidence", "unknown"}
_EVIDENCE_LEVELS = {"self_signed", "counter_signed", "transparency_logged"}
_DIGEST_ALGS = {"sha-256", "sha-384", "sha-512"}
_DIGEST_CANONICALIZATIONS = {"jcs-rfc8785", "none"}
_DIGEST_SCOPES = {"result", "normalized_input", "measurement", "custom"}
_DENIAL_REASONS = {
    "policy_denied",
    "budget_exhausted",
    "insufficient_evidence",
    "revoked",
    "chain_invalid",
    "unknown",
    "observation_gap",
}
_SENSITIVITY_LEVELS = {
    "public",
    "internal",
    "confidential",
    "restricted",
    "regulated",
    "unknown",
}
_SHA256_HEX_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TOKEN_FIELD_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _canonical_json(payload: dict[str, Any]) -> str:
    return canonical_json_text(payload)


def _stable_identifier(prefix: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}:{digest}"


class BoundedReplayCache(MutableSet[str]):
    """Small bounded replay cache for receipt verification callers.

    ``verify_receipt`` refuses plain unbounded ``set`` instances because a
    long-running verifier would otherwise grow memory without limit. This class
    provides the minimal mutable-set API plus LRU-style eviction.
    """

    def __init__(self, max_entries: int = DEFAULT_REPLAY_CACHE_MAX_ENTRIES) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = int(max_entries)
        self._items: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, value: object) -> bool:
        return value in self._items

    def __iter__(self) -> Iterator[str]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def add(self, value: str) -> None:
        self._items[value] = None
        self._items.move_to_end(value)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)

    def discard(self, value: str) -> None:
        self._items.pop(value, None)


def _b64url_sha256(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _digest_object(scope: str, payload: dict[str, Any]) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "canonicalization": "jcs-rfc8785",
        "scope": scope,
        "value": _b64url_sha256(payload),
    }


def _schema_violation(message: str) -> NoReturn:
    raise jwt.InvalidTokenError(f"receipt schema violation: {message}")


def _require_string(claims: dict[str, Any], key: str, *, non_empty: bool = True) -> str:
    value = claims.get(key)
    if not isinstance(value, str):
        _schema_violation(f"{key} must be a string")
    if non_empty and value == "":
        _schema_violation(f"{key} must be non-empty")
    return value


def _require_enum(claims: dict[str, Any], key: str, allowed: set[str]) -> str:
    value = _require_string(claims, key)
    if value not in allowed:
        _schema_violation(f"{key} has invalid value {value!r}")
    return value


def _validate_digest_object(value: Any, key: str) -> None:
    if not isinstance(value, dict):
        _schema_violation(f"{key} must be an object")
    if set(value) - {"alg", "canonicalization", "scope", "value"}:
        _schema_violation(f"{key} contains unknown fields")
    alg = value.get("alg")
    if not isinstance(alg, str) or alg not in _DIGEST_ALGS:
        _schema_violation(f"{key}.alg has invalid value")
    canonicalization = value.get("canonicalization")
    if canonicalization is not None and (
        not isinstance(canonicalization, str)
        or canonicalization not in _DIGEST_CANONICALIZATIONS
    ):
        _schema_violation(f"{key}.canonicalization has invalid value")
    scope = value.get("scope")
    if scope is not None and (
        not isinstance(scope, str) or scope not in _DIGEST_SCOPES
    ):
        _schema_violation(f"{key}.scope has invalid value")
    digest_value = value.get("value")
    if not isinstance(digest_value, str) or not _BASE64URL_RE.fullmatch(digest_value):
        _schema_violation(f"{key}.value must be base64url")


def _validate_budget_delta(value: Any) -> None:
    if not isinstance(value, dict):
        _schema_violation("budget_delta must be an object")
    if {"bucket", "delta"} <= set(value):
        allowed = {"bucket", "unit", "delta", "remaining_after", "ceiling"}
        if set(value) - allowed:
            _schema_violation("budget_delta contains unknown legacy fields")
        _require_string(value, "bucket")
        unit = value.get("unit")
        if unit not in {"invocations", "tokens", "bytes", "usd", "custom"}:
            _schema_violation("budget_delta.unit has invalid value")
        for key in ("delta", "remaining_after", "ceiling"):
            if key in value and (not isinstance(value[key], int) or value[key] < 0):
                _schema_violation(f"budget_delta.{key} must be a non-negative integer")
        return
    if {"operation", "resource", "amount", "unit"} <= set(value):
        allowed = {
            "operation",
            "resource",
            "amount",
            "unit",
            "remaining_for_parent",
            "remaining_after",
            "used_total",
            "reserved_total",
            "side_effect_class",
            "delegation_request_id",
            "idempotent",
        }
        if set(value) - allowed:
            _schema_violation("budget_delta contains unknown lineage fields")
        if value.get("operation") not in {"consume", "reserve", "reject", "release"}:
            _schema_violation("budget_delta.operation has invalid value")
        _require_string(value, "resource")
        _require_string(value, "unit")
        for key in (
            "amount",
            "remaining_for_parent",
            "remaining_after",
            "used_total",
            "reserved_total",
        ):
            if key in value and (not isinstance(value[key], int) or value[key] < 0):
                _schema_violation(f"budget_delta.{key} must be a non-negative integer")
        if (
            "side_effect_class" in value
            and value["side_effect_class"] not in _SIDE_EFFECT_CLASSES
        ):
            _schema_violation("budget_delta.side_effect_class has invalid value")
        if "delegation_request_id" in value:
            _require_string(value, "delegation_request_id")
        if "idempotent" in value and not isinstance(value["idempotent"], bool):
            _schema_violation("budget_delta.idempotent must be boolean")
        return
    spend_required = {
        "operation",
        "resource",
        "requested",
        "reserved",
        "actual",
        "refunded",
        "remaining",
        "currency",
        "quote_digest",
        "reservation_hash",
        "reason_code",
    }
    if spend_required <= set(value):
        allowed = spend_required | {"idempotent", "reconciled"}
        if set(value) - allowed:
            _schema_violation("budget_delta contains unknown spend fields")
        if value.get("operation") not in {
            "reserve",
            "reject",
            "release",
            "settle",
            "quarantine",
        }:
            _schema_violation("budget_delta.operation has invalid spend value")
        if value.get("resource") != "spend":
            _schema_violation("budget_delta.resource must be 'spend'")
        for field_name in ("requested", "reserved", "actual", "refunded"):
            _validate_spend_amounts(value.get(field_name), f"budget_delta.{field_name}")
        remaining = value.get("remaining")
        if not isinstance(remaining, dict) or set(remaining) != {
            "session",
            "agent",
            "lineage",
        }:
            _schema_violation(
                "budget_delta.remaining must contain session, agent, and lineage"
            )
        for scope in ("session", "agent", "lineage"):
            _validate_spend_amounts(
                remaining[scope],
                f"budget_delta.remaining.{scope}",
            )
        currency = value.get("currency")
        if not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None:
            _schema_violation("budget_delta.currency must be an uppercase code")
        for key in ("quote_digest", "reservation_hash"):
            digest = value.get(key)
            if not isinstance(digest, str) or not _SHA256_HEX_RE.fullmatch(digest):
                _schema_violation(f"budget_delta.{key} must be a SHA-256 hex digest")
        reason_code = value.get("reason_code")
        if (
            not isinstance(reason_code, str)
            or not reason_code
            or len(reason_code) > 128
            or _TOKEN_FIELD_RE.fullmatch(reason_code) is None
        ):
            _schema_violation("budget_delta.reason_code has invalid value")
        for key in ("idempotent", "reconciled"):
            if key in value and not isinstance(value[key], bool):
                _schema_violation(f"budget_delta.{key} must be boolean")
        return
    _schema_violation("budget_delta must match a supported shape")


def _validate_spend_amounts(value: Any, field_name: str) -> None:
    if not isinstance(value, dict) or set(value) != {"tokens", "currency_micros"}:
        _schema_violation(f"{field_name} must contain tokens and currency_micros")
    for dimension in ("tokens", "currency_micros"):
        amount = value[dimension]
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or amount < 0
            or amount > 9_007_199_254_740_991
        ):
            _schema_violation(f"{field_name}.{dimension} must be a safe integer")


def _validate_receipt_claim_schema(claims: dict[str, Any]) -> None:
    schema_version = claims.get("schema_version")
    if schema_version is None:
        allowed_claims = _LEGACY_ALLOWED_CLAIMS
    elif schema_version == RECEIPT_SCHEMA_VERSION:
        allowed_claims = _ALLOWED_CLAIMS
        missing_v02 = sorted(_V02_REQUIRED_CLAIMS - set(claims))
        if missing_v02:
            _schema_violation(
                f"{missing_v02[0]} is required for {RECEIPT_SCHEMA_VERSION}"
            )
        if claims.get("canonicalization") != RECEIPT_CANONICALIZATION:
            _schema_violation(f"canonicalization must be {RECEIPT_CANONICALIZATION!r}")
        if claims.get("receipt_kind") != RECEIPT_KIND_ACTION:
            _schema_violation(f"receipt_kind must be {RECEIPT_KIND_ACTION!r}")
    else:
        _schema_violation(f"unsupported schema_version {schema_version!r}")
    extra = set(claims) - allowed_claims
    if extra:
        _schema_violation(f"unknown claims: {', '.join(sorted(extra))}")
    for key in (
        "receipt_id",
        "grant_id",
        "actor",
        "verifier_id",
        "trace_id",
        "run_nonce",
        "step_id",
        "tool",
        "target",
        "resource_family",
        "reason",
        "iss",
        "jti",
    ):
        _require_string(claims, key)
    if (
        not _BASE64URL_RE.fullmatch(claims["run_nonce"])
        or len(claims["run_nonce"]) < 16
    ):
        _schema_violation("run_nonce must be base64url and at least 16 characters")
    if claims.get("parent_receipt_id") is not None:
        _require_string(claims, "parent_receipt_id")
    parent_hash = claims.get("parent_receipt_hash")
    if parent_hash is not None and (
        not isinstance(parent_hash, str) or not _SHA256_HEX_RE.fullmatch(parent_hash)
    ):
        _schema_violation("parent_receipt_hash must be null or a SHA-256 hex digest")
    _require_enum(claims, "action_class", _ACTION_CLASSES)
    _require_enum(claims, "side_effect_class", _SIDE_EFFECT_CLASSES)
    verdict = _require_enum(claims, "verdict", _VERDICTS)
    _require_enum(claims, "evidence_level", _EVIDENCE_LEVELS)
    _validate_digest_object(claims.get("invocation_digest"), "invocation_digest")
    if not isinstance(claims.get("iat"), int) or claims["iat"] < 0:
        _schema_violation("iat must be a non-negative integer")
    if not isinstance(claims.get("exp"), int) or claims["exp"] < 0:
        _schema_violation("exp must be a non-negative integer")
    if not _SHA256_HEX_RE.fullmatch(_require_string(claims, "arguments_hash")):
        _schema_violation("arguments_hash must be a SHA-256 hex digest")
    policy_decisions = claims.get("policy_decisions")
    if not isinstance(policy_decisions, list):
        _schema_violation("policy_decisions must be an array")
    for item in policy_decisions:
        if not isinstance(item, dict):
            _schema_violation("policy_decisions items must be objects")
        if set(item) - {"backend", "decision", "reason", "rule_id", "eval_ms"}:
            _schema_violation("policy_decisions item contains unknown fields")
        _require_string(item, "backend")
        _require_string(item, "decision")
        if (
            "reason" in item
            and item["reason"] is not None
            and not isinstance(item["reason"], str)
        ):
            _schema_violation("policy_decisions.reason must be string or null")
        if "rule_id" in item:
            rule_id = _require_string(item, "rule_id")
            if len(rule_id) > 256 or not rule_id.isprintable():
                _schema_violation(
                    "policy_decisions.rule_id must be a printable string of at most 256 characters"
                )
        if "eval_ms" in item and (
            not isinstance(item["eval_ms"], (int, float)) or item["eval_ms"] < 0
        ):
            _schema_violation("policy_decisions.eval_ms must be non-negative")
    budget_remaining = claims.get("budget_remaining")
    if not isinstance(budget_remaining, dict):
        _schema_violation("budget_remaining must be an object")
    for key, value in budget_remaining.items():
        if not isinstance(key, str) or not _TOKEN_FIELD_RE.fullmatch(key):
            _schema_violation("budget_remaining keys must be token strings")
        if not isinstance(value, int) or value < 0:
            _schema_violation("budget_remaining values must be non-negative integers")
    if verdict == "compliant":
        if "public_denial_reason" in claims or "internal_denial_code" in claims:
            _schema_violation("compliant receipts must not carry denial reasons")
    else:
        if claims.get("public_denial_reason") not in _DENIAL_REASONS:
            _schema_violation("public_denial_reason has invalid value")
        internal_code = claims.get("internal_denial_code")
        if not isinstance(internal_code, str) or not _TOKEN_FIELD_RE.fullmatch(
            internal_code
        ):
            _schema_violation("internal_denial_code must be an audit token")
    if "sensitivity" in claims and claims["sensitivity"] not in _SENSITIVITY_LEVELS:
        _schema_violation("sensitivity has invalid value")
    if "instruction_bearing" in claims and not isinstance(
        claims["instruction_bearing"], bool
    ):
        _schema_violation("instruction_bearing must be boolean")
    if "budget_delta" in claims:
        _validate_budget_delta(claims["budget_delta"])
    if "result_hash" in claims:
        _validate_digest_object(claims["result_hash"], "result_hash")


def _numeric_date(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _decision_name(decision: Any) -> str:
    value = getattr(decision, "value", decision)
    return str(value).upper()


def _verdict_from_decision(decision: Any) -> str:
    name = _decision_name(decision)
    if name == "PERMIT":
        return "compliant"
    if name == "INSUFFICIENT_EVIDENCE":
        return "insufficient_evidence"
    if name == "UNKNOWN":
        return "unknown"
    if name in {"DENY", "VIOLATION", "INSPECT"}:
        return "violation"
    return "violation"


def _denial_code_from_event(event: PolicyEvent) -> str | None:
    raw_denial_reason = getattr(event, "denial_reason", None)
    if raw_denial_reason is None:
        return None
    return str(getattr(raw_denial_reason, "value", raw_denial_reason))


def _public_denial_reason(verdict: str, internal_denial_code: str | None) -> str | None:
    if verdict == "compliant":
        return None
    if verdict == "insufficient_evidence":
        return "insufficient_evidence"
    if verdict == "unknown":
        return "unknown"
    if internal_denial_code in {"budget_exhausted", "risk_budget_exhausted"}:
        return "budget_exhausted"
    if internal_denial_code in {"revoked", "mission_revoked"}:
        return "revoked"
    if internal_denial_code in {"chain_invalid"}:
        return "chain_invalid"
    return "policy_denied"


def _invocation_digest_payload(event: PolicyEvent) -> dict[str, Any]:
    return {
        "grant_id": str(getattr(event, "passport_jti", "")),
        "actor": str(getattr(event, "actor", "")),
        "verifier_id": str(getattr(event, "verifier_id", "") or DEFAULT_ISSUER),
        "step_id": str(getattr(event, "step_id", "") or ""),
        "tool": str(getattr(event, "tool_name", "")),
        "action_class": str(getattr(event, "action_class", "") or "observe"),
        "target": str(getattr(event, "target", "") or getattr(event, "tool_name", "")),
        "resource_family": str(getattr(event, "resource_family", "") or "general"),
        "side_effect_class": str(getattr(event, "side_effect_class", "") or "none"),
        "arguments": dict(getattr(event, "arguments", {}) or {}),
    }


def _trace_id_from_event(event: PolicyEvent) -> str:
    raw_trace_id = getattr(event, "trace_id", None)
    if raw_trace_id:
        return str(raw_trace_id)
    return str(getattr(event, "passport_jti", "") or "unknown-trace")


def _run_nonce_from_event(event: PolicyEvent, trace_id: str) -> str:
    raw_run_nonce = getattr(event, "run_nonce", None)
    if raw_run_nonce:
        return str(raw_run_nonce)
    return _b64url_sha256(
        {
            "trace_id": trace_id,
            "grant_id": str(getattr(event, "passport_jti", "")),
            "timestamp": str(getattr(event, "timestamp", "")),
            "step_id": str(getattr(event, "step_id", "")),
        }
    )[:32]


@dataclass(slots=True)
class ExecutionReceipt:
    """Signed per-hop receipt payload."""

    schema_version: str
    canonicalization: str
    receipt_kind: str
    receipt_id: str
    grant_id: str
    parent_receipt_hash: str | None
    parent_receipt_id: str | None
    actor: str
    verifier_id: str
    step_id: str
    tool: str
    action_class: str
    target: str
    resource_family: str
    side_effect_class: str
    verdict: str
    evidence_level: str
    reason: str
    policy_decisions: list[dict[str, Any]]
    arguments_hash: str
    trace_id: str
    run_nonce: str
    invocation_digest: dict[str, str]
    budget_remaining: dict[str, int]
    timestamp: str
    iss: str
    iat: int
    exp: int
    jti: str
    public_denial_reason: str | None = None
    internal_denial_code: str | None = None
    evidence_proof_ref: str | None = None
    content_class: str | None = None
    content_provenance: dict[str, Any] | None = None
    sensitivity: str | None = None
    instruction_bearing: bool | None = None
    budget_delta: dict[str, Any] | None = None
    result_hash: dict[str, Any] | None = None
    measurements: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "canonicalization": self.canonicalization,
            "receipt_kind": self.receipt_kind,
            "receipt_id": self.receipt_id,
            "grant_id": self.grant_id,
            "parent_receipt_hash": self.parent_receipt_hash,
            "parent_receipt_id": self.parent_receipt_id,
            "actor": self.actor,
            "verifier_id": self.verifier_id,
            "step_id": self.step_id,
            "tool": self.tool,
            "action_class": self.action_class,
            "target": self.target,
            "resource_family": self.resource_family,
            "side_effect_class": self.side_effect_class,
            "verdict": self.verdict,
            "evidence_level": self.evidence_level,
            "reason": self.reason,
            "policy_decisions": list(self.policy_decisions),
            "arguments_hash": self.arguments_hash,
            "trace_id": self.trace_id,
            "run_nonce": self.run_nonce,
            "invocation_digest": dict(self.invocation_digest),
            "budget_remaining": dict(self.budget_remaining),
            "timestamp": self.timestamp,
            "iss": self.iss,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }
        optional_fields = {
            "public_denial_reason": self.public_denial_reason,
            "internal_denial_code": self.internal_denial_code,
            "evidence_proof_ref": self.evidence_proof_ref,
            "content_class": self.content_class,
            "content_provenance": self.content_provenance,
            "sensitivity": self.sensitivity,
            "instruction_bearing": self.instruction_bearing,
            "budget_delta": self.budget_delta,
            "result_hash": self.result_hash,
            "measurements": self.measurements,
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = value
        return payload


def build_receipt(
    decision: Any,
    event: PolicyEvent,
    parent_receipt_hash: str | None = None,
    *,
    policy_decisions: list[dict[str, Any]] | None = None,
    reason: str | None = None,
    budget_remaining: dict[str, int] | None = None,
) -> ExecutionReceipt:
    verdict = _verdict_from_decision(decision)
    internal_denial_code = None
    public_denial_reason = None
    if verdict != "compliant":
        internal_denial_code = _denial_code_from_event(event) or "unknown"
        public_denial_reason = _public_denial_reason(verdict, internal_denial_code)
    raw_reason = reason if reason is not None else str(getattr(event, "reason", ""))
    reason_text = str(raw_reason).strip() or "unspecified"
    payload_policy_decisions = (
        _signed_policy_decisions(event, decision, reason_text)
        if policy_decisions is None
        else [dict(item) for item in policy_decisions]
    )
    # Canonicalize via the same helper used for receipt_id/step_id so that
    # non-ASCII argument values hash consistently across the receipt schema.
    # Default json.dumps escapes non-ASCII (ensure_ascii=True) while
    # _canonical_json does not — flagged in Phase 3 audit HIGH #2.
    arguments_hash = hashlib.sha256(
        _canonical_json(dict(getattr(event, "arguments", {}) or {})).encode("utf-8")
    ).hexdigest()
    remaining_budget = dict(budget_remaining or {})
    timestamp = str(getattr(event, "timestamp", ""))
    trace_id = _trace_id_from_event(event)
    run_nonce = _run_nonce_from_event(event, trace_id)
    invocation_digest = _digest_object(
        "normalized_input", _invocation_digest_payload(event)
    )
    observed_at = _numeric_date(timestamp)
    now = int(time.time())
    iat = max(now, observed_at or now)
    exp = iat + DEFAULT_RECEIPT_TTL_S
    verifier_id = str(getattr(event, "verifier_id", "") or DEFAULT_ISSUER)
    step_id = str(getattr(event, "step_id", "")).strip()
    if not step_id:
        step_id = _stable_identifier(
            "step",
            {
                "grant_id": str(getattr(event, "passport_jti", "")),
                "timestamp": timestamp,
                "tool": str(getattr(event, "tool_name", "")),
                "arguments": dict(getattr(event, "arguments", {}) or {}),
            },
        )

    payload_without_ids = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "canonicalization": RECEIPT_CANONICALIZATION,
        "receipt_kind": RECEIPT_KIND_ACTION,
        "grant_id": str(getattr(event, "passport_jti", "")),
        "parent_receipt_hash": parent_receipt_hash,
        "parent_receipt_id": parent_receipt_hash[:16]
        if parent_receipt_hash is not None
        else None,
        "actor": str(getattr(event, "actor", "")),
        "verifier_id": verifier_id,
        "step_id": step_id,
        "tool": str(getattr(event, "tool_name", "")),
        "action_class": str(getattr(event, "action_class", "") or "observe"),
        "target": str(getattr(event, "target", "") or getattr(event, "tool_name", "")),
        "resource_family": str(getattr(event, "resource_family", "") or "general"),
        "side_effect_class": str(getattr(event, "side_effect_class", "") or "none"),
        "verdict": verdict,
        "evidence_level": str(
            getattr(event, "evidence_level", "") or DEFAULT_EVIDENCE_LEVEL
        ),
        "reason": reason_text,
        "policy_decisions": payload_policy_decisions,
        "arguments_hash": arguments_hash,
        "trace_id": trace_id,
        "run_nonce": run_nonce,
        "invocation_digest": invocation_digest,
        "budget_remaining": remaining_budget,
        "timestamp": timestamp,
        "iss": verifier_id,
        "public_denial_reason": public_denial_reason,
        "internal_denial_code": internal_denial_code,
        "evidence_proof_ref": getattr(event, "evidence_proof_ref", None),
    }
    receipt_id = _stable_identifier("receipt", payload_without_ids)

    return ExecutionReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        canonicalization=RECEIPT_CANONICALIZATION,
        receipt_kind=RECEIPT_KIND_ACTION,
        receipt_id=receipt_id,
        grant_id=payload_without_ids["grant_id"],
        parent_receipt_hash=parent_receipt_hash,
        parent_receipt_id=payload_without_ids["parent_receipt_id"],
        actor=payload_without_ids["actor"],
        verifier_id=verifier_id,
        step_id=step_id,
        tool=payload_without_ids["tool"],
        action_class=payload_without_ids["action_class"],
        target=payload_without_ids["target"],
        resource_family=payload_without_ids["resource_family"],
        side_effect_class=payload_without_ids["side_effect_class"],
        verdict=verdict,
        evidence_level=payload_without_ids["evidence_level"],
        reason=reason_text,
        policy_decisions=payload_policy_decisions,
        arguments_hash=arguments_hash,
        trace_id=trace_id,
        run_nonce=run_nonce,
        invocation_digest=invocation_digest,
        budget_remaining=remaining_budget,
        timestamp=timestamp,
        iss=verifier_id,
        iat=iat,
        exp=exp,
        jti=receipt_id,
        public_denial_reason=public_denial_reason,
        internal_denial_code=internal_denial_code,
        evidence_proof_ref=getattr(event, "evidence_proof_ref", None),
        content_class=getattr(event, "content_class", None),
        content_provenance=getattr(event, "content_provenance", None),
        sensitivity=getattr(event, "sensitivity", None),
        instruction_bearing=getattr(event, "instruction_bearing", None),
        budget_delta=getattr(event, "budget_delta", None),
        result_hash=getattr(event, "result_hash", None),
        measurements=getattr(event, "measurements", None),
    )


class ReceiptKeyIdMismatchError(jwt.InvalidTokenError):
    """The receipt's protected-header ``kid`` names a key other than the
    verifying key.

    Subclasses :class:`jwt.InvalidTokenError` on purpose. Every existing
    fail-closed caller of :func:`verify_receipt` — including
    :func:`verify_chain` — funnels errors through ``except jwt.PyJWTError``,
    and a verifier that trials several candidate keys relies on that same
    catch to move on to the next key. Raising outside the PyJWT hierarchy
    would turn those handled denials into unhandled crashes, so the distinct
    machine-readable ``code`` rides along on a PyJWT-compatible exception
    instead.
    """

    code = "receipt_kid_mismatch"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = ReceiptKeyIdMismatchError.code


def receipt_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    """Return the ``kid`` a receipt signed by ``public_key``'s pair must carry.

    This is the shared ``sha256:<hex>`` SPKI fingerprint from
    :mod:`vibap.key_fingerprint`, untruncated. Using the full digest keeps the
    receipt ``kid`` byte-identical to the ``spki_fingerprint`` the offline
    verifier already prints for its trust roots, so an evaluator can match the
    two by eye without knowing a second convention. The identifier is
    content-addressed: a verifier recomputes it from the public key it already
    holds rather than resolving it through a registry, which is what lets the
    check run fully offline.
    """

    try:
        return _public_key_fingerprint(public_key)
    except KeyFingerprintError as exc:
        raise ReceiptKeyIdMismatchError(
            "receipt signing key cannot be named: it is not SPKI-encodable"
        ) from exc


def sign_receipt(
    receipt: ExecutionReceipt, private_key: ec.EllipticCurvePrivateKey
) -> str:
    # ``kid`` goes in the protected header only, never in the payload: the
    # v0.2 claim schema sets ``additionalProperties: false`` and
    # ``_validate_receipt_claim_schema`` rejects unknown claims, so a payload
    # field would be a breaking format migration. The header is already
    # covered by the JWS signature, so it is protected either way.
    #
    # Scope note: passports (``vibap.passport``) and the kernel attestation
    # carry no ``kid`` yet even though the same argument applies to them.
    # Keeping this change to receipts keeps the diff reviewable; extending it
    # is deliberate follow-up work, not an oversight.
    return jwt.encode(
        receipt.to_dict(),
        private_key,
        algorithm=ALGORITHM,
        headers={
            "typ": RECEIPT_JWT_TYPE,
            "kid": receipt_key_id(private_key.public_key()),
        },
        json_encoder=RFC8785JSONEncoder,
    )


def _assert_key_id_binds_verifying_key(
    jwt_str: str, public_key: ec.EllipticCurvePublicKey
) -> None:
    """Fail closed when a present ``kid`` names a different key.

    Called only after the signature has already verified, so reaching a
    mismatch means the header asserts a binding the signature contradicts.
    In practice an attacker who rewrites ``kid`` invalidates the signature —
    the header is inside the JWS signing input — so this is defence in depth
    against a producer bug or a key mix-up rather than a forgery gate.

    An **absent** ``kid`` is not an error. Receipts issued before Ardur
    emitted one must keep verifying exactly as they did, and
    ``docs/specs/execution-receipt-v0.1.md`` §9.1 makes the header a SHOULD,
    not a MUST. Absence is silence, not a contradicted claim.
    """

    try:
        header = jwt.get_unverified_header(jwt_str)
    except jwt.PyJWTError as exc:  # pragma: no cover - decode already parsed it
        raise ReceiptKeyIdMismatchError(
            f"receipt JWS header could not be read: {exc}"
        ) from exc
    if "kid" not in header:
        return
    kid = header["kid"]
    expected = receipt_key_id(public_key)
    if not isinstance(kid, str) or kid != expected:
        # Both values are public-key fingerprints, so echoing them leaks
        # nothing an evidence holder does not already have, and it is the
        # only way an operator can tell a key mix-up from a real tamper.
        raise ReceiptKeyIdMismatchError(
            "receipt kid names a different signing key than the key used to "
            f"verify it (header kid={kid!r}, verifying key={expected!r})"
        )


def _validate_canonical_payload(jwt_str: str, claims: dict[str, Any]) -> None:
    if claims.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        return
    try:
        encoded_payload = jwt_str.split(".")[1]
        padding = "=" * (-len(encoded_payload) % 4)
        payload_bytes = base64.urlsafe_b64decode(encoded_payload + padding)
        expected = canonical_json_bytes(claims)
    except (IndexError, ValueError, TypeError) as exc:
        _schema_violation(f"canonical payload could not be evaluated: {exc}")
    if payload_bytes != expected:
        _schema_violation("JWS payload is not RFC 8785 canonical JSON")


def verify_receipt(
    jwt_str: str,
    public_key: ec.EllipticCurvePublicKey,
    *,
    expected_trace_id: str | None = None,
    expected_run_nonce: str | None = None,
    expected_invocation_digest: dict[str, Any] | None = None,
    replay_cache: MutableSet[str] | None = None,
    trusted_issuer_bindings: dict[str, set[str] | list[str] | tuple[str, ...]]
    | None = None,
    verify_expiry: bool = True,
    iat_future_skew_s: int | None = _IAT_FUTURE_SKEW_S,
    iat_past_skew_s: int | None = _IAT_PAST_SKEW_S,
    now_fn: "callable[..., float] | None" = None,
) -> dict[str, Any]:
    """Verify a single Execution Receipt JWT.

    ``iat_future_skew_s`` / ``iat_past_skew_s`` close FIX-6 from the
    2026-04-28 hostile audit: previously ``verify_receipt`` only checked
    ``exp`` (via PyJWT's ``verify_exp``) and never bounded ``iat``, which
    let a forged receipt claim ``iat=year_3000`` pass validation as long
    as ``exp`` was also future-dated. Receipts whose ``iat`` lies outside
    ``now - iat_past_skew_s ... now + iat_future_skew_s`` now fail closed.
    Set both skews to ``None`` (or 0) only in archival-replay contexts
    where legitimately old receipts must be re-verified.

    The protected-header ``kid``, when present, must equal
    :func:`receipt_key_id` of ``public_key`` or verification fails with
    :class:`ReceiptKeyIdMismatchError`. ``kid`` is never used to *select* a
    key — ``public_key`` is still the caller's trust decision — and an absent
    ``kid`` is not an error, so receipts predating the header verify
    unchanged.
    """
    claims = jwt.decode(
        jwt_str,
        public_key,
        algorithms=[ALGORITHM],
        options={
            "require": _PYJWT_REQUIRED_CLAIMS,
            "verify_aud": False,
            "verify_exp": verify_expiry,
            # Disable PyJWT's default iat validation — its "not yet valid"
            # rejection (with a fixed leeway) collides with our explicit
            # bounded-skew gate below, masking error messages and making
            # behavior less testable. We control iat semantics ourselves.
            "verify_iat": False,
        },
    )
    # Header/key binding gate. Runs after jwt.decode so the signature has
    # already been checked and ``public_key`` is known to be a usable key;
    # a present-but-wrong kid then fails closed rather than warning.
    _assert_key_id_binds_verifying_key(jwt_str, public_key)
    # Bounded-iat skew gate (FIX-6 + round 3 generalization, 2026-04-28).
    # Delegates to the shared helper so receipts and every other JWT
    # verifier (AAT, MD, passport, status list) use the same window.
    assert_iat_in_window(
        claims.get("iat"),
        future_skew_s=iat_future_skew_s,
        past_skew_s=iat_past_skew_s,
        now=(now_fn() if now_fn is not None else None),
        field_name="receipt iat",
    )
    missing = [claim for claim in _REQUIRED_CLAIMS if claim not in claims]
    if missing:
        raise jwt.MissingRequiredClaimError(missing[0])
    _validate_canonical_payload(jwt_str, claims)
    _validate_receipt_claim_schema(claims)
    issuer = claims.get("iss")
    verifier_id = claims.get("verifier_id")
    if issuer != verifier_id:
        allowed_verifiers = (
            trusted_issuer_bindings.get(issuer)
            if trusted_issuer_bindings is not None and isinstance(issuer, str)
            else None
        )
        if not allowed_verifiers or verifier_id not in allowed_verifiers:
            raise jwt.InvalidTokenError("receipt issuer is not trusted for verifier_id")
    verdict = claims.get("verdict")
    if verdict == "compliant":
        if "public_denial_reason" in claims or "internal_denial_code" in claims:
            raise jwt.InvalidTokenError(
                "compliant receipts must not carry denial reasons"
            )
    else:
        if "public_denial_reason" not in claims:
            raise jwt.MissingRequiredClaimError("public_denial_reason")
        if "internal_denial_code" not in claims:
            raise jwt.MissingRequiredClaimError("internal_denial_code")
    invocation_digest = claims.get("invocation_digest")
    if not isinstance(invocation_digest, dict):
        raise jwt.InvalidTokenError("invocation_digest must be an object")
    for field in ("alg", "canonicalization", "scope", "value"):
        if not invocation_digest.get(field):
            raise jwt.InvalidTokenError(f"invocation_digest.{field} is required")
    if expected_trace_id is not None and claims.get("trace_id") != expected_trace_id:
        raise jwt.InvalidTokenError("receipt trace_id does not match replay context")
    if expected_run_nonce is not None and claims.get("run_nonce") != expected_run_nonce:
        raise jwt.InvalidTokenError("receipt run_nonce does not match replay context")
    if (
        expected_invocation_digest is not None
        and invocation_digest != expected_invocation_digest
    ):
        raise jwt.InvalidTokenError(
            "receipt invocation_digest does not match replay context"
        )
    if replay_cache is not None:
        max_entries = getattr(replay_cache, "max_entries", None)
        if not isinstance(max_entries, int) or max_entries <= 0:
            raise TypeError(
                "replay_cache must be bounded; use BoundedReplayCache or an "
                "equivalent MutableSet with positive max_entries"
            )
        replay_key = f"{claims['trace_id']}:{claims['run_nonce']}:{claims['jti']}"
        if replay_key in replay_cache:
            raise jwt.InvalidTokenError("receipt replay detected")
        replay_cache.add(replay_key)
    return claims


class ReceiptChainError(ValueError):
    """Raised when a receipt sequence fails parent hash validation."""


def verify_chain(
    receipts: list[str | dict[str, Any]],
    public_key: ec.EllipticCurvePublicKey,
    *,
    verify_expiry: bool = True,
    iat_future_skew_s: int | None = _IAT_FUTURE_SKEW_S,
    iat_past_skew_s: int | None = _IAT_PAST_SKEW_S,
) -> list[dict[str, Any]]:
    """Verify receipt signatures and the receipt-chain hash."""
    tokens = [_receipt_token(item) for item in receipts]
    verified_claims: list[dict[str, Any]] = []
    for index, token in enumerate(tokens):
        try:
            verified_claims.append(
                verify_receipt(
                    token,
                    public_key,
                    verify_expiry=verify_expiry,
                    iat_future_skew_s=iat_future_skew_s,
                    iat_past_skew_s=iat_past_skew_s,
                )
            )
        except jwt.PyJWTError as exc:
            raise ReceiptChainError(
                f"receipt signature/schema invalid at index {index}: {exc}"
            ) from exc
    for index, claims in enumerate(verified_claims):
        if index == 0:
            if claims.get("parent_receipt_hash") is not None:
                raise ReceiptChainError(
                    "receipt chain does not start at a root receipt "
                    f"(index 0 has parent_receipt_hash={claims.get('parent_receipt_hash')})"
                )
            # Root receipts must also carry a null-shaped parent_receipt_id —
            # a non-null id without a matching hash is a chain-anomaly.
            pid = claims.get("parent_receipt_id")
            if pid is not None:
                raise ReceiptChainError(
                    f"root receipt has parent_receipt_id={pid!r} without a "
                    "parent_receipt_hash; chain head must have neither"
                )
            continue
        expected_hash = hashlib.sha256(tokens[index - 1].encode("ascii")).hexdigest()
        if claims.get("parent_receipt_hash") != expected_hash:
            raise ReceiptChainError(
                f"parent_receipt_hash mismatch at index {index}: "
                f"expected {expected_hash}, got {claims.get('parent_receipt_hash')}"
            )
        # FIX-6 (2026-04-28): receipts emit ``parent_receipt_id`` as a
        # 16-hex-char prefix of ``parent_receipt_hash``. If a receipt
        # carries a non-null parent_receipt_id that disagrees with this
        # derivation, the producer mis-linked or tampered with the chain.
        # Ignore None to preserve back-compat with pre-shim consumers.
        pid = claims.get("parent_receipt_id")
        if pid is not None:
            expected_pid = expected_hash[:16]
            if pid != expected_pid:
                raise ReceiptChainError(
                    f"parent_receipt_id mismatch at index {index}: "
                    f"expected {expected_pid!r}, got {pid!r} "
                    "(parent_receipt_id must equal parent_receipt_hash[:16])"
                )
    return verified_claims


def _signed_policy_decisions(
    event: PolicyEvent,
    decision: Any,
    reason: str,
) -> list[dict[str, Any]]:
    raw_policy_decisions = list(getattr(event, "policy_decisions", []) or [])
    if not raw_policy_decisions:
        return [
            {
                "backend": "native",
                "decision": "Allow" if _decision_name(decision) == "PERMIT" else "Deny",
                "reason": reason or None,
            }
        ]
    compact: list[dict[str, Any]] = []
    for item in raw_policy_decisions:
        backend = str(item.get("backend", "unknown"))
        if backend == "native_claims":
            backend = "native"
        reasons = tuple(str(entry) for entry in item.get("reasons", []) or [])
        compact.append(
            {
                "backend": backend,
                "decision": str(item.get("decision", "Abstain")),
                "reason": "; ".join(reasons) if reasons else None,
            }
        )
    return compact


def _receipt_token(receipt: str | dict[str, Any]) -> str:
    if isinstance(receipt, str):
        return receipt
    if isinstance(receipt, dict) and isinstance(receipt.get("jwt"), str):
        return str(receipt["jwt"])
    raise TypeError(
        "receipt chain entries must be JWT strings or dicts with a 'jwt' field"
    )
