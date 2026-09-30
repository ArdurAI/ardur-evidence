"""Mission passport issuance and verification for VIBAP."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import posixpath
import stat
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Mapping, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .spend_budget import normalize_spend_budget

ALGORITHM = "ES256"
DEFAULT_ISSUER = "vibap-governance-proxy"
DEFAULT_AUDIENCE = "vibap-proxy"
DELEGATION_CHAIN_CLAIM = "delegation_chain"
MAX_DELEGATION_DEPTH = 16
UNRESTRICTED_RESOURCE_SCOPE_PATTERN = "**"
_DELEGATED_MIC_CLAIMS = (
    "conformance_profile",
    "receipt_policy",
    "tool_manifest_digest",
)
_SUPPORTED_CONFORMANCE_PROFILES = frozenset(
    {"Delegation-Core", "MIC-State", "MIC-Evidence"}
)
_SUPPORTED_RECEIPT_LEVELS = frozenset(
    {"minimal", "counter_signed", "transparency_logged"}
)


def resource_scope_is_explicitly_unrestricted(scope: list[str]) -> bool:
    """Return whether ``scope`` is the sole explicit unrestricted sentinel."""

    return scope == [UNRESTRICTED_RESOURCE_SCOPE_PATTERN]


# Bounded-iat skew window applied to every JWT we verify (passport, AAT,
# Mission Declaration, status list, and receipt).
#
# Round-2 audit (2026-04-28) flagged that FIX-6 closed the iat-future
# bypass only in receipt.verify_receipt — leaving AAT, MD, and passport
# verifiers wide open to "iat=year_3000, exp=year_3001" forgeries. PyJWT's
# default iat verification is also defensive but uses zero leeway and
# raises "not yet valid" (ImmatureSignatureError), which collides with
# legitimate clock drift across nodes. This helper provides a single
# explicit bound; each verifier disables PyJWT's verify_iat and calls
# this instead so the security choice is visible at every JWT decode.
DEFAULT_IAT_FUTURE_SKEW_S = 300  # 5 min — clock-drift tolerance
DEFAULT_IAT_PAST_SKEW_S = 30 * 86400  # 30 days — long-lived caches OK,
# archival replay handled by jti
# replay caches at the verifier
# boundary, not iat alone.


def assert_iat_in_window(
    iat: Any,
    *,
    future_skew_s: int | None = DEFAULT_IAT_FUTURE_SKEW_S,
    past_skew_s: int | None = DEFAULT_IAT_PAST_SKEW_S,
    now: float | None = None,
    field_name: str = "iat",
) -> None:
    """Validate that ``iat`` lies within a bounded window around ``now``.

    Raises :class:`jwt.InvalidTokenError` (so callers can catch the same
    exception family they catch for signature/claim errors). Set either
    skew to ``None`` (or ``0``) to disable that side of the bound — only
    do this in archival-replay contexts where legitimately old tokens
    must be re-verified.

    The check is fail-closed: a non-integer ``iat``, or one outside the
    window, raises immediately. This is how round-3 (2026-04-28) closes
    the JWT iat-future-skew bypass that FIX-6 only addressed in receipts.
    """
    try:
        iat_int = int(iat)
    except (TypeError, ValueError) as exc:
        raise jwt.InvalidTokenError(
            f"{field_name} must be an integer epoch second"
        ) from exc
    if isinstance(iat, bool):  # bool is an int subclass — reject explicitly.
        raise jwt.InvalidTokenError(
            f"{field_name} must be an integer epoch second, not bool"
        )
    now_ts = float(time.time() if now is None else now)
    if future_skew_s and iat_int > now_ts + future_skew_s:
        raise jwt.InvalidTokenError(
            f"{field_name} lies more than {future_skew_s}s in the future "
            f"(iat={iat_int}, now={int(now_ts)})"
        )
    if past_skew_s and iat_int < now_ts - past_skew_s:
        raise jwt.InvalidTokenError(
            f"{field_name} lies more than {past_skew_s}s in the past "
            f"(iat={iat_int}, now={int(now_ts)})"
        )


def _try_chmod_0700_warn(target: Path) -> None:
    """Best-effort chmod 0o700 with a stderr warning on failure.

    Some filesystems (read-only bind mounts, certain container overlays,
    NFS with no_root_squash off) reject chmod even when mkdir succeeds.
    Don't fail home discovery on that — the home dir still exists and is
    usable. But DO emit a stderr warning so operators see the security
    trade-off: the dir may be world-readable under the caller's umask,
    exposing private-key material that later lands inside.
    Set VIBAP_HOME explicitly to a chmod-capable fs to silence.
    """
    try:
        os.chmod(target, stat.S_IRWXU)
    except OSError as exc:
        import sys

        print(
            f"warning: could not chmod 0o700 on VIBAP home {target}: "
            f"{exc}. Private-key material may be world-readable. "
            f"Set VIBAP_HOME to a chmod-capable filesystem.",
            file=sys.stderr,
        )


def _default_home_dir() -> Path:
    """Pure path resolver — no filesystem mutation.

    Returns ``$VIBAP_HOME`` (if set and non-empty) or the first viable
    candidate from ``$CWD/.vibap`` / ``$HOME/.vibap``.  Does NOT create
    directories or chmod anything; call :func:`_ensure_default_home_dir`
    to materialise the home with 0o700 on first actual use.
    """
    explicit = os.environ.get("VIBAP_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    candidates = [
        Path.cwd() / ".vibap",
        Path.home() / ".vibap",
    ]
    for candidate in candidates:
        target = candidate.expanduser()
        # Pure resolver: return the first candidate whose parent exists
        # (so we know the filesystem is reachable) without creating anything.
        try:
            if target.parent.is_dir():
                return target
        except OSError:
            continue
    raise OSError("unable to determine a writable VIBAP home directory")


def _ensure_default_home_dir() -> Path:
    """Materialise DEFAULT_HOME with 0o700 on first actual use.

    Idempotent: if the directory already exists, ``mkdir(exist_ok=True)``
    is a no-op and the mode of an *existing* directory is NOT changed
    (preserving the legacy contract for explicit ``$VIBAP_HOME`` dirs).
    Only a newly-created directory gets ``0o700``.
    """
    target = _default_home_dir()
    already_existed = target.exists()
    try:
        target.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
    except OSError:
        # If we can't even create the directory, the caller will get a
        # follow-up error from whatever write path triggered this.
        return target
    if not already_existed:
        _try_chmod_0700_warn(target)
    return target


def _is_under_default_home(path: Path) -> bool:
    """Return True if *path* is equal to or lies under DEFAULT_HOME.

    Uses unresolved string comparison — sufficient because DEFAULT_HOME
    is always a concrete path (``$VIBAP_HOME``, ``$CWD/.vibap``, or
    ``$HOME/.vibap``) with no symlink component in practice.
    """
    home_str = str(DEFAULT_HOME)
    path_str = str(path)
    if path_str == home_str:
        return True
    return path_str.startswith(home_str + os.sep)


DEFAULT_HOME = _default_home_dir()
DEFAULT_KEYS_DIR = Path(
    os.environ.get("VIBAP_KEYS_DIR", DEFAULT_HOME / "keys")
).expanduser()


class KeyDirectoryError(ValueError):
    """Fail-closed error for invalid Mission Passport key directory inputs."""

    def __init__(
        self,
        detail: str = (
            "The selected Mission Passport key path already exists as a file or other non-directory."
        ),
        *,
        condition: str = "keys_dir_not_directory",
    ) -> None:
        super().__init__(detail)
        self.condition = condition
        self.detail = detail


def _normalize_cwd(value: str | None) -> str | None:
    """Validate + canonicalize an optional ``cwd`` claim.

    Rules (C8):

    - ``None`` passes through as-is (no cwd declared).
    - Empty string (or whitespace-only) is coerced to ``None``. Mission file
      authors sometimes emit ``"cwd": ""`` when they mean "unset"; we prefer
      forgiving coercion over a hard error at the JSON boundary.
    - Non-empty value must be a ``str`` that starts with ``/`` after strip.
      Anything else (relative path, Windows drive, URL) is rejected with
      ``ValueError`` — "resolve relative-against-cwd" is undefined unless
      cwd itself is absolute.
    - The value is normalized via ``posixpath.normpath`` so narrowing
      comparisons in ``derive_child_passport`` don't hinge on trailing
      slashes or ``./`` noise.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"cwd must be a string or None, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        return None
    if not stripped.startswith("/"):
        raise ValueError(
            f"cwd must be an absolute path (start with '/'), got {value!r}"
        )
    # Phase-3.1a C-3 (external-review-X F3 + SF-P3-04): reject any ``..`` segment
    # BEFORE calling posixpath.normpath. normpath silently collapses
    # ``/workspace/../etc`` → ``/etc``, which would let a passport claim
    # an arbitrary absolute anchor via a single ``..`` the issuer didn't
    # audit. The resource_scope sanitizer has the same defense (``_sanitize_value``
    # Layer 3); we mirror it here so the cwd claim can never anchor to a
    # path the mission author didn't explicitly write. Doc §11 promises
    # this behavior but pre-3.1a only ``posixpath.normpath`` enforced it.
    for segment in stripped.split("/"):
        if segment == "..":
            raise ValueError(f"cwd must not contain '..' segments: {value!r}")
    # Normalize away trailing slashes and './' segments so comparisons in
    # _cwd_is_subpath are consistent. Keep the root '/' intact.
    normalized = posixpath.normpath(stripped)
    return normalized


def _cwd_is_subpath(child: str, parent: str) -> bool:
    """True iff ``child`` is equal to or lies strictly under ``parent``.

    Both inputs must be already-normalized absolute paths (output of
    :func:`_normalize_cwd`). The boundary check uses a trailing ``/`` so
    ``/workspaceabc`` is NOT considered a subpath of ``/workspace``.
    The root ``/`` is handled specially — every absolute path is under it.
    """
    if child == parent:
        return True
    if parent == "/":
        return child.startswith("/")
    return child.startswith(parent + "/")


@dataclass(slots=True)
class MissionPassport:
    agent_id: str
    mission: str
    allowed_tools: list[str]
    forbidden_tools: list[str] = field(default_factory=list)
    resource_scope: list[str] = field(default_factory=list)
    max_tool_calls: int = 50
    max_duration_s: int = 600
    delegation_allowed: bool = False
    max_delegation_depth: int = 0
    parent_jti: Optional[str] = None
    cwd: Optional[str] = None
    # Side-effect-class enforcement. When non-empty, only tool calls whose
    # computed side_effect_class is in this list are PERMITTED. Empty list
    # means unrestricted (backward compatible). Values: "none" (read-only),
    # "internal_write", "external_send", "state_change".
    allowed_side_effect_classes: list[str] = field(default_factory=list)
    # Cumulative per-class budget. Maps side-effect-class → max count allowed
    # in this session. e.g. {"external_send": 1, "state_change": 2}. Caps that
    # class even when it's in allowed_side_effect_classes. Empty = unbounded
    # per-class (the overall max_tool_calls still applies).
    max_tool_calls_per_class: dict[str, int] = field(default_factory=dict)
    # K2 (Round 11): Proof of Possession. When set, the passport is bound to
    # this holder key via a `cnf` claim (JWK thumbprint). Presenters must prove
    # they hold the corresponding private key via a KB-JWT. Without this, a
    # stolen bearer token is fully usable at the enforcement boundary.
    holder_key_thumbprint: Optional[str] = None
    holder_spiffe_id: Optional[str] = None
    # H1 (2026-04-19): stable identifier for the MISSION (as opposed to
    # the per-issuance ``jti`` or the per-agent ``agent_id``). Optional;
    # when unset, :func:`encode_passport` and :func:`issue_biscuit_passport`
    # derive a stable default via
    # ``f"mission:{agent_id}:{sha256(mission_text)[:12]}"``. The derivation
    # guarantees that two credentials issued for the same ``(agent_id,
    # mission)`` pair land on the same store key, while two different
    # missions for the same agent get distinct keys. Operators who want
    # to pin a deployment-wide mission identifier (e.g. a UUIDv7 from
    # their mission registry) can set this explicitly and the derivation
    # is bypassed.
    mission_id: Optional[str] = None
    # Pluggable policy backends evaluated in addition to native claims. Each
    # entry is a dict matching PolicySpec shape (below). Composition is
    # DENY-wins across native + additional; formally verified in
    # verification/composition_smt.py (properties P1-P4).
    additional_policies: list[dict[str, Any]] = field(default_factory=list)
    # Optional pre-action monetary/token authority. The mission form omits a
    # lineage_id; issue_passport binds it to the fresh root JTI. Derived
    # children inherit the signed policy and lineage identifier unchanged.
    spend_budget: dict[str, Any] | None = None
    # Optional typed dangerous-action policy. When present, trusted proxy-side
    # tool contracts derive risk facts before execution and reserve the signed
    # session/agent/lineage ceilings atomically. Absence preserves the legacy
    # behavior for missions that have not opted into impact governance.
    risk_budget: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        # Validate/normalize cwd at construction time so an invalid passport
        # can never be issued. Empty string → None; relative → ValueError.
        self.cwd = _normalize_cwd(self.cwd)
        if self.spend_budget is not None:
            self.spend_budget = normalize_spend_budget(self.spend_budget)
        if (
            UNRESTRICTED_RESOURCE_SCOPE_PATTERN in self.resource_scope
            and not resource_scope_is_explicitly_unrestricted(self.resource_scope)
        ):
            raise ValueError(
                "unrestricted '**' must be the only resource_scope pattern"
            )

    # Phase-3.1b M-3 (external-review-G F6): canonical set of keys this constructor
    # understands. Anything outside this set is a typo (e.g. `resourc_scope`
    # missing the `e`) that previously was silently dropped, causing the
    # mistyped field to default. Empty scope now denies resource authority,
    # but silently discarding a declared policy field is still unsafe and
    # misleading. Raise instead so operators see the typo at load time. The set
    # includes every dataclass field + mission-file metadata keys that
    # `_ttl_from_payload` understands (`ttl_s`, `issued_at`, `expires_at`)
    # and the legacy `budget` dict shape that exposes nested
    # max_tool_calls / max_duration_s.
    _KNOWN_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            # MissionPassport dataclass fields
            "agent_id",
            "mission",
            "allowed_tools",
            "forbidden_tools",
            "resource_scope",
            "max_tool_calls",
            "max_duration_s",
            "delegation_allowed",
            "max_delegation_depth",
            "parent_jti",
            "cwd",
            "allowed_side_effect_classes",  # side-effect-class enforcement
            "max_tool_calls_per_class",  # cumulative per-class budget
            "holder_key_thumbprint",  # K2 PoP
            "holder_spiffe_id",
            "additional_policies",  # pluggable policy backends
            "spend_budget",  # pre-action token and monetary authority
            "risk_budget",  # typed dangerous-action blast-radius caps
            "mission_id",  # H1: stable mission identifier for PolicyStore lookup
            # Mission-file metadata handled by load_mission_file / issue_passport
            "budget",
            "ttl_s",
            "issued_at",
            "expires_at",
        }
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MissionPassport":
        # Phase-3.1b M-3 (external-review-G F6): reject unknown fields so a typo
        # like `resourc_scope` (missing `e`) surfaces at construction
        # time instead of silently replacing the intended resource policy with
        # the empty deny-all default.
        # The canonical key set is `_KNOWN_FIELDS`; anything else is a
        # typo or an unversioned schema extension — either way we fail
        # closed and let the caller decide.
        unknown = set(data.keys()) - cls._KNOWN_FIELDS
        if unknown:
            unknown_fields = sorted(unknown)
            known_fields = sorted(cls._KNOWN_FIELDS)
            if "lineage_budgets" in unknown:
                raise ValueError(
                    "lineage_budgets is Phase 1 deferred and is not enforced "
                    "by MissionPassport issuance yet; remove lineage_budgets "
                    "from this mission until compiler/runtime support lands. "
                    f"Unknown fields in mission: {unknown_fields} "
                    f"(known: {known_fields})"
                )
            raise ValueError(
                f"unknown fields in mission: {unknown_fields} (known: {known_fields})"
            )
        budget = data.get("budget") or {}
        if "spend_budget" in data and not isinstance(data["spend_budget"], dict):
            raise ValueError("spend_budget must be a JSON object when present")
        if "risk_budget" in data and not isinstance(data["risk_budget"], dict):
            raise ValueError("risk_budget must be a JSON object when present")
        return cls(
            agent_id=data["agent_id"],
            mission=data["mission"],
            allowed_tools=list(data.get("allowed_tools", [])),
            forbidden_tools=list(data.get("forbidden_tools", [])),
            resource_scope=list(data.get("resource_scope", [])),
            max_tool_calls=int(
                data.get("max_tool_calls", budget.get("max_tool_calls", 50))
            ),
            max_duration_s=int(
                data.get("max_duration_s", budget.get("max_duration_s", 600))
            ),
            delegation_allowed=bool(data.get("delegation_allowed", False)),
            max_delegation_depth=int(data.get("max_delegation_depth", 0)),
            parent_jti=data.get("parent_jti"),
            cwd=data.get("cwd"),
            allowed_side_effect_classes=list(
                data.get("allowed_side_effect_classes", [])
            ),
            max_tool_calls_per_class=dict(data.get("max_tool_calls_per_class", {})),
            holder_key_thumbprint=data.get("holder_key_thumbprint"),
            holder_spiffe_id=data.get("holder_spiffe_id"),
            additional_policies=list(data.get("additional_policies", [])),
            mission_id=data.get("mission_id"),
            spend_budget=(
                dict(data["spend_budget"])
                if isinstance(data.get("spend_budget"), dict)
                else None
            ),
            risk_budget=(
                dict(data["risk_budget"])
                if isinstance(data.get("risk_budget"), dict)
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        # asdict() serializes every field, but we want to omit cwd when it's
        # None so old passports remain byte-identical in the wire format.
        data = asdict(self)
        if data.get("cwd") is None:
            data.pop("cwd", None)
        if data.get("spend_budget") is None:
            data.pop("spend_budget", None)
        if data.get("risk_budget") is None:
            data.pop("risk_budget", None)
        return data


def resolve_keys_dir(keys_dir: str | Path | None = None) -> Path:
    target = Path(keys_dir).expanduser() if keys_dir is not None else DEFAULT_KEYS_DIR
    if target.exists() and not target.is_dir():
        raise KeyDirectoryError()
    # If the target is under DEFAULT_HOME, materialise the home with 0o700
    # first so the leaf mkdir(parents=True) doesn't create it with the
    # process umask.
    if _is_under_default_home(target):
        _ensure_default_home_dir()
    try:
        target.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError) as exc:
        raise KeyDirectoryError() from exc
    except OSError as exc:
        raise KeyDirectoryError(
            f"Cannot create key directory: {exc.strerror or type(exc).__name__}",
            condition="keys_dir_unreachable",
        ) from exc
    if not target.is_dir():
        raise KeyDirectoryError()
    return target


def _write_private_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
    finally:
        if fd != -1:
            os.close(fd)
    actual_mode = path.stat().st_mode & 0o777
    if actual_mode != 0o600:
        import sys

        print(
            f"WARNING: {path} permissions are {actual_mode:o}, expected 600; "
            f"private key may be readable by other users on this filesystem",
            file=sys.stderr,
        )


def _write_public_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def generate_keypair(
    force: bool = False,
    keys_dir: str | Path | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    target_dir = resolve_keys_dir(keys_dir)
    priv_path = target_dir / "passport_private.pem"
    pub_path = target_dir / "passport_public.pem"

    if priv_path.exists() and pub_path.exists() and not force:
        priv_key = serialization.load_pem_private_key(
            priv_path.read_bytes(), password=None
        )
        pub_key = serialization.load_pem_public_key(pub_path.read_bytes())
        return priv_key, pub_key

    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()

    _write_private_bytes(
        priv_path,
        priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_public_bytes(
        pub_path,
        pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    return priv_key, pub_key


def load_private_key(keys_dir: str | Path | None = None) -> ec.EllipticCurvePrivateKey:
    target_dir = resolve_keys_dir(keys_dir)
    priv_path = target_dir / "passport_private.pem"
    if not priv_path.exists():
        return generate_keypair(keys_dir=target_dir)[0]
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)


def load_existing_private_key(
    keys_dir: str | Path | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Load ``passport_private.pem`` without creating directories or key material."""
    target_dir = (
        Path(keys_dir).expanduser() if keys_dir is not None else DEFAULT_KEYS_DIR
    )
    try:
        if target_dir.exists() and not target_dir.is_dir():
            raise KeyDirectoryError()
    except OSError as exc:
        raise KeyDirectoryError() from exc
    private_path = target_dir / "passport_private.pem"
    try:
        if private_path.is_symlink():
            raise ValueError("passport_private.pem must not be a symlink")
        if os.name == "posix" and private_path.stat().st_mode & 0o077:
            raise PermissionError("passport_private.pem must use mode 0600 or stricter")
        private_bytes = private_path.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "passport_private.pem is missing from the Mission Passport key directory"
        ) from exc
    except PermissionError:
        raise
    except NotADirectoryError as exc:
        raise KeyDirectoryError() from exc
    except OSError as exc:
        raise ValueError(
            "passport_private.pem is not a readable EC private key"
        ) from exc
    private_key = serialization.load_pem_private_key(private_bytes, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("passport_private.pem must contain an EC private key")
    return private_key


def load_public_key(keys_dir: str | Path | None = None) -> ec.EllipticCurvePublicKey:
    target_dir = resolve_keys_dir(keys_dir)
    pub_path = target_dir / "passport_public.pem"
    if not pub_path.exists():
        return generate_keypair(keys_dir=target_dir)[1]
    return serialization.load_pem_public_key(pub_path.read_bytes())


def load_report_public_key(
    keys_dir: str | Path | None = None,
    *,
    evidence_present: bool,
) -> ec.EllipticCurvePublicKey | None:
    """Load the verification key for a read-only report path.

    Reporting must never mint key material: a command whose job is to verify
    existing evidence cannot be allowed to invent the key it verifies against.
    But a fresh install with no receipts still needs its onboarding report, so
    a missing ``passport_public.pem`` is only an error when there is something
    to verify.

    The key directory itself is validated either way, so a malformed
    ``--keys-dir`` keeps failing closed whether or not evidence exists.

    Returns ``None`` only when no evidence is present and no key exists.
    """

    if evidence_present:
        return load_existing_public_key(keys_dir)
    try:
        return load_existing_public_key(keys_dir)
    except FileNotFoundError:
        return None


def load_existing_public_key(
    keys_dir: str | Path | None = None,
) -> ec.EllipticCurvePublicKey:
    """Load ``passport_public.pem`` without creating key directories or key material."""
    target_dir = (
        Path(keys_dir).expanduser() if keys_dir is not None else DEFAULT_KEYS_DIR
    )
    try:
        if target_dir.exists() and not target_dir.is_dir():
            raise KeyDirectoryError()
    except OSError as exc:
        raise KeyDirectoryError() from exc
    pub_path = target_dir / "passport_public.pem"
    try:
        public_bytes = pub_path.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "passport_public.pem is missing from the Mission Passport key directory"
        ) from exc
    except NotADirectoryError as exc:
        raise KeyDirectoryError() from exc
    except OSError as exc:
        raise ValueError("passport_public.pem is not a readable EC public key") from exc
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("passport_public.pem must contain an EC public key")
    return public_key


def derive_mission_id(agent_id: str, mission_text: str) -> str:
    """Stable fallback ``mission_id`` when the MissionPassport doesn't set one.

    Deterministic across re-issuances of the same ``(agent_id, mission_text)``
    pair — two credentials issued for the same mission land on the same
    PolicyStore key, even if the random ``jti`` differs. Distinct from
    the ``agent_id`` itself (so that two missions assigned to the same
    agent get distinct keys) and distinct from ``jti`` (which is per-
    issuance and therefore unstable).

    NOT a cryptographic identifier — the 48-bit prefix is a stable tag,
    not a secret. Operators who want a deployment-wide mission identity
    (e.g. a UUIDv7 from a mission registry) should set
    ``MissionPassport.mission_id`` explicitly to bypass this derivation.
    """
    digest = hashlib.sha256(mission_text.encode("utf-8")).hexdigest()[:12]
    return f"mission:{agent_id}:{digest}"


def issue_passport(
    mission: MissionPassport,
    private_key: ec.EllipticCurvePrivateKey,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    ttl_s: int | None = None,
    extra_claims: dict[str, Any] | None = None,
    *,
    jti_override: str | None = None,
) -> str:
    now = int(time.time())
    ttl = int(ttl_s if ttl_s is not None else mission.max_duration_s)
    if ttl <= 0:
        raise ValueError("ttl_s must be positive")

    if jti_override is not None and (
        not isinstance(jti_override, str)
        or not jti_override
        or len(jti_override.encode("utf-8")) > 1024
    ):
        raise ValueError(
            "jti_override must be a non-empty string of at most 1024 bytes"
        )
    if jti_override is not None:
        try:
            parsed_jti = uuid.UUID(jti_override)
        except ValueError as exc:
            raise ValueError("jti_override must use canonical UUID format") from exc
        if str(parsed_jti).lower() != jti_override.lower():
            raise ValueError("jti_override must use canonical UUID format")
    jti = jti_override or str(uuid.uuid4())
    # H1 (2026-04-19): ``mission_id`` is DISTINCT from ``jti``.
    # Previously this field was set to ``jti`` which re-randomized every
    # issuance — the PolicyStore's key would rotate with every re-issued
    # credential for the same mission, making mission-scoped policy
    # registrations practically unusable. The correct semantic is: same
    # mission ⇒ same ``mission_id`` across all credential issuances.
    effective_mission_id = mission.mission_id or derive_mission_id(
        mission.agent_id, mission.mission
    )
    claims = {
        "iss": issuer,
        "sub": mission.agent_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": jti,
        "mission_id": effective_mission_id,
        "mission": mission.mission,
        "allowed_tools": mission.allowed_tools,
        "forbidden_tools": mission.forbidden_tools,
        "resource_scope": mission.resource_scope,
        "max_tool_calls": mission.max_tool_calls,
        "max_duration_s": mission.max_duration_s,
        "delegation_allowed": mission.delegation_allowed,
        "max_delegation_depth": mission.max_delegation_depth,
    }
    if mission.parent_jti:
        claims["parent_jti"] = mission.parent_jti
    # Only include `cwd` when set. Passports without cwd stay bit-identical
    # to the pre-C8 format so existing tokens and downstream consumers
    # (that never expected cwd) are unaffected.
    if mission.cwd is not None:
        claims["cwd"] = mission.cwd
    # Side-effect-class enforcement: only include when non-empty
    if mission.allowed_side_effect_classes:
        claims["allowed_side_effect_classes"] = mission.allowed_side_effect_classes
    if mission.max_tool_calls_per_class:
        claims["max_tool_calls_per_class"] = mission.max_tool_calls_per_class
    if mission.additional_policies:
        claims["additional_policies"] = mission.additional_policies
    if mission.spend_budget is not None:
        inherited_lineage_id = mission.spend_budget.get("lineage_id")
        if mission.parent_jti is None and inherited_lineage_id is not None:
            raise ValueError(
                "root spend_budget must omit lineage_id; issuance binds it to the fresh jti"
            )
        if mission.parent_jti is not None and inherited_lineage_id is None:
            raise ValueError("child spend_budget must inherit the parent lineage_id")
        claims["spend_budget"] = normalize_spend_budget(
            mission.spend_budget,
            lineage_id=(
                str(inherited_lineage_id) if inherited_lineage_id is not None else jti
            ),
            require_lineage_id=True,
        )
    if mission.risk_budget is not None:
        from .risk_budget import normalize_risk_budget

        risk_budget = dict(mission.risk_budget)
        if risk_budget.get("lineage_id") is None:
            risk_budget = normalize_risk_budget(risk_budget, lineage_id=jti)
        else:
            risk_budget = normalize_risk_budget(risk_budget)
        if not set(risk_budget["tools"]).issubset(mission.allowed_tools):
            raise ValueError("risk_budget tools must be a subset of allowed_tools")
        claims["risk_budget"] = risk_budget
    # K2 (I6): Proof of Possession via cnf claim. When the mission declares
    # a holder_key_thumbprint, the passport is bound to that key. Presenters
    # must prove possession by signing a KB-JWT with the matching private key.
    # Without cnf, the passport is a bearer token — usable by anyone who
    # captures the raw JWT string.
    if mission.holder_key_thumbprint:
        claims["cnf"] = {"jkt": mission.holder_key_thumbprint}
    if extra_claims:
        protected_claims = set(claims)
        collisions = set(extra_claims).intersection(protected_claims)
        if collisions:
            raise ValueError(
                "extra_claims cannot override protected passport claims: "
                f"{sorted(collisions)}"
            )
        claims.update(extra_claims)

    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def compute_jwk_thumbprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """Compute RFC 7638 JWK Thumbprint (SHA-256) for an EC P-256 public key.

    Used to populate the `cnf.jkt` claim for Proof of Possession binding.
    The thumbprint is a deterministic hash of the key's canonical JWK
    representation, so verifiers can independently compute it from the
    holder's public key and check it against the passport's cnf claim.
    """
    nums = public_key.public_numbers()
    # RFC 7638: sort members alphabetically, use no whitespace
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    canonical = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )


def create_kb_jwt(
    holder_private_key: ec.EllipticCurvePrivateKey,
    passport_token: str,
    nonce: str | None = None,
) -> str:
    """Create a Key Binding JWT proving the presenter holds the private key.

    Per SD-JWT-VC / AAT §5: the KB-JWT is a short-lived JWT signed by the
    holder's private key, binding the holder to a specific passport and
    moment in time. The proxy verifies this at session start.

    Claims:
    - iat: current timestamp
    - nonce: random or proxy-supplied challenge
    - sd_hash: SHA-256 of the passport token (binds KB-JWT to this specific passport)
    """
    now = int(time.time())
    if nonce is None:
        nonce = str(uuid.uuid4())
    # sd_hash uses base64url-no-pad per SD-JWT-VC §4.2.1 (cryptographer R2 #3)
    raw_hash = hashlib.sha256(passport_token.encode("ascii")).digest()
    sd_hash = base64.urlsafe_b64encode(raw_hash).rstrip(b"=").decode()
    kb_claims = {
        "iat": now,
        "nonce": nonce,
        "sd_hash": sd_hash,
    }
    return jwt.encode(kb_claims, holder_private_key, algorithm=ALGORITHM)


def verify_pop(
    passport_claims: dict[str, Any],
    passport_token: str,
    holder_public_key: ec.EllipticCurvePublicKey | None = None,
    kb_jwt: str | None = None,
    max_age_s: int = 300,
) -> bool:
    """Verify Proof of Possession: key binding + KB-JWT possession proof.

    Two-layer check (per cryptographer review #07):

    Layer 1 — Key Binding: cnf.jkt in the passport matches the holder's
    public key thumbprint. This proves the passport was ISSUED for this key.

    Layer 2 — Key Possession (KB-JWT): a short-lived JWT signed by the
    holder's private key, containing sd_hash (binding to this passport)
    and iat (freshness). This proves the PRESENTER holds the private key
    right now, not just that someone once had the public key.

    Without Layer 2, an attacker who captures the passport JWT and knows
    the holder's public key (not secret) passes Layer 1 trivially.

    Returns True if passport has no cnf claim (bearer mode — backward compat).
    Raises PermissionError on any verification failure.
    """
    cnf = passport_claims.get("cnf")
    if cnf is None:
        return True  # bearer mode — no PoP required

    # 2026-04-21 audit fix: a cnf claim whose value is a non-dict JSON
    # primitive (``{}``, ``""``, ``0``, ``false``, ``[]``, or an integer)
    # previously crashed with AttributeError when ``cnf.get("jkt")`` ran
    # on a non-mapping. Fail closed with a PermissionError so the proxy
    # returns a consistent auth decision instead of a 500 trace.
    if not isinstance(cnf, dict):
        raise PermissionError(
            f"passport cnf claim must be a JSON object, got {type(cnf).__name__}"
        )

    jkt = cnf.get("jkt")
    if not isinstance(jkt, str) or not jkt:
        raise PermissionError("passport has cnf claim but missing jkt (thumbprint)")

    # Layer 1: key binding (thumbprint match)
    if holder_public_key is None:
        raise PermissionError(
            "passport requires proof of possession (cnf claim) "
            "but no holder_public_key was supplied"
        )
    actual_thumbprint = compute_jwk_thumbprint(holder_public_key)
    if actual_thumbprint != jkt:
        raise PermissionError(
            "key binding failed: holder key thumbprint does not match cnf.jkt"
        )

    # Layer 2: key possession via KB-JWT
    if kb_jwt is None:
        raise PermissionError(
            "passport requires proof of possession (cnf claim) "
            "but no KB-JWT was supplied — key binding alone is insufficient"
        )
    try:
        kb_claims = jwt.decode(
            kb_jwt,
            holder_public_key,
            algorithms=[ALGORITHM],
            options={
                "verify_aud": False,
                "verify_iat": False,
                "require": ["iat", "nonce", "sd_hash"],
            },
        )
    except jwt.exceptions.InvalidSignatureError:
        raise PermissionError(
            "KB-JWT signature invalid — presenter does not hold the private key"
        )
    except jwt.PyJWTError as e:
        raise PermissionError(f"KB-JWT decode failed: {e}")

    # Freshness check (cryptographer R2 finding #1: reject future-dated iat)
    kb_iat = kb_claims.get("iat")
    if not isinstance(kb_iat, int) or isinstance(kb_iat, bool):
        raise PermissionError("KB-JWT iat must be an integer timestamp")
    nonce = kb_claims.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise PermissionError("KB-JWT nonce must be a non-empty string")
    sd_hash = kb_claims.get("sd_hash")
    if not isinstance(sd_hash, str) or not sd_hash:
        raise PermissionError("KB-JWT sd_hash must be a non-empty string")
    now = int(time.time())
    clock_skew_tolerance = 30  # seconds
    if kb_iat > now + clock_skew_tolerance:
        raise PermissionError(
            f"KB-JWT iat is in the future: iat={kb_iat}, now={now} "
            f"(tolerance={clock_skew_tolerance}s) — possible pre-signed stockpile"
        )
    if now - kb_iat > max_age_s:
        raise PermissionError(
            f"KB-JWT expired: iat={kb_iat}, now={now}, max_age={max_age_s}s"
        )

    # Binding check: KB-JWT must reference THIS passport
    # Cryptographer R2 finding #3: use base64url-no-pad for SD-JWT-VC interop
    raw_hash = hashlib.sha256(passport_token.encode("ascii")).digest()
    expected_hash = base64.urlsafe_b64encode(raw_hash).rstrip(b"=").decode()
    if sd_hash != expected_hash:
        raise PermissionError(
            "KB-JWT sd_hash does not match passport token — "
            "KB-JWT was created for a different passport"
        )

    return True


def _decode_passport(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
    audience: str = DEFAULT_AUDIENCE,
) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        audience=audience,
        options={
            "require": ["iss", "sub", "aud", "iat", "exp", "jti"],
            # Round 3 (2026-04-28): we apply our own bounded-iat check
            # below; PyJWT's zero-leeway iat check would collide with
            # legitimate clock drift across nodes.
            "verify_iat": False,
        },
    )
    assert_iat_in_window(claims.get("iat"), field_name="passport iat")
    return claims


def _token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _inherited_mic_conformance_claims(
    parent_claims: Mapping[str, Any],
    *,
    credential_label: str = "parent",
) -> dict[str, Any]:
    """Return the validated, closed MIC claim bundle for a child passport.

    Conformance profiles and receipt levels are ordered, non-weakening policy
    claims.  ``derive_child_passport`` has no child override surface, so exact
    inheritance is the only safe behavior.  Copying a reviewed allowlist also
    prevents issuer-controlled extras from colliding with child lineage or
    budget claims.
    """

    # Older passports may carry receipt or digest metadata without declaring a
    # conformance profile.  They remain legacy credentials: do not activate
    # MIC validation or copy any part of a bundle until a profile is explicit.
    if "conformance_profile" not in parent_claims:
        return {}

    present = {claim for claim in _DELEGATED_MIC_CLAIMS if claim in parent_claims}
    expected = set(_DELEGATED_MIC_CLAIMS)
    if present != expected:
        missing = sorted(expected - present)
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle is incomplete; "
            f"missing {missing}"
        )

    profile = parent_claims["conformance_profile"]
    if not isinstance(profile, str) or profile not in _SUPPORTED_CONFORMANCE_PROFILES:
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle has an unsupported "
            "conformance_profile"
        )

    receipt_policy = parent_claims["receipt_policy"]
    if not isinstance(receipt_policy, dict) or set(receipt_policy) != {"level"}:
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle has a malformed "
            "receipt_policy"
        )
    receipt_level = receipt_policy.get("level")
    if (
        not isinstance(receipt_level, str)
        or receipt_level not in _SUPPORTED_RECEIPT_LEVELS
    ):
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle has an unsupported "
            "receipt level"
        )
    if profile == "MIC-Evidence" and receipt_level == "minimal":
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle weakens MIC-Evidence "
            "with a minimal receipt level"
        )

    manifest_digest = parent_claims["tool_manifest_digest"]
    digest_prefix = "sha-256:"
    digest_hex = (
        manifest_digest[len(digest_prefix) :]
        if isinstance(manifest_digest, str)
        and manifest_digest.startswith(digest_prefix)
        else ""
    )
    if len(digest_hex) != 64 or any(
        character not in "0123456789abcdef" for character in digest_hex
    ):
        raise PermissionError(
            f"{credential_label} MIC conformance claim bundle has a malformed "
            "tool_manifest_digest"
        )

    return {
        claim: copy.deepcopy(parent_claims[claim]) for claim in _DELEGATED_MIC_CLAIMS
    }


def _require_nonempty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PermissionError(f"delegated passport has malformed {field}")
    return value


def delegation_chain_entries(claims: dict[str, Any]) -> list[dict[str, str]]:
    """Return a normalized signed ancestor chain from immediate parent to root.

    Each entry contains the ancestor ``jti`` and, when the ancestor was itself
    delegated, its ``parent_jti`` and optional ``parent_token_hash``. The
    entire structure is signed as part of the passport JWT, so callers can walk
    ancestry without loading ancestor session blobs from disk.
    """

    current_jti = _require_nonempty_str(claims.get("jti"), field="jti")
    parent_jti_raw = claims.get("parent_jti")
    raw_chain = claims.get(DELEGATION_CHAIN_CLAIM)
    if parent_jti_raw is None:
        if raw_chain in (None, []):
            return []
        raise PermissionError("root passport must not include delegation_chain")

    parent_jti = _require_nonempty_str(parent_jti_raw, field="parent_jti")
    if not isinstance(raw_chain, list) or not raw_chain:
        raise PermissionError("delegated passport missing delegation_chain")
    if len(raw_chain) > MAX_DELEGATION_DEPTH:
        raise PermissionError("delegation depth exceeded")

    normalized: list[dict[str, str]] = []
    seen = {current_jti}
    expected_jti = parent_jti
    for index, raw_link in enumerate(raw_chain):
        if not isinstance(raw_link, dict):
            raise PermissionError("delegated passport has malformed delegation_chain")
        link_jti = _require_nonempty_str(
            raw_link.get("jti"),
            field=f"{DELEGATION_CHAIN_CLAIM}[{index}].jti",
        )
        if link_jti != expected_jti:
            raise PermissionError(
                "delegated passport has inconsistent delegation_chain"
            )
        if link_jti in seen:
            raise PermissionError(f"passport lineage cycle detected at '{link_jti}'")
        seen.add(link_jti)

        normalized_link: dict[str, str] = {"jti": link_jti}
        token_hash = raw_link.get("token_hash")
        if token_hash is not None:
            normalized_link["token_hash"] = _require_nonempty_str(
                token_hash,
                field=f"{DELEGATION_CHAIN_CLAIM}[{index}].token_hash",
            )
        next_parent_raw = raw_link.get("parent_jti")
        if next_parent_raw is not None:
            next_parent = _require_nonempty_str(
                next_parent_raw,
                field=f"{DELEGATION_CHAIN_CLAIM}[{index}].parent_jti",
            )
            normalized_link["parent_jti"] = next_parent
            parent_token_hash = raw_link.get("parent_token_hash")
            if parent_token_hash is not None:
                normalized_link["parent_token_hash"] = _require_nonempty_str(
                    parent_token_hash,
                    field=f"{DELEGATION_CHAIN_CLAIM}[{index}].parent_token_hash",
                )
        normalized.append(normalized_link)
        expected_jti = normalized_link.get("parent_jti")

    if expected_jti is not None:
        raise PermissionError("delegated passport missing delegation_chain ancestry")
    return normalized


def _expected_chain_for_parent(
    parent_claims: dict[str, Any],
    parent_token: str,
) -> list[dict[str, str]]:
    parent_link = {
        "jti": str(parent_claims["jti"]),
        "token_hash": _token_sha256(parent_token),
    }
    parent_parent_jti = parent_claims.get("parent_jti")
    if parent_parent_jti is not None:
        parent_link["parent_jti"] = str(parent_parent_jti)
        parent_parent_hash = parent_claims.get("parent_token_hash")
        if isinstance(parent_parent_hash, str) and parent_parent_hash:
            parent_link["parent_token_hash"] = parent_parent_hash
    return [parent_link, *delegation_chain_entries(parent_claims)]


def verify_passport(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
    audience: str = DEFAULT_AUDIENCE,
    parent_token: str | None = None,
    trusted_parent_token_hashes: Mapping[str, str] | None = None,
    trusted_parent_lineage: Mapping[str, tuple[str | None, str | None]] | None = None,
) -> dict[str, Any]:
    claims = _decode_passport(token, public_key, audience=audience)
    chain = delegation_chain_entries(claims)

    parent_jti = claims.get("parent_jti")
    if parent_jti is not None:
        parent_token_hash = claims.get("parent_token_hash")
        if not isinstance(parent_token_hash, str) or not parent_token_hash:
            raise PermissionError("delegated passport missing parent_token_hash")
        if parent_token is None:
            if trusted_parent_token_hashes is None or trusted_parent_lineage is None:
                raise PermissionError(
                    "delegated passport verification requires parent_token "
                    "or trusted_parent_token_hashes plus trusted_parent_lineage"
                )
            if not chain:
                raise PermissionError("delegated passport missing delegation_chain")
            chain_token_hash = chain[0].get("token_hash")
            if chain_token_hash != parent_token_hash:
                raise PermissionError(
                    "delegation chain parent hash does not match parent_token_hash"
                )
            for link in chain:
                link_hash = link.get("token_hash")
                if not isinstance(link_hash, str) or not link_hash:
                    raise PermissionError(
                        "delegation chain missing ancestor token_hash"
                    )
                trusted_hash = trusted_parent_token_hashes.get(link["jti"])
                if trusted_hash != link_hash:
                    raise PermissionError(
                        "delegation chain ancestor token hash is not trusted"
                    )
                trusted_edge = trusted_parent_lineage.get(link["jti"])
                if trusted_edge is None:
                    raise PermissionError(
                        "delegation chain ancestor lineage edge is not trusted"
                    )
                trusted_parent_jti, trusted_parent_hash = trusted_edge
                link_parent_jti = link.get("parent_jti")
                if trusted_parent_jti != link_parent_jti:
                    raise PermissionError(
                        "delegation chain ancestor parent_jti is not trusted"
                    )
                link_parent_hash = link.get("parent_token_hash")
                if trusted_parent_hash != link_parent_hash:
                    raise PermissionError(
                        "delegation chain ancestor parent hash is not trusted"
                    )
            # The cold lineage indexes anchor hashes and parent edges, but do
            # not persist ancestor policy claims.  MIC bundle equality can
            # only be enforced below when the signed parent token is present.
            return claims
        parent_claims = _decode_passport(parent_token, public_key, audience=audience)
        if str(parent_claims["jti"]) != str(parent_jti):
            raise PermissionError(
                "delegated passport parent_jti does not match supplied parent token"
            )
        if parent_token_hash != _token_sha256(parent_token):
            raise PermissionError("delegated passport parent token hash mismatch")

        expected_chain = _expected_chain_for_parent(parent_claims, parent_token)
        if chain != expected_chain:
            raise PermissionError(
                "delegation chain does not match supplied parent lineage"
            )

        parent_mic_claims = _inherited_mic_conformance_claims(parent_claims)
        if parent_mic_claims:
            child_mic_claims = _inherited_mic_conformance_claims(
                claims,
                credential_label="child",
            )
            if child_mic_claims != parent_mic_claims:
                raise PermissionError(
                    "child MIC conformance claim bundle does not match parent"
                )

    return claims


def derive_child_passport(
    parent_token: str,
    public_key: ec.EllipticCurvePublicKey,
    private_key: ec.EllipticCurvePrivateKey,
    child_agent_id: str,
    child_allowed_tools: list[str],
    child_mission: str,
    child_ttl_s: int | None = None,
    child_max_tool_calls: int | None = None,
    parent_calls_remaining: int | None = None,
    parent_reserved_for_descendants: int = 0,
    child_resource_scope: list[str] | None = None,
    child_cwd: str | None = None,
    child_risk_budget: Mapping[str, Any] | None = None,
) -> str:
    """Derive a child passport with strictly narrowed scope.

    Narrowing rules enforced here:
      - allowed_tools: must be a subset of parent (raises PermissionError on escalation)
      - max_delegation_depth: decrements by 1
      - delegation_allowed: only True if child depth remains > 0
      - exp (TTL): clamped to parent's remaining lifetime
      - max_tool_calls: ESCROW SEMANTICS (April 15 2026 sprint #1/#17). Child budget is
                        clamped to min(child_max_tool_calls, parent_calls_remaining,
                        parent_budget_ceiling - parent_reserved_for_descendants,
                        parent_budget_ceiling). The proxy passes
                        ``parent_reserved_for_descendants`` from live reserved budget;
                        the signed claim ``reserved_budget_share`` audits the tree.
      - resource_scope: an empty scope grants no resource authority; ``["**"]``
                        is the explicit unrestricted sentinel. An unrestricted
                        parent may delegate any valid narrower scope. A bounded
                        or empty parent may delegate ``[]`` (deny all), while a
                        bounded child otherwise remains an exact pattern subset.
                        If not provided, inherit parent's scope verbatim.
      - cwd: if ``child_cwd`` is ``None``, child inherits parent's ``cwd``
             verbatim. If the parent has no ``cwd``, the child MAY NOT
             introduce one (cwd can only be inherited or narrowed, never
             spawned). If the parent has a ``cwd``, the child's request must
             equal it or lie strictly under it (subpath with ``/`` boundary
             — ``/workspace/a`` narrows ``/workspace``; ``/workspaceabc``
             does not). Anything else raises ``PermissionError`` with a
             ``cwd escalation`` reason.
      - risk_budget: a governed parent policy is inherited or explicitly
                     attenuated; an ungoverned parent cannot introduce one.
      - MIC conformance: an explicit, complete profile / receipt-policy /
                         manifest-digest bundle is validated and inherited
                         exactly; partial or malformed bundles fail closed.
    """
    # Signature-and-claims decode only. The full chain-anchor verification
    # (``verify_passport`` with ``parent_token=grandparent_token``) is the
    # CALLER'S responsibility — they chose to hold this ``parent_token`` and
    # should have verified its own lineage before extending it. Re-running
    # the strict verifier here would require passing the grandparent (and
    # great-grandparent, and so on) through derive_child_passport, which
    # doesn't generalize to chains of arbitrary depth.
    parent = _decode_passport(parent_token, public_key)
    parent_chain = delegation_chain_entries(parent)

    if not parent.get("delegation_allowed"):
        raise PermissionError("parent passport does not allow delegation")
    if parent.get("max_delegation_depth", 0) <= 0:
        raise PermissionError("delegation depth exhausted")

    parent_tools = set(parent["allowed_tools"])
    child_tools = set(child_allowed_tools)
    if not child_tools.issubset(parent_tools):
        escalated = sorted(child_tools - parent_tools)
        raise PermissionError(f"scope escalation (tools): {escalated}")
    if not child_tools:
        raise PermissionError("child_allowed_tools must be non-empty")

    parent_exp = int(parent["exp"])
    max_ttl = parent_exp - int(time.time())
    if max_ttl <= 0:
        raise PermissionError("parent passport expired")
    requested_ttl = (
        min(child_ttl_s, max_ttl) if child_ttl_s is not None else min(300, max_ttl)
    )
    if requested_ttl <= 0:
        raise PermissionError("insufficient TTL for child passport")

    child_depth = int(parent["max_delegation_depth"]) - 1
    parent_budget_ceiling = int(parent.get("max_tool_calls", 50))

    # Budget narrowing — ESCROW SEMANTICS (STAC sibling-amplification fix).
    if parent_reserved_for_descendants < 0:
        raise PermissionError("parent_reserved_for_descendants must be non-negative")
    if parent_reserved_for_descendants > parent_budget_ceiling:
        raise PermissionError(
            "parent_reserved_for_descendants exceeds parent ceiling — "
            "lineage budget already over-allocated"
        )
    escrow_remaining = parent_budget_ceiling - parent_reserved_for_descendants
    candidates = [parent_budget_ceiling, escrow_remaining]
    if escrow_remaining <= 0:
        raise PermissionError(
            "parent passport descendant-reservation pool exhausted; cannot delegate"
        )
    if parent_calls_remaining is not None:
        if parent_calls_remaining <= 0:
            raise PermissionError("parent passport budget exhausted; cannot delegate")
        candidates.append(int(parent_calls_remaining))
    if child_max_tool_calls is not None:
        if child_max_tool_calls <= 0:
            raise PermissionError("child_max_tool_calls must be positive")
        candidates.append(int(child_max_tool_calls))
    child_budget = min(candidates)

    # Resource scope narrowing. Empty means no resource authority; ["**"] is
    # the sole explicit unrestricted sentinel. Bounded pattern comparison stays
    # exact because a safe glob-language intersector is outside this boundary.
    parent_scope = list(parent.get("resource_scope", []))
    if child_resource_scope is not None:
        child_scope_set = set(child_resource_scope)
        requested_scope = sorted(child_scope_set)
        if (
            UNRESTRICTED_RESOURCE_SCOPE_PATTERN in requested_scope
            and not resource_scope_is_explicitly_unrestricted(requested_scope)
        ):
            raise PermissionError(
                "unrestricted '**' must be the only child_resource_scope pattern"
            )
        if not requested_scope:
            final_scope = []
        elif resource_scope_is_explicitly_unrestricted(parent_scope):
            final_scope = requested_scope
        else:
            parent_scope_set = set(parent_scope)
            new_patterns = child_scope_set - parent_scope_set
            if new_patterns:
                raise PermissionError(
                    f"scope escalation (resources): {sorted(new_patterns)}"
                )
            final_scope = requested_scope
    else:
        final_scope = parent_scope

    # cwd narrowing: the child either inherits the parent's cwd verbatim
    # (child_cwd is None) or requests a narrower one. "Narrower" means
    # equal-or-subpath with a '/' boundary (so '/workspaceabc' does NOT
    # narrow '/workspace'). If the parent has no cwd, the child MAY NOT
    # introduce one — cwd is a semantic anchor chosen at the top of the
    # delegation chain.
    parent_cwd_raw = parent.get("cwd")
    parent_cwd = _normalize_cwd(parent_cwd_raw) if parent_cwd_raw is not None else None

    if child_cwd is None:
        final_cwd: str | None = parent_cwd
    else:
        # Normalize first so "/workspace/" and "/workspace/./a" are compared
        # in canonical form. _normalize_cwd also enforces the "absolute,
        # non-empty" rule — relative cwd raises ValueError here, which the
        # caller should see as a bad request.
        final_cwd = _normalize_cwd(child_cwd)
        if final_cwd is None:
            # Caller explicitly passed "" or whitespace — treat as "clear
            # the cwd". If the parent had one, this is a widening and is
            # rejected; if the parent had none, it's a no-op.
            if parent_cwd is not None:
                raise PermissionError(
                    f"cwd escalation: clearing parent's cwd {parent_cwd!r} is not allowed"
                )
        else:
            if parent_cwd is None:
                raise PermissionError(
                    f"cannot introduce cwd: parent has none (child requested {final_cwd!r})"
                )
            if not _cwd_is_subpath(final_cwd, parent_cwd):
                raise PermissionError(
                    f"cwd escalation: {final_cwd!r} is not a subpath of parent's {parent_cwd!r}"
                )

    parent_risk_budget = parent.get("risk_budget")
    if parent_risk_budget is None:
        if child_risk_budget is not None:
            raise PermissionError("cannot introduce risk_budget: parent has none")
        final_risk_budget = None
    else:
        from .risk_budget import attenuate_risk_budget, project_risk_budget

        if not isinstance(parent_risk_budget, dict):
            raise PermissionError("parent risk_budget is invalid")
        projected_parent = project_risk_budget(parent_risk_budget, child_tools)
        if projected_parent is None:
            if child_risk_budget is not None:
                raise PermissionError(
                    "cannot retain risk_budget after removing all governed tools"
                )
            final_risk_budget = None
        else:
            final_risk_budget = attenuate_risk_budget(
                projected_parent,
                child_risk_budget,
            )
            if set(final_risk_budget["tools"]) != set(projected_parent["tools"]):
                raise PermissionError(
                    "risk_budget tool removal must match child allowed_tools"
                )

    child = MissionPassport(
        agent_id=child_agent_id,
        mission=child_mission,
        allowed_tools=sorted(child_tools),
        forbidden_tools=sorted(
            set(parent.get("forbidden_tools", [])) | (parent_tools - child_tools)
        ),
        resource_scope=final_scope,
        max_tool_calls=child_budget,
        max_duration_s=int(requested_ttl),
        delegation_allowed=child_depth > 0,
        max_delegation_depth=child_depth,
        parent_jti=parent["jti"],
        cwd=final_cwd,
        spend_budget=(
            normalize_spend_budget(
                parent["spend_budget"],
                require_lineage_id=True,
            )
            if parent.get("spend_budget") is not None
            else None
        ),
        risk_budget=final_risk_budget,
    )
    child_chain: list[dict[str, str]] = [{"jti": str(parent["jti"])}]
    # Embed parent's own token hash in the chain link. This is ONE of two
    # anchors the verifier consults during cold lineage verification; the
    # other is the trusted_parent_lineage map written to
    # lineage_hashes.json by _record_passport_use (ADR-016). Chain
    # token_hash alone is NOT sufficient to close the multi-hop splice
    # gap: a compromised issuer could fabricate any chain token_hash, so
    # the ancestor's (parent_jti, parent_token_hash) edge must also match
    # the operator-trusted lineage index. See ADR-016 for the two-anchor
    # design; any comment here claiming chain token_hash alone closes the
    # splice gap is stale.
    child_chain[0]["token_hash"] = _token_sha256(parent_token)
    parent_parent_jti = parent.get("parent_jti")
    if parent_parent_jti is not None:
        child_chain[0]["parent_jti"] = str(parent_parent_jti)
        parent_parent_hash = parent.get("parent_token_hash")
        if isinstance(parent_parent_hash, str) and parent_parent_hash:
            child_chain[0]["parent_token_hash"] = parent_parent_hash
    child_chain.extend(parent_chain)
    if len(child_chain) > MAX_DELEGATION_DEPTH:
        raise PermissionError("delegation depth exceeded")
    return issue_passport(
        child,
        private_key,
        ttl_s=requested_ttl,
        extra_claims={
            **_inherited_mic_conformance_claims(parent),
            "parent_token_hash": _token_sha256(parent_token),
            DELEGATION_CHAIN_CLAIM: child_chain,
            "reserved_budget_share": int(child_budget),
        },
    )


def _ttl_from_payload(data: dict[str, Any]) -> int | None:
    if "ttl_s" in data:
        return int(data["ttl_s"])
    if "expires_at" in data:
        reference = int(data.get("issued_at", time.time()))
        ttl = int(data["expires_at"]) - reference
        if ttl <= 0:
            raise ValueError(
                "mission file expires_at must be greater than issued_at/current time"
            )
        return ttl
    return None


def load_mission_file(
    path: str | Path,
) -> tuple[MissionPassport, int | None, dict[str, Any]]:
    mission_path = Path(path).expanduser()
    payload = json.loads(mission_path.read_text(encoding="utf-8"))
    mission = MissionPassport.from_dict(payload)
    ttl_s = _ttl_from_payload(payload)
    return mission, ttl_s, payload
