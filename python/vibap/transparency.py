"""Portable transparency anchors for Ardur Execution Receipts.

The signed receipt JWT is immutable.  Transparency state lives in a sidecar
bundle that starts as ``pending`` and is replaced atomically after an external
log returns verifiable evidence.  Receipt sinks only enqueue local files;
network submission is deliberately left to a separate worker or CLI process.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from jsonschema import Draft202012Validator, ValidationError

from ._specs import transparency_anchor_v01_schema
from .canonical_json import canonical_json_bytes
from .receipt import RECEIPT_JWT_TYPE, assert_receipt_shaped, verify_receipt

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None  # type: ignore[assignment]


ANCHOR_SCHEMA_VERSION = "ardur.transparency_anchor.v0.1"
LOCAL_ENTRY_SCHEMA_VERSION = "ardur.transparency_log_entry.v0.1"
BACKEND_UNCONFIGURED = "unconfigured"
BACKEND_LOCAL_SIGNED = "c2sp-local-v1"
BACKEND_REKOR_V1 = "rekor-v1"
DEFAULT_MAX_REGISTRATION_DELAY_S = 86_400
DEFAULT_NETWORK_TIMEOUT_S = 10.0
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_NOTE_BYTES = 128 * 1024
MAX_NOTE_SIGNATURES = 16


class TransparencyError(ValueError):
    """Base error for malformed anchor data or backend failures."""


class AnchorVerificationError(TransparencyError):
    """Raised when a transparency anchor fails closed."""


class AnchorBackend(Protocol):
    """Backend contract used by the outbox drainer."""

    def submit(
        self,
        pending_bundle: Mapping[str, Any],
        *,
        receipt_private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, Any]:
        """Submit a pending bundle and return the anchored bundle.

        Protocol abstract method; implementations must override.
        """
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AnchorDrainResult:
    anchor_id: str
    status: str
    path: Path
    error: str | None = None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def receipt_subject(receipt_jwt: str) -> dict[str, Any]:
    """Return the exact compact-JWS subject bound by an anchor."""
    token = receipt_jwt.strip()
    if not token or len(token.encode("utf-8")) > MAX_BUNDLE_BYTES:
        raise TransparencyError("receipt JWT is empty or exceeds the anchor size limit")
    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TransparencyError("receipt JWT must be ASCII compact JWS") from exc
    if token.count(".") != 2:
        raise TransparencyError("receipt JWT must contain three compact-JWS segments")
    return {
        "media_type": RECEIPT_JWT_TYPE,
        "digest": {"algorithm": "sha256", "value": _sha256_hex(token_bytes)},
    }


def pending_anchor_bundle(
    receipt_jwt: str,
    *,
    backend_kind: str = BACKEND_UNCONFIGURED,
    queued_at: int | None = None,
) -> dict[str, Any]:
    subject = receipt_subject(receipt_jwt)
    digest = subject["digest"]["value"]
    if backend_kind not in {
        BACKEND_UNCONFIGURED,
        BACKEND_LOCAL_SIGNED,
        BACKEND_REKOR_V1,
    }:
        raise TransparencyError(f"unsupported transparency backend {backend_kind!r}")
    return {
        "schema_version": ANCHOR_SCHEMA_VERSION,
        "anchor_id": f"anchor:{digest}",
        "status": "pending",
        "subject": subject,
        "receipt_jwt": receipt_jwt.strip(),
        "backend": {"kind": backend_kind},
        "queued_at": int(time.time() if queued_at is None else queued_at),
    }


def anchor_store_for_receipt_log(receipt_log_path: str | Path) -> Path:
    path = Path(receipt_log_path).expanduser()
    return path.parent / f"{path.name}.anchors"


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise TransparencyError(
            f"private anchor directory must not be a symlink: {path}"
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise TransparencyError(f"private anchor path is not a directory: {path}")
    path.chmod(0o700)


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    data = canonical_json_bytes(dict(payload)) + b"\n"
    if len(data) > MAX_BUNDLE_BYTES:
        raise TransparencyError("anchor bundle exceeds the size limit")
    _ensure_private_directory(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd: int | None = None
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            # tmp was already consumed by os.replace or a prior cleanup;
            # nothing to unlink.
            pass


def queue_receipt_anchor(
    receipt_jwt: str,
    receipt_log_path: str | Path,
    *,
    backend_kind: str | None = None,
) -> Path:
    """Idempotently create a pending sidecar next to a receipt log."""
    selected_backend = (
        backend_kind
        if backend_kind is not None
        else os.environ.get("ARDUR_TRANSPARENCY_BACKEND", BACKEND_UNCONFIGURED).strip()
        or BACKEND_UNCONFIGURED
    )
    bundle = pending_anchor_bundle(receipt_jwt, backend_kind=selected_backend)
    digest = bundle["subject"]["digest"]["value"]
    store = anchor_store_for_receipt_log(receipt_log_path)
    anchored = store / "anchored" / f"{digest}.json"
    pending = store / "pending" / f"{digest}.json"
    for existing_path in (anchored, pending):
        if not existing_path.exists() and not existing_path.is_symlink():
            continue
        existing = load_anchor_bundle(existing_path)
        _validate_anchor_identity(existing)
        if (
            existing.get("subject") != bundle["subject"]
            or existing.get("receipt_jwt") != bundle["receipt_jwt"]
        ):
            raise TransparencyError("existing anchor does not match the receipt")
        return existing_path
    _atomic_write_json(pending, bundle)
    return pending


def queue_receipt_anchor_best_effort(
    receipt_jwt: str, receipt_log_path: str | Path
) -> bool:
    """Queue an anchor without allowing queue failures to affect governance."""
    try:
        queue_receipt_anchor(receipt_jwt, receipt_log_path)
    except (OSError, TransparencyError):
        return False
    return True


def load_anchor_bundle(path: str | Path) -> dict[str, Any]:
    bundle_path = Path(path).expanduser()
    if bundle_path.is_symlink():
        raise TransparencyError("anchor bundle path must not be a symlink")
    try:
        with bundle_path.open("rb") as handle:
            raw = handle.read(MAX_BUNDLE_BYTES + 1)
        if not raw or len(raw) > MAX_BUNDLE_BYTES:
            raise TransparencyError("anchor bundle is empty or exceeds the size limit")
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        # Never embed raw ``str(exc)`` in the TransparencyError message:
        # ``OSError`` carries filesystem paths / errno, ``JSONDecodeError``
        # carries file offsets. Propagate only the error class for diagnostics.
        raise TransparencyError(
            f"anchor bundle could not be read: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise TransparencyError("anchor bundle must be a JSON object")
    validate_anchor_bundle(payload)
    return payload


def validate_anchor_bundle(bundle: Mapping[str, Any]) -> None:
    """Validate the portable envelope before backend or crypto processing."""
    try:
        Draft202012Validator(transparency_anchor_v01_schema()).validate(dict(bundle))
    except ValidationError as exc:
        raise TransparencyError(
            f"anchor schema violation: {exc.message[:500]}"
        ) from exc


def _validate_pending_bundle(bundle: Mapping[str, Any]) -> str:
    validate_anchor_bundle(bundle)
    if bundle.get("status") != "pending":
        raise TransparencyError("anchor backend accepts pending bundles only")
    return _validate_anchor_identity(bundle)


def _validate_subject(subject: Any, receipt_jwt: str) -> str:
    expected = receipt_subject(receipt_jwt)
    if subject != expected:
        raise AnchorVerificationError(
            "anchor subject does not match the exact receipt JWT"
        )
    return str(expected["digest"]["value"])


def _validate_anchor_identity(bundle: Mapping[str, Any]) -> str:
    receipt_jwt = bundle.get("receipt_jwt")
    if not isinstance(receipt_jwt, str):
        raise AnchorVerificationError("anchor bundle has no receipt JWT")
    digest = _validate_subject(bundle.get("subject"), receipt_jwt)
    if bundle.get("anchor_id") != f"anchor:{digest}":
        raise AnchorVerificationError("anchor id does not match the exact receipt JWT")
    return digest


def _validate_anchored_metadata(bundle: Mapping[str, Any]) -> None:
    backend = bundle.get("backend")
    evidence = bundle.get("evidence")
    if not isinstance(backend, Mapping) or not isinstance(evidence, Mapping):
        raise AnchorVerificationError("anchor backend/evidence is malformed")
    if bundle.get("anchored_at") != evidence.get("integrated_time"):
        raise AnchorVerificationError(
            "anchor time disagrees with the log integration time"
        )
    if backend.get("log_id") != evidence.get("log_id"):
        raise AnchorVerificationError(
            "anchor backend log id disagrees with the evidence"
        )


def _hash_leaf(body: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body).digest()


def _hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = [_hash_leaf(leaf) for leaf in leaves]
    while len(level) > 1:
        next_level: list[bytes] = []
        for offset in range(0, len(level), 2):
            if offset + 1 < len(level):
                next_level.append(_hash_children(level[offset], level[offset + 1]))
            else:
                next_level.append(level[offset])
        level = next_level
    return level[0]


def _merkle_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise TransparencyError("Merkle proof index is outside the tree")
    level = [_hash_leaf(leaf) for leaf in leaves]
    proof: list[bytes] = []
    current_index = index
    while len(level) > 1:
        if current_index % 2:
            proof.append(level[current_index - 1])
        elif current_index + 1 < len(level):
            proof.append(level[current_index + 1])
        next_level: list[bytes] = []
        for offset in range(0, len(level), 2):
            if offset + 1 < len(level):
                next_level.append(_hash_children(level[offset], level[offset + 1]))
            else:
                next_level.append(level[offset])
        current_index //= 2
        level = next_level
    return proof


def verify_inclusion_proof(
    body: bytes,
    *,
    log_index: int,
    tree_size: int,
    hashes_hex: list[str],
    root_hash_hex: str,
) -> None:
    if tree_size <= 0 or log_index < 0 or log_index >= tree_size:
        raise AnchorVerificationError("inclusion proof index/tree size is invalid")
    try:
        expected_root = bytes.fromhex(root_hash_hex)
    except ValueError as exc:
        raise AnchorVerificationError("inclusion proof root hash is not hex") from exc
    if len(expected_root) != hashlib.sha256().digest_size:
        raise AnchorVerificationError("inclusion proof root hash has the wrong length")
    current = _hash_leaf(body)
    index = log_index
    width = tree_size
    proof_index = 0
    while width > 1:
        needs_left = index % 2 == 1
        needs_right = not needs_left and index + 1 < width
        if needs_left or needs_right:
            if proof_index >= len(hashes_hex):
                raise AnchorVerificationError(
                    "inclusion proof is missing a sibling hash"
                )
            try:
                sibling = bytes.fromhex(hashes_hex[proof_index])
            except ValueError as exc:
                raise AnchorVerificationError(
                    "inclusion proof contains a non-hex hash"
                ) from exc
            if len(sibling) != hashlib.sha256().digest_size:
                raise AnchorVerificationError(
                    "inclusion proof hash has the wrong length"
                )
            current = (
                _hash_children(sibling, current)
                if needs_left
                else _hash_children(current, sibling)
            )
            proof_index += 1
        index //= 2
        width = (width + 1) // 2
    if proof_index != len(hashes_hex):
        raise AnchorVerificationError("inclusion proof contains extra sibling hashes")
    if current != expected_root:
        raise AnchorVerificationError(
            "inclusion proof does not reach the signed root hash"
        )


def _public_key_spki(public_key: Any) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _note_key_id(name: str, public_key: Any) -> bytes:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        material = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(name.encode("utf-8") + b"\n\x01" + material).digest()[:4]
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Rekor v1's signed-note implementation predates the generic C2SP
        # name/type construction and uses SHA-256(SPKI)[:4] for ECDSA keys.
        return hashlib.sha256(_public_key_spki(public_key)).digest()[:4]
    raise TransparencyError("unsupported transparency-log public key type")


def _sign_note(note: bytes, signer_name: str, private_key: Any) -> str:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(note)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        digest = hashlib.sha256(note).digest()
        signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    else:
        raise TransparencyError("unsupported transparency-log private key type")
    key_id = _note_key_id(signer_name, private_key.public_key())
    encoded = base64.b64encode(key_id + signature).decode("ascii")
    return note.decode("utf-8") + f"\n\N{EM DASH} {signer_name} {encoded}\n"


def _signed_checkpoint(
    origin: str,
    tree_size: int,
    root_hash: bytes,
    private_key: Any,
    *,
    signer_name: str | None = None,
) -> str:
    if not origin or "\n" in origin:
        raise TransparencyError("checkpoint origin must be one non-empty line")
    selected_signer = origin if signer_name is None else signer_name
    if (
        not selected_signer
        or any(character.isspace() for character in selected_signer)
        or "+" in selected_signer
    ):
        raise TransparencyError("signed-note key name must not contain spaces or plus")
    note = f"{origin}\n{tree_size}\n{base64.b64encode(root_hash).decode('ascii')}\n".encode()
    return _sign_note(note, selected_signer, private_key)


def verify_signed_checkpoint(
    signed_checkpoint: str,
    public_key: Any,
    *,
    expected_origin: str | None = None,
) -> tuple[str, int, bytes]:
    raw = signed_checkpoint.encode("utf-8")
    if len(raw) > MAX_NOTE_BYTES or not signed_checkpoint.endswith("\n"):
        raise AnchorVerificationError("signed checkpoint is oversized or unterminated")
    if any(
        ord(character) < 0x20 and character != "\n" for character in signed_checkpoint
    ):
        raise AnchorVerificationError(
            "signed checkpoint contains a forbidden control character"
        )
    split = signed_checkpoint.rfind("\n\n")
    if split < 0:
        raise AnchorVerificationError("signed checkpoint has no signature separator")
    note_text = signed_checkpoint[: split + 1]
    signature_block = signed_checkpoint[split + 2 :]
    lines = note_text.splitlines()
    if len(lines) < 3 or any(not line for line in lines[:3]):
        raise AnchorVerificationError(
            "checkpoint must contain origin, size, and root hash"
        )
    origin = lines[0]
    if expected_origin is not None and origin != expected_origin:
        raise AnchorVerificationError(
            "checkpoint origin does not match the trusted log"
        )
    size_text = lines[1]
    if (
        not size_text.isascii()
        or not size_text.isdecimal()
        or (len(size_text) > 1 and size_text.startswith("0"))
    ):
        raise AnchorVerificationError("checkpoint tree size is not canonical decimal")
    tree_size = int(size_text)
    try:
        root_hash = base64.b64decode(lines[2], validate=True)
    except binascii.Error as exc:
        raise AnchorVerificationError(
            "checkpoint root hash is not canonical base64"
        ) from exc
    if len(root_hash) != hashlib.sha256().digest_size:
        raise AnchorVerificationError("checkpoint root hash has the wrong length")
    signature_lines = [line for line in signature_block.splitlines() if line]
    if not signature_lines or len(signature_lines) > MAX_NOTE_SIGNATURES:
        raise AnchorVerificationError("checkpoint signature count is invalid")
    note_bytes = note_text.encode("utf-8")
    known_signature_seen = False
    for line in signature_lines:
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[0] != "\N{EM DASH}" or not parts[1]:
            raise AnchorVerificationError("checkpoint signature line is malformed")
        signer_name, encoded = parts[1], parts[2]
        try:
            signature_blob = base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise AnchorVerificationError(
                "checkpoint signature is not canonical base64"
            ) from exc
        if len(signature_blob) < 5:
            raise AnchorVerificationError("checkpoint signature is truncated")
        if signature_blob[:4] != _note_key_id(signer_name, public_key):
            continue
        known_signature_seen = True
        signature = signature_blob[4:]
        try:
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, note_bytes)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                digest = hashlib.sha256(note_bytes).digest()
                public_key.verify(
                    signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                )
            else:
                raise AnchorVerificationError("unsupported checkpoint key type")
        except InvalidSignature as exc:
            raise AnchorVerificationError("checkpoint signature is invalid") from exc
    if not known_signature_seen:
        raise AnchorVerificationError(
            "checkpoint has no signature from the trusted log key"
        )
    return origin, tree_size, root_hash


class LocalSignedLogBackend:
    """Small separately-keyed RFC 6962 log for self-hosted/offline deployments."""

    def __init__(
        self,
        log_path: str | Path,
        private_key: ed25519.Ed25519PrivateKey,
        *,
        origin: str,
        clock: Callable[[], float] = time.time,
        receipt_public_key: ec.EllipticCurvePublicKey | None = None,
    ) -> None:
        self.log_path = Path(log_path).expanduser()
        self.private_key = private_key
        self.origin = origin
        self.clock = clock
        # Optional because this backend is usable with no receipt key at all.
        # When supplied, submissions are checked against it, which is strictly
        # stronger than the structural gate every submission gets.
        self.receipt_public_key = receipt_public_key

    def _read_entries_locked(self) -> list[bytes]:
        if not self.log_path.exists():
            return []
        if self.log_path.stat().st_size > MAX_LOG_BYTES:
            raise TransparencyError("local transparency log exceeds the supported size")
        entries: list[bytes] = []
        bytes_read = 0
        with self.log_path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                bytes_read += len(raw_line)
                if bytes_read > MAX_LOG_BYTES:
                    raise TransparencyError(
                        "local transparency log exceeds the supported size"
                    )
                body = raw_line.rstrip(b"\n")
                if not body:
                    raise TransparencyError(
                        f"local transparency log has an empty line at {line_number}"
                    )
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError as exc:
                    raise TransparencyError(
                        f"local transparency log line {line_number} is invalid JSON"
                    ) from exc
                if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != body:
                    raise TransparencyError(
                        f"local transparency log line {line_number} is not canonical JSON"
                    )
                entries.append(body)
        return entries

    def _assert_submittable(self, receipt_jwt: str) -> None:
        """Refuse to commit anything that is not a receipt.

        A Merkle-tree leaf cannot be withdrawn, so submission is the last
        point at which refusal is free. The Rekor backend already refuses an
        unverifiable receipt before its transport call; the two backends must
        not disagree about what is anchorable just because this one holds no
        key by default.

        Without a receipt public key this is a structural gate only: it stops
        a non-receipt, not a receipt signed by the wrong key. Pass
        ``receipt_public_key`` to get the full check.
        """

        try:
            assert_receipt_shaped(receipt_jwt)
            if self.receipt_public_key is not None:
                verify_receipt(
                    receipt_jwt,
                    self.receipt_public_key,
                    verify_expiry=False,
                    iat_future_skew_s=None,  # type: ignore[arg-type]
                    iat_past_skew_s=None,  # type: ignore[arg-type]
                )
        except jwt.PyJWTError as exc:
            raise TransparencyError(
                f"refusing to anchor an invalid receipt: {type(exc).__name__}"
            ) from exc

    def submit(
        self,
        pending_bundle: Mapping[str, Any],
        *,
        receipt_private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, Any]:
        del receipt_private_key
        digest = _validate_pending_bundle(pending_bundle)
        self._assert_submittable(str(pending_bundle.get("receipt_jwt", "")))
        if fcntl is None:
            raise TransparencyError(
                "local signed log backend requires POSIX file locking"
            )
        integrated_time = int(self.clock())
        entry = {
            "schema_version": LOCAL_ENTRY_SCHEMA_VERSION,
            "subject": pending_bundle["subject"],
            "integrated_time": integrated_time,
        }
        body = canonical_json_bytes(entry)
        _ensure_private_directory(self.log_path.parent)
        if self.log_path.is_symlink():
            raise TransparencyError("local transparency log must not be a symlink")
        lock_path = self.log_path.with_name(f".{self.log_path.name}.lock")
        if lock_path.is_symlink():
            raise TransparencyError("local transparency lock must not be a symlink")
        with lock_path.open("a+b") as lock_handle:
            lock_path.chmod(0o600)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                entries = self._read_entries_locked()
                log_index = len(entries)
                with self.log_path.open("ab") as log_handle:
                    log_handle.write(body + b"\n")
                    log_handle.flush()
                    os.fsync(log_handle.fileno())
                self.log_path.chmod(0o600)
                entries.append(body)
                root_hash = _merkle_root(entries)
                proof = _merkle_proof(entries, log_index)
                checkpoint = _signed_checkpoint(
                    self.origin,
                    len(entries),
                    root_hash,
                    self.private_key,
                )
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        anchored = dict(pending_bundle)
        anchored.update(
            {
                "status": "anchored",
                "backend": {"kind": BACKEND_LOCAL_SIGNED, "log_id": self.origin},
                "anchored_at": integrated_time,
                "evidence": {
                    "body": base64.b64encode(body).decode("ascii"),
                    "integrated_time": integrated_time,
                    "log_id": self.origin,
                    "log_index": log_index,
                    "verification": {
                        "inclusion_proof": {
                            "checkpoint": checkpoint,
                            "hashes": [item.hex() for item in proof],
                            "log_index": log_index,
                            "root_hash": root_hash.hex(),
                            "tree_size": len(entries),
                        }
                    },
                },
            }
        )
        if anchored["subject"]["digest"]["value"] != digest:
            raise TransparencyError("local anchor subject changed during submission")
        validate_anchor_bundle(anchored)
        _validate_anchored_metadata(anchored)
        return anchored


RekorTransport = Callable[[str, bytes, float, int], bytes]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _classify_rekor_transport_error(
    exc: BaseException,
) -> TransparencyError:
    """Map raw urllib/socket errors to clean structured TransparencyError.

    Same defect class as ``cli._kill_switch_classify_error``: the default
    ``str(exc)`` for ``URLError`` includes ``<urlopen error [Errno 61]
    Connection refused>`` (raw CPython urllib internals).  Consumers of
    ``cmd_anchor`` and ``drain_anchor_store`` surface ``str(exc)`` directly
    in JSON ``message`` / ``error`` fields, so we must replace the raw
    representation with a stable, human-readable classification that does not
    leak errno strings, socket paths, or internal exception class names.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return TransparencyError(
            f"Rekor submission failed: HTTP {exc.code} {exc.reason}"
        )
    if isinstance(exc, TimeoutError):
        return TransparencyError("Rekor submission timed out")
    # urllib.error.URLError wraps the real socket error in ``.reason``.
    reason = getattr(exc, "reason", None)
    if isinstance(reason, OSError):
        if reason.errno is not None:
            return TransparencyError(
                f"Rekor submission failed: network error ({reason.errno})"
            )
        return TransparencyError("Rekor submission failed: network error")
    if isinstance(reason, str) and reason.strip():
        return TransparencyError(f"Rekor submission failed: {reason.strip()}")
    return TransparencyError("Rekor submission failed: network error")


def _default_rekor_transport(
    url: str, payload: bytes, timeout: float, max_bytes: int
) -> bytes:
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise _classify_rekor_transport_error(exc) from exc
    if len(data) > max_bytes:
        raise TransparencyError("Rekor response exceeds the size limit")
    return data


class RekorV1Backend:
    """Rekor v1 hashedrekord submitter with an injectable test transport."""

    def __init__(
        self,
        base_url: str = "https://rekor.sigstore.dev",
        *,
        timeout_s: float = DEFAULT_NETWORK_TIMEOUT_S,
        allow_insecure_loopback: bool = False,
        transport: RekorTransport = _default_rekor_transport,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise TransparencyError(
                "Rekor URL must not contain credentials, query, or fragment"
            )
        if parsed.scheme != "https":
            loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            if not (allow_insecure_loopback and parsed.scheme == "http" and loopback):
                raise TransparencyError(
                    "Rekor URL must use HTTPS (HTTP is loopback-test only)"
                )
        if not parsed.hostname:
            raise TransparencyError("Rekor URL must include a hostname")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = float(timeout_s)
        self.transport = transport

    def submit(
        self,
        pending_bundle: Mapping[str, Any],
        *,
        receipt_private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, Any]:
        digest_hex = _validate_pending_bundle(pending_bundle)
        if receipt_private_key is None:
            raise TransparencyError("Rekor submission requires the receipt signing key")
        receipt_jwt = str(pending_bundle.get("receipt_jwt", ""))
        try:
            verify_receipt(
                receipt_jwt,
                receipt_private_key.public_key(),
                verify_expiry=False,
                iat_future_skew_s=None,  # type: ignore[arg-type]
                iat_past_skew_s=None,  # type: ignore[arg-type]
            )
        except jwt.PyJWTError as exc:
            raise TransparencyError(
                f"refusing to submit an invalid receipt: {type(exc).__name__}"
            ) from exc
        digest = bytes.fromhex(digest_hex)
        detached_signature = receipt_private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        public_pem = receipt_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        proposal = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": base64.b64encode(detached_signature).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(public_pem).decode("ascii")
                    },
                },
                "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
            },
        }
        response_bytes = self.transport(
            f"{self.base_url}/api/v1/log/entries",
            canonical_json_bytes(proposal),
            self.timeout_s,
            MAX_BUNDLE_BYTES,
        )
        try:
            response = json.loads(response_bytes)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise TransparencyError("Rekor response is not valid JSON") from exc
        if not isinstance(response, dict) or len(response) != 1:
            raise TransparencyError("Rekor response must contain exactly one log entry")
        entry_uuid, entry = next(iter(response.items()))
        if not isinstance(entry_uuid, str) or not isinstance(entry, dict):
            raise TransparencyError("Rekor response entry is malformed")
        required = {"body", "integratedTime", "logID", "logIndex", "verification"}
        if not required <= set(entry):
            raise TransparencyError("Rekor response is missing inclusion evidence")
        anchored = dict(pending_bundle)
        anchored.update(
            {
                "status": "anchored",
                "backend": {
                    "kind": BACKEND_REKOR_V1,
                    "log_id": entry["logID"],
                    "url": self.base_url,
                    "entry_uuid": entry_uuid,
                },
                "anchored_at": entry["integratedTime"],
                "evidence": {
                    "body": entry["body"],
                    "integrated_time": entry["integratedTime"],
                    "log_id": entry["logID"],
                    "log_index": entry["logIndex"],
                    "verification": entry["verification"],
                },
            }
        )
        validate_anchor_bundle(anchored)
        _validate_anchor_identity(anchored)
        _validate_anchored_metadata(anchored)
        _verify_rekor_body(
            _decode_base64(entry["body"], "Rekor body"),
            receipt_digest_hex=digest_hex,
            receipt_public_key=receipt_private_key.public_key(),
        )
        return anchored


def _decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise AnchorVerificationError(f"{label} must be non-empty base64")
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise AnchorVerificationError(f"{label} is not canonical base64") from exc


def _verify_log_signature(public_key: Any, signature: bytes, message: bytes) -> None:
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            raise AnchorVerificationError("unsupported transparency-log key type")
    except InvalidSignature as exc:
        raise AnchorVerificationError("transparency-log signature is invalid") from exc


def _verify_rekor_body(
    body: bytes,
    *,
    receipt_digest_hex: str,
    receipt_public_key: ec.EllipticCurvePublicKey,
) -> None:
    try:
        entry = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AnchorVerificationError("Rekor body is not valid JSON") from exc
    if (
        not isinstance(entry, dict)
        or entry.get("kind") != "hashedrekord"
        or entry.get("apiVersion") != "0.0.1"
    ):
        raise AnchorVerificationError("Rekor body is not hashedrekord v0.0.1")
    try:
        spec = entry["spec"]
        signature = spec["signature"]
        digest_claim = spec["data"]["hash"]
        detached = _decode_base64(signature["content"], "Rekor detached signature")
        public_pem = _decode_base64(
            signature["publicKey"]["content"], "Rekor public key"
        )
    except (KeyError, TypeError) as exc:
        raise AnchorVerificationError("Rekor hashedrekord body is incomplete") from exc
    if digest_claim != {"algorithm": "sha256", "value": receipt_digest_hex}:
        raise AnchorVerificationError(
            "Rekor hashedrekord digest does not match the receipt"
        )
    try:
        embedded_key = serialization.load_pem_public_key(public_pem)
    except ValueError as exc:
        raise AnchorVerificationError(
            "Rekor hashedrekord public key is invalid"
        ) from exc
    if not isinstance(embedded_key, ec.EllipticCurvePublicKey):
        raise AnchorVerificationError("Rekor hashedrekord public key must be EC")
    if _public_key_spki(embedded_key) != _public_key_spki(receipt_public_key):
        raise AnchorVerificationError(
            "Rekor hashedrekord key does not match the receipt trust key"
        )
    try:
        receipt_public_key.verify(
            detached,
            bytes.fromhex(receipt_digest_hex),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature as exc:
        raise AnchorVerificationError(
            "Rekor detached receipt-digest signature is invalid"
        ) from exc


def _normalise_inclusion_proof(
    verification: Any,
) -> tuple[str, list[str], int, str, int]:
    if not isinstance(verification, dict):
        raise AnchorVerificationError("anchor verification material must be an object")
    proof = verification.get("inclusion_proof", verification.get("inclusionProof"))
    if not isinstance(proof, dict):
        raise AnchorVerificationError("anchor has no inclusion proof")
    checkpoint = proof.get("checkpoint")
    hashes_hex = proof.get("hashes")
    log_index = proof.get("log_index", proof.get("logIndex"))
    root_hash = proof.get("root_hash", proof.get("rootHash"))
    tree_size = proof.get("tree_size", proof.get("treeSize"))
    if (
        not isinstance(checkpoint, str)
        or not isinstance(hashes_hex, list)
        or not all(isinstance(item, str) for item in hashes_hex)
    ):
        raise AnchorVerificationError(
            "inclusion proof checkpoint or hash path is malformed"
        )
    if isinstance(log_index, bool) or not isinstance(log_index, int):
        raise AnchorVerificationError("inclusion proof log index must be an integer")
    if (
        not isinstance(root_hash, str)
        or isinstance(tree_size, bool)
        or not isinstance(tree_size, int)
    ):
        raise AnchorVerificationError("inclusion proof root/tree size is malformed")
    return checkpoint, hashes_hex, log_index, root_hash, tree_size


def verify_anchor_bundle(
    bundle: Mapping[str, Any],
    *,
    receipt_public_key: ec.EllipticCurvePublicKey,
    log_public_key: Any,
    max_registration_delay_s: int | None = DEFAULT_MAX_REGISTRATION_DELAY_S,
    allowed_clock_skew_s: int = 300,
) -> dict[str, Any]:
    """Verify a portable anchor without contacting the transparency service."""
    if max_registration_delay_s is not None and (
        isinstance(max_registration_delay_s, bool)
        or not isinstance(max_registration_delay_s, int)
        or max_registration_delay_s < 0
    ):
        raise AnchorVerificationError(
            "maximum registration delay must be a non-negative integer"
        )
    if (
        isinstance(allowed_clock_skew_s, bool)
        or not isinstance(allowed_clock_skew_s, int)
        or allowed_clock_skew_s < 0
    ):
        raise AnchorVerificationError(
            "allowed clock skew must be a non-negative integer"
        )
    try:
        validate_anchor_bundle(bundle)
    except TransparencyError as exc:
        raise AnchorVerificationError(str(exc)) from exc
    if bundle.get("schema_version") != ANCHOR_SCHEMA_VERSION:
        raise AnchorVerificationError("unsupported anchor schema version")
    if bundle.get("status") != "anchored":
        raise AnchorVerificationError(
            f"receipt is not anchored (status={bundle.get('status')!r})"
        )
    receipt_jwt = str(bundle["receipt_jwt"])
    receipt_digest_hex = _validate_anchor_identity(bundle)
    _validate_anchored_metadata(bundle)
    try:
        claims = verify_receipt(
            receipt_jwt,
            receipt_public_key,
            verify_expiry=False,
            iat_future_skew_s=None,  # type: ignore[arg-type]
            iat_past_skew_s=None,  # type: ignore[arg-type]
        )
    except jwt.PyJWTError as exc:
        raise AnchorVerificationError(
            f"receipt signature/schema verification failed: {type(exc).__name__}"
        ) from exc
    backend = bundle.get("backend")
    evidence = bundle.get("evidence")
    if not isinstance(backend, dict) or not isinstance(evidence, dict):
        raise AnchorVerificationError("anchor backend/evidence is malformed")
    backend_kind = backend.get("kind")
    if backend_kind not in {BACKEND_LOCAL_SIGNED, BACKEND_REKOR_V1}:
        raise AnchorVerificationError(f"unsupported anchored backend {backend_kind!r}")
    body = _decode_base64(evidence.get("body"), "anchor body")
    integrated_time = evidence.get("integrated_time")
    log_index = evidence.get("log_index")
    log_id = evidence.get("log_id")
    if (
        isinstance(integrated_time, bool)
        or not isinstance(integrated_time, int)
        or integrated_time < 0
    ):
        raise AnchorVerificationError(
            "anchor integrated time must be a non-negative integer"
        )
    if isinstance(log_index, bool) or not isinstance(log_index, int) or log_index < 0:
        raise AnchorVerificationError("anchor log index must be a non-negative integer")
    if not isinstance(log_id, str) or not log_id:
        raise AnchorVerificationError("anchor log id must be non-empty")
    checkpoint, hashes_hex, proof_index, root_hash_hex, tree_size = (
        _normalise_inclusion_proof(evidence.get("verification"))
    )
    if proof_index != log_index:
        raise AnchorVerificationError(
            "anchor log index disagrees with the inclusion proof"
        )
    checkpoint_origin, checkpoint_size, checkpoint_root = verify_signed_checkpoint(
        checkpoint,
        log_public_key,
        expected_origin=log_id if backend_kind == BACKEND_LOCAL_SIGNED else None,
    )
    if checkpoint_size != tree_size or checkpoint_root.hex() != root_hash_hex.lower():
        raise AnchorVerificationError(
            "inclusion proof does not match the signed checkpoint"
        )
    verify_inclusion_proof(
        body,
        log_index=log_index,
        tree_size=tree_size,
        hashes_hex=hashes_hex,
        root_hash_hex=root_hash_hex,
    )
    if backend_kind == BACKEND_LOCAL_SIGNED:
        try:
            local_entry = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AnchorVerificationError(
                "local transparency entry is invalid JSON"
            ) from exc
        expected_entry = {
            "schema_version": LOCAL_ENTRY_SCHEMA_VERSION,
            "subject": bundle["subject"],
            "integrated_time": integrated_time,
        }
        if local_entry != expected_entry or canonical_json_bytes(local_entry) != body:
            raise AnchorVerificationError(
                "local transparency entry does not bind the anchor subject"
            )
    else:
        _verify_rekor_body(
            body,
            receipt_digest_hex=receipt_digest_hex,
            receipt_public_key=receipt_public_key,
        )
        verification = evidence["verification"]
        set_value = verification.get(
            "signed_entry_timestamp", verification.get("signedEntryTimestamp")
        )
        signed_entry_timestamp = _decode_base64(
            set_value, "Rekor signed entry timestamp"
        )
        set_payload = canonical_json_bytes(
            {
                "body": evidence["body"],
                "integratedTime": integrated_time,
                "logIndex": log_index,
                "logID": log_id,
            }
        )
        _verify_log_signature(log_public_key, signed_entry_timestamp, set_payload)
    receipt_iat = int(claims["iat"])
    if integrated_time + allowed_clock_skew_s < receipt_iat:
        raise AnchorVerificationError(
            "log integrated the receipt before its claimed issuance time"
        )
    registration_delay = integrated_time - receipt_iat
    if (
        max_registration_delay_s is not None
        and registration_delay > max_registration_delay_s
    ):
        raise AnchorVerificationError(
            f"receipt exceeded the maximum registration delay ({registration_delay}s > {max_registration_delay_s}s)"
        )
    return {
        "valid": True,
        "schema_version": ANCHOR_SCHEMA_VERSION,
        "anchor_id": bundle.get("anchor_id"),
        "backend": backend_kind,
        "log_id": log_id,
        "checkpoint_origin": checkpoint_origin,
        "tree_size": tree_size,
        "log_index": log_index,
        "integrated_time": integrated_time,
        "receipt_id": claims["receipt_id"],
        "receipt_digest": f"sha256:{receipt_digest_hex}",
        "registration_delay_s": registration_delay,
    }


def drain_anchor_store(
    store_path: str | Path,
    backend: AnchorBackend,
    *,
    receipt_private_key: ec.EllipticCurvePrivateKey | None = None,
) -> list[AnchorDrainResult]:
    """Submit pending sidecars and atomically move successful proofs."""
    store = Path(store_path).expanduser()
    pending_dir = store / "pending"
    anchored_dir = store / "anchored"
    if not pending_dir.exists():
        return []
    _ensure_private_directory(anchored_dir)
    results: list[AnchorDrainResult] = []
    for pending_path in sorted(pending_dir.glob("*.json")):
        try:
            pending = load_anchor_bundle(pending_path)
            anchored = backend.submit(
                pending,
                receipt_private_key=receipt_private_key,
            )
            validate_anchor_bundle(anchored)
            if anchored.get("status") != "anchored":
                raise TransparencyError(
                    "anchor backend did not return an anchored bundle"
                )
            digest = _validate_anchor_identity(anchored)
            _validate_anchored_metadata(anchored)
            destination = anchored_dir / f"{digest}.json"
            _atomic_write_json(destination, anchored)
            pending_path.unlink()
            results.append(
                AnchorDrainResult(
                    anchor_id=str(anchored.get("anchor_id", "")),
                    status="anchored",
                    path=destination,
                )
            )
        except (OSError, TransparencyError) as exc:
            # Use exception class name only to avoid leaking filesystem
            # paths / errno from ``OSError`` or ``TransparencyError`` text.
            results.append(
                AnchorDrainResult(
                    anchor_id=pending_path.stem,
                    status="pending",
                    path=pending_path,
                    error=type(exc).__name__,
                )
            )
    return results
