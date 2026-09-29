"""Local-only Ardur adapter for Gemini CLI hook/context proof fixtures.

This module intentionally implements a narrow no-provider proof surface: it can
write a local Gemini settings/context fixture, consume local hook-shaped JSON,
append signed Ardur receipts, and render redacted shareable reports. It does not
claim live Gemini enforcement, provider-side hidden action visibility, or
server-side tool-call capture.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .claude_code_hook import HOOK_INPUT_MAX_CHARS, MissionLoadError, load_active_passport
from .denial import DenialReason
from .passport import DEFAULT_HOME, _ensure_default_home_dir, load_report_public_key, load_private_key, resolve_keys_dir
from .receipt import build_receipt, sign_receipt, verify_chain
from .shareable_redaction import path_aliases, redact_local_paths

PASSPORT_ENV_VAR = "ARDUR_MISSION_PASSPORT"
CHAIN_DIR_ENV_VAR = "ARDUR_GEMINI_HOOK_DIR"
DEFAULT_GEMINI_FIXTURE_HOME = DEFAULT_HOME / "gemini-cli-fixture" / ".gemini"
DEFAULT_CHAIN_DIR = DEFAULT_HOME / "gemini-cli-hook"
CHAIN_FILENAME = "receipts.jsonl"
HOOK_VERIFIER_ID = "ardur-gemini-cli-hook"
UNKNOWN_BOUNDARIES = (
    "provider_hidden_actions",
    "provider_server_side_tool_calls",
    "gemini_cli_hook_schema_drift",
)
SENSITIVE_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|credential|authorization|cookie|session[_-]?key)",
    re.IGNORECASE,
)
_SAFE_TRACE_DIR_ID_RE = re.compile(r"^gemini-[a-f0-9]{32}$")


@dataclass(frozen=True)
class ChainState:
    chain_dir: Path
    trace_id: str
    trace_dir_id: str

    @property
    def file(self) -> Path:
        return self.chain_dir / self.trace_dir_id / CHAIN_FILENAME

    @property
    def lock_file(self) -> Path:
        return self.chain_dir / self.trace_dir_id / ".lock"


class FixtureProjectDirError(ValueError):
    """Raised when a fixture project path cannot safely receive context files.

    A ``ValueError`` subclass so it is still caught by the generic handler, but
    distinct enough for the CLI to emit a structured, sanitized failure response
    instead of the raw exception text. Carries a stable ``condition`` attribute
    so callers can distinguish empty/whitespace, symlink, and existing-file
    failures without parsing exception prose.
    """

    def __init__(self, detail: str, *, condition: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.condition = condition


class FixturePathError(ValueError):
    """Raised when a fixture path argument is not a directory (existing file, dangling symlink, etc.)."""

    def __init__(self, detail: str, *, condition: str) -> None:
        super().__init__(detail)
        self.condition = condition
        self.detail = detail


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest_payload(payload: Any) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "canonicalization": "jcs-rfc8785",
        "value": hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
    }


def _digest_file(path: Path) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "value": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _default_gemini_fixture_home() -> Path:
    """Return the isolated default Gemini fixture home.

    The default deliberately lives under Ardur/VIBAP local state rather than
    the caller's real ``~/.gemini``. Operators can still target a real Gemini
    home explicitly with ``--home`` when they intend to mutate that install.
    """
    if "VIBAP_HOME" not in os.environ:
        return DEFAULT_GEMINI_FIXTURE_HOME
    ardur_home = Path(os.environ["VIBAP_HOME"]).expanduser()
    return ardur_home / "gemini-cli-fixture" / ".gemini"


def _without_empty_values(payload: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or value == "":
            continue
        if isinstance(value, Mapping):
            nested = _without_empty_values(value)
            if nested:
                clean[key] = nested
            continue
        if isinstance(value, list):
            nested_list = [item for item in value if item not in (None, "")]
            if nested_list:
                clean[key] = nested_list
            continue
        clean[key] = value
    return clean


def _external_trace_id(raw: str) -> str:
    value = str(raw or "").strip()
    return value or "gemini:trace-unknown"


def _trace_dir_id(trace_id: str) -> str:
    """Map untrusted external trace material to a single safe path segment."""
    digest = hashlib.sha256(_external_trace_id(trace_id).encode("utf-8")).hexdigest()[:32]
    value = f"gemini-{digest}"
    if not _SAFE_TRACE_DIR_ID_RE.fullmatch(value):  # pragma: no cover - defensive invariant
        raise ValueError("internal trace directory id is not path-safe")
    return value


def _ensure_under_chain_root(*, chain_root: Path, path: Path) -> None:
    root = chain_root.resolve(strict=False)
    candidate = path.resolve(strict=False)
    if not candidate.is_relative_to(root):
        raise ValueError(f"Gemini receipt path escapes chain directory: {candidate}")


def _trace_id_from_input(hook_input: Mapping[str, Any], claims: Mapping[str, Any]) -> str:
    override = os.environ.get("ARDUR_TRACE_ID", "").strip()
    if override:
        return _external_trace_id(override)
    return _external_trace_id(str(hook_input.get("session_id") or claims.get("jti") or ""))


def resolve_chain_state(*, trace_id: str) -> ChainState:
    base = Path(os.environ.get(CHAIN_DIR_ENV_VAR, str(DEFAULT_CHAIN_DIR))).expanduser().resolve(strict=False)
    # When the chain dir falls through to the DEFAULT_HOME-derived default,
    # materialise the home with 0o700 before creating trace directories.
    if CHAIN_DIR_ENV_VAR not in os.environ:
        _ensure_default_home_dir()
    state = ChainState(chain_dir=base, trace_id=trace_id, trace_dir_id=_trace_dir_id(trace_id))
    _ensure_under_chain_root(chain_root=base, path=state.file)
    _ensure_under_chain_root(chain_root=base, path=state.lock_file)
    state.file.parent.mkdir(parents=True, exist_ok=True)
    return state


@contextmanager
def _locked(state: ChainState):
    state.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(state.lock_file, "a+b") as fd:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)


def _append_receipt_unlocked(state: ChainState, signed_jwt: str) -> None:
    with open(state.file, "a", encoding="utf-8") as f:
        f.write(signed_jwt.strip() + "\n")
    from .transparency import queue_receipt_anchor_best_effort

    queue_receipt_anchor_best_effort(signed_jwt, state.file)


def _previous_receipt_hash_unlocked(state: ChainState) -> str | None:
    if not state.file.exists():
        return None
    with open(state.file, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return None
        read_size = min(size, 16 * 1024)
        f.seek(-read_size, os.SEEK_END)
        tail = f.read(read_size).decode("utf-8", errors="replace")
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    if not lines:
        return None
    return hashlib.sha256(lines[-1].encode("utf-8")).hexdigest()


def _redact_sensitive_values(value: Any) -> Any:
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if SENSITIVE_KEY_RE.search(key) and not (
                key.lower().endswith("_count") and type(raw_value) is int
            ):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = _redact_sensitive_values(raw_value)
        return clean
    if isinstance(value, list):
        return [_redact_sensitive_values(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive_values(item) for item in value]
    return value


def _root_pairs(mapping: Mapping[str, str | Path | None]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for label, path in mapping.items():
        placeholder = f"<{label}>"
        for alias in path_aliases(path):
            pairs.append((alias, placeholder))
    # Replace longest aliases first so /private/var/... wins over /private.
    return sorted(set(pairs), key=lambda item: len(item[0]), reverse=True)


def _shareable_redact(value: Any, *, roots: Mapping[str, str | Path | None]) -> Any:
    return redact_local_paths(_redact_sensitive_values(value), root_pairs=_root_pairs(roots))


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        # Best-effort local fixture hardening; writing already succeeded.
        pass


def _validate_fixture_project_dir(project: Path) -> None:
    raw = str(project)
    if not raw.strip():
        raise FixtureProjectDirError(
            "fixture project directory must not be empty or whitespace-only",
            condition="gemini_cli_fixture_project_dir_empty",
        )
    if project.is_symlink() and not project.exists():
        raise FixtureProjectDirError(
            "fixture project directory is a dangling symlink",
            condition="gemini_cli_fixture_project_dir_not_directory",
        )
    if project.exists() and not project.is_dir():
        raise FixtureProjectDirError(
            "fixture project directory must be a directory",
            condition="gemini_cli_fixture_project_dir_not_directory",
        )


def _validate_fixture_path_not_file(path: Path, *, label: str, condition: str) -> None:
    """Fail closed when a fixture path argument is an existing non-directory.

    Catches: regular files, dangling symlinks, broken symlinks, and any
    existing filesystem entry that is not a directory.
    """
    if path.is_symlink() and not path.exists():
        raise FixturePathError(
            f"{label} is a dangling symlink",
            condition=condition,
        )
    if path.exists() and not path.is_dir():
        raise FixturePathError(
            f"{label} is not a directory",
            condition=condition,
        )


def _validate_fixture_path_parents_not_dangling(
    path: Path,
    *,
    dangling_condition: str,
    not_dir_condition: str,
) -> None:
    """Reject a fixture path whose parent chain crosses a dangling symlink or
    an existing non-directory, BEFORE ``Path.resolve()`` / ``mkdir(parents=True)``
    follows the link and silently materialises the missing target.

    Mirrors ``personal_hub.validate_personal_home_path_components``: walk each
    *parent* component of the un-resolved expanded path and reject when any
    parent is a dangling symlink (``parent.is_symlink() and not
    parent.exists()``) or an existing non-directory (regular file, socket,
    block device, etc.).

    Operating on the un-resolved path is essential because ``.resolve()``
    collapses the symlink chain before the leaf-only check in
    ``_validate_fixture_path_not_file`` can see it.

    The direct dangling-symlink leaf case is still rejected by
    ``_validate_fixture_path_not_file``; this helper deliberately does not
    duplicate that so callers keep firing the leaf-specific condition.
    """
    for parent in path.parents:
        is_symlink = parent.is_symlink()
        exists = parent.exists()
        if is_symlink and not exists:
            raise FixturePathError(
                "home parent component is a dangling symlink",
                condition=dangling_condition,
            )
        if exists and not parent.is_dir():
            raise FixturePathError(
                "home parent component is not a directory",
                condition=not_dir_condition,
            )


def _fixture_path_failure_response(*, condition: str, label: str, arg_name: str) -> dict[str, Any]:
    is_empty = condition.endswith("_empty")
    if is_empty:
        message = f"Gemini CLI fixture {label} is empty."
        detail = (
            f"The {arg_name} argument is empty or whitespace-only. "
            f"Provide a directory path where Ardur can write fixture artifacts."
        )
        step_detail = f"Replace <{label}> with a directory path (not empty, whitespace, a file, or a symlink)."
    else:
        message = f"Gemini CLI fixture {label} is not a directory."
        detail = (
            f"The {arg_name} argument points at an existing non-directory. "
            f"Use an existing directory or a new directory path that Ardur can create."
        )
        step_detail = f"Replace <{label}> with a directory path, not a regular file."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": [
            {
                "condition": condition,
                "action": f"rerun_gemini_fixture_with_{label.replace(' ', '_')}",
                "command": f"ardur gemini-cli-fixture {arg_name} <{label}>",
                "detail": step_detail,
            }
        ],
    }


def fixture_project_dir_failure_response(condition: str = "gemini_cli_fixture_project_dir_not_directory") -> dict[str, Any]:
    """Structured failure response for an invalid ``--project-dir`` argument.

    Mirrors the fixture path-failure convention: a stable ``condition``/
    ``error`` pair, a human-readable ``message`` with no raw exception text or
    local paths, a ``detail`` explaining how to choose a valid directory, and
    placeholder-only ``next_steps``.
    """

    messages = {
        "gemini_cli_fixture_project_dir_empty": (
            "Gemini CLI fixture project directory is empty."
        ),
        "gemini_cli_fixture_project_dir_not_directory": (
            "Gemini CLI fixture project directory is not a directory."
        ),
    }
    details = {
        "gemini_cli_fixture_project_dir_empty": (
            "The --project-dir argument is empty or whitespace-only. "
            "Provide a project directory path where Ardur can write GEMINI.md."
        ),
        "gemini_cli_fixture_project_dir_not_directory": (
            "The --project-dir argument points at an existing non-directory. "
            "Use an existing project directory or a new directory path that Ardur can create."
        ),
    }
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": messages.get(condition, "Gemini CLI fixture project directory is invalid."),
        "detail": details.get(condition, "Provide a project directory path for the --project-dir argument."),
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_gemini_fixture_with_project_directory",
                "command": "ardur gemini-cli-fixture --project-dir <your-project>",
                "detail": "Replace <your-project> with a directory path (new or existing, not a file, symlink, or empty value).",
            }
        ],
    }


def build_local_fixture(
    *,
    home: str | Path | None = None,
    project_dir: str | Path | None = None,
    chain_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Write a private local Gemini settings/context fixture.

    The fixture is deliberately a local proof harness. It records the command a
    user can wire into Gemini CLI hook/config surfaces, but does not mutate a
    real Gemini install unless the caller explicitly points ``home`` there.
    """
    # Reject empty/whitespace-only path arguments before Path() normalises them
    # to the current working directory. Path("") silently becomes Path(".") so
    # the empty input would otherwise pollute CWD with fixture artifacts.
    if home is not None and not str(home).strip():
        raise FixturePathError(
            "home is empty or whitespace-only",
            condition="gemini_cli_fixture_home_empty",
        )
    if chain_dir is not None and not str(chain_dir).strip():
        raise FixturePathError(
            "chain dir is empty or whitespace-only",
            condition="gemini_cli_fixture_chain_dir_empty",
        )
    if keys_dir is not None and not str(keys_dir).strip():
        raise FixturePathError(
            "keys dir is empty or whitespace-only",
            condition="gemini_cli_fixture_keys_dir_empty",
        )
    gemini_home_raw = Path(home or _default_gemini_fixture_home()).expanduser()
    project_raw_value = str(project_dir) if project_dir is not None else ""
    if not project_raw_value.strip():
        raise FixtureProjectDirError(
            "fixture project directory must not be empty or whitespace-only",
            condition="gemini_cli_fixture_project_dir_empty",
        )
    project_raw = Path(project_raw_value).expanduser()
    ardur_chain_raw = Path(chain_dir or DEFAULT_CHAIN_DIR).expanduser()
    # Validate parent components for dangling symlinks / non-directory parents
    # BEFORE the leaf-only check and resolve() collapse the symlink chain.
    _validate_fixture_path_parents_not_dangling(
        gemini_home_raw,
        dangling_condition="gemini_cli_fixture_home_dangling_symlink_parent",
        not_dir_condition="gemini_cli_fixture_home_parent_not_directory",
    )
    _validate_fixture_path_parents_not_dangling(
        ardur_chain_raw,
        dangling_condition="gemini_cli_fixture_chain_dir_dangling_symlink_parent",
        not_dir_condition="gemini_cli_fixture_chain_dir_parent_not_directory",
    )
    # Validate raw paths for dangling symlinks before resolve() follows them.
    _validate_fixture_path_not_file(gemini_home_raw, label="home", condition="gemini_cli_fixture_home_not_directory")
    _validate_fixture_path_not_file(ardur_chain_raw, label="chain dir", condition="gemini_cli_fixture_chain_dir_not_directory")
    _validate_fixture_project_dir(project_raw)
    if keys_dir is not None:
        keys_raw = Path(keys_dir).expanduser()
        _validate_fixture_path_not_file(keys_raw, label="keys dir", condition="gemini_cli_fixture_keys_dir_not_directory")
    gemini_home = gemini_home_raw.resolve(strict=False)
    project = project_raw.resolve(strict=False)
    ardur_chain = ardur_chain_raw.resolve(strict=False)
    # When chain_dir falls through to the DEFAULT_HOME-derived default,
    # materialise the home with 0o700 before creating directories inside it.
    if chain_dir is None:
        _ensure_default_home_dir()
    signing_keys = resolve_keys_dir(keys_dir)

    settings_path = gemini_home / "settings.json"
    extension_dir = gemini_home / "extensions" / "ardur-local"
    extension_path = extension_dir / "gemini-extension.json"
    project_context_path = project / "GEMINI.md"

    hook_command = "ardur gemini-cli-hook --phase pre --keys-dir " + str(signing_keys)
    settings = {
        "schemaVersion": "ardur.gemini_cli.settings_fixture.v0.1",
        "mcpServers": {},
        "hooks": {
            "preToolCall": [hook_command],
        },
        "ardur": {
            "mode": "local-proof-only",
            "chainDir": str(ardur_chain),
            "missionPassportEnv": PASSPORT_ENV_VAR,
            "unknownBoundaries": list(UNKNOWN_BOUNDARIES),
        },
    }
    extension = {
        "name": "ardur-local-proof",
        "version": "0.1.0",
        "description": "Local-only Ardur receipt hook fixture for Gemini CLI.",
        "hooks": {"preToolCall": hook_command},
    }
    context_text = "\n".join(
        [
            "# Gemini local Ardur context fixture",
            "",
            "This project is configured for a local-only Ardur proof harness.",
            "The hook emits signed local receipts for visible tool-boundary events.",
            "It does not claim provider-hidden reasoning or server-side tool-call visibility.",
            "",
        ]
    )

    _write_private_text(settings_path, json.dumps(settings, indent=2, sort_keys=True) + "\n")
    _write_private_text(extension_path, json.dumps(extension, indent=2, sort_keys=True) + "\n")
    project.mkdir(parents=True, exist_ok=True)
    _write_private_text(project_context_path, context_text)
    ardur_chain.mkdir(parents=True, exist_ok=True)
    signing_keys.mkdir(parents=True, exist_ok=True)

    return {
        "schema_version": "ardur.gemini_cli.local_fixture.v0.1",
        "home": str(gemini_home),
        "project_dir": str(project),
        "chain_dir": str(ardur_chain),
        "keys_dir": str(signing_keys),
        "settings_path": str(settings_path),
        "extension_path": str(extension_path),
        "project_context_path": str(project_context_path),
        "hook_command": hook_command,
    }


def build_shareable_context(fixture: Mapping[str, Any]) -> dict[str, Any]:
    settings_path = Path(str(fixture["settings_path"]))
    extension_path = Path(str(fixture["extension_path"]))
    project_context_path = Path(str(fixture["project_context_path"]))
    roots = {
        "GEMINI_HOME": fixture.get("home"),
        "GEMINI_PROJECT": fixture.get("project_dir"),
        "ARDUR_GEMINI_CHAIN": fixture.get("chain_dir"),
        "ARDUR_KEYS": fixture.get("keys_dir"),
    }
    payload = {
        "schema_version": "ardur.gemini_cli.local_context.v0.1",
        "claim_boundary": {
            "scope": "local_fixture_only",
            "verified": [
                "settings/context fixture files written locally",
                "hook command points at Ardur receipt adapter",
                "shareable artifact carries digests instead of raw secrets",
            ],
            "not_claimed": [
                "live Gemini enforcement",
                "provider-hidden reasoning visibility",
                "server-side tool-call capture",
                "sandbox isolation",
            ],
        },
        "unknown_boundaries": list(UNKNOWN_BOUNDARIES),
        "host_context": {
            "settings_digest": _digest_file(settings_path),
            "extension_digest": _digest_file(extension_path),
            "project_context_digest": _digest_file(project_context_path),
            "hook_command": fixture.get("hook_command"),
        },
        "artifacts": {
            "settings_path": fixture.get("settings_path"),
            "extension_path": fixture.get("extension_path"),
            "project_context_path": fixture.get("project_context_path"),
        },
    }
    return _shareable_redact(payload, roots=roots)


_MAPPED_TOOLS: dict[str, dict[str, str]] = {
    "read_file": {"action_class": "read", "resource_family": "filesystem", "side_effect_class": "none"},
    "readfile": {"action_class": "read", "resource_family": "filesystem", "side_effect_class": "none"},
    "list_directory": {"action_class": "read", "resource_family": "filesystem", "side_effect_class": "none"},
    "list_files": {"action_class": "read", "resource_family": "filesystem", "side_effect_class": "none"},
    "write_file": {"action_class": "write", "resource_family": "filesystem", "side_effect_class": "internal_write"},
    "edit_file": {"action_class": "write", "resource_family": "filesystem", "side_effect_class": "internal_write"},
    "delete_file": {"action_class": "write", "resource_family": "filesystem", "side_effect_class": "internal_write"},
    "run_shell_command": {"action_class": "execute", "resource_family": "process", "side_effect_class": "state_change"},
    "shell": {"action_class": "execute", "resource_family": "process", "side_effect_class": "state_change"},
    "web_fetch": {"action_class": "read", "resource_family": "network_resource", "side_effect_class": "none"},
    "web_search": {"action_class": "search", "resource_family": "network_resource", "side_effect_class": "none"},
}
_TARGET_KEYS = (
    "path",
    "file_path",
    "filename",
    "directory",
    "url",
    "uri",
    "target",
    "resource",
    "destination",
    "dest",
    "to",
    "command",
    "query",
    "opaque_target",
)


def _normalize_tool_args(hook_input: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("tool_args", "tool_input", "args", "arguments", "parameters"):
        value = hook_input.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _target_from_args(tool_name: str, args: Mapping[str, Any]) -> str:
    for key in _TARGET_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return tool_name


def _map_tool_call(tool_name: str, tool_args: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    normalized_name = str(tool_name or "").strip()
    key = normalized_name.lower().replace("-", "_")
    mapping = _MAPPED_TOOLS.get(key)
    target = _target_from_args(normalized_name, tool_args)
    base = dict(tool_args)
    if mapping is None:
        return (
            {
                **base,
                "tool_name": normalized_name,
                "target": target,
                "action_class": "observe",
                "resource_family": "general",
                "content_class": "unknown_tool_invocation",
                "content_provenance": "gemini_cli_hook_input",
                "side_effect_class": "none",
                "visibility": "tool_boundary_only",
                "sensitivity": "unknown",
                "instruction_bearing": False,
                "budget_delta": 1,
            },
            "unknown",
        )
    if key in {"run_shell_command", "shell"}:
        # Mirror the existing Bash boundary: a visible command string is not a
        # full account of subprocess side effects, so it remains tool-boundary
        # evidence even when policy allows the launch.
        visibility = "tool_boundary_only"
        content_class = "command"
    elif mapping["resource_family"] == "filesystem":
        visibility = "full"
        content_class = "filesystem_path"
    else:
        visibility = "tool_boundary_only"
        content_class = mapping["resource_family"]
    return (
        {
            **base,
            "tool_name": normalized_name,
            "target": target,
            "action_class": mapping["action_class"],
            "resource_family": mapping["resource_family"],
            "content_class": content_class,
            "content_provenance": "gemini_cli_hook_input",
            "side_effect_class": mapping["side_effect_class"],
            "visibility": visibility,
            "sensitivity": "unknown",
            "instruction_bearing": False,
            "budget_delta": 5 if mapping["side_effect_class"] != "none" else 1,
        },
        "mapped",
    )


def _host_context_summary(host_context: Mapping[str, Any]) -> dict[str, Any]:
    clean = _redact_sensitive_values(dict(host_context))
    summary: dict[str, Any] = {}
    for key in ("settings", "policy", "extension", "environment"):
        value = clean.get(key)
        if isinstance(value, Mapping):
            summary[f"{key}_digest"] = _digest_payload(value)
    if not summary and clean:
        summary["payload_digest"] = _digest_payload(clean)
    return summary


def _gemini_measurements(
    hook_input: Mapping[str, Any],
    *,
    trace_id: str,
    tool_name: str,
    mapped_tool_name: str,
    mapping_confidence: str,
    receipt_id: str | None = None,
    verdict: str | None = None,
) -> dict[str, Any]:
    host_context = hook_input.get("host_context")
    if not isinstance(host_context, Mapping):
        host_context = {}
    unknown_boundaries: list[str] = list(UNKNOWN_BOUNDARIES)
    if mapping_confidence == "unknown":
        unknown_boundaries.append("unmapped_gemini_tool_schema")
    return _without_empty_values(
        {
            "schema_version": "ardur.gemini_cli.measurements.v0.1",
            "trace_id": trace_id,
            "gemini_session_id": str(hook_input.get("session_id", "") or ""),
            "event_name": str(hook_input.get("event_name", "") or ""),
            "cwd": str(hook_input.get("cwd", "") or ""),
            "tool_name": tool_name,
            "mapped_policy_tool": mapped_tool_name,
            "mapping_confidence": mapping_confidence,
            "host_context": _host_context_summary(host_context),
            "unknown_boundaries": unknown_boundaries,
            "claim_boundary": "visible Gemini CLI hook/tool-boundary evidence only",
            "verdict": verdict,
            "receipt_id": receipt_id,
        }
    )


def _build_policy_event(
    *,
    claims: Mapping[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    trace_id: str,
    phase: str,
):
    from .proxy import Decision, PolicyEvent, _receipt_step_id

    timestamp = _utc_timestamp()
    step_id = _receipt_step_id(str(claims.get("jti", "")), timestamp, tool_name, arguments)
    return PolicyEvent(
        timestamp=timestamp,
        step_id=f"{step_id}:{phase}",
        actor=str(claims.get("sub", "unknown")),
        verifier_id=HOOK_VERIFIER_ID,
        tool_name=tool_name,
        arguments=arguments,
        action_class=str(arguments["action_class"]),
        target=str(arguments["target"]),
        resource_family=str(arguments["resource_family"]),
        side_effect_class=str(arguments["side_effect_class"]),
        decision=Decision.PERMIT,
        reason="pending policy evaluation",
        passport_jti=str(claims.get("jti", "")),
        trace_id=trace_id,
        budget_delta=None,
    )


def _evaluate_native_policy(event: Any, claims: Mapping[str, Any]) -> tuple[str, list[Any]]:
    from .policy_backend import compose_decisions, get_backend, timed_evaluate

    backend = get_backend("native")
    decision = timed_evaluate(
        backend,
        tool_name=event.tool_name,
        arguments=event.arguments,
        principal=event.actor,
        target=event.target,
        context={
            "passport": dict(claims),
            "session": {},
            "policy_metadata": {
                "action_class": event.action_class,
                "resource_family": event.resource_family,
                "side_effect_class": event.side_effect_class,
            },
        },
        policy_spec={},
    )
    decisions = [decision]
    final, _denier = compose_decisions(decisions)
    return final, decisions


def _policy_decision_dicts(decisions: Iterable[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in decisions:
        if hasattr(item, "to_dict"):
            result.append(dict(item.to_dict()))
        elif isinstance(item, Mapping):
            result.append(dict(item))
    return result


def _set_receipt_metadata(receipt_obj: Any, arguments: Mapping[str, Any], metadata: Mapping[str, Any]) -> None:
    content_class = arguments.get("content_class")
    if content_class:
        receipt_obj.content_class = str(content_class)
    provenance = arguments.get("content_provenance")
    if provenance:
        receipt_obj.content_provenance = {"source": str(provenance)}
    instruction_bearing = arguments.get("instruction_bearing")
    if instruction_bearing is not None:
        receipt_obj.instruction_bearing = bool(instruction_bearing)
    receipt_obj.measurements = {"gemini_cli": dict(metadata)}


def _emit_chained_receipt(
    *,
    decision_enum: Any,
    event: Any,
    reason: str,
    trace_id: str,
    keys_dir: Path | None,
    arguments: Mapping[str, Any],
    measurements: Mapping[str, Any],
) -> Any:
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    with _locked(state):
        parent_hash = _previous_receipt_hash_unlocked(state)
        receipt_obj = build_receipt(
            decision_enum,
            event,
            parent_hash,
            policy_decisions=None,
            reason=reason,
        )
        metadata = dict(measurements)
        metadata["verdict"] = receipt_obj.verdict
        metadata["receipt_id"] = receipt_obj.receipt_id
        _set_receipt_metadata(receipt_obj, arguments, metadata)
        signed = sign_receipt(receipt_obj, private_key)
        _append_receipt_unlocked(state, signed)
    return receipt_obj


def _missing_active_passport_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "issue_mission_passport",
            "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
            "detail": (
                "Issue a local Mission Passport for the agent and mission you want this "
                "Gemini CLI hook proof to evaluate. Keep the token private."
            ),
        },
        {
            "condition": condition,
            "action": "configure_active_mission_passport",
            "command": "export ARDUR_MISSION_PASSPORT=<token-or-token-file>",
            "detail": (
                "Set ARDUR_MISSION_PASSPORT to the issued JWT or to a file containing it; "
                "alternatively place it at <ardur-home>/active_mission.jwt for local runs."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_gemini_cli_hook",
            "command": "ardur gemini-cli-hook pre --keys-dir <keys-dir> < <gemini-hook-event-json-file>",
            "detail": (
                "Rerun the Gemini CLI hook with a JSON object from <gemini-hook-event-json-file>. "
                "This proof surface emits no receipt until a valid active Mission Passport is available."
            ),
        },
    ]


def _missing_active_passport_response() -> dict[str, Any]:
    condition = "gemini_cli_hook_missing_active_passport"
    return {
        "status": "deny",
        "block": True,
        "error": condition,
        "condition": condition,
        "message": "ardur: blocked - no valid active Mission Passport was available",
        "detail": "Set ARDUR_MISSION_PASSPORT or issue/configure a local Mission Passport before rerunning the hook.",
        "claim_boundary": "no receipt emitted because no valid mission passport was available",
        "next_steps": _missing_active_passport_next_steps(condition),
    }


def handle_pre_tool_call(hook_input: dict[str, Any], *, keys_dir: Path | None = None) -> dict[str, Any]:
    """Handle a visible Gemini CLI pre-tool-call payload.

    Return values use an Ardur-local shape: ``status=allow`` records evidence
    without claiming provider enforcement; ``status=deny`` and
    ``status=unknown`` are blocking outputs for local wrappers that choose to
    fail closed.
    """
    from .proxy import Decision, PolicyEvent

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError:
        return _missing_active_passport_response()

    tool_name = str(hook_input.get("tool_name", "") or "").strip() or "unknown_gemini_tool"
    tool_args = _normalize_tool_args(hook_input)
    arguments, mapping_confidence = _map_tool_call(tool_name, tool_args)
    trace_id = _trace_id_from_input(hook_input, claims)
    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
        phase="pre",
    )
    measurements = _gemini_measurements(
        hook_input,
        trace_id=trace_id,
        tool_name=tool_name,
        mapped_tool_name=tool_name,
        mapping_confidence=mapping_confidence,
    )

    if mapping_confidence == "unknown":
        unknown_event = PolicyEvent(
            timestamp=event.timestamp,
            step_id=event.step_id,
            actor=event.actor,
            verifier_id=event.verifier_id,
            tool_name=event.tool_name,
            arguments=event.arguments,
            action_class=event.action_class,
            target=event.target,
            resource_family=event.resource_family,
            side_effect_class=event.side_effect_class,
            decision=Decision.INSUFFICIENT_EVIDENCE,
            reason="insufficient evidence: unmapped Gemini CLI tool schema",
            passport_jti=event.passport_jti,
            trace_id=event.trace_id,
            denial_reason=DenialReason.TELEMETRY_MISSING,
            budget_delta=event.budget_delta,
        )
        receipt_obj = _emit_chained_receipt(
            decision_enum=Decision.INSUFFICIENT_EVIDENCE,
            event=unknown_event,
            reason="insufficient evidence: unmapped Gemini CLI tool schema",
            trace_id=trace_id,
            keys_dir=keys_dir,
            arguments=arguments,
            measurements=measurements,
        )
        return {
            "status": "unknown",
            "block": True,
            "message": f"ardur: insufficient evidence (receipt {receipt_obj.receipt_id})",
            "receipt_id": receipt_obj.receipt_id,
            "claim_boundary": "visible Gemini CLI hook/tool-boundary evidence only",
            "unknown_boundaries": list(UNKNOWN_BOUNDARIES) + ["unmapped_gemini_tool_schema"],
        }

    final, decisions = _evaluate_native_policy(event, claims)
    if final == "Deny":
        denier = next((d for d in decisions if getattr(d, "decision", None) == "Deny"), None)
        reasons = list(getattr(denier, "reasons", ()) or ["denied by composed policy"])
        reason_text = "; ".join(str(item) for item in reasons)
        deny_event = PolicyEvent(
            timestamp=event.timestamp,
            step_id=event.step_id,
            actor=event.actor,
            verifier_id=event.verifier_id,
            tool_name=event.tool_name,
            arguments=event.arguments,
            action_class=event.action_class,
            target=event.target,
            resource_family=event.resource_family,
            side_effect_class=event.side_effect_class,
            decision=Decision.DENY,
            reason=reason_text,
            passport_jti=event.passport_jti,
            trace_id=event.trace_id,
            denial_reason=DenialReason.POLICY_DENIED,
            budget_delta=event.budget_delta,
            policy_decisions=_policy_decision_dicts(decisions),
        )
        receipt_obj = _emit_chained_receipt(
            decision_enum=Decision.DENY,
            event=deny_event,
            reason=reason_text,
            trace_id=trace_id,
            keys_dir=keys_dir,
            arguments=arguments,
            measurements=measurements,
        )
        return {
            "status": "deny",
            "block": True,
            "message": f"ardur: blocked - {reason_text}",
            "receipt_id": receipt_obj.receipt_id,
            "claim_boundary": "visible Gemini CLI hook/tool-boundary evidence only",
        }

    event.policy_decisions = _policy_decision_dicts(decisions)
    receipt_obj = _emit_chained_receipt(
        decision_enum=Decision.PERMIT,
        event=event,
        reason="allowed by composed policy",
        trace_id=trace_id,
        keys_dir=keys_dir,
        arguments=arguments,
        measurements=measurements,
    )
    return {
        "status": "allow",
        "block": False,
        "message": f"ardur: allowed/evidence recorded (receipt {receipt_obj.receipt_id})",
        "receipt_id": receipt_obj.receipt_id,
        "claim_boundary": "evidence-only allow; Gemini/user permission flow remains authoritative",
        "unknown_boundaries": list(UNKNOWN_BOUNDARIES),
    }


def _iter_chain_files(chain_dir: Path) -> list[Path]:
    if chain_dir.is_file():
        return [chain_dir]
    if not chain_dir.exists():
        return []
    return sorted(path for path in chain_dir.rglob(CHAIN_FILENAME) if path.is_file())


def _status_from_verdict(verdict: str) -> str:
    if verdict == "compliant":
        return "allow"
    if verdict == "insufficient_evidence":
        return "unknown"
    if verdict == "unknown":
        return "unknown"
    return "deny"


def _empty_report_next_steps() -> list[dict[str, str]]:
    """Deterministic local remediation hints for a Gemini report with no receipts."""
    return [
        {
            "condition": "no_gemini_cli_receipts",
            "action": "create_gemini_cli_fixture",
            "command": "ardur gemini-cli-fixture --project-dir <your-project>",
            "detail": (
                "Create a local-only Gemini CLI fixture and inspect the generated settings/context. "
                "Use --home <ardur-home> or --chain-dir <chain-dir> when you need explicit local paths."
            ),
        },
        {
            "condition": "no_gemini_cli_receipts",
            "action": "run_gemini_cli_with_local_hook",
            "command": "gemini",
            "detail": (
                "Configure Gemini CLI to use the generated local hook/settings, then run a local "
                "Gemini CLI command for <your-project> that triggers a hook."
            ),
        },
        {
            "condition": "no_gemini_cli_receipts",
            "action": "rerun_receipt_report",
            "command": "ardur gemini-cli-report --home <ardur-home>",
            "detail": (
                "Verify the local receipt chains after the run. This report reads local fixture "
                "receipts only and does not prove live provider behavior or provider-hidden actions."
            ),
        },
    ]


def build_shareable_report(
    *,
    home: Path | None = None,
    chain_dir: Path | None = None,
    keys_dir: Path | None = None,
    redaction_roots: Mapping[str, str | Path | None] | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    ardur_home = Path(home or os.environ.get("VIBAP_HOME", str(DEFAULT_HOME))).expanduser().resolve(strict=False)
    chains = Path(chain_dir or os.environ.get(CHAIN_DIR_ENV_VAR, str(DEFAULT_CHAIN_DIR))).expanduser().resolve(strict=False)
    signing_keys = resolve_keys_dir(keys_dir)
    roots: dict[str, str | Path | None] = {
        "GEMINI_HOME": ardur_home,
        "ARDUR_GEMINI_CHAIN": chains,
        "ARDUR_KEYS": signing_keys,
    }
    if redaction_roots:
        roots.update(dict(redaction_roots))

    chain_files = _iter_chain_files(chains)
    public_key = load_report_public_key(
        signing_keys, evidence_present=bool(chain_files)
    )
    receipt_claims: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    invalid_chains: list[dict[str, Any]] = []
    for path in chain_files:
        tokens = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if tokens:
            try:
                verified_claims = verify_chain(list(tokens), public_key, verify_expiry=verify_expiry)
                receipt_claims.extend(verified_claims)
                verification.append(
                    {
                        "chain": str(path),
                        "valid": True,
                        "receipt_count": len(verified_claims),
                        "token_count": len(tokens),
                    }
                )
            except Exception as exc:  # noqa: BLE001 - report validation state without leaking stack
                invalid = {
                    "chain": str(path),
                    "valid": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "receipt_count": 0,
                    "token_count": len(tokens),
                }
                verification.append(dict(invalid))
                invalid_chains.append(dict(invalid))

    counts = {"allow": 0, "deny": 0, "unknown": 0}
    coverage_gaps: set[str] = set()
    for claims in receipt_claims:
        counts[_status_from_verdict(str(claims.get("verdict", "")))] += 1
        measurements = claims.get("measurements", {})
        gemini = measurements.get("gemini_cli", {}) if isinstance(measurements, Mapping) else {}
        if isinstance(gemini, Mapping):
            for gap in gemini.get("unknown_boundaries", []) or []:
                coverage_gaps.add(str(gap))

    payload = {
        "schema_version": "ardur.gemini_cli.shareable_report.v0.1",
        "home": str(ardur_home),
        "chain_dir": str(chains),
        "receipt_count": len(receipt_claims),
        "chain_count": len(chain_files),
        "policy_verdict_counts": counts,
        "coverage_gaps": sorted(coverage_gaps),
        "unknown_boundary_count": len(coverage_gaps),
        "verification": verification,
        "invalid_chains": invalid_chains,
        "next_steps": _empty_report_next_steps() if not receipt_claims else [],
        "claim_boundary": {
            "scope": "local_fixture_only",
            "not_claimed": [
                "live Gemini enforcement",
                "provider-hidden reasoning visibility",
                "server-side tool-call capture",
                "sandbox isolation",
            ],
        },
        "receipts": receipt_claims,
    }
    return _shareable_redact(payload, roots=roots)


def _gemini_cli_hook_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_gemini_cli_fixture",
            "command": "ardur gemini-cli-fixture --project-dir <your-project>",
            "detail": (
                "Create a local-only Gemini CLI fixture and inspect the generated settings/context "
                "before feeding hook JSON."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_with_hook_event_json_file",
            "command": "ardur gemini-cli-hook pre --keys-dir <keys-dir> < <gemini-hook-event-json-file>",
            "detail": (
                "Feed a Gemini CLI hook JSON object from <gemini-hook-event-json-file>. "
                "Keep raw tokens and local private paths out of shared logs and reports."
            ),
        },
    ]


def _gemini_cli_hook_input_failure_response(exc: Exception) -> dict[str, Any]:
    msg = str(exc)
    if isinstance(exc, json.JSONDecodeError):
        condition = "gemini_cli_hook_input_malformed"
        message = "Gemini CLI hook input is not valid JSON."
        detail = (
            "Input must be a valid JSON object; "
            f"parsing failed at line {exc.lineno}, column {exc.colno}."
        )
    elif "exceeds" in msg and "character limit" in msg:
        condition = "gemini_cli_hook_input_oversize"
        message = "Gemini CLI hook input exceeds the size limit."
        detail = msg
    else:
        condition = "gemini_cli_hook_input_not_object"
        message = "Gemini CLI hook input must be a JSON object."
        detail = (
            "Input must be a JSON object from <gemini-hook-event-json-file>; arrays, "
            "strings, numbers, booleans, and null are not accepted."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _gemini_cli_hook_input_next_steps(condition),
    }


def _load_json_stdin() -> dict[str, Any]:
    raw = sys.stdin.read(HOOK_INPUT_MAX_CHARS + 1)
    if len(raw) > HOOK_INPUT_MAX_CHARS:
        raise ValueError(
            f"Gemini hook input exceeds {HOOK_INPUT_MAX_CHARS} character limit"
        )
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Gemini hook payload must be a JSON object")
    return parsed


def _gemini_fail_safe_block() -> dict[str, Any]:
    """Return a protocol-valid block response when the hook cannot process input.

    Gemini CLI hooks cannot block the host the way Claude Code PreToolUse can,
    but emitting a ``block: True`` response with valid JSON (instead of a raw
    traceback / non-JSON crash) keeps downstream consumers parseable and fails
    closed for local wrappers that honour the ``block`` field.
    """
    return {
        "status": "deny",
        "block": True,
        "message": "ardur: blocked - hook input could not be processed safely",
        "claim_boundary": "visible Gemini CLI hook/tool-boundary evidence only",
    }


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(dict(payload), indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run local Ardur Gemini CLI hook/fixture helpers")
    parser.add_argument("phase_pos", nargs="?", choices=["pre", "fixture", "report"], help="hook/helper phase")
    parser.add_argument("--phase", choices=["pre", "fixture", "report"], help="hook/helper phase")
    parser.add_argument("--keys-dir", type=str, help="Ardur signing keys directory")
    parser.add_argument("--home", type=str, help="explicit Gemini home for fixture writes; defaults to isolated Ardur local state")
    parser.add_argument("--project-dir", type=str, help="project directory for fixture generation")
    parser.add_argument("--chain-dir", type=str, help="Gemini receipt chain directory")
    parser.add_argument("--verify-expiry", action="store_true", help="enforce short receipt expiry while verifying reports")
    args = parser.parse_args(list(argv) if argv is not None else None)
    phase = args.phase or args.phase_pos or "pre"

    if phase == "pre":
        try:
            hook_input = _load_json_stdin()
        except (json.JSONDecodeError, ValueError) as exc:
            _print_json(_gemini_cli_hook_input_failure_response(exc))
            return 1
        try:
            output = handle_pre_tool_call(hook_input, keys_dir=args.keys_dir)
        except Exception as exc:  # noqa: BLE001 - fail safe without leaking stack
            sys.stderr.write(f"ardur: gemini hook handler crashed: {exc}\n")
            output = _gemini_fail_safe_block()
        _print_json(output)
        return 2 if output.get("block") else 0
    if phase == "fixture":
        try:
            fixture = build_local_fixture(
                home=args.home,
                project_dir=args.project_dir,
                chain_dir=args.chain_dir,
                keys_dir=args.keys_dir,
            )
        except FixtureProjectDirError as exc:
            _print_json(fixture_project_dir_failure_response(exc.condition))
            return 1
        _print_json(build_shareable_context(fixture))
        return 0
    if phase == "report":
        report = build_shareable_report(
            home=args.home,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
            verify_expiry=args.verify_expiry,
        )
        _print_json(report)
        return 0
    parser.error(f"unsupported phase: {phase}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
