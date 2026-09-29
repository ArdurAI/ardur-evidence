"""Local-only Ardur adapter for Codex app-server / host-event proof fixtures.

This module intentionally implements a narrow no-provider proof surface: it can
write a local Codex-style config/schema/context fixture, consume representative
local host-event JSON, append signed Ardur receipts, and render redacted
shareable reports. It does not claim live Codex cloud enforcement,
provider-hidden reasoning visibility, sandbox isolation, or production runtime
capture.
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

from .claude_code_hook import MissionLoadError, load_active_passport
from .denial import DenialReason
from .passport import DEFAULT_HOME, _ensure_default_home_dir, load_report_public_key, load_private_key, resolve_keys_dir
from .receipt import build_receipt, sign_receipt, verify_chain
from .shareable_redaction import path_aliases, redact_local_paths

PASSPORT_ENV_VAR = "ARDUR_MISSION_PASSPORT"
CHAIN_DIR_ENV_VAR = "ARDUR_CODEX_APP_SERVER_DIR"
DEFAULT_CODEX_FIXTURE_HOME = DEFAULT_HOME / "codex-app-server-fixture" / ".codex"
DEFAULT_CHAIN_DIR = DEFAULT_HOME / "codex-app-server"
CHAIN_FILENAME = "receipts.jsonl"
HOOK_VERIFIER_ID = "ardur-codex-app-server-fixture"
UNKNOWN_BOUNDARIES = (
    "provider_hidden_actions",
    "provider_server_side_tool_calls",
    "codex_cloud_action_enforcement",
    "codex_app_server_schema_drift",
    "unmapped_codex_canonical_event_type",
    "unmapped_extension_tool",
    "mcp_auth_elicitation",
    "app_server_hosted_auth",
    "code_mode_hosted_by_default",
)

# Canonical event types introduced in Codex rust-v0.144.0.
# These are host-emitted evidence events, not Ardur-originated.
# Each maps to Ardur's receipt schema: action_class, resource_family, side_effect_class.
CANONICAL_EVENT_TYPES: dict[str, dict[str, str]] = {
    "command_execution": {
        "action_class": "execute",
        "resource_family": "process",
        "side_effect_class": "state_change",
    },
    "dynamic_tool_call": {
        "action_class": "observe",
        "resource_family": "general",
        "side_effect_class": "none",
    },
    "sub_agent_activity": {
        "action_class": "observe",
        "resource_family": "agent_lifecycle",
        "side_effect_class": "none",
    },
    "collab_tool_call": {
        "action_class": "observe",
        "resource_family": "collaboration",
        "side_effect_class": "none",
    },
    "collab_wait": {
        "action_class": "observe",
        "resource_family": "collaboration",
        "side_effect_class": "none",
    },
    "review_mode": {
        "action_class": "observe",
        "resource_family": "review",
        "side_effect_class": "none",
    },
    "hook_prompt": {
        "action_class": "observe",
        "resource_family": "hook",
        "side_effect_class": "none",
    },
}

# Tool source classes for Codex turn items.
# extension_owned: tools dispatched by Codex extensions rather than built-in tools.
TOOL_SOURCE_CLASSES = frozenset({"built_in", "extension_owned"})
SENSITIVE_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|credential|authorization|cookie|session[_-]?key)",
    re.IGNORECASE,
)
_SAFE_TRACE_DIR_ID_RE = re.compile(r"^codex-[a-f0-9]{32}$")


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
    return {"alg": "sha-256", "value": hashlib.sha256(path.read_bytes()).hexdigest()}


def _default_codex_fixture_home() -> Path:
    """Return an isolated default Codex fixture home.

    The default deliberately lives under Ardur/VIBAP local state rather than the
    caller's real ``~/.codex``. Operators can target a real Codex home only by
    explicitly passing ``--home``.
    """
    if "VIBAP_HOME" not in os.environ:
        return DEFAULT_CODEX_FIXTURE_HOME
    ardur_home = Path(os.environ["VIBAP_HOME"]).expanduser()
    return ardur_home / "codex-app-server-fixture" / ".codex"


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
    return value or "codex:trace-unknown"


def _trace_dir_id(trace_id: str) -> str:
    """Map untrusted external trace material to a single safe path segment."""
    digest = hashlib.sha256(_external_trace_id(trace_id).encode("utf-8")).hexdigest()[:32]
    value = f"codex-{digest}"
    if not _SAFE_TRACE_DIR_ID_RE.fullmatch(value):  # pragma: no cover - defensive invariant
        raise ValueError("internal trace directory id is not path-safe")
    return value


def _ensure_under_chain_root(*, chain_root: Path, path: Path) -> None:
    root = chain_root.resolve(strict=False)
    candidate = path.resolve(strict=False)
    if not candidate.is_relative_to(root):
        raise ValueError(f"Codex receipt path escapes chain directory: {candidate}")


def _trace_id_from_input(host_event: Mapping[str, Any], claims: Mapping[str, Any]) -> str:
    override = os.environ.get("ARDUR_TRACE_ID", "").strip()
    if override:
        return _external_trace_id(override)
    return _external_trace_id(str(host_event.get("session_id") or claims.get("jti") or ""))


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
            condition="codex_app_server_fixture_project_dir_empty",
        )
    if project.is_symlink() and not project.exists():
        raise FixtureProjectDirError(
            "fixture project directory is a dangling symlink",
            condition="codex_app_server_fixture_project_dir_not_directory",
        )
    if project.exists() and not project.is_dir():
        raise FixtureProjectDirError(
            "fixture project directory must be a directory",
            condition="codex_app_server_fixture_project_dir_not_directory",
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
        message = f"Codex app-server fixture {label} is empty."
        detail = (
            f"The {arg_name} argument is empty or whitespace-only. "
            f"Provide a directory path where Ardur can write fixture artifacts."
        )
        step_detail = f"Replace <{label}> with a directory path (not empty, whitespace, a file, or a symlink)."
    else:
        message = f"Codex app-server fixture {label} is not a directory."
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
                "action": f"rerun_codex_fixture_with_{label.replace(' ', '_')}",
                "command": f"ardur codex-app-server-fixture {arg_name} <{label}>",
                "detail": step_detail,
            }
        ],
    }


def fixture_project_dir_failure_response(condition: str = "codex_app_server_fixture_project_dir_not_directory") -> dict[str, Any]:
    """Structured failure response for an invalid ``--project-dir`` argument.

    Mirrors the fixture path-failure convention: a stable ``condition``/
    ``error`` pair, a human-readable ``message`` with no raw exception text or
    local paths, a ``detail`` explaining how to choose a valid directory, and
    placeholder-only ``next_steps``.
    """

    messages = {
        "codex_app_server_fixture_project_dir_empty": (
            "Codex app-server fixture project directory is empty."
        ),
        "codex_app_server_fixture_project_dir_not_directory": (
            "Codex app-server fixture project directory is not a directory."
        ),
    }
    details = {
        "codex_app_server_fixture_project_dir_empty": (
            "The --project-dir argument is empty or whitespace-only. "
            "Provide a project directory path where Ardur can write CODEX.md."
        ),
        "codex_app_server_fixture_project_dir_not_directory": (
            "The --project-dir argument points at an existing non-directory. "
            "Use an existing project directory or a new directory path that Ardur can create."
        ),
    }
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": messages.get(condition, "Codex app-server fixture project directory is invalid."),
        "detail": details.get(condition, "Provide a project directory path for the --project-dir argument."),
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_codex_app_server_fixture_with_project_directory",
                "command": "ardur codex-app-server-fixture --project-dir <your-project>",
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
    """Write a private local Codex config/context fixture.

    The fixture is deliberately a local proof harness. It records the command a
    user can wire into Codex app-server/host-event surfaces, but does not mutate
    a real Codex install unless the caller explicitly points ``home`` there.
    """
    # Reject empty/whitespace-only path arguments before Path() normalises them
    # to the current working directory. Path("") silently becomes Path(".") so
    # the empty input would otherwise pollute CWD with fixture artifacts.
    if home is not None and not str(home).strip():
        raise FixturePathError(
            "home is empty or whitespace-only",
            condition="codex_app_server_fixture_home_empty",
        )
    if chain_dir is not None and not str(chain_dir).strip():
        raise FixturePathError(
            "chain dir is empty or whitespace-only",
            condition="codex_app_server_fixture_chain_dir_empty",
        )
    if keys_dir is not None and not str(keys_dir).strip():
        raise FixturePathError(
            "keys dir is empty or whitespace-only",
            condition="codex_app_server_fixture_keys_dir_empty",
        )
    codex_home_raw = Path(home or _default_codex_fixture_home()).expanduser()
    project_raw_value = str(project_dir) if project_dir is not None else ""
    if not project_raw_value.strip():
        raise FixtureProjectDirError(
            "fixture project directory must not be empty or whitespace-only",
            condition="codex_app_server_fixture_project_dir_empty",
        )
    project_raw = Path(project_raw_value).expanduser()
    ardur_chain_raw = Path(chain_dir or DEFAULT_CHAIN_DIR).expanduser()
    # Validate parent components for dangling symlinks / non-directory parents
    # BEFORE the leaf-only check and resolve() collapse the symlink chain.
    _validate_fixture_path_parents_not_dangling(
        codex_home_raw,
        dangling_condition="codex_app_server_fixture_home_dangling_symlink_parent",
        not_dir_condition="codex_app_server_fixture_home_parent_not_directory",
    )
    _validate_fixture_path_parents_not_dangling(
        ardur_chain_raw,
        dangling_condition="codex_app_server_fixture_chain_dir_dangling_symlink_parent",
        not_dir_condition="codex_app_server_fixture_chain_dir_parent_not_directory",
    )
    # Validate raw paths for dangling symlinks before resolve() follows them.
    _validate_fixture_path_not_file(codex_home_raw, label="home", condition="codex_app_server_fixture_home_not_directory")
    _validate_fixture_path_not_file(ardur_chain_raw, label="chain dir", condition="codex_app_server_fixture_chain_dir_not_directory")
    _validate_fixture_project_dir(project_raw)
    if keys_dir is not None:
        keys_raw = Path(keys_dir).expanduser()
        _validate_fixture_path_not_file(keys_raw, label="keys dir", condition="codex_app_server_fixture_keys_dir_not_directory")
    codex_home = codex_home_raw.resolve(strict=False)
    project = project_raw.resolve(strict=False)
    ardur_chain = ardur_chain_raw.resolve(strict=False)
    # When chain_dir falls through to the DEFAULT_HOME-derived default,
    # materialise the home with 0o700 before creating directories inside it.
    if chain_dir is None:
        _ensure_default_home_dir()
    signing_keys = resolve_keys_dir(keys_dir)

    config_path = codex_home / "config.json"
    hook_schema_path = codex_home / "ardur-host-event.schema.json"
    project_context_path = project / "CODEX.md"

    hook_command = "ardur codex-app-server-event --keys-dir " + str(signing_keys)
    config = {
        "schemaVersion": "ardur.codex_app_server.config_fixture.v0.1",
        "mode": "local-proof-only",
        "approval_policy": "never",
        "sandbox_mode": "workspace-write",
        "appServer": {
            "hostEventCommand": hook_command,
            "receiptChainDir": str(ardur_chain),
            "missionPassportEnv": PASSPORT_ENV_VAR,
            "unknownBoundaries": list(UNKNOWN_BOUNDARIES),
        },
    }
    hook_schema = {
        "schemaVersion": "ardur.codex_app_server.host_event_schema.v0.1",
        "description": "Representative local Codex app-server host-event fixture schema for Ardur evidence tests.",
        "type": "object",
        "required": ["event_type", "session_id", "tool_name"],
        "properties": {
            "event_type": {"type": "string", "examples": ["tool_decision"]},
            "event_id": {"type": "string"},
            "session_id": {"type": "string"},
            "cwd": {"type": "string"},
            "tool_name": {"type": "string"},
            "tool_input": {"type": "object"},
            "host_context": {"type": "object"},
            "canonical_event_type": {
                "type": "string",
                "description": "Codex canonical event class (host-emitted evidence, not Ardur-originated)",
                "examples": [
                    "command_execution",
                    "dynamic_tool_call",
                    "sub_agent_activity",
                    "collab_tool_call",
                    "collab_wait",
                    "review_mode",
                    "hook_prompt",
                ],
            },
            "tool_source_class": {
                "type": "string",
                "description": "Codex turn item source class",
                "enum": ["built_in", "extension_owned"],
            },
        },
        "claimBoundary": "visible local host-event fixture fields only; canonical events are host-emitted evidence, not Ardur-originated; not live Codex cloud enforcement",
    }
    context_text = "\n".join(
        [
            "# Codex local Ardur context fixture",
            "",
            "This project is configured for a local-only Ardur proof harness.",
            "The host-event adapter emits signed local receipts for visible Codex app-server-style events.",
            "It does not claim live Codex cloud enforcement, provider-hidden reasoning, or sandbox isolation.",
            "",
        ]
    )

    _write_private_text(config_path, json.dumps(config, indent=2, sort_keys=True) + "\n")
    _write_private_text(hook_schema_path, json.dumps(hook_schema, indent=2, sort_keys=True) + "\n")
    project.mkdir(parents=True, exist_ok=True)
    _write_private_text(project_context_path, context_text)
    ardur_chain.mkdir(parents=True, exist_ok=True)
    signing_keys.mkdir(parents=True, exist_ok=True)

    return {
        "schema_version": "ardur.codex_app_server.local_fixture.v0.1",
        "home": str(codex_home),
        "project_dir": str(project),
        "chain_dir": str(ardur_chain),
        "keys_dir": str(signing_keys),
        "config_path": str(config_path),
        "hook_schema_path": str(hook_schema_path),
        "project_context_path": str(project_context_path),
        "hook_command": hook_command,
    }


def build_shareable_context(fixture: Mapping[str, Any]) -> dict[str, Any]:
    config_path = Path(str(fixture["config_path"]))
    hook_schema_path = Path(str(fixture["hook_schema_path"]))
    project_context_path = Path(str(fixture["project_context_path"]))
    roots = {
        "CODEX_HOME": fixture.get("home"),
        "CODEX_PROJECT": fixture.get("project_dir"),
        "ARDUR_CODEX_CHAIN": fixture.get("chain_dir"),
        "ARDUR_KEYS": fixture.get("keys_dir"),
    }
    payload = {
        "schema_version": "ardur.codex_app_server.local_context.v0.1",
        "claim_boundary": {
            "scope": "local_fixture_only",
            "verified": [
                "config/schema/context fixture files written locally",
                "host-event command points at Ardur receipt adapter",
                "shareable artifact carries digests instead of raw secrets",
            ],
            "not_claimed": [
                "live Codex cloud enforcement",
                "provider-hidden reasoning visibility",
                "sandbox isolation",
                "universal CLI/eBPF/kernel capture",
                "production enforcement",
            ],
            "canonical_events": "host-emitted evidence, not Ardur-originated",
        },
        "unknown_boundaries": list(UNKNOWN_BOUNDARIES),
        "host_context": {
            "config_digest": _digest_file(config_path),
            "hook_schema_digest": _digest_file(hook_schema_path),
            "project_context_digest": _digest_file(project_context_path),
            "hook_command": fixture.get("hook_command"),
        },
        "artifacts": {
            "config_path": fixture.get("config_path"),
            "hook_schema_path": fixture.get("hook_schema_path"),
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
    "apply_patch": {"action_class": "write", "resource_family": "filesystem", "side_effect_class": "internal_write"},
    "shell_command": {"action_class": "execute", "resource_family": "process", "side_effect_class": "state_change"},
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


def _normalize_tool_args(host_event: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("tool_input", "tool_args", "args", "arguments", "parameters"):
        value = host_event.get(key)
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
                "content_provenance": "codex_app_server_host_event",
                "side_effect_class": "none",
                "visibility": "tool_boundary_only",
                "sensitivity": "unknown",
                "instruction_bearing": False,
                "budget_delta": 1,
            },
            "unknown",
        )
    if key in {"shell_command", "run_shell_command", "shell"}:
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
            "content_provenance": "codex_app_server_host_event",
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
    for key in ("config", "hook_schema", "protocol", "policy", "environment"):
        value = clean.get(key)
        if isinstance(value, Mapping):
            summary[f"{key}_digest"] = _digest_payload(value)
    if not summary and clean:
        summary["payload_digest"] = _digest_payload(clean)
    return summary


def _policy_input_summary(host_event: Mapping[str, Any]) -> dict[str, Any]:
    host_context = host_event.get("host_context")
    if not isinstance(host_context, Mapping):
        host_context = {}
    config = host_context.get("config")
    policy = host_context.get("policy")
    sources: list[Mapping[str, Any]] = []
    if isinstance(config, Mapping):
        sources.append(config)
    if isinstance(policy, Mapping):
        sources.append(policy)
    sources.append(host_event)
    summary: dict[str, Any] = {}
    for key in ("approval_policy", "sandbox_mode", "model", "profile"):
        for source in sources:
            value = source.get(key)
            if isinstance(value, str) and value:
                summary[key] = value
                break
    # Recognized approval_policy values (Codex rust-v0.144.0+).
    # "writes" means declared read-only actions are allowed while writes prompt for approval.
    _RECOGNIZED_APPROVAL_POLICIES = frozenset({"never", "always", "writes"})
    approval = summary.get("approval_policy")
    if isinstance(approval, str) and approval not in _RECOGNIZED_APPROVAL_POLICIES:
        summary["approval_policy_unrecognized"] = approval
    return _redact_sensitive_values(summary)


def _codex_measurements(
    host_event: Mapping[str, Any],
    *,
    trace_id: str,
    tool_name: str,
    mapped_tool_name: str,
    mapping_confidence: str,
    receipt_id: str | None = None,
    verdict: str | None = None,
    canonical_event_type: str | None = None,
    tool_source_class: str = "built_in",
) -> dict[str, Any]:
    host_context = host_event.get("host_context")
    if not isinstance(host_context, Mapping):
        host_context = {}
    unknown_boundaries: list[str] = list(UNKNOWN_BOUNDARIES)
    if mapping_confidence == "unknown":
        unknown_boundaries.append("unmapped_codex_host_event_schema")
    if canonical_event_type and canonical_event_type not in CANONICAL_EVENT_TYPES:
        unknown_boundaries.append("unmapped_codex_canonical_event_type")
    if tool_source_class == "extension_owned":
        unknown_boundaries.append("unmapped_extension_tool")
    return _without_empty_values(
        {
            "schema_version": "ardur.codex_app_server.measurements.v0.1",
            "trace_id": trace_id,
            "event_type": str(host_event.get("event_type", "") or ""),
            "event_id": str(host_event.get("event_id", "") or ""),
            "session_context": {
                "session_id": str(host_event.get("session_id", "") or ""),
                "cwd": str(host_event.get("cwd", "") or ""),
            },
            "policy_input": _policy_input_summary(host_event),
            "tool_name": tool_name,
            "mapped_policy_tool": mapped_tool_name,
            "mapping_confidence": mapping_confidence,
            "host_context": _host_context_summary(host_context),
            "unknown_boundaries": unknown_boundaries,
            "claim_boundary": "visible Codex app-server/host-event fixture evidence only; canonical events are host-emitted evidence, not Ardur-originated",
            "verdict": verdict,
            "receipt_id": receipt_id,
            "canonical_event_type": canonical_event_type,
            "tool_source_class": tool_source_class,
        }
    )


def _build_policy_event(
    *,
    claims: Mapping[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    trace_id: str,
):
    from .proxy import Decision, PolicyEvent, _receipt_step_id

    timestamp = _utc_timestamp()
    step_id = _receipt_step_id(str(claims.get("jti", "")), timestamp, tool_name, arguments)
    return PolicyEvent(
        timestamp=timestamp,
        step_id=f"{step_id}:codex-app-server",
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
    receipt_obj.measurements = {"codex_app_server": dict(metadata)}


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
                "Codex app-server proof event to evaluate. Keep the token private."
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
            "action": "rerun_codex_app_server_event",
            "command": "ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>",
            "detail": (
                "Rerun the Codex app-server event helper with a JSON object from <event-json-file>. "
                "This proof surface emits no receipt until a valid active Mission Passport is available."
            ),
        },
    ]


def _missing_active_passport_response() -> dict[str, Any]:
    condition = "codex_app_server_event_missing_active_passport"
    return {
        "status": "deny",
        "block": True,
        "error": condition,
        "condition": condition,
        "message": "ardur: blocked - no valid active Mission Passport was available",
        "detail": "Set ARDUR_MISSION_PASSPORT or issue/configure a local Mission Passport before rerunning the event helper.",
        "claim_boundary": "no receipt emitted because no valid mission passport was available",
        "next_steps": _missing_active_passport_next_steps(condition),
    }


def handle_host_event(host_event: dict[str, Any], *, keys_dir: Path | None = None) -> dict[str, Any]:
    """Handle a visible local Codex app-server/host-event payload.

    Return values use an Ardur-local shape: ``status=allow`` records evidence
    without claiming live Codex enforcement; ``status=deny`` and
    ``status=unknown`` are blocking outputs for local wrappers that choose to
    fail closed.
    """
    from .proxy import Decision, PolicyEvent

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError:
        return _missing_active_passport_response()

    tool_name = str(host_event.get("tool_name", "") or "").strip() or "unknown_codex_tool"
    tool_args = _normalize_tool_args(host_event)
    arguments, mapping_confidence = _map_tool_call(tool_name, tool_args)
    trace_id = _trace_id_from_input(host_event, claims)

    # Extract canonical event type and tool source class from host event.
    # canonical_event_type: one of CANONICAL_EVENT_TYPES keys (host-emitted evidence).
    # tool_source_class: "built_in" (default) or "extension_owned" (extension-dispatched tools).
    canonical_event_type = str(host_event.get("canonical_event_type", "") or "").strip() or None
    tool_source_class = str(host_event.get("tool_source_class", "") or "").strip() or "built_in"
    if tool_source_class not in TOOL_SOURCE_CLASSES:
        tool_source_class = "built_in"

    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
    )
    measurements = _codex_measurements(
        host_event,
        trace_id=trace_id,
        tool_name=tool_name,
        mapped_tool_name=tool_name,
        mapping_confidence=mapping_confidence,
        canonical_event_type=canonical_event_type,
        tool_source_class=tool_source_class,
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
            reason="insufficient evidence: unmapped Codex app-server host-event schema",
            passport_jti=event.passport_jti,
            trace_id=event.trace_id,
            denial_reason=DenialReason.TELEMETRY_MISSING,
            budget_delta=event.budget_delta,
        )
        receipt_obj = _emit_chained_receipt(
            decision_enum=Decision.INSUFFICIENT_EVIDENCE,
            event=unknown_event,
            reason="insufficient evidence: unmapped Codex app-server host-event schema",
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
            "claim_boundary": "visible Codex app-server/host-event fixture evidence only",
            "unknown_boundaries": list(UNKNOWN_BOUNDARIES) + ["unmapped_codex_host_event_schema"],
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
            "claim_boundary": "visible Codex app-server/host-event fixture evidence only",
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
        "claim_boundary": "evidence-only allow; Codex/user permission flow remains authoritative",
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
    """Deterministic local remediation hints for a Codex app-server report with no receipts."""
    return [
        {
            "condition": "no_codex_app_server_receipts",
            "action": "create_codex_app_server_fixture",
            "command": "ardur codex-app-server-fixture --project-dir <your-project>",
            "detail": (
                "Create a local-only Codex app-server fixture and inspect the generated config/schema. "
                "Use --home <ardur-home> or --chain-dir <chain-dir> when you need explicit local paths."
            ),
        },
        {
            "condition": "no_codex_app_server_receipts",
            "action": "feed_local_codex_app_server_event",
            "command": "ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>",
            "detail": (
                "Feed a local Codex app-server host-event JSON object from <event-json-file> "
                "through Ardur's fixture/helper so a local receipt chain is written."
            ),
        },
        {
            "condition": "no_codex_app_server_receipts",
            "action": "rerun_receipt_report",
            "command": "ardur codex-app-server-report --home <ardur-home>",
            "detail": (
                "Verify the local receipt chains after the event. This report reads local fixture "
                "receipts only and does not prove live Codex cloud behavior or provider-hidden actions."
            ),
        },
    ]


def _digest_text(value: str) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "value": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _redacted_digest_marker(kind: str, digest: Mapping[str, str]) -> str:
    return f"<redacted-{kind}:sha256:{digest['value'][:16]}>"


def _deep_public_copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _deep_public_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_deep_public_copy(item) for item in value]
    if isinstance(value, tuple):
        return [_deep_public_copy(item) for item in value]
    return value


def _redact_digest_string_field(
    payload: dict[str, Any],
    *,
    field: str,
    kind: str,
    digest_field: str,
) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        return
    digest = _digest_text(value)
    payload[field] = _redacted_digest_marker(kind, digest)
    payload[digest_field] = digest


def _public_receipt_claims(claims: Mapping[str, Any]) -> dict[str, Any]:
    """Return a report-safe copy of verified receipt claims.

    Raw local receipts remain verified before this function runs. The shareable
    report then exposes deterministic digests for target and policy-detail text
    instead of copying command, URL/query, opaque-target, or denial-reason echo
    strings into a public artifact.
    """
    public = _deep_public_copy(claims)
    _redact_digest_string_field(
        public,
        field="target",
        kind="target",
        digest_field="target_digest",
    )
    _redact_digest_string_field(
        public,
        field="reason",
        kind="policy-reason",
        digest_field="reason_digest",
    )
    policy_decisions = public.get("policy_decisions")
    if isinstance(policy_decisions, list):
        for item in policy_decisions:
            if isinstance(item, dict):
                _redact_digest_string_field(
                    item,
                    field="reason",
                    kind="policy-reason",
                    digest_field="reason_digest",
                )
    return public


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
        "CODEX_HOME": ardur_home,
        "ARDUR_CODEX_CHAIN": chains,
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
                    "message": type(exc).__name__,
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
        codex = measurements.get("codex_app_server", {}) if isinstance(measurements, Mapping) else {}
        if isinstance(codex, Mapping):
            for gap in codex.get("unknown_boundaries", []) or []:
                coverage_gaps.add(str(gap))
            session_context = codex.get("session_context", {})
            if isinstance(session_context, Mapping):
                cwd = session_context.get("cwd")
                if isinstance(cwd, str) and cwd:
                    digest = hashlib.sha256(cwd.encode("utf-8")).hexdigest()[:8]
                    roots[f"CODEX_CWD_{digest}"] = cwd

    payload = {
        "schema_version": "ardur.codex_app_server.shareable_report.v0.1",
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
                "live Codex cloud enforcement",
                "provider-hidden reasoning visibility",
                "sandbox isolation",
                "universal CLI/eBPF/kernel capture",
                "production enforcement",
            ],
        },
        "receipts": [_public_receipt_claims(claims) for claims in receipt_claims],
    }
    return _shareable_redact(payload, roots=roots)


def _load_json_stdin() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Codex app-server host-event payload must be a JSON object")
    return parsed


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(dict(payload), indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run local Ardur Codex app-server fixture helpers")
    parser.add_argument("phase_pos", nargs="?", choices=["event", "fixture", "report"], help="helper phase")
    parser.add_argument("--phase", choices=["event", "fixture", "report"], help="helper phase")
    parser.add_argument("--keys-dir", type=str, help="Ardur signing keys directory")
    parser.add_argument("--home", type=str, help="explicit Codex home for fixture writes; defaults to isolated Ardur local state")
    parser.add_argument("--project-dir", type=str, help="project directory for fixture generation")
    parser.add_argument("--chain-dir", type=str, help="Codex receipt chain directory")
    parser.add_argument("--verify-expiry", action="store_true", help="enforce short receipt expiry while verifying reports")
    args = parser.parse_args(list(argv) if argv is not None else None)
    phase = args.phase or args.phase_pos or "event"

    if phase == "event":
        output = handle_host_event(_load_json_stdin(), keys_dir=args.keys_dir)
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
    report = build_shareable_report(
        home=args.home,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
        verify_expiry=args.verify_expiry,
    )
    _print_json(report)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
