"""Console entry point for the pip-installable VIBAP proxy package."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

import jwt
from spiffe.errors import PySpiffeError

from . import __version__
from .ardur_profile import (
    PROFILE_TEMPLATES,
    ArdurProfile,
    InvalidProfilePathError,
    load_ardur_profile,
    write_profile_template,
)
from .ardur_personal_native_host import (
    NativeHostManifestValidationError,
    build_native_host_manifest,
    handle_native_host_message,
    run_native_host,
)
from .passport import (
    DEFAULT_HOME,
    DEFAULT_KEYS_DIR,
    KeyDirectoryError,
    MissionPassport,
    UNRESTRICTED_RESOURCE_SCOPE_PATTERN,
    _ensure_default_home_dir,
    derive_mission_id,
    generate_keypair,
    load_existing_private_key,
    load_existing_public_key,
    issue_passport,
    load_mission_file,
    verify_passport,
)
from .attestation import verify_attestation
from .package_assets import claude_code_plugin_dir
from .personal_hub import (
    DEFAULT_HUB_HOST,
    DEFAULT_HUB_PORT,
    DEFAULT_HUB_URL,
    HOME_DANGLING_SYMLINK_PARENT_CONDITION,
    HOME_PARENT_NOT_DIRECTORY_CONDITION,
    HUB_TLS_MATERIAL_INVALID_CONDITION,
    HubError,
    HubTLSConfigurationError,
    SETUP_HOME_INVALID_CONDITION,
    desktop_observe,
    doctor_personal,
    home_dangling_symlink_parent_failure_response,
    home_parent_not_directory_failure_response,
    hub_request,
    run_under_hub,
    serve_hub,
    setup_home_invalid_failure_response,
    setup_personal,
    status_response_with_next_steps,
    uninstall_personal,
    validate_personal_home_path_components,
)
from .personal_firewall import (
    MAX_DEMO_SECONDS as PERSONAL_FIREWALL_MAX_DEMO_SECONDS,
    PersonalFirewallDemoError,
    run_personal_firewall_demo,
)
from .claude_code_report import build_claude_code_report
from .latency_gate import (
    LatencyGateError,
    GateProtocol,
)
from .latency_gate_cli import (
    LatencyGateCliError,
    format_gate_output,
    load_reports_from_directory,
    run_gate,
)
from .claude_code_hook import main as claude_code_hook_main
from .gemini_cli_hook import (
    FixtureProjectDirError as GeminiFixtureProjectDirError,
    FixturePathError as GeminiFixturePathError,
    build_local_fixture as build_gemini_local_fixture,
    build_shareable_context as build_gemini_shareable_context,
    build_shareable_report as build_gemini_shareable_report,
    fixture_project_dir_failure_response as gemini_fixture_project_dir_failure_response,
    _fixture_path_failure_response as gemini_fixture_path_failure_response,
    main as gemini_cli_hook_main,
)
from .codex_app_server_fixture import (
    FixtureProjectDirError as CodexFixtureProjectDirError,
    FixturePathError as CodexFixturePathError,
    build_local_fixture as build_codex_local_fixture,
    build_shareable_context as build_codex_shareable_context,
    build_shareable_report as build_codex_shareable_report,
    fixture_project_dir_failure_response as codex_fixture_project_dir_failure_response,
    _fixture_path_failure_response as codex_fixture_path_failure_response,
    handle_host_event as handle_codex_host_event,
)
from .posture_index import (
    build_posture_index,
    format_posture_report,
    posture_receipts_failure_response,
    PostureReceiptsError,
    posture_input_failure_response,
    PostureInputError,
)
from .claude_code_daemon import (
    install_native_pre_tool_use_command,
    resolve_native_pre_tool_use_command_path,
)
from .proxy import (
    DEFAULT_STATE_DIR,
    GovernanceProxy,
    GovernanceSession,
    TLSConfigurationError,
    serve_proxy,
)
from .run_bridge import VALID_VIA_MODES, _redact_local_path, run_governed_cli
from .shareable_redaction import path_aliases, redact_local_path_text
from .spiffe_identity import (
    SvidBundle,
    TrustBundle,
    fetch_svid,
    load_biscuit_public_key,
    load_trust_bundle,
)
from .tool_preflight import (
    FAIL_ON_CHOICES,
    ToolPreflightError,
    error_response as tool_preflight_error_response,
    fail_threshold_reached,
    render_tool_preflight_markdown,
    scan_tool_server_config,
)
from .tls import tls_disabled_by_environment


_ATTEST_SESSION_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _print_json(payload: dict) -> None:
    """Emit a structured CLI response to stdout without using a logging sink."""

    # This is a command response, not an application log. Some CLI commands
    # intentionally return freshly generated local tokens to the invoking user,
    # while setup/hub recovery paths return non-secret condition codes.
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _spiffe_svid_fetch_failure_response() -> dict[str, object]:
    return {
        "ok": False,
        "error": "spiffe_svid_fetch_failed",
        "error_code": "spiffe_svid_fetch_failed",
        "condition": "spiffe_svid_fetch_failed",
        "message": "Configured SPIFFE workload identity could not be established.",
        "detail": (
            "Verify --spiffe-endpoint-socket or SPIFFE_ENDPOINT_SOCKET points to "
            "a reachable SPIFFE Workload API socket and that this workload is registered."
        ),
    }


def _fetch_configured_workload_identity(socket_path: str | None) -> SvidBundle | None:
    if socket_path is None:
        return None
    normalized = str(socket_path).strip()
    if not normalized:
        raise ValueError("configured SPIFFE endpoint socket is empty")
    return fetch_svid(normalized)


def _biscuit_peer_configuration_failure_response() -> dict[str, object]:
    return {
        "ok": False,
        "error": "biscuit_peer_verification_config_invalid",
        "error_code": "biscuit_peer_verification_config_invalid",
        "condition": "biscuit_peer_verification_config_invalid",
        "message": "Biscuit peer JWT-SVID verification configuration is invalid.",
        "detail": (
            "Configure a trust bundle and Biscuit issuer public key together. "
            "Raw SPIRE bundles also require a trust domain, and the expected "
            "JWT-SVID audience must be non-empty."
        ),
    }


def _optional_config_value(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _load_biscuit_peer_configuration(
    args: argparse.Namespace,
) -> tuple[Any | None, TrustBundle | None, str]:
    bundle_path = _optional_config_value(
        getattr(args, "biscuit_peer_trust_bundle", None)
    )
    trust_domain = _optional_config_value(
        getattr(args, "biscuit_peer_trust_domain", None)
    )
    issuer_key_path = _optional_config_value(
        getattr(args, "biscuit_issuer_public_key", None)
    )
    audience = str(getattr(args, "biscuit_svid_audience", "ardur-proxy")).strip()
    if not audience or len(audience.encode("utf-8")) > 256:
        raise ValueError("Biscuit JWT-SVID audience is invalid")

    enabled = any((bundle_path, trust_domain, issuer_key_path))
    if not enabled:
        return None, None, audience
    if bundle_path is None or issuer_key_path is None:
        raise ValueError("Biscuit peer verification requires bundle and issuer key")

    bundle = load_trust_bundle(bundle_path, trust_domain=trust_domain)
    keys = bundle.jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("Biscuit peer trust bundle has no keys")
    if not any(
        isinstance(key, dict) and ("use" not in key or key["use"] == "jwt-svid")
        for key in keys
    ):
        raise ValueError("Biscuit peer trust bundle has no JWT-SVID signing keys")
    issuer_key = load_biscuit_public_key(issuer_key_path)
    return issuer_key, bundle, audience


def _write_json_report_to_file(path: str | Path, report: object) -> bytes:
    """Serialize *report* to canonical JSON and atomically write it to *path*.

    Reuses the no-follow atomic writer from ``runtime_evidence`` so that the
    same safe-replace semantics (owner-only regular file, directory-handle
    rename, no symlink follow) apply to every report-producing command.
    Returns the serialized bytes so callers can compute a digest.

    Raises ``ValueError`` with a safe message (no local path) when the atomic
    writer rejects the target shape.
    """

    from .runtime_evidence import RuntimeEvidenceError, write_report

    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    try:
        write_report(path, payload)
    except RuntimeEvidenceError as exc:
        raise ValueError(exc.code) from exc
    return payload


def _handle_output_and_redact(
    args: argparse.Namespace,
    response: dict[str, Any],
    *,
    command: str,
    exit_code: int | None = None,
) -> int:
    """Apply ``--redact-paths`` and ``--output`` to *response*, then emit.

    Shared terminal logic for commands whose JSON response is the final
    output.  When ``--redact-paths`` is set, local absolute paths in
    *response* are recursively replaced.  When ``--output`` is set, the
    (possibly redacted) response is atomically written to an owner-only
    file and a success confirmation is printed instead.  When neither is
    set, *response* is printed directly to stdout via :func:`_print_json`.

    If *exit_code* is ``None`` (default), returns ``0`` on success.  When
    the caller provides an explicit *exit_code*, that value is returned
    after successful output so commands like ``anchor`` can propagate
    their ``ok``-based exit status even when writing to a file.
    """

    redact = getattr(args, "redact_paths", False)
    output = getattr(args, "output", None)
    if redact and not getattr(args, "json", False) and output is None:
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if redact:
        response = _redact_paths_deep(response)
    if output is not None:
        try:
            payload = _write_json_report_to_file(output, response)
        except ValueError as exc:
            _print_json(
                {
                    "ok": False,
                    **_output_write_error_response(command, exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": f"{command}_report_written",
                "output": str(output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return exit_code if exit_code is not None else 0
    _print_json(response)
    return exit_code if exit_code is not None else 0


def _output_write_error_response(command: str, exc: Exception) -> dict[str, Any]:
    """Build an enriched structured-error dict for a ``--output`` write failure.

    Shared by inline verify handlers and report handlers so every command
    that catches ``ValueError`` from ``_write_json_report_to_file`` emits the
    same structured shape as ``_handle_output_and_redact``.
    """
    _condition = f"{command}_output_write_failed"
    return {
        "error": _condition,
        "error_code": _condition,
        "condition": _condition,
        "message": (
            f"Writing the --output file for ardur {command.replace('_', '-')} "
            "failed because the path is invalid or not writable."
        ),
        "detail": str(exc),
        "next_steps": [
            {
                "action": "choose_writable_output_path",
                "command": (
                    f"ardur {command.replace('_', '-')} --output <writable-file-path>"
                ),
                "detail": (
                    "Provide a writable file path (not an existing "
                    "directory or protected location) for the JSON report."
                ),
            },
        ],
    }


def _hub_path_error_code() -> str:
    return "_".join(("personal", "home", "not", "directory"))


def _path_not_directory_condition() -> str:
    return "path_not_directory"


def _path_not_directory_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_personal_home_directory",
            "command": "ardur setup --home <ardur-dir>",
            "detail": (
                "Choose a directory path for local Ardur state. If the selected "
                "path is an existing file, move it aside or pick a different "
                "directory before setup."
            ),
        },
        {
            "condition": condition,
            "action": "start_personal_hub_after_setup",
            "command": "ardur hub --home <ardur-dir>",
            "detail": (
                "Start the loopback Hub only after the selected path is a directory. "
                "Keep raw local paths, tokens, and receipt locations out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_doctor",
            "command": "ardur doctor --home <ardur-dir>",
            "detail": (
                "Re-run local setup diagnostics after choosing a valid directory. "
                "This guidance is local/no-key recovery only."
            ),
        },
    ]


def _offline_verification_next_steps(error_code: str) -> list[dict[str, str]]:
    """Return actionable next steps for offline verification error codes."""
    if error_code == "input_missing":
        return [
            {
                "condition": "input_missing",
                "action": "check_journal_path",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal file was not found at the given path. "
                    "Verify the file path and ensure the journal exists."
                ),
            },
        ]
    if error_code == "input_not_file":
        return [
            {
                "condition": "input_not_file",
                "action": "use_regular_file",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal path must be a regular file, not a directory or special file. "
                    "Pass the path to a regular journal file."
                ),
            },
        ]
    if error_code == "malformed_json":
        return [
            {
                "condition": "malformed_json",
                "action": "validate_journal_json",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal contains malformed JSON. Validate the JSON syntax "
                    "and ensure each line is a valid compact JWS or JSON object."
                ),
            },
        ]
    if error_code == "input_symlink":
        return [
            {
                "condition": "input_symlink",
                "action": "use_regular_file",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal path must not be a symlink. "
                    "Pass the path to the actual regular file."
                ),
            },
        ]
    if error_code == "input_size_invalid" or error_code == "input_too_large":
        return [
            {
                "condition": error_code,
                "action": "check_journal_size",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal file size is outside the allowed range. "
                    "Ensure the file is between 1 byte and 64 MiB."
                ),
            },
        ]
    if error_code == "duplicate_json_key":
        return [
            {
                "condition": "duplicate_json_key",
                "action": "validate_journal_json",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "The journal contains duplicate JSON object keys. "
                    "Remove duplicate keys and retry."
                ),
            },
        ]
    if error_code == "journal_entry_invalid" or error_code == "journal_token_invalid":
        return [
            {
                "condition": error_code,
                "action": "validate_journal_entries",
                "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
                "detail": (
                    "One or more journal entries are not valid compact JWS tokens. "
                    "Check the journal format and ensure each line is a valid receipt."
                ),
            },
        ]
    # Generic fallback for unknown error codes
    return [
        {
            "condition": error_code,
            "action": "check_input_files",
            "command": "ardur verify --receipt-public-key <key.pem> <journal.jsonl>",
            "detail": (
                "Offline verification failed. Check that your journal file, "
                "receipt public key, and any optional key files are valid and accessible."
            ),
        },
    ]


def _path_not_directory_response() -> dict:
    condition = _path_not_directory_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur setup path must be a directory.",
        "detail": (
            "The selected Ardur setup path already exists as a file or other "
            "non-directory. Choose a directory path before running setup or starting the Hub."
        ),
        "next_steps": _path_not_directory_next_steps(condition),
    }


def _path_failure_exit_code(exc: HubError) -> int:
    if exc.code == SETUP_HOME_INVALID_CONDITION:
        _print_json(setup_home_invalid_failure_response())
        return 1
    if exc.code == HOME_DANGLING_SYMLINK_PARENT_CONDITION:
        _print_json(home_dangling_symlink_parent_failure_response())
        return 1
    if exc.code == HOME_PARENT_NOT_DIRECTORY_CONDITION:
        _print_json(home_parent_not_directory_failure_response())
        return 1
    if exc.code != _hub_path_error_code():
        raise exc
    _print_json(_path_not_directory_response())
    return 1


def _print_report_next_steps(report: dict) -> None:
    next_steps = report.get("next_steps") or []
    if not next_steps:
        return
    print("Next steps:")
    for index, step in enumerate(next_steps, start=1):
        command = step.get("command", "")
        detail = step.get("detail", "")
        print(f"{index}. {command}")
        if detail:
            print(f"   {detail}")


def _keys_dir_failure_condition(exc: KeyDirectoryError) -> str:
    return getattr(exc, "condition", "keys_dir_not_directory")


def _keys_dir_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_keys_directory",
            "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
            "detail": (
                "Choose a directory path for Mission Passport signing keys. If the selected "
                "path is an existing file, move it aside or use a different directory."
            ),
        },
        {
            "condition": condition,
            "action": "verify_with_valid_keys_directory",
            "command": "ardur verify --token <token> --keys-dir <keys-dir>",
            "detail": (
                "Use the same key directory that issued the Mission Passport. Keep raw tokens, "
                "private keys, and local paths out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "attest_with_valid_keys_directory",
            "command": (
                "ardur attest --session <session-id> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log>"
            ),
            "detail": (
                "Retry attestation only after selecting a real key directory and the matching "
                "local state/log locations."
            ),
        },
    ]


def _keys_dir_failure_response(exc: KeyDirectoryError) -> dict:
    condition = _keys_dir_failure_condition(exc)
    detail = getattr(
        exc, "detail", "The selected Mission Passport key path is not a directory."
    )
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport key directory must be a directory.",
        "detail": detail,
        "next_steps": _keys_dir_failure_next_steps(condition),
    }


def _path_points_to_existing_non_directory(path: Path | None) -> bool:
    if path is None:
        return False
    candidate = Path(path).expanduser()
    try:
        candidate.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    try:
        return not candidate.is_dir()
    except OSError:
        return True


def _keys_dir_failure_exit_code(path: Path | None) -> int | None:
    candidate = Path(path).expanduser() if path is not None else DEFAULT_KEYS_DIR
    if not _path_points_to_existing_non_directory(
        candidate
    ) and not _path_has_existing_non_directory_parent(candidate):
        return None
    _print_json(_keys_dir_failure_response(KeyDirectoryError()))
    return 1


def _state_dir_failure_condition() -> str:
    return "state_dir_not_directory"


def _state_dir_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_state_directory",
            "command": (
                "ardur start --keys-dir <keys-dir> --state-dir <state-dir> "
                "--log-path <audit-log>"
            ),
            "detail": (
                "Choose a directory path for persisted Mission Passport state. If the selected "
                "path is an existing file, move it aside or use a different directory."
            ),
        },
        {
            "condition": condition,
            "action": "attest_with_valid_state_directory",
            "command": (
                "ardur attest --session <session-id> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log>"
            ),
            "detail": (
                "Retry attestation only after selecting a real state directory that contains "
                "the governed session records."
            ),
        },
    ]


def _state_dir_failure_response() -> dict:
    condition = _state_dir_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport state directory must be a directory.",
        "detail": (
            "The selected Mission Passport state path already exists as a file or other "
            "non-directory. Choose a directory path before starting or attesting a session."
        ),
        "next_steps": _state_dir_failure_next_steps(condition),
    }


def _state_dir_parent_failure_condition() -> str:
    return "state_dir_parent_not_directory"


def _state_dir_parent_failure_response() -> dict:
    condition = _state_dir_parent_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport state directory parent must be a directory.",
        "detail": (
            "A parent of the selected Mission Passport state path already exists as a "
            "file or other non-directory. Choose a state directory whose parents are directories."
        ),
        "next_steps": _state_dir_failure_next_steps(condition),
    }


def _state_dir_points_to_existing_non_directory(path: Path | None) -> bool:
    if path is None:
        return False
    candidate = Path(path).expanduser()
    try:
        return candidate.exists() and not candidate.is_dir()
    except OSError:
        return False


def _path_has_existing_non_directory_parent(path: Path | None) -> bool:
    if path is None:
        return False
    candidate = Path(path).expanduser()
    for parent in candidate.parents:
        try:
            parent.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        try:
            return not parent.is_dir()
        except OSError:
            return True
    return False


def _state_dir_failure_exit_code(path: Path | None) -> int | None:
    if not _state_dir_points_to_existing_non_directory(path):
        return None
    _print_json(_state_dir_failure_response())
    return 1


def _state_dir_parent_failure_exit_code(path: Path | None) -> int | None:
    if not _path_has_existing_non_directory_parent(path):
        return None
    _print_json(_state_dir_parent_failure_response())
    return 1


def _log_path_failure_condition() -> str:
    return "log_path_not_file"


def _log_path_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_audit_log_file",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log>"
            ),
            "detail": (
                "Choose a JSONL audit-log file path. If the selected path is an "
                "existing directory or other non-file, move it aside or use a file path."
            ),
        },
        {
            "condition": condition,
            "action": "attest_with_valid_audit_log_file",
            "command": (
                "ardur attest --session <session-id> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log>"
            ),
            "detail": (
                "Retry attestation only after selecting a writable audit-log file path. "
                "Keep raw local paths, tokens, and private-key material out of shared logs."
            ),
        },
    ]


def _log_path_failure_response() -> dict:
    condition = _log_path_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport audit log path must be a file path.",
        "detail": (
            "The selected Mission Passport audit log path already exists as a directory "
            "or other non-file. Choose a JSONL file path before starting or attesting a session."
        ),
        "next_steps": _log_path_failure_next_steps(condition),
    }


def _log_path_parent_failure_condition() -> str:
    return "log_path_parent_not_directory"


def _log_path_parent_failure_response() -> dict:
    condition = _log_path_parent_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport audit log parent must be a directory.",
        "detail": (
            "A parent of the selected Mission Passport audit log path already exists as "
            "a file or other non-directory. Choose an audit-log path whose parents are directories."
        ),
        "next_steps": _log_path_failure_next_steps(condition),
    }


def _log_path_points_to_existing_non_file(path: Path | None) -> bool:
    if path is None:
        return False
    candidate = Path(path).expanduser()
    try:
        return candidate.exists() and not candidate.is_file()
    except OSError:
        return False


def _log_path_failure_exit_code(path: Path | None) -> int | None:
    if not _log_path_points_to_existing_non_file(path):
        return None
    _print_json(_log_path_failure_response())
    return 1


def _log_path_parent_failure_exit_code(path: Path | None) -> int | None:
    if not _path_has_existing_non_directory_parent(path):
        return None
    _print_json(_log_path_parent_failure_response())
    return 1


def _start_port_failure_condition() -> str:
    return "start_port_invalid"


def _start_port_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_valid_start_port",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <port>"
            ),
            "detail": (
                "Use an integer TCP port from 0 through 65535. Use 0 when you "
                "want the operating system to choose an available local port."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_ephemeral_port",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <valid-port>"
            ),
            "detail": (
                "For local setup checks, --port 0 avoids collisions and stays within "
                "the valid TCP port range. Keep raw local paths, tokens, and key "
                "material out of shared logs."
            ),
        },
    ]


def _start_port_failure_response() -> dict:
    condition = _start_port_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start port must be within the valid TCP port range.",
        "detail": "Choose an integer port from 0 through 65535 before starting Ardur.",
        "next_steps": _start_port_failure_next_steps(condition),
    }


def _start_port_failure_exit_code(port: int) -> int | None:
    if 0 <= port <= 65535:
        return None
    _print_json(_start_port_failure_response())
    return 1


def _start_port_in_use_condition() -> str:
    return "start_port_in_use"


def _start_port_in_use_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_available_start_port",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <available-port>"
            ),
            "detail": (
                "The configured port is already in use by another process. "
                "Choose a different port or pass --port 0 to let the operating "
                "system choose an available local port."
            ),
        },
    ]


def _start_port_in_use_response() -> dict:
    condition = _start_port_in_use_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start port is already in use by another process.",
        "detail": (
            "Stop the process occupying the port or choose a different --port. "
            "Use --port 0 for an ephemeral port."
        ),
        "next_steps": _start_port_in_use_next_steps(condition),
    }


def _start_oserror_condition() -> str:
    return "start_oserror"


def _start_oserror_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "check_start_permissions",
            "command": "ardur start --mission <mission.json> --keys-dir <keys-dir>",
            "detail": (
                "If the error is EACCES or EPERM, verify the user has permission "
                "to bind the requested host and port."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_ephemeral_port",
            "command": "ardur start --mission <mission.json> --keys-dir <keys-dir> --port 0",
            "detail": "Use --port 0 for an ephemeral port to avoid conflicts.",
        },
    ]


def _start_oserror_response(exc: OSError) -> dict:
    import errno as _errno

    condition = _start_oserror_condition()
    detail = f"OSError errno {_errno.errorcode.get(exc.errno or 0, exc.errno)}: {exc.strerror or str(exc)}"
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start failed with an unexpected OSError.",
        "detail": detail,
        "next_steps": _start_oserror_next_steps(condition),
    }


def _start_host_failure_condition() -> str:
    return "start_host_invalid"


def _start_host_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_bindable_start_host",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <port>"
            ),
            "detail": (
                "Pass only a host name or IP address that this machine can bind. "
                "Do not include URL schemes, ports, paths, credentials, or empty values."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_loopback_host",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host 127.0.0.1 --port <valid-port>"
            ),
            "detail": (
                "For local setup checks, use a loopback host such as 127.0.0.1 or "
                "localhost with --port 0. Keep raw local paths, URLs, tokens, and key "
                "material out of shared logs."
            ),
        },
    ]


def _start_host_failure_response() -> dict:
    condition = _start_host_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start host must be a bindable host name or IP address.",
        "detail": (
            "Choose a host value that can be bound locally before starting Ardur. "
            "Use --port for the port; do not include a URL scheme, path, or empty host."
        ),
        "next_steps": _start_host_failure_next_steps(condition),
    }


def _start_host_has_url_shape(host: str) -> bool:
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(host)
    except ValueError:
        return True
    return bool(
        "://" in host
        or host.startswith("//")
        or "/" in host
        or "?" in host
        or "#" in host
        or (parsed.scheme and not host.startswith("["))
        or parsed.netloc
    )


def _start_host_is_bindable(host: str) -> bool:
    import socket

    try:
        candidates = socket.getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    for family, socktype, proto, _canonname, sockaddr in candidates:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.bind(sockaddr)
            return True
        except OSError:
            continue
    return False


def _start_host_failure_exit_code(host: str) -> int | None:
    host_value = str(host)
    stripped = host_value.strip()
    if (
        not stripped
        or stripped != host_value
        or _start_host_has_url_shape(stripped)
        or not _start_host_is_bindable(stripped)
    ):
        _print_json(_start_host_failure_response())
        return 1
    return None


def _hub_port_failure_condition() -> str:
    return "hub_port_invalid"


def _hub_port_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_valid_hub_port",
            "command": "ardur hub --host <loopback-host> --port <port> --home <ardur-home>",
            "detail": (
                "Use an integer TCP port from 0 through 65535. Use 0 when you "
                "want the operating system to choose an available local port."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_personal_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "After choosing a valid local Hub port, check Ardur Personal setup "
                "with placeholder-only local diagnostics."
            ),
        },
    ]


def _hub_port_failure_response() -> dict:
    condition = _hub_port_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur Personal Hub port must be within the valid TCP port range.",
        "detail": "Choose an integer port from 0 through 65535 before starting the Hub.",
        "next_steps": _hub_port_failure_next_steps(condition),
    }


def _hub_port_failure_exit_code(port: int) -> int | None:
    if 0 <= port <= 65535:
        return None
    _print_json(_hub_port_failure_response())
    return 1


def _hub_port_in_use_condition() -> str:
    return "hub_port_in_use"


def _hub_port_in_use_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_available_hub_port",
            "command": "ardur hub --host <loopback-host> --port <available-port> --home <ardur-home>",
            "detail": (
                "The configured port is already in use by another process. "
                "Choose a different port or pass --port 0 to let the operating "
                "system choose an available local port."
            ),
        },
    ]


def _hub_port_in_use_response() -> dict:
    condition = _hub_port_in_use_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur hub port is already in use by another process.",
        "detail": (
            "Stop the process occupying the port or choose a different --port. "
            "Use --port 0 for an ephemeral port."
        ),
        "next_steps": _hub_port_in_use_next_steps(condition),
    }


def _hub_oserror_condition() -> str:
    return "hub_oserror"


def _hub_oserror_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "check_hub_permissions",
            "command": "ardur hub",
            "detail": (
                "If the error is EACCES or EPERM, verify the user has permission "
                "to bind the requested host and port."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_ephemeral_port",
            "command": "ardur hub --port 0",
            "detail": "Use --port 0 for an ephemeral port to avoid conflicts.",
        },
    ]


def _hub_oserror_response(exc: OSError) -> dict:
    import errno as _errno

    condition = _hub_oserror_condition()
    detail = f"OSError errno {_errno.errorcode.get(exc.errno or 0, exc.errno)}: {exc.strerror or str(exc)}"
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur hub failed with an unexpected OSError.",
        "detail": detail,
        "next_steps": _hub_oserror_next_steps(condition),
    }


def _hub_host_failure_condition() -> str:
    return "hub_host_invalid"


def _hub_host_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_bindable_hub_host",
            "command": "ardur hub --host <loopback-host> --port <port> --home <ardur-home>",
            "detail": (
                "Pass only a host name or IP address that this machine can bind. "
                "Do not include URL schemes, ports, paths, credentials, or empty values."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_loopback_host",
            "command": "ardur hub --host 127.0.0.1 --port <valid-port> --home <ardur-home>",
            "detail": (
                "For local setup checks, use a loopback host such as 127.0.0.1, "
                "::1, or localhost with --port 0. Keep raw local paths, URLs, "
                "tokens, and key material out of shared logs."
            ),
        },
    ]


def _hub_host_failure_response() -> dict:
    condition = _hub_host_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur Personal Hub host must be a bindable host name or IP address.",
        "detail": (
            "Choose a host value that can be bound locally before starting the Hub. "
            "Use --port for the port; do not include a URL scheme, path, or empty host."
        ),
        "next_steps": _hub_host_failure_next_steps(condition),
    }


def _hub_host_is_bindable(host: str) -> bool:
    import socket

    try:
        candidates = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    for family, socktype, proto, _canonname, sockaddr in candidates:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.bind(sockaddr)
            return True
        except OSError:
            continue
    return False


def _hub_host_failure_exit_code(host: str) -> int | None:
    host_value = str(host)
    stripped = host_value.strip()
    if (
        not stripped
        or stripped != host_value
        or _start_host_has_url_shape(stripped)
        or not _hub_host_is_bindable(stripped)
    ):
        _print_json(_hub_host_failure_response())
        return 1
    return None


def _hub_tls_material_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_readable_hub_tls_files",
            "command": (
                "ardur hub --host <loopback-host> --port <port> --home <ardur-home> "
                "--tls-cert <tls-cert.pem> --tls-key <tls-key.pem>"
            ),
            "detail": (
                "When providing explicit Hub TLS material, use an existing certificate "
                "and matching private-key file. Keep raw paths, tokens, and key material "
                "out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "use_hub_auto_tls_or_explicit_no_tls",
            "command": "ardur hub --host <loopback-host> --port <port> --home <ardur-home>",
            "detail": (
                "Omit --tls-cert/--tls-key to create local self-signed TLS, or add "
                "--no-tls only when plain loopback HTTP is explicitly intended. "
                "Environment variables alone cannot authorize a TLS downgrade."
            ),
        },
    ]


def _hub_tls_material_failure_response(detail: str | None = None) -> dict:
    condition = HUB_TLS_MATERIAL_INVALID_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur Personal Hub TLS material is invalid.",
        "detail": detail
        or (
            "TLS remains enabled unless --no-tls is explicitly supplied. Explicit "
            "certificate and key values must identify a usable matching pair."
        ),
        "next_steps": _hub_tls_material_failure_next_steps(condition),
    }


def _start_tls_material_failure_condition() -> str:
    return "start_tls_material_invalid"


def _start_tls_material_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "choose_readable_tls_files",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <port> "
                "--tls-cert <tls-cert.pem> --tls-key <tls-key.pem>"
            ),
            "detail": (
                "Use existing certificate and private-key files when providing explicit TLS "
                "material. Keep raw local paths, tokens, and private-key material out of "
                "shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "use_local_auto_tls_or_no_tls",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log> "
                "--host <loopback-host> --port <port>"
            ),
            "detail": (
                "Omit --tls-cert/--tls-key to let Ardur create local self-signed TLS, "
                "or add --no-tls only for loopback development when plain HTTP is intended."
            ),
        },
    ]


def _start_tls_material_failure_response(detail: str | None = None) -> dict:
    condition = _start_tls_material_failure_condition()
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start TLS material is invalid.",
        "detail": detail
        or (
            "TLS stays enabled unless --no-tls is explicitly supplied. When explicit "
            "--tls-cert and --tls-key values are used, both must point to existing files "
            "before Ardur starts the local governance proxy."
        ),
        "next_steps": _start_tls_material_failure_next_steps(condition),
    }


def _start_tls_material_invalid(args: argparse.Namespace) -> bool:
    if args.no_tls:
        return False
    if tls_disabled_by_environment():
        return True
    if args.tls_cert is None and args.tls_key is None:
        return False
    if args.tls_cert is None or args.tls_key is None:
        return True
    try:
        return (
            not Path(args.tls_cert).expanduser().is_file()
            or not Path(args.tls_key).expanduser().is_file()
        )
    except OSError:
        return True


def _start_tls_material_failure_exit_code(args: argparse.Namespace) -> int | None:
    if not _start_tls_material_invalid(args):
        return None
    _print_json(_start_tls_material_failure_response())
    return 1


def _start_mission_file_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "fix_mission_file_and_restart",
            "command": (
                "ardur start --mission <mission.json> --keys-dir <keys-dir> "
                "--state-dir <state-dir> --log-path <audit-log>"
            ),
            "detail": (
                "Replace <mission.json> with a readable JSON object containing "
                "agent_id, mission, and any intended mission constraints. Keep raw "
                "local paths and file contents out of shared logs."
            ),
        }
    ]


def _start_mission_file_failure_condition(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, FileNotFoundError):
        return (
            "start_mission_file_missing",
            "The --mission file could not be found. Provide an existing mission JSON file before starting Ardur.",
        )
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return (
            "start_mission_file_malformed_json",
            "The --mission file must be valid UTF-8 JSON containing a mission object.",
        )
    if isinstance(exc, PermissionError):
        return (
            "start_mission_file_unreadable",
            "The --mission file could not be read. Check file permissions and retry with a readable mission JSON file.",
        )
    if isinstance(exc, IsADirectoryError):
        return (
            "start_mission_file_invalid",
            "The --mission input must point to a mission JSON file, not a directory.",
        )
    if isinstance(exc, OSError):
        return (
            "start_mission_file_unreadable",
            "The --mission file could not be read. Retry with a readable mission JSON file.",
        )
    return (
        "start_mission_file_invalid",
        "The --mission JSON object does not match Ardur's mission schema. Include required fields and valid values.",
    )


def _start_mission_file_failure_response(exc: Exception) -> dict:
    condition, detail = _start_mission_file_failure_condition(exc)
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur start could not load the mission file.",
        "detail": detail,
        "next_steps": _start_mission_file_failure_next_steps(condition),
    }


def _start_mission_path_invalid_response() -> dict[str, object]:
    """Failure response for an empty/whitespace --mission path on start.

    ``--mission`` on ``ardur start`` is a mission JSON file path, not a
    directory, so the generic ``_path_arg_invalid_response`` hint that
    suggests ``--mission .`` would mislead the user into an
    ``IsADirectoryError``. Use the mission-file-specific guidance instead.
    """
    return {
        "ok": False,
        "error": "start_mission_path_invalid",
        "error_code": "start_mission_path_invalid",
        "condition": "start_mission_path_invalid",
        "message": "ardur start --mission must be a mission JSON file path after trimming whitespace.",
        "detail": (
            "An empty or whitespace-only --mission path was provided on start. "
            "Provide an explicit mission JSON file path."
        ),
        "next_steps": _start_mission_file_failure_next_steps(
            "start_mission_path_invalid"
        ),
    }


def _start_api_token_invalid_response() -> dict[str, object]:
    """Failure response for an empty/whitespace --api-token on start.

    ``--api-token`` is stripped inside ``serve_proxy`` (mirroring the env-var
    and Go TrimSpace paths), but an explicit whitespace-only argument is
    truthy before stripping and falsy after, so it entered the argument
    branch and resolved to an empty bearer token. Reject it here, before any
    key material is generated, with the same structured shape the other
    ``start`` validation helpers use. An unset ``--api-token`` (None) and an
    empty string ``""`` (falsy, falls through to ``_generate_api_token``)
    remain valid: only whitespace-only strings are rejected, matching the
    silent-empty-token bug class closed for ``--proxy-url`` in 4d98a01.
    """
    return {
        "ok": False,
        "error": "start_api_token_invalid",
        "error_code": "start_api_token_invalid",
        "condition": "start_api_token_invalid",
        "message": "ardur start --api-token must be a non-empty token after trimming whitespace.",
        "detail": (
            "An empty or whitespace-only --api-token was provided on start. "
            "Provide an explicit bearer token, or omit --api-token to have "
            "ardur generate a random one."
        ),
        "next_steps": [
            {
                "action": "pass_explicit_api_token",
                "command": "ardur start --api-token <api-token>",
                "detail": "Provide an explicit --api-token bearer token.",
            },
            {
                "action": "omit_api_token_to_autogenerate",
                "command": "ardur start",
                "detail": (
                    "Omit --api-token so ardur generates a random bearer token. "
                    "VIBAP_API_TOKEN still takes precedence when set."
                ),
            },
        ],
    }


def _start_api_token_invalid_failure(
    args: argparse.Namespace,
) -> dict[str, object] | None:
    """Return the api-token-invalid response when --api-token is whitespace-only.

    ``None`` means the argument is acceptable: either unset (None), an empty
    string (falsy, falls through to autogeneration), or a real token.
    """
    value = getattr(args, "api_token", None)
    if isinstance(value, str) and value and not value.strip():
        return _start_api_token_invalid_response()
    return None


def _hub_token_invalid_response() -> dict[str, object]:
    """Failure response for a whitespace-only ``--hub-token`` on Hub-client commands.

    ``resolve_hub_token`` strips the env-var path (``os.environ...strip()``) but
    returns the CLI-explicit path verbatim (``if explicit: return explicit``),
    so a whitespace-only ``--hub-token '   '`` is truthy before stripping and
    resolves to a whitespace bearer token inside ``hub_request``. That reaches
    ``urlrequest.urlopen`` and surfaces as a confusing ``hub_unavailable`` after
    a 5-second network timeout rather than a clear input-validation error.

    An unset ``--hub-token`` (None) and an empty string ``""`` (falsy, falls
    through to the env-var/config lookup) remain valid: only whitespace-only
    strings are rejected. This mirrors the ``_start_api_token_invalid_response``
    helper and the silent-empty-token bug class already closed for ``--api-token``
    and ``--proxy-url``.
    """
    return {
        "ok": False,
        "error": "hub_token_invalid",
        "error_code": "hub_token_invalid",
        "condition": "hub_token_invalid",
        "message": "ardur --hub-token must be a non-empty token after trimming whitespace.",
        "detail": (
            "A whitespace-only --hub-token was provided. Provide an explicit "
            "Hub bearer token, or omit --hub-token so ardur resolves the token "
            "from ARDUR_HUB_TOKEN or the local Personal Hub config. An empty "
            'string --hub-token "" is intentionally valid and means fall '
            "through to env/config."
        ),
        "next_steps": [
            {
                "action": "pass_explicit_hub_token",
                "command": "ardur <command> --hub-token <hub-token>",
                "detail": "Provide an explicit --hub-token Hub bearer token.",
            },
            {
                "action": "omit_hub_token_to_use_env_or_config",
                "command": "ardur <command>",
                "detail": (
                    "Omit --hub-token so ardur resolves the token from "
                    "ARDUR_HUB_TOKEN or the Personal Hub config. An empty "
                    '--hub-token "" has the same fall-through semantics.'
                ),
            },
        ],
    }


def _hub_token_invalid_failure(
    args: argparse.Namespace,
) -> dict[str, object] | None:
    """Return the hub-token-invalid response when ``--hub-token`` is whitespace-only.

    ``None`` means the argument is acceptable: either unset (None), an empty
    string (falsy, falls through to env/config), or a real token.
    """
    value = getattr(args, "hub_token", None)
    if isinstance(value, str) and value and not value.strip():
        return _hub_token_invalid_response()
    return None


_PATH_ARG_SPECS = (
    "keys_dir",
    "state_dir",
    "log_path",
    "tls_cert",
    "tls_key",
    "anchor_bundle",
    "journal",
    "receipt_public_key",
    "transparency_log_key",
    "receiver_envelope",
    "receiver_public_key",
    "mcp_request",
    "mcp_response",
    "html_report",
    "receipt_log",
    "local_log",
    "log_private_key",
    "evidence_events",
    "evidence_output",
    "telemetry_output",
    "temp_parent",
    "once_json",
    "config",
    "output",
    "extension_path",
    "path",
    "plugin_dir",
)


def _path_arg_is_empty(value: object) -> bool:
    """True when a CLI path argument is an empty or whitespace-only string."""
    return isinstance(value, str) and not value.strip()


def _path_arg_invalid_response(arg_name: str) -> dict[str, object]:
    return {
        "ok": False,
        "error": "path_arg_invalid",
        "error_code": "path_arg_invalid",
        "condition": "path_arg_invalid",
        "message": f"ardur --{arg_name.replace('_', '-')} must be a non-empty path after trimming whitespace.",
        "detail": (
            "An empty or whitespace-only path argument was provided. "
            "Pass an explicit directory or file path, or use '.' for the current working directory."
        ),
        "next_steps": [
            {
                "action": f"pass_{arg_name}",
                "command": f"ardur <command> --{arg_name.replace('_', '-')} <{arg_name.replace('_', '-')}>",
                "detail": f"Provide an explicit --{arg_name.replace('_', '-')} path.",
            },
            {
                "action": "use_cwd",
                "command": f"ardur <command> --{arg_name.replace('_', '-')} .",
                "detail": "Use '.' explicitly to target the current working directory.",
            },
        ],
    }


def _path_arg_invalid_failure(args: argparse.Namespace) -> dict[str, object] | None:
    """Check all path-typed args for empty/whitespace strings.

    Returns the first invalid response dict, or None if all are valid.
    Coerces validated non-None str values back to Path on the namespace
    so downstream Path | None consumers see identical types.
    """
    for name in _PATH_ARG_SPECS:
        value = getattr(args, name, None)
        if _path_arg_is_empty(value):
            return _path_arg_invalid_response(name)
    # Coerce validated str values back to Path for downstream type consistency.
    for name in _PATH_ARG_SPECS:
        value = getattr(args, name, None)
        if isinstance(value, str):
            setattr(args, name, Path(value))
    return None


def cmd_start(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    # --mission on start is a JSON file path, guarded inline (on issue it is a
    # description string already covered by _issue_identity_failure). The file
    # path is not a directory, so use the mission-file-specific guidance rather
    # than the generic _path_arg_invalid_response hint that suggests '.'.
    if isinstance(args.mission, str) and not args.mission.strip():
        _print_json(_start_mission_path_invalid_response())
        return 1
    port_failure = _start_port_failure_exit_code(args.port)
    if port_failure is not None:
        return port_failure
    host_failure = _start_host_failure_exit_code(args.host)
    if host_failure is not None:
        return host_failure
    tls_material_failure = _start_tls_material_failure_exit_code(args)
    if tls_material_failure is not None:
        return tls_material_failure
    mission = None
    ttl_s = None
    if args.mission:
        try:
            mission, ttl_s, _ = load_mission_file(args.mission)
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
        ) as exc:
            _print_json(_start_mission_file_failure_response(exc))
            return 1
    state_dir_failure = _state_dir_failure_exit_code(args.state_dir)
    if state_dir_failure is not None:
        return state_dir_failure
    state_dir_parent_failure = _state_dir_parent_failure_exit_code(args.state_dir)
    if state_dir_parent_failure is not None:
        return state_dir_parent_failure
    log_path_failure = _log_path_failure_exit_code(args.log_path)
    if log_path_failure is not None:
        return log_path_failure
    log_path_parent_failure = _log_path_parent_failure_exit_code(args.log_path)
    if log_path_parent_failure is not None:
        return log_path_parent_failure
    api_token_failure = _start_api_token_invalid_failure(args)
    if api_token_failure is not None:
        _print_json(api_token_failure)
        return 1
    try:
        biscuit_issuer_public_key, biscuit_peer_trust_bundle, biscuit_svid_audience = (
            _load_biscuit_peer_configuration(args)
        )
    except (KeyError, OSError, TypeError, ValueError):
        _print_json(_biscuit_peer_configuration_failure_response())
        return 1
    try:
        workload_identity = _fetch_configured_workload_identity(
            getattr(args, "spiffe_endpoint_socket", None)
        )
    except (OSError, PySpiffeError, RuntimeError, ValueError):
        _print_json(_spiffe_svid_fetch_failure_response())
        return 1
    if workload_identity is not None:
        print(
            f"[spiffe] workload identity established: {workload_identity.spiffe_id}",
            file=sys.stderr,
        )
    try:
        private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
        biscuit_issuer_public_key=biscuit_issuer_public_key,
        biscuit_peer_trust_bundle=biscuit_peer_trust_bundle,
        biscuit_svid_audience=biscuit_svid_audience,
        workload_identity=workload_identity,
    )

    initial_session_id = None
    if mission is not None:
        token = issue_passport(mission, private_key, ttl_s=ttl_s)
        session = proxy.start_session(token)
        initial_session_id = session.jti
        _print_json(
            {
                "status": "session_started",
                "mission_file": str(Path(args.mission).expanduser()),
                "session_id": session.jti,
                "agent_id": mission.agent_id,
                "mission": mission.mission,
                "token": token,
            }
        )

    try:
        serve_proxy(
            proxy=proxy,
            private_key=private_key,
            host=args.host,
            port=args.port,
            initial_session_id=initial_session_id,
            require_auth=args.require_auth,
            api_token=args.api_token,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            no_tls=args.no_tls,
        )
    except TLSConfigurationError as exc:
        _print_json(_start_tls_material_failure_response(detail=str(exc)))
        return 1
    except OSError as exc:
        import errno

        if exc.errno == errno.EADDRINUSE:
            _print_json(_start_port_in_use_response())
            return 1
        _print_json(_start_oserror_response(exc))
        return 1
    return 0


def _issue_budget_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "rerun_issue_with_valid_budget",
            "command": (
                "ardur issue --agent-id <agent-id> --mission <mission> "
                "--max-duration-s <seconds> --ttl-s <seconds> --keys-dir <keys-dir>"
            ),
            "detail": (
                "Use a positive duration, a non-negative max tool-call budget, "
                "a non-negative delegation-depth budget, and a positive TTL override "
                "when provided before issuing a passport."
            ),
        }
    ]


def _issue_budget_failure_response(condition: str, detail: str) -> dict:
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Mission Passport issue budget is invalid.",
        "detail": detail,
        "next_steps": _issue_budget_failure_next_steps(condition),
    }


def _issue_budget_int(
    value: str | int, condition: str, detail: str
) -> tuple[int | None, tuple[dict, int] | None]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, (_issue_budget_failure_response(condition, detail), 2)
    return parsed, None


def _issue_budget_failure(args: argparse.Namespace) -> tuple[dict, int] | None:
    max_duration_s, failure = _issue_budget_int(
        args.max_duration_s,
        "issue_budget_max_duration_invalid",
        "--max-duration-s must be a positive integer number of seconds.",
    )
    if failure is not None:
        return failure
    assert max_duration_s is not None
    args.max_duration_s = max_duration_s
    max_tool_calls, failure = _issue_budget_int(
        args.max_tool_calls,
        "issue_budget_max_tool_calls_invalid",
        "--max-tool-calls must be zero or a positive integer.",
    )
    if failure is not None:
        return failure
    assert max_tool_calls is not None
    args.max_tool_calls = max_tool_calls
    max_delegation_depth, failure = _issue_budget_int(
        args.max_delegation_depth,
        "issue_budget_max_delegation_depth_invalid",
        "--max-delegation-depth must be zero or a positive integer.",
    )
    if failure is not None:
        return failure
    assert max_delegation_depth is not None
    args.max_delegation_depth = max_delegation_depth
    if args.ttl_s is not None:
        ttl_s, failure = _issue_budget_int(
            args.ttl_s,
            "issue_budget_ttl_invalid",
            "--ttl-s must be a positive integer number of seconds.",
        )
        if failure is not None:
            return failure
        assert ttl_s is not None
        args.ttl_s = ttl_s
    if args.max_duration_s <= 0:
        return _issue_budget_failure_response(
            "issue_budget_max_duration_invalid",
            "--max-duration-s must be a positive integer number of seconds.",
        ), 1
    if args.max_tool_calls < 0:
        return _issue_budget_failure_response(
            "issue_budget_max_tool_calls_invalid",
            "--max-tool-calls must be zero or a positive integer.",
        ), 1
    if args.max_delegation_depth < 0:
        return _issue_budget_failure_response(
            "issue_budget_max_delegation_depth_invalid",
            "--max-delegation-depth must be zero or a positive integer.",
        ), 1
    if args.ttl_s is not None and args.ttl_s <= 0:
        return _issue_budget_failure_response(
            "issue_budget_ttl_invalid",
            "--ttl-s must be a positive integer number of seconds.",
        ), 1
    return None


def _issue_identity_failure_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "rerun_issue_with_valid_identity",
            "command": (
                "ardur issue --agent-id <agent-id> --mission <mission> "
                "--keys-dir <keys-dir>"
            ),
            "detail": (
                "Provide a non-empty agent subject identifier and a non-empty "
                "mission string after trimming whitespace before issuing a "
                "Mission Passport."
            ),
        }
    ]


def _issue_identity_failure_response(condition: str, detail: str) -> dict:
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport issue identity is invalid.",
        "detail": detail,
        "next_steps": _issue_identity_failure_next_steps(condition),
    }


def _issue_identity_failure(args: argparse.Namespace) -> tuple[dict, int] | None:
    agent_id = args.agent_id
    if not isinstance(agent_id, str) or not agent_id.strip():
        return (
            _issue_identity_failure_response(
                "issue_agent_id_invalid",
                "--agent-id must be a non-empty string after trimming whitespace.",
            ),
            1,
        )
    mission = args.mission
    if not isinstance(mission, str) or not mission.strip():
        return (
            _issue_identity_failure_response(
                "issue_mission_invalid",
                "--mission must be a non-empty string after trimming whitespace.",
            ),
            1,
        )
    return None


def _issue_tool_list_invalid_failure(
    args: argparse.Namespace,
) -> tuple[dict, int] | None:
    """Reject empty or whitespace-only elements in nargs list arguments."""
    for field_name, flag_name in (
        ("allowed_tools", "--allowed-tools"),
        ("forbidden_tools", "--forbidden-tools"),
        ("resource_scope", "--resource-scope"),
    ):
        values = getattr(args, field_name, None) or []
        for element in values:
            if not isinstance(element, str) or not element.strip():
                return (
                    {
                        "ok": False,
                        "error": "issue_tool_list_invalid",
                        "error_code": "issue_tool_list_invalid",
                        "condition": "issue_tool_list_invalid",
                        "detail": (
                            f"{flag_name} must not contain empty or whitespace-only"
                            f" elements (offending value in {field_name})."
                        ),
                        "next_steps": [
                            {
                                "condition": "issue_tool_list_invalid",
                                "action": "rerun_issue_with_valid_tool_list",
                                "command": (
                                    "ardur issue --agent-id <id> --mission <mission>"
                                    " --allowed-tools <tool> ... --keys-dir <dir>"
                                ),
                                "detail": (
                                    "Each tool name or resource scope pattern must be"
                                    " a non-empty string after trimming whitespace."
                                ),
                            }
                        ],
                    },
                    1,
                )
    return None


def cmd_issue(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    issue_identity_failure = _issue_identity_failure(args)
    if issue_identity_failure is not None:
        response, exit_code = issue_identity_failure
        _print_json(response)
        return exit_code
    issue_budget_failure = _issue_budget_failure(args)
    if issue_budget_failure is not None:
        response, exit_code = issue_budget_failure
        _print_json(response)
        return exit_code
    issue_tool_list_failure = _issue_tool_list_invalid_failure(args)
    if issue_tool_list_failure is not None:
        response, exit_code = issue_tool_list_failure
        _print_json(response)
        return exit_code
    requested_scope = list(args.resource_scope or [])
    if UNRESTRICTED_RESOURCE_SCOPE_PATTERN in requested_scope and requested_scope != [
        UNRESTRICTED_RESOURCE_SCOPE_PATTERN
    ]:
        _print_json(
            {
                "ok": False,
                "condition": "issue_resource_scope_invalid",
                "error": "issue_resource_scope_invalid",
                "error_code": "issue_resource_scope_invalid",
                "message": "The unrestricted resource scope sentinel must stand alone.",
                "detail": "unrestricted '**' must be the only resource_scope pattern",
                "next_steps": [
                    {
                        "condition": "issue_resource_scope_invalid",
                        "action": "choose_bounded_or_unrestricted_scope",
                        "command": "ardur issue ... --resource-scope <pattern>",
                        "detail": (
                            "Use bounded patterns, or use the sole '**' pattern "
                            "only when every resource is intentionally permitted."
                        ),
                    }
                ],
            }
        )
        return 1
    try:
        private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    mission = MissionPassport(
        agent_id=args.agent_id,
        mission=args.mission,
        allowed_tools=list(args.allowed_tools or []),
        forbidden_tools=list(args.forbidden_tools or []),
        resource_scope=requested_scope,
        max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s,
        delegation_allowed=args.delegation_allowed,
        max_delegation_depth=args.max_delegation_depth,
    )
    token = issue_passport(mission, private_key, ttl_s=args.ttl_s)
    claims = verify_passport(token, public_key)
    response: dict[str, Any] = {"token": token, "claims": claims}
    if mission.resource_scope == [UNRESTRICTED_RESOURCE_SCOPE_PATTERN]:
        response["warnings"] = [
            "resource_scope explicitly permits all resources via the sole '**' pattern"
        ]
    return _handle_output_and_redact(args, response, command="issue")


def _verify_failure_next_steps(label: str = "Mission Passport") -> list[dict[str, str]]:
    if label == "Mission Passport":
        condition = "invalid_passport_token"
        return [
            {
                "condition": condition,
                "action": "verify_a_fresh_passport_token",
                "command": "ardur verify --token <token> --keys-dir <keys-dir>",
                "detail": (
                    "Use a Mission Passport JWT issued by this Ardur key directory. "
                    "Keep raw tokens out of shared logs and reports."
                ),
            },
            {
                "condition": condition,
                "action": "issue_a_new_passport_if_needed",
                "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
                "detail": "Issue a fresh local Mission Passport when the old token is malformed, expired, or signed by a different key.",
            },
        ]
    condition = "invalid_attestation_token"
    return [
        {
            "condition": condition,
            "action": "verify_a_fresh_attestation_token",
            "command": "ardur verify --attestation-token <token> --keys-dir <keys-dir>",
            "detail": (
                "Use a Behavioral Attestation JWT issued by this Ardur key "
                "directory. Keep raw tokens out of shared logs and reports."
            ),
        },
        {
            "condition": condition,
            "action": "issue_a_new_attestation_if_needed",
            "command": "ardur attest --session <session-id> --keys-dir <keys-dir>",
            "detail": (
                "Issue a fresh local Behavioral Attestation when the old token "
                "is malformed, expired, or signed by a different key."
            ),
        },
    ]


def _verify_failure_response(exc: Exception, label: str = "Mission Passport") -> dict:
    detail = _safe_exception_message(exc)
    is_attestation = label != "Mission Passport"
    error_code = (
        "invalid_attestation_token" if is_attestation else "invalid_passport_token"
    )
    return {
        "ok": False,
        "valid": False,
        "error": error_code,
        "condition": error_code,
        "message": f"{label} token could not be verified.",
        "detail": detail,
        "next_steps": _verify_failure_next_steps(label=label),
    }


def _verify_public_key_missing_next_steps(
    label: str = "Mission Passport",
) -> list[dict[str, str]]:
    condition = (
        "attestation_public_key_missing"
        if label != "Mission Passport"
        else "passport_public_key_missing"
    )
    if label != "Mission Passport":
        return [
            {
                "condition": condition,
                "action": "verify_with_issuing_key_directory",
                "command": "ardur verify --attestation-token <token> --keys-dir <keys-dir>",
                "detail": (
                    "Use the key directory that issued this Behavioral "
                    "Attestation. Keep raw tokens, private keys, and local "
                    "paths out of shared logs."
                ),
            },
            {
                "condition": condition,
                "action": "issue_a_new_attestation_if_needed",
                "command": "ardur attest --session <session-id> --keys-dir <keys-dir>",
                "detail": (
                    "Issue a fresh local Behavioral Attestation when the "
                    "original public key is unavailable."
                ),
            },
        ]
    return [
        {
            "condition": condition,
            "action": "verify_with_issuing_key_directory",
            "command": "ardur verify --token <token> --keys-dir <keys-dir>",
            "detail": (
                "Use the key directory that issued this Mission Passport. Keep raw "
                "tokens, private keys, and local paths out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "issue_a_new_passport_if_needed",
            "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
            "detail": (
                "Issue a fresh local Mission Passport when the original public key is unavailable."
            ),
        },
    ]


def _verify_public_key_missing_response(label: str = "Mission Passport") -> dict:
    if label != "Mission Passport":
        condition = "attestation_public_key_missing"
        return {
            "ok": False,
            "valid": False,
            "error": condition,
            "error_code": condition,
            "condition": condition,
            "message": "Behavioral Attestation public key is required for verification.",
            "detail": (
                "The selected key directory does not contain passport_public.pem. "
                "Verification is read-only and will not create signing keys."
            ),
            "next_steps": _verify_public_key_missing_next_steps(label=label),
        }
    condition = "passport_public_key_missing"
    return {
        "ok": False,
        "valid": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport public key is required for verification.",
        "detail": (
            "The selected key directory does not contain passport_public.pem. "
            "Verification is read-only and will not create signing keys."
        ),
        "next_steps": _verify_public_key_missing_next_steps(),
    }


def _verify_public_key_invalid_next_steps(
    label: str = "Mission Passport",
) -> list[dict[str, str]]:
    condition = (
        "attestation_public_key_invalid"
        if label != "Mission Passport"
        else "passport_public_key_invalid"
    )
    if label != "Mission Passport":
        return [
            {
                "condition": condition,
                "action": "restore_issuing_public_key",
                "command": "ardur verify --attestation-token <token> --keys-dir <keys-dir>",
                "detail": (
                    "Replace passport_public.pem with the EC public key that "
                    "issued this Behavioral Attestation, then retry verification. "
                    "Keep raw tokens, private keys, and local paths out of shared logs."
                ),
            },
            {
                "condition": condition,
                "action": "issue_a_new_attestation_if_needed",
                "command": "ardur attest --session <session-id> --keys-dir <keys-dir>",
                "detail": (
                    "Issue a fresh local Behavioral Attestation only after "
                    "choosing a key directory with valid key material."
                ),
            },
        ]
    return [
        {
            "condition": condition,
            "action": "restore_issuing_public_key",
            "command": "ardur verify --token <token> --keys-dir <keys-dir>",
            "detail": (
                "Replace passport_public.pem with the EC public key that issued this "
                "Mission Passport, then retry verification. Keep raw tokens, private "
                "keys, and local paths out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "issue_a_new_passport_if_needed",
            "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
            "detail": (
                "Issue a fresh local Mission Passport only after choosing a key directory "
                "with valid Mission Passport key material."
            ),
        },
    ]


def _verify_public_key_invalid_response(label: str = "Mission Passport") -> dict:
    if label != "Mission Passport":
        condition = "attestation_public_key_invalid"
        return {
            "ok": False,
            "valid": False,
            "error": condition,
            "error_code": condition,
            "condition": condition,
            "message": "Behavioral Attestation public key could not be loaded for verification.",
            "detail": (
                "passport_public.pem exists but is not a readable EC public key. "
                "Verification is read-only and will not repair, overwrite, or create signing keys."
            ),
            "next_steps": _verify_public_key_invalid_next_steps(label=label),
        }
    condition = "passport_public_key_invalid"
    return {
        "ok": False,
        "valid": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Mission Passport public key could not be loaded for verification.",
        "detail": (
            "passport_public.pem exists but is not a readable EC public key. "
            "Verification is read-only and will not repair, overwrite, or create signing keys."
        ),
        "next_steps": _verify_public_key_invalid_next_steps(),
    }


def _verify_malformed_token_failure_exit_code(
    token: str, label: str = "Mission Passport"
) -> int | None:
    try:
        jwt.get_unverified_header(token)
        jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_iss": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError:
        _print_json(
            _verify_failure_response(
                jwt.DecodeError(f"{label} token is malformed."),
                label=label,
            )
        )
        return 1
    return None


def _cmd_verify_attestation(args: argparse.Namespace) -> int:
    """Verify a behavioral attestation JWT and display its signed claims."""
    malformed_token_failure = _verify_malformed_token_failure_exit_code(
        args.attestation_token, label="Behavioral attestation"
    )
    if malformed_token_failure is not None:
        return malformed_token_failure
    keys_dir_failure = _keys_dir_failure_exit_code(args.keys_dir)
    if keys_dir_failure is not None:
        return keys_dir_failure
    try:
        public_key = load_existing_public_key(keys_dir=args.keys_dir)
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    except FileNotFoundError:
        _print_json(_verify_public_key_missing_response(label="Behavioral attestation"))
        return 1
    except ValueError:
        _print_json(_verify_public_key_invalid_response(label="Behavioral attestation"))
        return 1
    try:
        claims = verify_attestation(args.attestation_token, public_key)
    except (jwt.PyJWTError, PermissionError, ValueError) as exc:
        _print_json(_verify_failure_response(exc, label="Behavioral attestation"))
        return 1
    token_report = {"valid": True, "claims": claims}
    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        token_report = _redact_paths_deep(token_report)
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, token_report)
        except ValueError as exc:
            _print_json(
                {
                    "valid": False,
                    **_output_write_error_response("verify", exc),
                }
            )
            return 1
        _print_json(
            {
                "valid": True,
                "condition": "verify_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    _print_json(token_report)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    selected_inputs = sum(
        value is not None
        for value in (
            args.journal,
            args.token,
            args.attestation_token,
            args.anchor_bundle,
            args.receiver_envelope,
        )
    )
    if selected_inputs != 1:
        _print_json(
            {
                "valid": False,
                "error": "verify_input_invalid",
                "message": (
                    "Choose exactly one verification input: a positional journal, "
                    "--token, --attestation-token, --anchor-bundle, or --receiver-envelope."
                ),
            }
        )
        return 1
    if args.journal is not None:
        return _cmd_verify_offline(args)
    if any(
        (
            args.receipt_public_key is not None,
            args.chain_only,
            args.verify_expiry,
            args.html_report is not None,
            args.unsafe_show_sensitive,
            args.max_bundle_age_s is not None,
            args.freshness_clock_skew_s is not None,
        )
    ):
        _print_json(
            {
                "valid": False,
                "error": "verify_option_invalid",
                "message": "Offline journal options require a positional journal input.",
            }
        )
        return 1
    if args.anchor_bundle is not None:
        return _cmd_verify_anchor(args)
    if args.receiver_envelope is not None:
        return _cmd_verify_receiver_attestation(args)
    if args.attestation_token is not None:
        return _cmd_verify_attestation(args)
    keys_dir_failure = _keys_dir_failure_exit_code(args.keys_dir)
    if keys_dir_failure is not None:
        return keys_dir_failure
    malformed_token_failure = _verify_malformed_token_failure_exit_code(args.token)
    if malformed_token_failure is not None:
        return malformed_token_failure
    try:
        public_key = load_existing_public_key(keys_dir=args.keys_dir)
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    except FileNotFoundError:
        _print_json(_verify_public_key_missing_response())
        return 1
    except ValueError:
        _print_json(_verify_public_key_invalid_response())
        return 1
    try:
        claims = verify_passport(args.token, public_key)
    except (jwt.PyJWTError, PermissionError, ValueError) as exc:
        _print_json(_verify_failure_response(exc))
        return 1
    token_report = {"valid": True, "claims": claims}
    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        token_report = _redact_paths_deep(token_report)
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, token_report)
        except ValueError as exc:
            _print_json(
                {
                    "valid": False,
                    **_output_write_error_response("verify", exc),
                }
            )
            return 1
        _print_json(
            {
                "valid": True,
                "condition": "verify_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    _print_json(token_report)
    return 0


def _load_transparency_public_key(path: Path):  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    if path.is_symlink():
        raise ValueError("transparency log public key path must not be a symlink")
    if not path.is_file():
        raise FileNotFoundError("transparency log public key was not found")
    try:
        with path.open("rb") as handle:
            data = handle.read(64 * 1024 + 1)
    except PermissionError as exc:
        raise PermissionError(
            "transparency log public key could not be read (permission denied)"
        ) from exc
    except OSError as exc:
        raise OSError("transparency log public key could not be read") from exc
    if not data or len(data) > 64 * 1024:
        raise ValueError(
            "transparency log public key is empty or exceeds the size limit"
        )
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        raise ValueError("transparency log public key must be ECDSA or Ed25519")
    return key


def _cmd_verify_anchor(args: argparse.Namespace) -> int:
    from .transparency import (
        AnchorVerificationError,
        TransparencyError,
        load_anchor_bundle,
        verify_anchor_bundle,
    )

    if args.transparency_log_key is None:
        _print_json(
            {
                "valid": False,
                "error": "transparency_log_key_required",
                "message": "Anchor verification requires --transparency-log-key.",
            }
        )
        return 1
    if args.max_registration_delay_s < 0:
        _print_json(
            {
                "valid": False,
                "error": "registration_delay_invalid",
                "message": "--max-registration-delay-s must be zero or greater.",
            }
        )
        return 1
    keys_dir_failure = _keys_dir_failure_exit_code(args.keys_dir)
    if keys_dir_failure is not None:
        return keys_dir_failure
    try:
        receipt_public_key = load_existing_public_key(keys_dir=args.keys_dir)
        log_public_key = _load_transparency_public_key(args.transparency_log_key)
        bundle = load_anchor_bundle(args.anchor_bundle)
        report = verify_anchor_bundle(
            bundle,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
            max_registration_delay_s=args.max_registration_delay_s,
        )
    except (
        AnchorVerificationError,
        TransparencyError,
        KeyDirectoryError,
        FileNotFoundError,
        PermissionError,
        OSError,
        ValueError,
    ) as exc:
        _print_json(
            {
                "valid": False,
                "error": "anchor_verification_failed",
                "message": _safe_exception_message(exc),
            }
        )
        return 1
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "valid": False,
                    **_output_write_error_response("verify", exc),
                }
            )
            return 1
        _print_json(
            {
                "valid": True,
                "condition": "verify_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    _print_json(report)
    return 0


def _load_receiver_public_key(path: Path):  # type: ignore[no-untyped-def]
    return _load_p256_public_key(path, label="receiver public key")


def _load_p256_public_key(path: Path, *, label: str):  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if path.is_symlink():
        raise ValueError(f"{label} path must not be a symlink")
    if not path.is_file():
        raise FileNotFoundError(f"{label} was not found")
    try:
        with path.open("rb") as handle:
            data = handle.read(64 * 1024 + 1)
    except PermissionError as exc:
        raise PermissionError(f"{label} could not be read (permission denied)") from exc
    except OSError as exc:
        raise OSError(f"{label} could not be read") from exc
    if not data or len(data) > 64 * 1024:
        raise ValueError(f"{label} is empty or exceeds the size limit")
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} is not a valid PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError(f"{label} must be an ES256 P-256 key")
    return key


def _cmd_verify_offline(args: argparse.Namespace) -> int:
    from .offline_verification import (
        OfflineVerificationError,
        render_cli_report,
        verify_offline_path,
        write_html_report,
    )

    if args.receipt_public_key is not None and args.keys_dir is not None:
        _print_json(
            {
                "valid": False,
                "error": "receipt_key_source_conflict",
                "message": "Use either --receipt-public-key or --keys-dir, not both.",
            }
        )
        return 1
    if args.mcp_request is not None or args.mcp_response is not None:
        _print_json(
            {
                "valid": False,
                "error": "offline_mcp_input_invalid",
                "message": "Full bundles carry receiver sidecars; MCP request/response files apply only to --receiver-envelope.",
            }
        )
        return 1
    if args.receipt_public_key is None and args.keys_dir is None:
        _print_json(
            {
                "valid": False,
                "error": "receipt_public_key_required",
                "message": "Offline verification requires --receipt-public-key or --keys-dir.",
            }
        )
        return 1
    if (
        args.max_registration_delay_s < 0
        or args.max_attestation_delay_s < 0
        or args.receiver_clock_skew_s < 0
    ):
        _print_json(
            {
                "valid": False,
                "error": "offline_verification_window_invalid",
                "message": "Offline verification time windows must be zero or greater.",
            }
        )
        return 1
    invalid_max_age = args.max_bundle_age_s is not None and args.max_bundle_age_s < 0
    invalid_freshness_skew = (
        args.freshness_clock_skew_s is not None and args.freshness_clock_skew_s < 0
    )
    freshness_skew_without_age = (
        args.freshness_clock_skew_s is not None and args.max_bundle_age_s is None
    )
    if invalid_max_age or invalid_freshness_skew or freshness_skew_without_age:
        _print_json(
            {
                "valid": False,
                "error": "offline_freshness_policy_invalid",
                "message": (
                    "--max-bundle-age-s must be zero or greater; "
                    "--freshness-clock-skew-s requires it and must also be zero or greater."
                ),
            }
        )
        return 1
    try:
        receipt_public_key = (
            _load_p256_public_key(args.receipt_public_key, label="receipt public key")
            if args.receipt_public_key is not None
            else load_existing_public_key(keys_dir=args.keys_dir)
        )
    except (
        KeyDirectoryError,
        FileNotFoundError,
        OSError,
        PermissionError,
        ValueError,
    ) as exc:
        _print_json(
            {
                "valid": False,
                "error": "receipt_public_key_invalid",
                "message": str(exc),
            }
        )
        return 1
    try:
        log_public_key = (
            _load_transparency_public_key(args.transparency_log_key)
            if args.transparency_log_key is not None
            else None
        )
        receiver_public_key = (
            _load_receiver_public_key(args.receiver_public_key)
            if args.receiver_public_key is not None
            else None
        )
        report = verify_offline_path(
            args.journal,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
            receiver_public_key=receiver_public_key,
            chain_only=args.chain_only,
            verify_expiry=args.verify_expiry,
            max_registration_delay_s=args.max_registration_delay_s,
            max_attestation_delay_s=args.max_attestation_delay_s,
            receiver_clock_skew_s=args.receiver_clock_skew_s,
            max_bundle_age_s=args.max_bundle_age_s,
            freshness_clock_skew_s=args.freshness_clock_skew_s,
            redact=not args.unsafe_show_sensitive,
        )
        if args.html_report is not None:
            write_html_report(args.html_report, report)
    except (
        OfflineVerificationError,
        KeyDirectoryError,
        FileNotFoundError,
        PermissionError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        error_code = getattr(exc, "code", "offline_verification_failed")
        safe_message = _safe_exception_message(exc)
        response: dict[str, object] = {
            "valid": False,
            "error": error_code,
            "error_code": error_code,
            "condition": error_code,
            "message": safe_message,
            "detail": safe_message,
            "next_steps": _offline_verification_next_steps(error_code),
        }
        index = getattr(exc, "index", None)
        if index is not None:
            response["receipt_index"] = index
        _print_json(response)
        return 1
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "valid": False,
                    **_output_write_error_response("verify", exc),
                }
            )
            return 1
        _print_json(
            {
                "valid": True,
                "condition": "verify_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    if args.json:
        _print_json(report)
    else:
        sys.stdout.write(render_cli_report(report))
    return 0


def cmd_evidence_correlate(args: argparse.Namespace) -> int:
    """Verify a receipt journal and correlate imported runtime evidence."""

    from .offline_verification import OfflineVerificationError, verify_offline_path
    from .runtime_evidence import (
        RuntimeEvidenceError,
        canonical_report_bytes,
        correlate_verified_report,
        load_runtime_events,
        render_text_report,
        write_report,
    )

    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    if args.correlation_window_s < 0 or args.correlation_window_s > 3600:
        _print_json(
            {
                "ok": False,
                "valid": False,
                "error": "correlation_window_invalid",
                "message": (
                    "--correlation-window-s must be an integer "
                    "between 0 and 3600 seconds."
                ),
            }
        )
        return 1
    try:
        receipt_public_key = (
            _load_p256_public_key(args.receipt_public_key, label="receipt public key")
            if args.receipt_public_key is not None
            else load_existing_public_key(keys_dir=args.keys_dir)
        )
    except (
        KeyDirectoryError,
        FileNotFoundError,
        OSError,
        PermissionError,
        ValueError,
    ) as exc:
        _print_json(
            {
                "ok": False,
                "valid": False,
                "error": "receipt_public_key_invalid",
                "message": str(exc),
            }
        )
        return 1
    try:
        receipt_report = verify_offline_path(
            args.journal,
            receipt_public_key=receipt_public_key,
            chain_only=True,
            verify_expiry=args.verify_expiry,
            redact=False,
            include_correlation_fields=True,
        )
        event_batch = load_runtime_events(
            args.evidence_events,
            source_format=args.source_format,
        )
        report = correlate_verified_report(
            receipt_report,
            event_batch,
            correlation_window_s=args.correlation_window_s,
        )
        if (
            getattr(args, "redact_paths", False)
            and not getattr(args, "json", False)
            and getattr(args, "evidence_output", None) is None
        ):
            print(
                "ardur: warning: --redact-paths has no effect without --json or --output",
                file=sys.stderr,
            )
        if getattr(args, "redact_paths", False):
            report = _redact_paths_deep(report)
        payload = (
            canonical_report_bytes(report)
            if args.report_format == "json"
            else render_text_report(report).encode("utf-8")
        )
        if args.evidence_output is not None:
            write_report(args.evidence_output, payload)
            _print_json(
                {
                    "ok": True,
                    "condition": "runtime_evidence_report_written",
                    "report_sha256": hashlib.sha256(payload).hexdigest(),
                    "receipt_count": report["summary"]["receipt_count"],
                    "event_count": report["summary"]["event_count"],
                    "matched_event_count": report["summary"]["matched_event_count"],
                    "source_assurance": report["event_source"]["assurance"],
                }
            )
        elif args.report_format == "json":
            sys.stdout.buffer.write(payload)
        else:
            sys.stdout.write(payload.decode("utf-8"))
        return 0
    except (
        RuntimeEvidenceError,
        OfflineVerificationError,
        KeyDirectoryError,
    ) as exc:
        error_code = getattr(exc, "code", "runtime_evidence_correlation_failed")
        safe_message = _safe_exception_message(exc)
        response: dict[str, object] = {
            "ok": False,
            "valid": False,
            "error": error_code,
            "error_code": error_code,
            "condition": error_code,
            "message": safe_message,
            "detail": safe_message,
            "next_steps": _offline_verification_next_steps(error_code),
        }
        line = getattr(exc, "line", None)
        if line is not None:
            response["event_line"] = line
        index = getattr(exc, "index", None)
        if index is not None:
            response["receipt_index"] = index
        _print_json(response)
        return 1
    except (TypeError, ValueError) as exc:
        error_code = "runtime_evidence_correlation_failed"
        safe_message = _safe_exception_message(exc)
        response: dict[str, object] = {
            "ok": False,
            "valid": False,
            "error": error_code,
            "error_code": error_code,
            "condition": error_code,
            "message": safe_message,
            "detail": safe_message,
            "next_steps": _offline_verification_next_steps(error_code),
        }
        _print_json(response)
        return 1
    except OSError:
        error_code = "runtime_evidence_io_failed"
        safe_message = (
            "runtime evidence correlation could not access a required local file safely"
        )
        _print_json(
            {
                "ok": False,
                "valid": False,
                "error": error_code,
                "error_code": error_code,
                "condition": error_code,
                "message": safe_message,
                "detail": safe_message,
                "next_steps": _offline_verification_next_steps(error_code),
            }
        )
        return 1


def _cmd_verify_receiver_attestation(args: argparse.Namespace) -> int:
    from .receiver_attestation import (
        ASSURANCE_RECEIVER_ATTESTED,
        ReceiverAttestationError,
        ReceiverAttestationVerificationError,
        load_json_document,
        load_receiver_envelope,
        verify_receiver_envelope,
    )

    if args.max_attestation_delay_s < 0 or args.receiver_clock_skew_s < 0:
        _print_json(
            {
                "valid": False,
                "error": "receiver_attestation_window_invalid",
                "message": (
                    "--max-attestation-delay-s and --receiver-clock-skew-s "
                    "must be zero or greater."
                ),
            }
        )
        return 1
    if args.mcp_response is not None and args.mcp_request is None:
        _print_json(
            {
                "valid": False,
                "error": "receiver_attestation_request_required",
                "message": "--mcp-response also requires --mcp-request.",
            }
        )
        return 1
    keys_dir_failure = _keys_dir_failure_exit_code(args.keys_dir)
    if keys_dir_failure is not None:
        return keys_dir_failure
    try:
        receipt_public_key = load_existing_public_key(keys_dir=args.keys_dir)
        envelope = load_receiver_envelope(args.receiver_envelope)
        receiver_public_key = None
        if envelope.get("assurance_tier") == ASSURANCE_RECEIVER_ATTESTED:
            if args.receiver_public_key is None:
                raise ReceiverAttestationVerificationError(
                    "receiver public key is required for receiver-attested verification"
                )
            receiver_public_key = _load_receiver_public_key(args.receiver_public_key)
        expected_request = (
            load_json_document(args.mcp_request, label="MCP request")
            if args.mcp_request is not None
            else None
        )
        expected_response = (
            load_json_document(args.mcp_response, label="MCP response")
            if args.mcp_response is not None
            else None
        )
        report = verify_receiver_envelope(
            envelope,
            receipt_public_key=receipt_public_key,
            receiver_public_key=receiver_public_key,
            expected_request=expected_request,
            expected_response=expected_response,
            max_attestation_delay_s=args.max_attestation_delay_s,
            receiver_clock_skew_s=args.receiver_clock_skew_s,
        )
    except (
        ReceiverAttestationError,
        ReceiverAttestationVerificationError,
        KeyDirectoryError,
    ) as exc:
        _print_json(
            {
                "valid": False,
                "error": "receiver_attestation_verification_failed",
                "message": str(exc),
            }
        )
        return 1
    except (FileNotFoundError, PermissionError) as exc:
        _print_json(
            {
                "valid": False,
                "error": "receiver_attestation_verification_failed",
                "message": _safe_exception_message(exc),
            }
        )
        return 1
    except (OSError, ValueError) as exc:
        _print_json(
            {
                "valid": False,
                "error": "receiver_attestation_verification_failed",
                "message": _safe_exception_message(exc),
            }
        )
        return 1
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "valid": False,
                    **_output_write_error_response("verify", exc),
                }
            )
            return 1
        _print_json(
            {
                "valid": True,
                "condition": "verify_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    _print_json(report)
    return 0


def cmd_telemetry_export(args: argparse.Namespace) -> int:
    """Verify a receipt journal and export conservative governance telemetry."""

    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1

    from .receipt_telemetry import (
        TelemetryExportError,
        export_otlp_http,
        jsonl_bytes,
        otlp_bundle_bytes,
        otlp_payloads,
        verified_governance_events,
        write_export,
    )

    if args.timeout_s < 1 or args.timeout_s > 60:
        _print_json(
            {
                "ok": False,
                "error": "otlp_timeout_invalid",
                "message": "--timeout-s must be an integer from 1 to 60 seconds.",
            }
        )
        return 1

    try:
        receipt_public_key = (
            _load_p256_public_key(args.receipt_public_key, label="receipt public key")
            if args.receipt_public_key is not None
            else load_existing_public_key(keys_dir=args.keys_dir)
        )
    except (
        KeyDirectoryError,
        FileNotFoundError,
        OSError,
        PermissionError,
        ValueError,
    ) as exc:
        _print_json(
            {
                "ok": False,
                "error": "receipt_public_key_invalid",
                "message": str(exc),
            }
        )
        return 1

    try:
        events = verified_governance_events(
            args.journal,
            receipt_public_key=receipt_public_key,
            verify_expiry=args.verify_expiry,
        )
        if (
            getattr(args, "redact_paths", False)
            and not getattr(args, "json", False)
            and getattr(args, "telemetry_output", None) is None
        ):
            print(
                "ardur: warning: --redact-paths has no effect without --json or --output",
                file=sys.stderr,
            )
        if getattr(args, "redact_paths", False):
            events = _redact_paths_deep(events)
        payloads = otlp_payloads(events)
        artifact = (
            jsonl_bytes(events)
            if args.export_format == "jsonl"
            else otlp_bundle_bytes(payloads)
        )
        if args.telemetry_output is not None:
            write_export(args.telemetry_output, artifact)
        deliveries = (
            export_otlp_http(
                payloads,
                endpoint=args.otlp_endpoint,
                timeout_s=args.timeout_s,
            )
            if args.otlp_endpoint is not None
            else []
        )
    except TelemetryExportError as exc:
        error_code = exc.code
        safe_message = _safe_exception_message(exc)
        _print_json(
            {
                "ok": False,
                "error": error_code,
                "error_code": error_code,
                "condition": error_code,
                "message": safe_message,
                "detail": safe_message,
                "next_steps": _offline_verification_next_steps(error_code),
            }
        )
        return 1

    if args.telemetry_output is None and args.otlp_endpoint is None:
        sys.stdout.write(artifact.decode("utf-8"))
    else:
        _print_json(
            {
                "ok": True,
                "schema_version": "ardur.governance_telemetry_export.v0.1",
                "event_count": len(events),
                "format": args.export_format,
                "output_written": args.telemetry_output is not None,
                "deliveries": deliveries,
                "raw_content_exported": False,
            }
        )
    return 0


def _load_local_log_private_key(path: Path):  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if not path.is_file():
        raise FileNotFoundError(f"local transparency-log private key not found: {path}")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise PermissionError(
            "local transparency-log private key must use mode 0600 or stricter"
        )
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("local transparency-log private key must be Ed25519")
    return key


def cmd_anchor(args: argparse.Namespace) -> int:
    from .transparency import (
        BACKEND_LOCAL_SIGNED,
        LocalSignedLogBackend,
        RekorV1Backend,
        TransparencyError,
        anchor_store_for_receipt_log,
        drain_anchor_store,
    )

    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    receipt_log_path = Path(args.receipt_log).expanduser()
    if not receipt_log_path.is_file():
        _print_json(
            {
                "ok": False,
                "error": "receipt_log_not_file",
                "error_code": "receipt_log_not_file",
                "condition": "receipt_log_not_file",
                "message": "ardur --receipt-log must point to an existing receipts JSONL file.",
                "detail": "The --receipt-log path does not exist or is not a regular file. Directories, dangling symlinks, and device paths are rejected before anchoring.",
                "next_steps": [
                    {
                        "condition": "receipt_log_not_file",
                        "action": "pass_receipt_jsonl_file",
                        "command": "ardur anchor --receipt-log <receipts.jsonl> --backend <backend> ...",
                        "detail": "Pass the path to your signed receipt JSONL file (typically named receipts.jsonl in the Ardur home or claude-code-hook chain directory), not the parent directory.",
                    },
                    {
                        "condition": "receipt_log_not_file",
                        "action": "find_receipts_file",
                        "command": "find <ardur-home> -name 'receipts.jsonl' -type f",
                        "detail": "Locate the receipt journal file produced by ardur run, ardur hub, or the claude-code-hook before anchoring.",
                    },
                ],
            }
        )
        return 1
    store = anchor_store_for_receipt_log(args.receipt_log)
    try:
        receipt_private_key = None
        if args.backend == BACKEND_LOCAL_SIGNED:
            if (
                args.local_log is None
                or args.log_private_key is None
                or not args.origin
            ):
                raise TransparencyError(
                    "local anchoring requires --local-log, --log-private-key, and --origin"
                )
            # --keys-dir is optional here: local anchoring works with no
            # receipt key at all. When the operator does supply one, use it,
            # so a receipt signed by a different issuer is refused before the
            # irreversible log write rather than at verification time.
            local_receipt_public_key = (
                load_existing_public_key(keys_dir=args.keys_dir)
                if args.keys_dir is not None
                else None
            )
            backend = LocalSignedLogBackend(
                args.local_log,
                _load_local_log_private_key(args.log_private_key),
                origin=args.origin,
                receipt_public_key=local_receipt_public_key,
            )
        else:
            if args.keys_dir is None:
                raise TransparencyError(
                    "Rekor anchoring requires --keys-dir with the existing receipt issuer key"
                )
            receipt_private_key = load_existing_private_key(keys_dir=args.keys_dir)
            backend = RekorV1Backend(
                args.rekor_url,
                allow_insecure_loopback=args.allow_insecure_loopback,
            )
        results = drain_anchor_store(
            store,
            backend,
            receipt_private_key=receipt_private_key,
        )
    except (
        TransparencyError,
        KeyDirectoryError,
        FileNotFoundError,
        PermissionError,
        OSError,
        ValueError,
    ) as exc:
        _print_json(
            {
                "ok": False,
                "error": "anchor_submission_failed",
                "message": _safe_exception_message(exc),
            }
        )
        return 1
    output = {
        "ok": all(result.status == "anchored" for result in results),
        "store": str(store),
        "processed": len(results),
        "anchored": sum(result.status == "anchored" for result in results),
        "pending": sum(result.status == "pending" for result in results),
        "results": [
            {
                "anchor_id": result.anchor_id,
                "status": result.status,
                "path": str(result.path),
                **({"error": result.error} if result.error else {}),
            }
            for result in results
        ],
    }
    return _handle_output_and_redact(
        args, output, command="anchor", exit_code=0 if output["ok"] else 1
    )


def _attest_failure_condition(exc: Exception) -> tuple[str, str]:
    message = str(exc).lower()
    if "invalid session id format" in message:
        return (
            "invalid_session_id",
            "Session identifiers must be UUIDs produced by an Ardur governed session.",
        )
    if "unknown session" in message:
        return (
            "session_not_found",
            "No persisted session was found for the supplied session id in the selected state directory.",
        )
    if "session invalid" in message:
        return (
            "session_invalid",
            "Persisted session data is invalid or corrupt; start or locate a governed session before attesting.",
        )
    return (
        "attestation_failed",
        "The session could not be loaded or attested from the selected local state.",
    )


def _attest_failure_next_steps(condition: str) -> list[dict[str, str]]:
    steps = [
        {
            "condition": condition,
            "action": "retry_with_recorded_session_id",
            "command": "ardur attest --session <session-id> --keys-dir <keys-dir> --state-dir <state-dir> --log-path <audit-log>",
            "detail": (
                "Use the exact session_id emitted by the governed session and the same local state directory. "
                "Do not paste raw tokens or local private paths into shared artifacts."
            ),
        }
    ]
    if condition in {"invalid_session_id", "session_not_found", "session_invalid"}:
        steps.append(
            {
                "condition": condition,
                "action": "start_or_find_a_governed_session",
                "command": "ardur start --mission <mission.json> --keys-dir <keys-dir> --state-dir <state-dir> --log-path <audit-log>",
                "detail": "Start or locate the governed session first, then attest using its UUID session id.",
            }
        )
    return steps


def _attest_failure_response(exc: Exception) -> dict:
    condition, detail = _attest_failure_condition(exc)
    return {
        "ok": False,
        "valid": False,
        "error": condition,
        "condition": condition,
        "message": "Behavioral attestation could not be issued for the requested session.",
        "detail": detail,
        "next_steps": _attest_failure_next_steps(condition),
    }


def _attest_session_file_path(session_id: str, state_dir: Path | None) -> Path:
    root = Path(state_dir).expanduser() if state_dir is not None else DEFAULT_STATE_DIR
    return root / "sessions" / f"{session_id}.json"


def _attest_session_invalid_error() -> ValueError:
    return ValueError("session invalid: persisted session file is malformed")


def _validate_attest_session_file_before_artifacts(session_path: Path) -> int | None:
    try:
        raw_session = session_path.read_text(encoding="utf-8")
        payload = json.loads(raw_session)
        if not isinstance(payload, dict):
            raise ValueError("session file must contain a JSON object")
        session = GovernanceSession.from_dict(payload)
        if not isinstance(session.passport_token, str) or not session.passport_token:
            raise ValueError("session passport token is missing")
        for claim_name in ("jti", "sub", "mission"):
            claim_value = session.passport_claims.get(claim_name)
            if not isinstance(claim_value, str) or not claim_value:
                raise ValueError("session passport claims are incomplete")
    except (OSError, TypeError, ValueError, KeyError, AttributeError):
        _print_json(_attest_failure_response(_attest_session_invalid_error()))
        return 1
    return None


def _attest_session_failure_exit_code(
    session_id: str, state_dir: Path | None
) -> int | None:
    if not _ATTEST_SESSION_ID_RE.match(session_id):
        _print_json(
            _attest_failure_response(
                ValueError("invalid session ID format: must be UUID")
            )
        )
        return 1
    session_path = _attest_session_file_path(session_id, state_dir)
    try:
        session_exists = session_path.exists()
    except OSError:
        session_exists = False
    if session_exists:
        return _validate_attest_session_file_before_artifacts(session_path)
    _print_json(_attest_failure_response(ValueError("unknown session '<session-id>'")))
    return 1


def cmd_attest(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    state_dir_failure = _state_dir_failure_exit_code(args.state_dir)
    if state_dir_failure is not None:
        return state_dir_failure
    state_dir_parent_failure = _state_dir_parent_failure_exit_code(args.state_dir)
    if state_dir_parent_failure is not None:
        return state_dir_parent_failure
    log_path_failure = _log_path_failure_exit_code(args.log_path)
    if log_path_failure is not None:
        return log_path_failure
    log_path_parent_failure = _log_path_parent_failure_exit_code(args.log_path)
    if log_path_parent_failure is not None:
        return log_path_parent_failure
    keys_dir_failure = _keys_dir_failure_exit_code(args.keys_dir)
    if keys_dir_failure is not None:
        return keys_dir_failure
    session_failure = _attest_session_failure_exit_code(args.session, args.state_dir)
    if session_failure is not None:
        return session_failure
    try:
        private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )
    try:
        token, claims = proxy.issue_attestation_for_session(args.session, private_key)
    except (ValueError, PermissionError, jwt.PyJWTError) as exc:
        _print_json(_attest_failure_response(exc))
        return 1
    response = {"token": token, "claims": claims}
    return _handle_output_and_redact(args, response, command="attest")


def cmd_claude_code_hook(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    argv = [args.phase]
    if args.keys_dir:
        argv.extend(["--keys-dir", str(args.keys_dir)])
    return claude_code_hook_main(argv)


def cmd_claude_code_report(args: argparse.Namespace) -> int:
    path_failure = _coerce_report_path_args(
        args,
        command_name="claude-code-report",
        command_title="Claude Code report",
        specs=(
            ("home", "--home", "home", "claude_code_report_home_empty", False),
            (
                "chain_dir",
                "--chain-dir",
                "chain dir",
                "claude_code_report_chain_dir_empty",
                False,
            ),
            (
                "keys_dir",
                "--keys-dir",
                "keys dir",
                "claude_code_report_keys_dir_empty",
                False,
            ),
            (
                "output",
                "--output",
                "output",
                "claude_code_report_output_empty",
                False,
            ),
        ),
    )
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        report = build_claude_code_report(
            home=args.home,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
            verify_expiry=args.verify_expiry,
        )
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        report = _redact_paths_deep(report)
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "ok": False,
                    **_output_write_error_response("claude_code_report", exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": "claude_code_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    if args.json:
        _print_json(report)
        return 0

    print(
        f"Ardur Claude Code receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains"
    )
    print(f"Home: {report['home']}")
    print(f"Chains: {report['chain_dir']}")
    print(f"Tools: {report['totals']['tools']}")
    print(f"Verdicts: {report['totals']['verdicts']}")
    print(f"Side effects: {report['totals']['side_effect_classes']}")
    print(
        "Subagent dispatches: "
        f"{report['totals']['dispatch_launch_count']} launches, "
        f"{report['totals']['dispatch_observation_count']} post observations"
    )
    print(
        "Subagent lifecycle: "
        f"{report['totals']['subagents_started']} started, "
        f"{report['totals']['subagents_stopped']} stopped"
    )
    print(f"Per-child attribution: {report['coverage']['per_child_attribution']}")
    print(f"Attribution: {report['coverage']['attribution']}")
    actions = [
        action for chain in report["chains"] for action in chain.get("actions", [])
    ]
    if actions:
        print("Actions:")
        for action in actions[-20:]:
            request = action["request"]
            remaining = action.get("budget_remaining", {}).get("tool_calls")
            budget_text = (
                f"; {remaining} governed calls remain" if remaining is not None else ""
            )
            print(
                f"- {action['verdict'].upper()} {request['tool']} "
                f"({request['action_class']}/{request['side_effect_class']}): "
                f"{action['explanation']}{budget_text}"
            )
        if len(actions) > 20:
            print(f"  Showing the latest 20 of {len(actions)} signed actions.")
    print(f"Cost boundary: {report['cost_boundary']['detail']}")
    print(f"Verify later: {report['verification']['command']}")
    _print_report_next_steps(report)
    return 0


def _receiver_attestation_fixture_output_invalid_response(condition: str) -> dict:
    """Structured failure for an invalid ``--output`` argument.

    Mirrors the fixture-path failure convention used by the gemini-cli and
    codex-app-server fixtures: a stable ``condition``/``error`` pair, a
    human-readable ``message`` with no raw exception text or local paths, a
    ``detail`` explaining how to choose a valid directory, and placeholder-only
    ``next_steps``.
    """

    messages = {
        "receiver_attestation_fixture_output_empty": (
            "Receiver attestation fixture output path is empty."
        ),
        "receiver_attestation_fixture_output_symlink": (
            "Receiver attestation fixture output path must not be a symlink."
        ),
        "receiver_attestation_fixture_output_not_directory": (
            "Receiver attestation fixture output path is not a directory."
        ),
    }
    details = {
        "receiver_attestation_fixture_output_empty": (
            "The --output argument is empty or whitespace-only. "
            "Provide a directory path where Ardur can write the public fixture artifacts."
        ),
        "receiver_attestation_fixture_output_symlink": (
            "The --output argument points at a symlink. "
            "Provide a real directory path, not a symbolic link."
        ),
        "receiver_attestation_fixture_output_not_directory": (
            "The --output argument points at an existing regular file. "
            "Use an existing directory or a new directory path that Ardur can create."
        ),
    }
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": messages.get(
            condition, "Receiver attestation fixture output path is invalid."
        ),
        "detail": details.get(
            condition, "Provide a directory path for the --output argument."
        ),
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_receiver_attestation_fixture_with_output_directory",
                "command": "ardur receiver-attestation-fixture --output <fixture-dir>",
                "detail": "Replace <fixture-dir> with a directory path (new or existing, not a file or symlink).",
            }
        ],
    }


def _drp_profile_fixture_output_invalid_response(condition: str) -> dict:
    """Structured failure for an invalid ``--output`` argument.

    Mirrors the receiver-attestation-fixture convention: a stable
    ``condition``/``error`` pair, a human-readable ``message`` with no raw
    exception text or local paths, a ``detail`` explaining how to choose a
    valid directory, and placeholder-only ``next_steps``.
    """

    messages = {
        "drp_profile_fixture_output_empty": (
            "DRP profile fixture output path is empty."
        ),
        "drp_profile_fixture_output_symlink": (
            "DRP profile fixture output path must not be a symlink."
        ),
        "drp_profile_fixture_output_not_directory": (
            "DRP profile fixture output path is not a directory."
        ),
    }
    details = {
        "drp_profile_fixture_output_empty": (
            "The --output argument is empty or whitespace-only. "
            "Provide a directory path where Ardur can write the public fixture artifacts."
        ),
        "drp_profile_fixture_output_symlink": (
            "The --output argument points at a symlink. "
            "Provide a real directory path, not a symbolic link."
        ),
        "drp_profile_fixture_output_not_directory": (
            "The --output argument points at an existing regular file. "
            "Use an existing directory or a new directory path that Ardur can create."
        ),
    }
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": messages.get(
            condition, "DRP profile fixture output path is invalid."
        ),
        "detail": details.get(
            condition, "Provide a directory path for the --output argument."
        ),
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_drp_profile_fixture_with_output_directory",
                "command": "ardur drp-profile-fixture --output <fixture-dir>",
                "detail": "Replace <fixture-dir> with a directory path (new or existing, not a file or symlink).",
            }
        ],
    }


def _offline_verification_fixture_output_invalid_response(condition: str) -> dict:
    """Structured failure for an invalid ``--output`` argument.

    Mirrors the receiver-attestation-fixture convention: a stable
    ``condition``/``error`` pair, a human-readable ``message`` with no raw
    exception text or local paths, a ``detail`` explaining how to choose a
    valid directory, and placeholder-only ``next_steps``.
    """

    messages = {
        "offline_verification_fixture_output_empty": (
            "Offline verification fixture output path is empty."
        ),
        "offline_verification_fixture_output_symlink": (
            "Offline verification fixture output path must not be a symlink."
        ),
        "offline_verification_fixture_output_not_directory": (
            "Offline verification fixture output path is not a directory."
        ),
    }
    details = {
        "offline_verification_fixture_output_empty": (
            "The --output argument is empty or whitespace-only. "
            "Provide a directory path where Ardur can write the public fixture artifacts."
        ),
        "offline_verification_fixture_output_symlink": (
            "The --output argument points at a symlink. "
            "Provide a real directory path, not a symbolic link."
        ),
        "offline_verification_fixture_output_not_directory": (
            "The --output argument points at an existing regular file. "
            "Use an existing directory or a new directory path that Ardur can create."
        ),
    }
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": messages.get(
            condition, "Offline verification fixture output path is invalid."
        ),
        "detail": details.get(
            condition, "Provide a directory path for the --output argument."
        ),
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_offline_verification_fixture_with_output_directory",
                "command": "ardur offline-verification-fixture --output <fixture-dir>",
                "detail": "Replace <fixture-dir> with a directory path (new or existing, not a file or symlink).",
            }
        ],
    }


def _classify_fixture_error(exc: BaseException, error_code: str) -> tuple[str, str]:
    """Map a raw ``OSError``/``TypeError``/``ValueError`` to a safe message.

    Returns ``(error_code, safe_message)`` so the JSON response never leaks
    raw Python internals (e.g. ``[Errno 13] Permission denied:
    '/var/folders/...'``) or local filesystem paths into the ``message``
    field. ``error_code`` is kept command-specific by the caller.
    """
    if isinstance(exc, OSError):
        return error_code, "Filesystem error writing fixture output."
    return error_code, "Invalid input type or value for fixture generation."


def _safe_exception_message(exc: BaseException) -> str:
    """Return a user-safe representation of ``exc`` for JSON output.

    Domain exception types (``TransparencyError``, ``AnchorVerificationError``,
    ``KeyDirectoryError``, ``OfflineVerificationError``, ``TelemetryExportError``,
    ``RuntimeEvidenceError``, ``jwt.InvalidTokenError``, etc.) carry
    intentionally-safe, user-facing messages and are preserved verbatim.
    ``FileNotFoundError`` / ``PermissionError`` from the passport module are
    re-raised with safe messages and also preserved. Generic Python built-ins
    (``OSError``, bare ``TypeError``/``ValueError``) can carry filesystem
    paths, errno details, or Python internals in ``str(exc)``, so only the
    class name is returned.

    Heuristic: if the exception text contains ``[Errno`` (the raw OSError
    format), it is treated as unsafe regardless of type.
    """
    text = str(exc)
    # Raw OSError errno pattern: always sanitize.
    if "[Errno" in text:
        return type(exc).__name__
    # Domain exception types with safe, intentional messages.
    from vibap.transparency import TransparencyError

    if isinstance(exc, TransparencyError):
        return text
    try:
        from vibap.offline_verification import OfflineVerificationError

        if isinstance(exc, OfflineVerificationError):
            return text
    except ImportError:  # noqa: BLE001 - offline_verification optional in minimal installs
        pass
    try:
        from vibap.receipt_telemetry import TelemetryExportError

        if isinstance(exc, TelemetryExportError):
            return text
    except ImportError:  # noqa: BLE001 - receipt_telemetry optional in minimal installs
        pass
    try:
        from vibap.runtime_evidence import RuntimeEvidenceError

        # RuntimeEvidenceError carries safe, hardcoded user-facing messages
        # (e.g. "runtime evidence input is empty", "line N is malformed JSON")
        # with no filesystem paths, errno patterns, or Python internals.
        if isinstance(exc, RuntimeEvidenceError):
            return text
    except ImportError:  # noqa: BLE001 - runtime_evidence optional in minimal installs
        pass
    try:
        from vibap.passport import KeyDirectoryError

        if isinstance(exc, KeyDirectoryError):
            return text
    except ImportError:  # noqa: BLE001 - passport optional in minimal installs
        pass
    try:
        import jwt

        # PyJWT InvalidTokenError subclasses (ExpiredSignatureError,
        # ImmatureSignatureError, InvalidSignatureError, DecodeError,
        # InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError,
        # etc.) carry intentionally-safe, user-facing messages with no paths,
        # credentials, or Python internals.  InvalidKeyError and
        # PyJWKClientConnectionError can surface endpoint/key material and are
        # intentionally NOT included — only InvalidTokenError is safe.
        if isinstance(exc, jwt.InvalidTokenError):
            return text
    except ImportError:  # noqa: BLE001 - PyJWT optional in minimal installs
        pass
    # FileNotFoundError / PermissionError re-raised by the passport module
    # carry intentional messages (no errno pattern). Other OSError subclasses
    # are sanitized to class name.
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return text
    # Everything else: use class name only to avoid leaking internals.
    return type(exc).__name__


def cmd_receiver_attestation_fixture(args: argparse.Namespace) -> int:
    from .receiver_attestation_fixture import (
        ReceiverAttestationFixtureOutputError,
        run_receiver_attestation_fixture,
    )

    try:
        report = run_receiver_attestation_fixture(args.output)
    except ReceiverAttestationFixtureOutputError as exc:
        _print_json(
            _receiver_attestation_fixture_output_invalid_response(exc.condition)
        )
        return 1
    except (OSError, TypeError, ValueError) as exc:
        error_code, safe_message = _classify_fixture_error(
            exc, "receiver_attestation_fixture_failed"
        )
        _print_json(
            {
                "ok": False,
                "error": error_code,
                "message": safe_message,
            }
        )
        return 1
    _print_json(report)
    return 0


def cmd_drp_profile_fixture(args: argparse.Namespace) -> int:
    from .drp_fixture import DrpFixtureOutputError, run_drp_profile_fixture

    try:
        report = run_drp_profile_fixture(args.output)
    except DrpFixtureOutputError as exc:
        _print_json(_drp_profile_fixture_output_invalid_response(exc.condition))
        return 1
    except (OSError, TypeError, ValueError) as exc:
        error_code, safe_message = _classify_fixture_error(
            exc, "drp_profile_fixture_failed"
        )
        _print_json(
            {
                "ok": False,
                "error": error_code,
                "message": safe_message,
            }
        )
        return 1
    _print_json(report)
    return 0


def cmd_offline_verification_fixture(args: argparse.Namespace) -> int:
    from .offline_verification_fixture import (
        OfflineVerificationFixtureOutputError,
        run_offline_verification_fixture,
    )

    try:
        report = run_offline_verification_fixture(args.output)
    except OfflineVerificationFixtureOutputError as exc:
        _print_json(
            _offline_verification_fixture_output_invalid_response(exc.condition)
        )
        return 1
    except (OSError, TypeError, ValueError) as exc:
        error_code, safe_message = _classify_fixture_error(
            exc, "offline_verification_fixture_failed"
        )
        _print_json(
            {
                "ok": False,
                "error": error_code,
                "message": safe_message,
            }
        )
        return 1
    _print_json(report)
    return 0


def cmd_gemini_cli_hook(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    phase = args.phase or args.phase_pos or "pre"
    argv = ["--phase", phase]
    if args.keys_dir:
        argv.extend(["--keys-dir", str(args.keys_dir)])
    return gemini_cli_hook_main(argv)


def _gemini_fixture_path_error_label_arg(condition: str) -> tuple[str, str]:
    """Resolve (label, arg_name) for a Gemini fixture path-error condition.

    An earlier implementation derived both from the condition string via
    suffix stripping (``.replace("_not_directory", "")`` etc.), which broke
    for the ``_dangling_symlink_parent`` / ``_parent_not_directory`` suffixes
    (they contain underscores that produced wrong arg names like
    ``--home-dangling-symlink-parent``). An explicit table is robust to new
    parent-component conditions while preserving the existing leaf responses.
    """
    table = {
        "gemini_cli_fixture_home_empty": ("home", "--home"),
        "gemini_cli_fixture_home_not_directory": ("home", "--home"),
        "gemini_cli_fixture_home_dangling_symlink_parent": ("home", "--home"),
        "gemini_cli_fixture_home_parent_not_directory": ("home", "--home"),
        "gemini_cli_fixture_chain_dir_empty": ("chain dir", "--chain-dir"),
        "gemini_cli_fixture_chain_dir_not_directory": ("chain dir", "--chain-dir"),
        "gemini_cli_fixture_chain_dir_dangling_symlink_parent": (
            "chain dir",
            "--chain-dir",
        ),
        "gemini_cli_fixture_chain_dir_parent_not_directory": (
            "chain dir",
            "--chain-dir",
        ),
        "gemini_cli_fixture_keys_dir_empty": ("keys dir", "--keys-dir"),
        "gemini_cli_fixture_keys_dir_not_directory": ("keys dir", "--keys-dir"),
    }
    return table.get(condition, ("path", "--path"))


def _codex_fixture_path_error_label_arg(condition: str) -> tuple[str, str]:
    """Resolve (label, arg_name) for a Codex app-server fixture path-error condition.

    See ``_gemini_fixture_path_error_label_arg`` for why an explicit table is
    used instead of condition-string suffix stripping.
    """
    table = {
        "codex_app_server_fixture_home_empty": ("home", "--home"),
        "codex_app_server_fixture_home_not_directory": ("home", "--home"),
        "codex_app_server_fixture_home_dangling_symlink_parent": ("home", "--home"),
        "codex_app_server_fixture_home_parent_not_directory": ("home", "--home"),
        "codex_app_server_fixture_chain_dir_empty": ("chain dir", "--chain-dir"),
        "codex_app_server_fixture_chain_dir_not_directory": (
            "chain dir",
            "--chain-dir",
        ),
        "codex_app_server_fixture_chain_dir_dangling_symlink_parent": (
            "chain dir",
            "--chain-dir",
        ),
        "codex_app_server_fixture_chain_dir_parent_not_directory": (
            "chain dir",
            "--chain-dir",
        ),
        "codex_app_server_fixture_keys_dir_empty": ("keys dir", "--keys-dir"),
        "codex_app_server_fixture_keys_dir_not_directory": ("keys dir", "--keys-dir"),
    }
    return table.get(condition, ("path", "--path"))


def cmd_gemini_cli_fixture(args: argparse.Namespace) -> int:
    try:
        fixture = build_gemini_local_fixture(
            home=args.home,
            project_dir=args.project_dir,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
        )
    except GeminiFixtureProjectDirError as exc:
        _print_json(gemini_fixture_project_dir_failure_response(exc.condition))
        return 1
    except GeminiFixturePathError as exc:
        label, arg_name = _gemini_fixture_path_error_label_arg(exc.condition)
        _print_json(
            gemini_fixture_path_failure_response(
                condition=exc.condition,
                label=label,
                arg_name=arg_name,
            )
        )
        return 1
    except KeyDirectoryError:
        _print_json(
            gemini_fixture_path_failure_response(
                condition="gemini_cli_fixture_keys_dir_not_directory",
                label="keys dir",
                arg_name="--keys-dir",
            )
        )
        return 1
    _print_json(build_gemini_shareable_context(fixture))
    return 0


def _report_path_empty_failure_response(
    *,
    command_name: str,
    command_title: str,
    arg_name: str,
    label: str,
    condition: str,
    required: bool = False,
) -> dict[str, object]:
    placeholder = label.replace(" ", "-")
    action_command = command_name.replace(" ", "_").replace("-", "_")
    action_label = label.replace(" ", "_").replace("-", "_")
    if required:
        detail = f"The {arg_name} argument is empty or whitespace-only. Provide a {label} path."
    else:
        detail = (
            f"The {arg_name} argument is empty or whitespace-only. Provide a {label} path, "
            "or omit the option to use the default local Ardur location."
        )
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": f"{command_title} {label} is empty.",
        "detail": detail,
        "next_steps": [
            {
                "condition": condition,
                "action": f"rerun_{action_command}_with_{action_label}",
                "command": f"ardur {command_name} {arg_name} <{placeholder}>",
                "detail": f"Replace <{placeholder}> with an explicit non-empty path.",
            }
        ],
    }


def _coerce_report_path_args(
    args: argparse.Namespace,
    *,
    command_name: str,
    command_title: str,
    specs: Sequence[tuple[str, str, str, str, bool]],
) -> dict[str, object] | None:
    """Reject empty/whitespace report path args, then coerce strings to Path.

    Argparse ``type=Path`` normalizes ``""`` to ``PosixPath('.')`` before the
    command handler can distinguish an omitted value from an empty path. The
    report commands stay read-only, but an empty value can silently fall back to
    defaults or produce raw chain/input exceptions. Parse as ``str`` first and
    fail closed before converting non-empty values to ``Path`` for downstream
    report builders.
    """
    for attr, arg_name, label, condition, required in specs:
        value = getattr(args, attr, None)
        if value is None:
            continue
        if _path_arg_is_empty(value):
            return _report_path_empty_failure_response(
                command_name=command_name,
                command_title=command_title,
                arg_name=arg_name,
                label=label,
                condition=condition,
                required=required,
            )
    for attr, *_rest in specs:
        value = getattr(args, attr, None)
        if isinstance(value, str):
            setattr(args, attr, Path(value))
    return None


def cmd_gemini_cli_report(args: argparse.Namespace) -> int:
    path_failure = _coerce_report_path_args(
        args,
        command_name="gemini-cli-report",
        command_title="Gemini CLI report",
        specs=(
            ("home", "--home", "home", "gemini_cli_report_home_empty", False),
            (
                "chain_dir",
                "--chain-dir",
                "chain dir",
                "gemini_cli_report_chain_dir_empty",
                False,
            ),
            (
                "keys_dir",
                "--keys-dir",
                "keys dir",
                "gemini_cli_report_keys_dir_empty",
                False,
            ),
            (
                "output",
                "--output",
                "output",
                "gemini_cli_report_output_empty",
                False,
            ),
        ),
    )
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        report = build_gemini_shareable_report(
            home=args.home,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
            verify_expiry=args.verify_expiry,
        )
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        report = _redact_paths_deep(report)
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "ok": False,
                    **_output_write_error_response("gemini_cli_report", exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": "gemini_cli_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    if args.json:
        _print_json(report)
        return 0
    print(
        f"Ardur Gemini CLI receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains"
    )
    print(f"Chains: {report['chain_dir']}")
    print(f"Verdicts: {report['policy_verdict_counts']}")
    print(f"Coverage gaps: {report['coverage_gaps']}")
    _print_report_next_steps(report)
    return 0


def _codex_app_server_event_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_codex_app_server_fixture",
            "command": "ardur codex-app-server-fixture --project-dir <your-project>",
            "detail": (
                "Create a local-only Codex app-server fixture and inspect the generated "
                "config/schema before feeding host-event JSON."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_with_event_json_file",
            "command": "ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>",
            "detail": (
                "Feed a Codex app-server host-event JSON object from <event-json-file>. "
                "Keep raw tokens and local private paths out of shared logs and reports."
            ),
        },
    ]


def _codex_app_server_event_input_failure_response(exc: Exception) -> dict:
    if isinstance(exc, json.JSONDecodeError):
        condition = "codex_app_server_event_input_malformed"
        message = "Codex app-server host-event input is not valid JSON."
        detail = (
            "Input must be a valid JSON object; "
            f"parsing failed at line {exc.lineno}, column {exc.colno}."
        )
    else:
        condition = "codex_app_server_event_input_not_object"
        message = "Codex app-server host-event input must be a JSON object."
        detail = (
            "Input must be a JSON object from <event-json-file>; arrays, strings, "
            "numbers, booleans, and null are not accepted."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _codex_app_server_event_input_next_steps(condition),
    }


def _load_codex_app_server_event_stdin(raw: str) -> dict:
    if not raw.strip():
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Codex app-server host-event payload must be a JSON object")
    return payload


def cmd_codex_app_server_event(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    raw = sys.stdin.read()
    try:
        payload = _load_codex_app_server_event_stdin(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        _print_json(_codex_app_server_event_input_failure_response(exc))
        return 1
    output = handle_codex_host_event(payload, keys_dir=args.keys_dir)
    _print_json(output)
    return 2 if output.get("block") else 0


def cmd_codex_app_server_fixture(args: argparse.Namespace) -> int:
    try:
        fixture = build_codex_local_fixture(
            home=args.home,
            project_dir=args.project_dir,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
        )
    except CodexFixtureProjectDirError as exc:
        _print_json(codex_fixture_project_dir_failure_response(exc.condition))
        return 1
    except CodexFixturePathError as exc:
        label, arg_name = _codex_fixture_path_error_label_arg(exc.condition)
        _print_json(
            codex_fixture_path_failure_response(
                condition=exc.condition,
                label=label,
                arg_name=arg_name,
            )
        )
        return 1
    except KeyDirectoryError:
        _print_json(
            codex_fixture_path_failure_response(
                condition="codex_app_server_fixture_keys_dir_not_directory",
                label="keys dir",
                arg_name="--keys-dir",
            )
        )
        return 1
    _print_json(build_codex_shareable_context(fixture))
    return 0


def cmd_codex_app_server_report(args: argparse.Namespace) -> int:
    path_failure = _coerce_report_path_args(
        args,
        command_name="codex-app-server-report",
        command_title="Codex app-server report",
        specs=(
            ("home", "--home", "home", "codex_app_server_report_home_empty", False),
            (
                "chain_dir",
                "--chain-dir",
                "chain dir",
                "codex_app_server_report_chain_dir_empty",
                False,
            ),
            (
                "keys_dir",
                "--keys-dir",
                "keys dir",
                "codex_app_server_report_keys_dir_empty",
                False,
            ),
            (
                "output",
                "--output",
                "output",
                "codex_app_server_report_output_empty",
                False,
            ),
        ),
    )
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        report = build_codex_shareable_report(
            home=args.home,
            chain_dir=args.chain_dir,
            keys_dir=args.keys_dir,
            verify_expiry=args.verify_expiry,
        )
    except KeyDirectoryError as exc:
        _print_json(_keys_dir_failure_response(exc))
        return 1
    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        report = _redact_paths_deep(report)
    if getattr(args, "output", None) is not None:
        try:
            payload = _write_json_report_to_file(args.output, report)
        except ValueError as exc:
            _print_json(
                {
                    "ok": False,
                    **_output_write_error_response("codex_app_server_report", exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": "codex_app_server_report_written",
                "output": str(args.output),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        return 0
    if args.json:
        _print_json(report)
        return 0
    print(
        f"Ardur Codex app-server receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains"
    )
    print(f"Chains: {report['chain_dir']}")
    print(f"Verdicts: {report['policy_verdict_counts']}")
    print(f"Coverage gaps: {report['coverage_gaps']}")
    _print_report_next_steps(report)
    return 0


def cmd_posture_scan(args: argparse.Namespace) -> int:
    try:
        posture = build_posture_index(
            receipts=args.receipts,
            keys_dir=args.keys_dir,
            profile=args.profile,
            evidence_bundle=args.evidence_bundle,
            verify_expiry=args.verify_expiry,
        )
    except PostureReceiptsError as exc:
        _print_json(posture_receipts_failure_response(exc.condition))
        return 1
    except PostureInputError as exc:
        _print_json(posture_input_failure_response(exc.condition))
        return 1

    from .runtime_evidence import RuntimeEvidenceError, write_report

    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "posture_scan_output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        posture = _redact_paths_deep(posture)

    payload = (
        (json.dumps(posture, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if args.format == "json" or getattr(args, "json", False)
        else format_posture_report(posture).encode("utf-8")
    )
    if args.posture_scan_output is not None:
        if not str(args.posture_scan_output).strip():
            _print_json(
                {
                    "ok": False,
                    "error": "path_arg_invalid",
                    "condition": "path_arg_invalid",
                    "message": "ardur --output must be a non-empty path after trimming whitespace.",
                }
            )
            return 1
        try:
            write_report(args.posture_scan_output, payload)
        except RuntimeEvidenceError as exc:
            _print_json(
                {
                    "ok": False,
                    "error": exc.code,
                    "condition": exc.code,
                    "message": str(exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": "posture_scan_report_written",
                "format": args.format,
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    elif args.format == "json" or getattr(args, "json", False):
        sys.stdout.buffer.write(payload)
    else:
        sys.stdout.write(payload.decode("utf-8"))
    return 0


def cmd_tool_server_preflight(args: argparse.Namespace) -> int:
    """Statically inspect a tool-server configuration without executing it."""

    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1

    from .runtime_evidence import RuntimeEvidenceError, write_report

    try:
        report = scan_tool_server_config(args.config)
        if (
            getattr(args, "redact_paths", False)
            and not getattr(args, "json", False)
            and getattr(args, "output", None) is None
        ):
            print(
                "ardur: warning: --redact-paths has no effect without --json or --output",
                file=sys.stderr,
            )
        if getattr(args, "redact_paths", False):
            report = _redact_paths_deep(report)
        payload = (
            json.dumps(report, indent=2, sort_keys=True) + "\n"
            if args.format == "json"
            else render_tool_preflight_markdown(report)
        )
        threshold_reached = fail_threshold_reached(report, args.fail_on)
        if args.output is not None:
            encoded = payload.encode("utf-8")
            write_report(args.output, encoded)
            _print_json(
                {
                    "ok": not threshold_reached,
                    "condition": "tool_server_preflight_report_written",
                    "analysis_mode": "static_non_executing",
                    "verdict": report["summary"]["verdict"],
                    "finding_count": report["summary"]["finding_count"],
                    "fail_on": args.fail_on,
                    "threshold_reached": threshold_reached,
                    "report_sha256": hashlib.sha256(encoded).hexdigest(),
                }
            )
        else:
            sys.stdout.write(payload)
        return 2 if threshold_reached else 0
    except ToolPreflightError as exc:
        response = tool_preflight_error_response(exc)
    except RuntimeEvidenceError as exc:
        response = {
            "ok": False,
            "error": exc.code,
            "condition": exc.code,
            "message": str(exc),
            "analysis_mode": "static_non_executing",
        }
    if args.format == "json":
        _print_json(response)
    else:
        print(f"Error: {response['message']}")
        print(f"Condition: {response['condition']}")
    # When --fail-on is set, config parse errors are also failures that should
    # trigger the exit-2 threshold so CI pipelines don't miss broken configs.
    return 2 if args.fail_on != "none" else 1


def _posture_report_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_posture_json",
            "command": "ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format json > <posture-json>",
            "detail": (
                "Create a posture JSON document from local Ardur artifacts first. "
                "Keep local paths, private keys, and raw tokens out of shared reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_posture_report",
            "command": "ardur posture report --input <posture-json> --format json",
            "detail": "Render the generated posture JSON after the input file exists and parses successfully.",
        },
    ]


def _posture_report_input_failure_response(exc: Exception) -> dict:
    if isinstance(exc, FileNotFoundError):
        condition = "posture_report_input_missing"
        message = "Posture report input file could not be read."
        detail = "No posture JSON file was found at the supplied --input path."
    elif isinstance(exc, json.JSONDecodeError):
        condition = "posture_report_input_malformed"
        message = "Posture report input file is not valid JSON."
        detail = f"JSON parsing failed at line {exc.lineno}, column {exc.colno}."
    elif isinstance(exc, ValueError):
        condition = "posture_report_input_invalid"
        message = "Posture report input file is not a posture JSON object."
        detail = "The supplied --input file must contain a JSON object produced by ardur posture scan."
    else:
        condition = "posture_report_input_unreadable"
        message = "Posture report input file could not be read."
        detail = (
            f"Reading the supplied --input file failed with {exc.__class__.__name__}."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _posture_report_input_next_steps(condition),
    }


def cmd_posture_report(args: argparse.Namespace) -> int:
    path_failure = _coerce_report_path_args(
        args,
        command_name="posture report",
        command_title="Posture report",
        specs=(
            ("input", "--input", "posture json", "posture_report_input_empty", True),
        ),
    )
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        posture = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(posture, dict):
            raise ValueError("posture report input must be a JSON object")
    except (
        FileNotFoundError,
        PermissionError,
        IsADirectoryError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        response = _posture_report_input_failure_response(exc)
        if args.format == "json" or getattr(args, "json", False):
            _print_json(response)
        else:
            print(f"Error: {response['message']}")
            print(f"Detail: {response['detail']}")
            _print_report_next_steps(response)
        return 1

    from .runtime_evidence import RuntimeEvidenceError, write_report

    if (
        getattr(args, "redact_paths", False)
        and not getattr(args, "json", False)
        and getattr(args, "posture_report_output", None) is None
    ):
        print(
            "ardur: warning: --redact-paths has no effect without --json or --output",
            file=sys.stderr,
        )
    if getattr(args, "redact_paths", False):
        posture = _redact_paths_deep(posture)

    payload = (
        (json.dumps(posture, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if args.format == "json" or getattr(args, "json", False)
        else format_posture_report(posture).encode("utf-8")
    )
    if args.posture_report_output is not None:
        if not str(args.posture_report_output).strip():
            _print_json(
                {
                    "ok": False,
                    "error": "path_arg_invalid",
                    "condition": "path_arg_invalid",
                    "message": "ardur --output must be a non-empty path after trimming whitespace.",
                }
            )
            return 1
        try:
            write_report(args.posture_report_output, payload)
        except RuntimeEvidenceError as exc:
            _print_json(
                {
                    "ok": False,
                    "error": exc.code,
                    "condition": exc.code,
                    "message": str(exc),
                }
            )
            return 1
        _print_json(
            {
                "ok": True,
                "condition": "posture_report_written",
                "format": args.format,
                "report_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    elif args.format == "json" or getattr(args, "json", False):
        sys.stdout.buffer.write(payload)
    else:
        sys.stdout.write(payload.decode("utf-8"))
    return 0


def cmd_hub(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    port_failure = _hub_port_failure_exit_code(args.port)
    if port_failure is not None:
        return port_failure
    host_failure = _hub_host_failure_exit_code(args.host)
    if host_failure is not None:
        return host_failure
    try:
        workload_identity = _fetch_configured_workload_identity(
            getattr(args, "spiffe_endpoint_socket", None)
        )
    except (OSError, PySpiffeError, RuntimeError, ValueError):
        _print_json(_spiffe_svid_fetch_failure_response())
        return 1
    if workload_identity is not None:
        print(
            f"[spiffe] workload identity established: {workload_identity.spiffe_id}",
            file=sys.stderr,
        )
    try:
        serve_hub(
            host=args.host,
            port=args.port,
            home=args.home,
            workload_identity=workload_identity,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            no_tls=args.no_tls,
        )
    except HubTLSConfigurationError as exc:
        _print_json(_hub_tls_material_failure_response(detail=str(exc)))
        return 1
    except HubError as exc:
        return _path_failure_exit_code(exc)
    except OSError as exc:
        import errno

        if exc.errno == errno.EADDRINUSE:
            _print_json(_hub_port_in_use_response())
            return 1
        _print_json(_hub_oserror_response(exc))
        return 1
    return 0


def _kill_switch_invalid_proxy_url_next_steps() -> list[dict[str, str]]:
    return [
        {
            "condition": "proxy_url_invalid",
            "action": "check_proxy_url",
            "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
            "detail": (
                "Use a complete HTTP or HTTPS governance proxy endpoint such as "
                "https://127.0.0.1:<proxy-port>. Keep raw local paths, malformed URLs, "
                "URL credentials, and tokens out of shared logs."
            ),
        },
        {
            "condition": "proxy_url_invalid",
            "action": "start_or_check_governance_proxy",
            "command": "VIBAP_API_TOKEN=<api-token> ardur start --host 127.0.0.1 --port <proxy-port>",
            "detail": (
                "If the proxy is not running, start the local loopback governance proxy "
                "and copy only its scheme, host, and port into <proxy-url>."
            ),
        },
    ]


def _kill_switch_error_flags(
    error: str,
    *,
    status: int | None = None,
) -> dict[str, bool]:
    """Classify a raw kill-switch error string into boolean failure flags.

    Shared by ``_kill_switch_next_steps_for_failure`` (remediation hints) and
    ``_kill_switch_classify_error`` (structured ``error_code``/``message``).
    Centralizing the classification here prevents the raw Python exception
    string (e.g. ``<urlopen error [Errno 61] Connection refused>``) from
    leaking into the ``error`` field of the JSON response.
    """
    normalized_error = error.strip().lower().replace("_", " ")
    status_text = str(status or "").strip()

    if normalized_error == "proxy url invalid":
        return {"proxy_url_invalid": True}

    proxy_unavailable = any(
        marker in normalized_error
        for marker in {
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "no route to host",
            "name or service not known",
            "nodename nor servname",
            "timed out",
            "urlopen error",
        }
    )
    tls_problem = any(
        marker in normalized_error
        for marker in {
            "ssl",
            "tls",
            "certificate",
            "wrong version number",
            "handshake",
        }
    )
    token_problem = (
        status_text in {"401", "403"}
        or "authorization" in normalized_error
        or "unauthorized" in normalized_error
        or "bearer token" in normalized_error
        or "invalid bearer" in normalized_error
        or "api token" in normalized_error
    )
    endpoint_problem = status_text in {"404", "405"} or "not found" in normalized_error

    return {
        "proxy_unavailable": proxy_unavailable,
        "tls_problem": tls_problem,
        "token_problem": token_problem,
        "endpoint_problem": endpoint_problem,
    }


def _kill_switch_next_steps_for_failure(
    error: str,
    *,
    status: int | None = None,
) -> list[dict[str, str]]:
    """Return placeholder-only remediation hints for kill-switch setup failures."""
    flags = _kill_switch_error_flags(error, status=status)

    if flags.get("proxy_url_invalid"):
        return _kill_switch_invalid_proxy_url_next_steps()

    proxy_unavailable = flags["proxy_unavailable"]
    tls_problem = flags["tls_problem"]
    token_problem = flags["token_problem"]
    endpoint_problem = flags["endpoint_problem"]

    if (
        not proxy_unavailable
        and not tls_problem
        and not token_problem
        and not endpoint_problem
    ):
        return []

    steps: list[dict[str, str]] = []
    if proxy_unavailable or tls_problem or endpoint_problem:
        steps.append(
            {
                "condition": "proxy_tls_setup" if tls_problem else "proxy_unavailable",
                "action": "start_or_check_governance_proxy",
                "command": "VIBAP_API_TOKEN=<api-token> ardur start --host 127.0.0.1 --port <proxy-port>",
                "detail": (
                    "Start the local loopback governance proxy and keep its token private. "
                    "Use --tls-cert/--tls-key if your proxy URL uses https with explicit certs, "
                    "or --no-tls only for local development."
                ),
            }
        )
        steps.append(
            {
                "condition": "proxy_tls_setup" if tls_problem else "proxy_url_check",
                "action": "check_proxy_url_scheme",
                "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
                "detail": (
                    "Use the scheme, host, and port printed by ardur start; keep any URL "
                    "credentials or raw tokens out of logs and shared artifacts."
                ),
            }
        )

    if token_problem:
        steps.append(
            {
                "condition": "proxy_token_required",
                "action": "supply_proxy_api_token",
                "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
                "detail": (
                    "Pass the configured proxy API token with --api-token <api-token> or "
                    "ARDUR_API_TOKEN=<api-token>. Do not paste the raw token into shared logs."
                ),
            }
        )

    steps.append(
        {
            "condition": "kill_switch_proxy_request_failed",
            "action": "rerun_kill_switch_or_health_check",
            "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
            "detail": (
                "After local proxy setup is fixed, rerun ardur kill-switch or check the "
                "loopback proxy health endpoint. These hints are local/no-key setup guidance "
                "only and do not claim external provider visibility or live enforcement beyond "
                "the configured proxy."
            ),
        }
    )
    return steps


def _kill_switch_classify_error(
    error: str,
    *,
    status: int | None = None,
) -> tuple[str, str, str]:
    """Map a raw kill-switch error string to (error_code, message, detail).

    Returns a structured triple so the JSON response never leaks raw Python
    internals (e.g. ``<urlopen error [Errno 61] Connection refused>``) into the
    ``error`` field. Falls back to a generic ``kill_switch_request_failed``
    code when no known failure class is recognised.
    """
    flags = _kill_switch_error_flags(error, status=status)

    if flags.get("proxy_url_invalid"):
        return (
            "proxy_url_invalid",
            "Ardur governance proxy URL is invalid.",
            "The proxy URL could not be parsed as a complete HTTP or HTTPS endpoint.",
        )

    if flags["proxy_unavailable"]:
        return (
            "proxy_unavailable",
            "Ardur governance proxy is unreachable.",
            "The governance proxy did not respond. Ensure it is running on the configured loopback endpoint.",
        )

    if flags["tls_problem"]:
        return (
            "proxy_tls_error",
            "Ardur governance proxy TLS handshake failed.",
            "The proxy endpoint rejected the TLS connection. Check certificate validity or use matching --tls-cert/--tls-key options.",
        )

    if flags["token_problem"]:
        return (
            "proxy_auth_error",
            "Ardur governance proxy rejected the API token.",
            "The proxy returned an authentication error. Supply a valid --api-token or ARDUR_API_TOKEN.",
        )

    if flags["endpoint_problem"]:
        return (
            "proxy_endpoint_error",
            "Ardur governance proxy kill-switch endpoint was not found.",
            "The proxy responded, but the kill-switch admin endpoint returned an error status.",
        )

    return (
        "kill_switch_request_failed",
        "Ardur kill-switch request failed.",
        "The kill-switch request could not be completed. Check local proxy setup and retry.",
    )


def _kill_switch_failure_response(error: str, *, status: int | None = None) -> dict:
    error_code, message, detail = _kill_switch_classify_error(error, status=status)
    response: dict = {
        "ok": False,
        "error": error_code,
        "error_code": error_code,
        "condition": error_code,
        "message": message,
        "detail": detail,
    }
    if status is not None:
        response["status"] = status
    steps = _kill_switch_next_steps_for_failure(error, status=status)
    if steps:
        response["next_steps"] = steps
    return response


def _kill_switch_invalid_proxy_url_response() -> dict:
    return {
        "ok": False,
        "error": "proxy_url_invalid",
        "error_code": "proxy_url_invalid",
        "condition": "proxy_url_invalid",
        "message": "Ardur governance proxy URL is invalid.",
        "detail": (
            "The proxy URL could not be parsed as a complete HTTP or HTTPS endpoint. "
            "Use a loopback URL such as https://127.0.0.1:<proxy-port>."
        ),
        "next_steps": _kill_switch_invalid_proxy_url_next_steps(),
    }


def _kill_switch_api_token_invalid_response() -> dict:
    """Failure response for a whitespace-only --api-token on kill-switch.

    ``--api-token`` is sent verbatim as the bearer token for the loopback
    governance proxy admin endpoint. A whitespace-only argument is truthy
    in the ``args.api_token or os.environ.get(...)`` chain and therefore
    shadows any configured ``ARDUR_API_TOKEN``, but it resolves to an empty
    bearer token after the proxy strips whitespace, yielding a confusing
    401/``Connection refused`` instead of a clear CLI-layer rejection.

    Reject it here, before any network call, with the same structured shape
    the sibling ``start --api-token`` and ``status/doctor/desktop-observe
    --hub-token`` guards use. An unset ``--api-token`` (None) and an empty
    string ``""`` (falsy, falls through to ``ARDUR_API_TOKEN``) remain
    valid: only whitespace-only strings are rejected, matching the
    silent-empty-token bug class already closed for ``start --api-token``
    and ``kill-switch --proxy-url``.
    """
    return {
        "ok": False,
        "error": "kill_switch_api_token_invalid",
        "error_code": "kill_switch_api_token_invalid",
        "condition": "kill_switch_api_token_invalid",
        "message": (
            "ardur kill-switch --api-token must be a non-empty token after "
            "trimming whitespace."
        ),
        "detail": (
            "An empty or whitespace-only --api-token was provided on kill-switch. "
            "Pass an explicit bearer token with --api-token, set ARDUR_API_TOKEN, "
            "or omit --api-token to fall through to ARDUR_API_TOKEN."
        ),
        "next_steps": [
            {
                "condition": "kill_switch_api_token_invalid",
                "action": "supply_proxy_api_token",
                "command": (
                    "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>"
                ),
                "detail": (
                    "Pass the configured proxy API token with "
                    "--api-token <api-token>. Do not paste the raw token into "
                    "shared logs."
                ),
            },
            {
                "condition": "kill_switch_api_token_invalid",
                "action": "set_api_token_env_or_omit_flag",
                "command": "ARDUR_API_TOKEN=<api-token> ardur kill-switch",
                "detail": (
                    "Omit --api-token so ardur reads ARDUR_API_TOKEN, or export "
                    "ARDUR_API_TOKEN explicitly. An unset or empty --api-token "
                    "intentionally falls through to the environment."
                ),
            },
        ],
    }


def _kill_switch_api_token_invalid_failure(
    args: argparse.Namespace,
) -> dict | None:
    """Return the api-token-invalid response when --api-token is whitespace-only.

    ``None`` means the argument is acceptable: either unset (None), an empty
    string (falsy, falls through to ``ARDUR_API_TOKEN``), or a real token.
    """
    value = getattr(args, "api_token", None)
    if isinstance(value, str) and value and not value.strip():
        return _kill_switch_api_token_invalid_response()
    return None


def _validated_kill_switch_proxy_base_url(proxy_url: str) -> str | None:
    """Return a request base URL only for complete HTTP(S) kill-switch endpoints."""
    from urllib.parse import urlsplit

    base_url = str(proxy_url).strip()
    try:
        parsed = urlsplit(base_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.netloc or not parsed.hostname:
            return None
        _ = parsed.port
    except ValueError:
        return None
    return base_url.rstrip("/")


def _kill_switch_proxy_host_is_loopback(proxy_url: str) -> bool:
    import ipaddress
    from urllib.parse import urlparse

    try:
        host = urlparse(proxy_url).hostname
    except ValueError:
        return False
    if not host:
        return False
    normalized_host = host.strip().lower()
    if normalized_host == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized_host).is_loopback
    except ValueError:
        return False


def _kill_switch_ssl_context(proxy_url: str):
    import ssl

    ctx = ssl.create_default_context()
    if _kill_switch_proxy_host_is_loopback(proxy_url):
        # The local development proxy uses a self-signed certificate by default.
        # Keep that ergonomic localhost path, but do not carry the insecure TLS
        # policy to caller-supplied remote proxy URLs where bearer tokens cross
        # the network.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cmd_kill_switch(args: argparse.Namespace) -> int:
    import urllib.error as urlerror
    import urllib.request as urlreq

    # Distinguish "user explicitly passed --proxy-url ''" from "user omitted
    # the flag". An empty string is an invalid proxy URL and must reach the
    # validator below (which rejects it as proxy_url_invalid) rather than be
    # silently swallowed by an ``or`` fallback chain that treats '' as falsy.
    if args.proxy_url is None:
        proxy_url = os.environ.get("ARDUR_PROXY_URL") or "https://127.0.0.1:8443"
    else:
        proxy_url = args.proxy_url
    proxy_base_url = _validated_kill_switch_proxy_base_url(proxy_url)
    if proxy_base_url is None:
        _print_json(_kill_switch_invalid_proxy_url_response())
        return 1
    api_token_failure = _kill_switch_api_token_invalid_failure(args)
    if api_token_failure is not None:
        _print_json(api_token_failure)
        return 1
    api_token = args.api_token or os.environ.get("ARDUR_API_TOKEN", "")
    payload = json.dumps({"deactivate": args.deactivate}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    req = urlreq.Request(
        f"{proxy_base_url}/admin/kill-switch", data=payload, headers=headers
    )
    ctx = _kill_switch_ssl_context(proxy_base_url)
    try:
        with urlreq.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            _print_json(result)
            return 0
    except urlerror.HTTPError as exc:
        error = str(exc)
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict) and payload.get("error"):
            error = str(payload["error"])
        _print_json(_kill_switch_failure_response(error, status=exc.code))
        return 1
    except Exception as exc:
        _print_json(_kill_switch_failure_response(str(exc)))
        return 1


def cmd_setup(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        response = setup_personal(args)
    except HubError as exc:
        return _path_failure_exit_code(exc)
    return _handle_output_and_redact(
        args,
        response,
        command="setup",
        exit_code=0 if response.get("ok") else 1,
    )


def _redact_paths_in_response(response: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *response* with local absolute paths replaced.

    Used by ``status``, ``doctor``, and ``doctor-claude-code`` when
    ``--redact-paths`` is set so the JSON output is safe to share in CI
    artifacts or bug reports without leaking the filesystem layout.

    Recurses into nested dicts and lists via :func:`_redact_paths_deep`
    so that paths inside ``checks[].detail``, ``next_steps[].command``,
    and other nested fields are caught — not just top-level ``home``.
    """
    return _redact_paths_deep(response)


def _redact_paths_deep(obj: Any) -> Any:
    """Recursively redact local absolute paths in *obj*.

    Walks dicts, lists, and strings.  Every string value is passed through
    :func:`_redact_local_path` for prefix-based root replacement, and any
    remaining local-path roots that appear *inside* the string (e.g. in
    ``run_command`` fields like ``VIBAP_HOME=/private/tmp/...``) are replaced
    by a follow-up regex pass.

    Used by ``protect claude-code --json --redact-paths`` because the success
    response contains 10+ path-bearing fields across nested structures
    (``home``, ``active_passport``, ``plugin_dir``, ``run_command``,
    ``claims.resource_scope[]``, ``claims.cwd``, etc.) that the shallow
    :func:`_redact_paths_in_response` does not reach.
    """
    if isinstance(obj, str):
        return _redact_local_path_string(obj)
    if isinstance(obj, dict):
        return {key: _redact_paths_deep(val) for key, val in obj.items()}
    if isinstance(obj, list):
        return [_redact_paths_deep(item) for item in obj]
    return obj


def _redact_local_path_string(value: str) -> str:
    """Redact local path roots, ``file://`` URIs, and absolute paths from *value*.

    Uses a three-step approach for comprehensive coverage:

    1. :func:`_redact_local_path` replaces known prefix roots (``/tmp/``,
       ``/Users/``, ``/private/var/folders/``, etc.) anchored at the start.

    2. A non-anchored regex pass catches the same roots when they appear
       embedded in strings (e.g. ``VIBAP_HOME=/private/tmp/...``) and
       replaces them with the same stable placeholders.

    3. :func:`redact_local_path_text` from :mod:`shareable_redaction` catches
       what steps 1+2 miss: ``file://`` URIs, percent-encoded separators,
       and arbitrary local absolute paths under unknown roots
       (e.g. ``/opt/…``).

    This unification closes a path-leak vector where the previous hand-rolled
    regex pass only covered a fixed list of roots and missed ``file://`` URIs
    and absolute paths under unknown roots.
    """
    import tempfile

    result = _redact_local_path(value)
    if result is None:
        return value
    # Step 2: replace remaining local-path roots that appear inside the
    # string (not just at the start).  Ordered from most-specific to
    # least-specific so longer roots match before shorter substrings.
    temp_root = tempfile.gettempdir()
    home = os.path.expanduser("~")
    embedded_roots = [
        (re.escape("/private/var/folders/"), "<var-folders>/"),
        (re.escape("/var/folders/"), "<var-folders>/"),
        (re.escape("/private/tmp/"), "<tmp>/"),
        (re.escape("/tmp/"), "<tmp>/"),
        (re.escape(home + "/"), "<home>/"),
        (
            re.escape(temp_root + "/")
            if temp_root.endswith("/")
            else re.escape(temp_root),
            "<tmp>",
        ),
        (re.escape("/run/ardur/"), "<run-ardur>/"),
        (re.escape("/sys/fs/cgroup/"), "<cgroup>/"),
    ]
    for pattern, replacement in embedded_roots:
        result = re.sub(pattern, replacement, result)
    # Step 3: catch file:// URIs, percent-encoded separators, and arbitrary
    # local absolute paths under unknown roots.
    return redact_local_path_text(result)


def cmd_status(args: argparse.Namespace) -> int:
    hub_token_failure = _hub_token_invalid_failure(args)
    if hub_token_failure is not None:
        _print_json(hub_token_failure)
        return 1
    response = hub_request(
        "GET",
        "/v1/status",
        hub_url=args.hub_url,
        hub_token=args.hub_token,
        home=args.home,
    )
    response = status_response_with_next_steps(response)
    return _handle_output_and_redact(
        args,
        response,
        command="status",
        exit_code=0 if response.get("ok") else 1,
    )


def cmd_doctor(args: argparse.Namespace) -> int:
    hub_token_failure = _hub_token_invalid_failure(args)
    if hub_token_failure is not None:
        _print_json(hub_token_failure)
        return 1
    try:
        response = doctor_personal(args)
    except HubError as exc:
        return _path_failure_exit_code(exc)
    return _handle_output_and_redact(
        args,
        response,
        command="doctor",
        exit_code=0 if response.get("ok") else 1,
    )


def cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        response = uninstall_personal(args)
    except HubError as exc:
        return _path_failure_exit_code(exc)
    if getattr(args, "redact_paths", False):
        response = _redact_paths_deep(response)
    _print_json(response)
    return 0 if response.get("ok", True) else 1


def _run_has_governance_intent(args: argparse.Namespace) -> bool:
    """True when ``ardur run`` was invoked as a governance bridge.

    The legacy ``ardur run`` streams a command through the Ardur Personal Hub.
    The governance bridge (issue passport → start session → launch governed) is
    selected whenever any governance flag is present, keeping the legacy path
    untouched for existing callers.
    """
    return any(
        getattr(args, name, None) not in (None, False)
        for name in (
            "mission",
            "allowed_tools",
            "forbidden_tools",
            "via",
            "govern",
            "enforce",
            "no_kernel_correlation",
            "resource_scope",
            "no_resource_scope",
        )
    ) or any(
        getattr(args, name, None) is not None
        for name in ("max_tool_calls", "max_duration_s")
    )


def cmd_run(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    if _run_has_governance_intent(args):
        return run_governed_cli(args)
    # Legacy Hub-streaming path: reject whitespace-only --hub-token before the
    # network call. (The governance path ignores --hub-token entirely, so the
    # guard only applies here.)
    hub_token_failure = _hub_token_invalid_failure(args)
    if hub_token_failure is not None:
        _print_json(hub_token_failure)
        return 1
    return run_under_hub(args)


def cmd_desktop_observe(args: argparse.Namespace) -> int:
    hub_token_failure = _hub_token_invalid_failure(args)
    if hub_token_failure is not None:
        _print_json(hub_token_failure)
        return 1
    try:
        response = desktop_observe(args)
    except HubError as exc:
        return _path_failure_exit_code(exc)
    _print_json(response)
    return 0 if response.get("ok") else 1


def _personal_native_host_once_json_input_next_steps(
    condition: str,
) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_native_message_json",
            "command": "ardur personal-native-host --once-json <native-message.json> --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Create a local native-message JSON object before using --once-json. "
                "Keep local private paths and raw Hub tokens out of shared logs and reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_personal_native_host_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "After the input JSON is valid, check local Ardur Personal setup with doctor "
                "or rerun ardur personal-native-host --once-json <native-message.json>."
            ),
        },
    ]


def _personal_native_host_once_json_failure_response(exc: Exception) -> dict:
    if isinstance(exc, json.JSONDecodeError):
        condition = "personal_native_host_once_json_malformed"
        message = "Native Messaging --once-json input is not valid JSON."
        detail = f"JSON parsing failed at line {exc.lineno}, column {exc.colno}."
    elif isinstance(exc, ValueError):
        condition = "personal_native_host_once_json_not_object"
        message = "Native Messaging --once-json input must be a JSON object."
        detail = (
            "The supplied --once-json file must contain a native-message JSON object; "
            "arrays, strings, numbers, booleans, and null are not accepted."
        )
    elif isinstance(exc, FileNotFoundError):
        condition = "personal_native_host_once_json_missing"
        message = "Native Messaging --once-json input file could not be read."
        detail = (
            "No native-message JSON file was found at the supplied --once-json path."
        )
    else:
        condition = "personal_native_host_once_json_unreadable"
        message = "Native Messaging --once-json input file could not be read."
        detail = f"Reading the supplied --once-json file failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _personal_native_host_once_json_input_next_steps(condition),
    }


def _load_personal_native_host_once_json(path: Path) -> dict:
    message = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(message, dict):
        raise ValueError("native host once-json payload must be a JSON object")
    return message


def cmd_personal_native_host(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    hub_token_failure = _hub_token_invalid_failure(args)
    if hub_token_failure is not None:
        _print_json(hub_token_failure)
        return 1
    if args.once_json:
        try:
            message = _load_personal_native_host_once_json(args.once_json)
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            _print_json(_personal_native_host_once_json_failure_response(exc))
            return 1
        response = handle_native_host_message(
            message, hub_url=args.hub_url, hub_token=args.hub_token, home=args.home
        )
        _print_json(response)
        return 0 if response.get("ok") else 1
    run_native_host(
        sys.stdin.buffer,
        sys.stdout.buffer,
        hub_url=args.hub_url,
        hub_token=args.hub_token,
        home=args.home,
    )
    return 0


def cmd_personal_native_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = build_native_host_manifest(
            args.host_path,
            args.extension_id,
            browser=args.browser,
        )
    except NativeHostManifestValidationError as exc:
        _print_json(exc.response)
        return 1
    _print_json(manifest)
    return 0


def cmd_personal_firewall_demo(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        result = run_personal_firewall_demo(
            timeout_s=args.timeout_s,
            temp_parent=args.temp_parent.expanduser().resolve()
            if args.temp_parent
            else None,
            emit=not args.json,
        )
    except PersonalFirewallDemoError as exc:
        failure = {
            "ok": False,
            "error": "personal_firewall_demo_failed",
            "condition": "personal_firewall_demo_failed",
            "message": str(exc),
            "next_steps": [
                {
                    "action": "retry_local_demo",
                    "command": "ardur personal-firewall demo",
                    "detail": "Retry the provider-free local proof with the default temporary directory.",
                }
            ],
        }
        if args.json:
            _print_json(failure)
        else:
            print(f"FAIL  {failure['message']}")
        return 1
    if args.json:
        _print_json(result)
    return 0 if result.get("ok", True) else 1


CLAUDE_CODE_PROTECT_MODES = {
    "personal-firewall": {
        "mission": "Local personal action firewall for Claude Code.",
        "allowed_tools": ["Read", "Glob", "Grep", "Edit", "MultiEdit", "Write"],
        "forbidden_tools": ["Bash", "WebFetch", "WebSearch"],
    },
    "safe-coding": {
        "mission": "Safe Claude Code work inside the selected folder.",
        "allowed_tools": ["Read", "Glob", "Grep", "Edit", "MultiEdit", "Write"],
        "forbidden_tools": ["Bash"],
    },
    "read-only": {
        "mission": "Read-only Claude Code review inside the selected folder.",
        "allowed_tools": ["Read", "Glob", "Grep"],
        "forbidden_tools": ["Bash", "Edit", "MultiEdit", "Write"],
    },
}

_ARDUR_HOME_PLACEHOLDER = "<ardur-home>"
_CLAUDE_CODE_PLUGIN_PLACEHOLDER = "<claude-code-plugin>"
_PROJECT_PLACEHOLDER = "<your-project>"


def _claude_code_plugin_detail(kind: str, suffix: str = "") -> str:
    target = _CLAUDE_CODE_PLUGIN_PLACEHOLDER
    if suffix:
        target = f"{target}/{suffix}"
    return f"expected {kind} at {target}"


def _claude_code_doctor_path_placeholder(_value: str) -> str:
    return "<local-path>"


def _claude_code_doctor_file_uri_placeholder(_value: str) -> str:
    return "<local-file-uri>"


def _claude_code_plugin_validation_detail(
    raw_detail: str, *, plugin: Path, home: Path
) -> str:
    detail = raw_detail.strip()
    if not detail:
        return "Claude Code plugin validation failed; inspect the validation output."
    root_pairs: list[tuple[str, str]] = []
    for alias in path_aliases(plugin):
        root_pairs.append((alias, _CLAUDE_CODE_PLUGIN_PLACEHOLDER))
    for alias in path_aliases(home):
        root_pairs.append((alias, _ARDUR_HOME_PLACEHOLDER))
    return redact_local_path_text(
        detail,
        root_pairs=root_pairs,
        absolute_replacement=_claude_code_doctor_path_placeholder,
        file_uri_replacement=_claude_code_doctor_file_uri_placeholder,
    )


def _default_claude_plugin_dir() -> Path:
    return claude_code_plugin_dir()


def _normalize_protect_mode(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def _claude_code_plugin_checks(plugin_dir: Path) -> list[dict[str, object]]:
    return [
        {
            "name": "plugin_dir",
            "ok": plugin_dir.exists() and plugin_dir.is_dir(),
            "detail": _claude_code_plugin_detail("directory"),
        },
        {
            "name": "plugin_manifest",
            "ok": (plugin_dir / ".claude-plugin" / "plugin.json").is_file(),
            "detail": _claude_code_plugin_detail("file", ".claude-plugin/plugin.json"),
        },
        {
            "name": "plugin_hooks",
            "ok": (plugin_dir / "hooks" / "hooks.json").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/hooks.json"),
        },
        {
            "name": "pre_tool_use",
            "ok": (plugin_dir / "hooks" / "pre_tool_use").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/pre_tool_use"),
        },
        {
            "name": "post_tool_use",
            "ok": (plugin_dir / "hooks" / "post_tool_use").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/post_tool_use"),
        },
        {
            "name": "post_tool_use_failure",
            "ok": (plugin_dir / "hooks" / "post_tool_use_failure").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/post_tool_use_failure"),
        },
        {
            "name": "subagent_start",
            "ok": (plugin_dir / "hooks" / "subagent_start").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/subagent_start"),
        },
        {
            "name": "subagent_stop",
            "ok": (plugin_dir / "hooks" / "subagent_stop").is_file(),
            "detail": _claude_code_plugin_detail("file", "hooks/subagent_stop"),
        },
    ]


def _validate_claude_code_plugin_dir(plugin_dir: Path) -> None:
    failed = [
        check for check in _claude_code_plugin_checks(plugin_dir) if not check["ok"]
    ]
    if failed:
        details = ", ".join(str(item["detail"]) for item in failed)
        raise FileNotFoundError(f"Claude Code plugin is incomplete: {details}")


def _protect_claude_code_plugin_incomplete_response(
    failed_checks: list[dict[str, object]],
) -> dict[str, object]:
    missing_checks = [str(check["name"]) for check in failed_checks]
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "claude_code_plugin_incomplete",
        "condition": "claude_code_plugin_incomplete",
        "message": "Claude Code plugin directory is missing or incomplete.",
        "detail": "Missing Claude Code plugin checks: " + ", ".join(missing_checks),
        "missing_checks": missing_checks,
        "next_steps": [
            {
                "action": "check_plugin",
                "command": "ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>",
                "detail": "Verify the local Claude Code plugin files before configuring protection.",
            },
            {
                "action": "rerun_protect",
                "command": "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>",
                "detail": "After the plugin path is corrected, rerun protection for the project folder.",
            },
        ],
    }


_CLAUDE_CODE_REQUIRED_HOOK_EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
)


def _claude_code_plugin_json_object_check(
    path: Path, check_name: str, label: str
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    try:
        raw = path.read_text("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, {
            "name": check_name,
            "detail": f"{label} could not be read as UTF-8 JSON ({exc.__class__.__name__}).",
        }
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, {
            "name": check_name,
            "detail": f"{label} contains invalid JSON at line {exc.lineno}, column {exc.colno}.",
        }
    if not isinstance(parsed, dict):
        return None, {
            "name": check_name,
            "detail": f"{label} must be a JSON object.",
        }
    return parsed, None


def _claude_code_hooks_manifest_valid(hooks_manifest: dict[str, object]) -> bool:
    hooks = hooks_manifest.get("hooks")
    if not isinstance(hooks, dict):
        return False
    for event_name in _CLAUDE_CODE_REQUIRED_HOOK_EVENTS:
        event_entries = hooks.get(event_name)
        if not isinstance(event_entries, list) or not event_entries:
            return False
        for event_entry in event_entries:
            if not isinstance(event_entry, dict):
                return False
            command_hooks = event_entry.get("hooks")
            if not isinstance(command_hooks, list) or not command_hooks:
                return False
            has_command_hook = False
            for command_hook in command_hooks:
                if not isinstance(command_hook, dict):
                    return False
                if (
                    command_hook.get("type") == "command"
                    and isinstance(command_hook.get("command"), str)
                    and command_hook["command"].strip()
                ):
                    has_command_hook = True
            if not has_command_hook:
                return False
    return True


def _claude_code_plugin_content_checks(plugin_dir: Path) -> list[dict[str, object]]:
    failures: list[dict[str, object]] = []
    manifest, manifest_failure = _claude_code_plugin_json_object_check(
        plugin_dir / ".claude-plugin" / "plugin.json",
        "plugin_manifest",
        "Claude Code plugin manifest",
    )
    if manifest_failure:
        failures.append(manifest_failure)
    elif manifest is not None:
        missing_manifest_fields: list[str] = []
        for field_name in ("name", "version"):
            field_value = manifest.get(field_name)
            if not isinstance(field_value, str) or not field_value.strip():
                missing_manifest_fields.append(field_name)
        if missing_manifest_fields:
            failures.append(
                {
                    "name": "plugin_manifest",
                    "detail": "Claude Code plugin manifest is missing non-empty fields: "
                    + ", ".join(missing_manifest_fields)
                    + ".",
                }
            )

    hooks_manifest, hooks_failure = _claude_code_plugin_json_object_check(
        plugin_dir / "hooks" / "hooks.json",
        "plugin_hooks",
        "Claude Code hooks manifest",
    )
    if hooks_failure:
        failures.append(hooks_failure)
    elif hooks_manifest is not None and not _claude_code_hooks_manifest_valid(
        hooks_manifest
    ):
        failures.append(
            {
                "name": "plugin_hooks",
                "detail": (
                    "Claude Code hooks manifest must define command hooks for "
                    + ", ".join(_CLAUDE_CODE_REQUIRED_HOOK_EVENTS)
                    + "."
                ),
            }
        )
    return failures


def _protect_claude_code_plugin_invalid_response(
    failed_checks: list[dict[str, object]],
) -> dict[str, object]:
    invalid_checks = [str(check["name"]) for check in failed_checks]
    details = [
        str(check.get("detail", "")).strip()
        for check in failed_checks
        if str(check.get("detail", "")).strip()
    ]
    detail = "Invalid Claude Code plugin checks: " + ", ".join(invalid_checks)
    if details:
        detail += ". " + " ".join(details)
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "claude_code_plugin_invalid",
        "condition": "claude_code_plugin_invalid",
        "message": "Claude Code plugin content is invalid.",
        "detail": detail,
        "invalid_checks": invalid_checks,
        "next_steps": [
            {
                "action": "validate_plugin",
                "command": "claude plugin validate <claude-code-plugin>",
                "detail": "Validate the local Claude Code plugin manifest and hook schema before configuring protection.",
            },
            {
                "action": "rerun_protect",
                "command": "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>",
                "detail": "After the plugin content is corrected, rerun protection for the project folder.",
            },
        ],
    }


class _ProtectPolicyInputError(ValueError):
    def __init__(self, option: str, condition: str, detail: str) -> None:
        super().__init__(detail)
        self.option = option
        self.condition = condition
        self.detail = detail


def _protect_policy_input_placeholder(option: str) -> str:
    return {
        "--forbid-rules": "<forbid-rules.json>",
        "--cedar-policy": "<policy.cedar>",
        "--cedar-entities": "<cedar-entities.json>",
    }.get(option, "<policy-input-file>")


def _protect_policy_input_next_steps(
    option: str, condition: str
) -> list[dict[str, str]]:
    placeholder = _protect_policy_input_placeholder(option)
    steps: list[dict[str, str]] = []
    is_empty = condition.endswith("_empty")
    if is_empty:
        steps.append(
            {
                "condition": condition,
                "action": "provide_policy_path",
                "command": f"ardur protect claude-code {option} {placeholder}",
                "detail": f"Replace {placeholder} with an explicit, non-empty path to a local policy input file.",
            }
        )
    elif option in {"--forbid-rules", "--cedar-entities"}:
        steps.append(
            {
                "condition": condition,
                "action": "validate_policy_json",
                "command": f"python -m json.tool {placeholder}",
                "detail": "Validate the local policy JSON file before rerunning Claude Code protection.",
            }
        )
    else:
        steps.append(
            {
                "condition": condition,
                "action": "check_policy_file",
                "command": f"test -r {placeholder}",
                "detail": "Confirm the local policy file exists and is readable before rerunning protection.",
            }
        )

    if option == "--forbid-rules":
        rerun_suffix = "--forbid-rules <forbid-rules.json>"
    elif option == "--cedar-entities":
        rerun_suffix = (
            "--cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>"
        )
    else:
        rerun_suffix = "--cedar-policy <policy.cedar>"
    steps.append(
        {
            "condition": condition,
            "action": "rerun_protect",
            "command": (
                "ardur protect claude-code --scope <your-project> --home <ardur-home> "
                f"--plugin-dir <claude-code-plugin> {rerun_suffix}"
            ),
            "detail": "Rerun protection after the local policy input file is present, readable, and valid.",
        }
    )
    return steps


def _protect_policy_input_failure_response(
    exc: _ProtectPolicyInputError,
) -> dict[str, object]:
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_policy_input_invalid",
        "condition": exc.condition,
        "message": "Policy input file could not be loaded.",
        "detail": exc.detail,
        "policy_input": exc.option,
        "next_steps": _protect_policy_input_next_steps(exc.option, exc.condition),
    }


def _read_protect_policy_text(path: Path, option: str) -> str:
    try:
        return path.expanduser().read_text("utf-8")
    except FileNotFoundError as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_missing",
            f"Could not load {option}: the file was not found.",
        ) from exc
    except (PermissionError, IsADirectoryError, OSError, UnicodeDecodeError) as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_unreadable",
            f"Could not load {option}: reading the file failed with {exc.__class__.__name__}.",
        ) from exc


def _validate_protect_cedar_policy_syntax(
    policy_src: str, option: str = "--cedar-policy"
) -> None:
    try:
        import cedarpy  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency-gated install
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_validator_unavailable",
            "Could not load --cedar-policy: Cedar syntax validator is unavailable.",
        ) from exc

    try:
        # Use Cedar's policy serializer as a quiet syntax parser. The
        # authorization API can emit parse diagnostics directly to stdout for
        # malformed policies, which would corrupt `--json` output before this
        # setup-time failure response is printed.
        cedarpy.policies_to_json_str(policy_src)
    except ValueError as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            "Could not load --cedar-policy: invalid Cedar policy syntax.",
        ) from exc


def _validate_protect_cedar_entities(
    entities: object, option: str = "--cedar-entities"
) -> None:
    try:
        import cedarpy  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency-gated install
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_validator_unavailable",
            "Could not load --cedar-entities: Cedar entities validator is unavailable.",
        ) from exc

    if not isinstance(entities, (list, str)):
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            "Could not load --cedar-entities: invalid Cedar entities content.",
        )

    request = {
        "principal": 'User::"ardur-setup-validator"',
        "action": 'Action::"validate"',
        "resource": 'Resource::"ardur-setup"',
        "context": {},
    }
    try:
        # `is_authorized` is the cedarpy surface that parses entity payloads.
        # Keep this setup-time parser probe quiet so malformed local files
        # cannot corrupt `--json` output with validator diagnostics.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = cedarpy.is_authorized(
                request=request,
                policies="permit(principal, action, resource);\n",
                entities=entities,
            )
    except Exception as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            "Could not load --cedar-entities: invalid Cedar entities content.",
        ) from exc
    diagnostics = getattr(result, "diagnostics", None)
    errors = list(getattr(diagnostics, "errors", []) or []) if diagnostics else []
    if errors:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            "Could not load --cedar-entities: invalid Cedar entities content.",
        )


def _read_protect_policy_json(path: Path, option: str) -> object:
    text = _read_protect_policy_text(path, option)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            f"Could not load {option}: invalid JSON at line {exc.lineno}, column {exc.colno}.",
        ) from exc


def _write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
    finally:
        if fd != -1:
            os.close(fd)


def _claude_code_doctor_next_steps(
    checks: list[dict[str, object]],
) -> list[dict[str, str]]:
    by_name = {str(check["name"]): check for check in checks}
    steps: list[dict[str, str]] = []
    plugin_check_names = [
        "plugin_dir",
        "plugin_manifest",
        "plugin_hooks",
        "pre_tool_use",
        "post_tool_use",
        "subagent_start",
        "subagent_stop",
    ]
    missing_plugin_checks = [
        name for name in plugin_check_names if not bool(by_name.get(name, {}).get("ok"))
    ]
    if missing_plugin_checks:
        steps.append(
            {
                "check": "plugin_files",
                "action": "repair_plugin_path",
                "command": (
                    "ardur doctor-claude-code --plugin-dir "
                    f"{_CLAUDE_CODE_PLUGIN_PLACEHOLDER} --home {_ARDUR_HOME_PLACEHOLDER}"
                ),
                "detail": "Missing Claude Code plugin checks: "
                + ", ".join(missing_plugin_checks),
            }
        )

    claude_check = by_name.get("claude_binary", {})
    if not bool(claude_check.get("ok")):
        steps.append(
            {
                "check": "claude_binary",
                "action": "install_claude_code",
                "command": "claude --version",
                "detail": "Install Claude Code CLI and ensure `claude` is on PATH, then rerun doctor.",
            }
        )

    active_passport_check = by_name.get("active_passport", {})
    if not bool(active_passport_check.get("ok")):
        steps.append(
            {
                "check": "active_passport",
                "action": "run_protect_claude_code",
                "command": (
                    "ardur protect claude-code --scope "
                    f"{_PROJECT_PLACEHOLDER} --home {_ARDUR_HOME_PLACEHOLDER} "
                    f"--plugin-dir {_CLAUDE_CODE_PLUGIN_PLACEHOLDER}"
                ),
                "detail": "Create an active Mission Passport for the local Claude Code plugin.",
            }
        )

    plugin_validate_check = by_name.get("plugin_validate", {})
    if (
        not bool(plugin_validate_check.get("ok"))
        and not missing_plugin_checks
        and bool(claude_check.get("ok"))
    ):
        steps.append(
            {
                "check": "plugin_validate",
                "action": "validate_plugin",
                "command": f"claude plugin validate {_CLAUDE_CODE_PLUGIN_PLACEHOLDER}",
                "detail": str(
                    plugin_validate_check.get("detail")
                    or "Claude Code plugin validation failed; inspect the validation output."
                ),
            }
        )
    return steps


def claude_code_doctor(
    plugin_dir: Path | None = None, home: Path | None = None
) -> dict[str, object]:
    plugin = (plugin_dir or _default_claude_plugin_dir()).expanduser().resolve()
    plugin_checks = _claude_code_plugin_checks(plugin)
    checks = list(plugin_checks)
    claude_binary = shutil.which("claude")
    checks.append(
        {
            "name": "claude_binary",
            "ok": bool(claude_binary),
            "detail": "claude found on PATH"
            if claude_binary
            else "claude not found on PATH",
        }
    )
    active_passport = (
        home.expanduser() if home else DEFAULT_HOME
    ) / "active_mission.jwt"
    checks.append(
        {
            "name": "active_passport",
            "ok": active_passport.is_file(),
            "detail": f"expected file at {_ARDUR_HOME_PLACEHOLDER}/active_mission.jwt",
        }
    )
    if claude_binary and all(check["ok"] for check in plugin_checks):
        result = subprocess.run(
            [claude_binary, "plugin", "validate", str(plugin)],
            capture_output=True,
            text=True,
        )
        checks.append(
            {
                "name": "plugin_validate",
                "ok": result.returncode == 0,
                "detail": _claude_code_plugin_validation_detail(
                    result.stdout.strip() or result.stderr.strip(),
                    plugin=plugin,
                    home=active_passport.parent,
                ),
            }
        )
    else:
        checks.append(
            {
                "name": "plugin_validate",
                "ok": False,
                "detail": "skipped; missing claude binary or plugin files",
            }
        )
    ok = all(bool(check["ok"]) for check in checks)
    return {
        "ok": ok,
        "checks": checks,
        "next_steps": [] if ok else _claude_code_doctor_next_steps(checks),
    }


def _resolve_protect_policies(
    args: argparse.Namespace,
    profile: ArdurProfile | None,
    home: Path,
) -> list[dict[str, object]]:
    """Build additional_policies from CLI flags + profile."""
    policies: list[dict[str, object]] = []

    def forbid_rules_sha256(rules: object) -> str:
        canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # Reject empty/whitespace-only policy path arguments before Path()
    # normalises them to the current working directory. ``type=str`` on the
    # parser keeps the raw value so an empty/whitespace input can be detected
    # here instead of silently resolving to ``PosixPath('.')`` and producing a
    # confusing downstream file-read error (or, for ``--cedar-entities``,
    # silently succeeding because the handler only reads it inside the
    # ``--cedar-policy`` block).
    forbid_rules_raw = getattr(args, "forbid_rules", None)
    cedar_policy_raw = getattr(args, "cedar_policy", None)
    cedar_entities_raw = getattr(args, "cedar_entities", None)
    if forbid_rules_raw is not None and not str(forbid_rules_raw).strip():
        raise _ProtectPolicyInputError(
            "--forbid-rules",
            "protect_forbid_rules_empty",
            "The --forbid-rules argument is empty or whitespace-only.",
        )
    if cedar_policy_raw is not None and not str(cedar_policy_raw).strip():
        raise _ProtectPolicyInputError(
            "--cedar-policy",
            "protect_cedar_policy_empty",
            "The --cedar-policy argument is empty or whitespace-only.",
        )
    if cedar_entities_raw is not None and not str(cedar_entities_raw).strip():
        raise _ProtectPolicyInputError(
            "--cedar-entities",
            "protect_cedar_entities_empty",
            "Could not load --cedar-entities: path must not be empty or whitespace-only.",
        )

    # CLI flags (highest priority)
    if forbid_rules_raw is not None:
        rules = _read_protect_policy_json(Path(forbid_rules_raw), "--forbid-rules")
        if not isinstance(rules, list):
            rules = [rules]
        policies.append(
            {
                "backend": "forbid_rules",
                "label": "cli-forbid-rules",
                "policy_inline": "",
                "policy_sha256": forbid_rules_sha256(rules),
                "data_inline": rules,
            }
        )
    if cedar_policy_raw is not None:
        policy_src = _read_protect_policy_text(Path(cedar_policy_raw), "--cedar-policy")
        _validate_protect_cedar_policy_syntax(policy_src)
        entities: object = []
        if cedar_entities_raw is not None:
            entities = _read_protect_policy_json(
                Path(cedar_entities_raw), "--cedar-entities"
            )
            _validate_protect_cedar_entities(entities)
        policies.append(
            {
                "backend": "cedar",
                "label": "cli-cedar-policy",
                "policy_inline": policy_src,
                "policy_sha256": hashlib.sha256(policy_src.encode()).hexdigest(),
                "data_inline": entities,
            }
        )

    # Profile policies
    if profile and profile.forbid_rules:
        policies.append(
            {
                "backend": "forbid_rules",
                "label": "profile-forbid-rules",
                "policy_inline": "",
                "policy_sha256": forbid_rules_sha256(profile.forbid_rules),
                "data_inline": profile.forbid_rules,
            }
        )
    if profile and profile.cedar_policy:
        policies.append(
            {
                "backend": "cedar",
                "label": "profile-cedar-policy",
                "policy_inline": profile.cedar_policy,
                "policy_sha256": hashlib.sha256(
                    profile.cedar_policy.encode()
                ).hexdigest(),
                "data_inline": [],
            }
        )

    return policies


def _protect_claude_code_missing_scope_response(
    profile_present: bool,
) -> dict[str, object]:
    profile_detail = (
        "The selected profile does not define `Protect folder:`."
        if profile_present
        else "No `--scope` was provided and no profile with `Protect folder:` was selected."
    )
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "missing_scope",
        "condition": "missing_scope",
        "message": "ardur protect claude-code requires --scope or a profile with `Protect folder:`.",
        "next_steps": [
            {
                "action": "pass_scope",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Choose the local project folder Claude Code is allowed to work in.",
            },
            {
                "action": "create_profile",
                "command": "ardur profile init --template safe-coding --path ARDUR.md",
                "detail": "Create an editable profile that includes a `Protect folder:` line.",
            },
            {
                "action": "use_profile",
                "command": "ardur protect claude-code --profile ARDUR.md",
                "detail": "Run protection from the profile after setting `Protect folder:`.",
            },
        ],
        "detail": profile_detail,
    }


def _protect_claude_code_scope_invalid_response() -> dict[str, object]:
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_scope_invalid",
        "condition": "protect_scope_invalid",
        "message": "ardur protect claude-code --scope must be a non-empty path after trimming whitespace and must not be a dangling symlink or an existing regular file.",
        "detail": (
            "An empty, whitespace-only, dangling-symlink, or regular-file "
            "--scope was provided.  Pass an explicit project folder, or use "
            "`.` to protect the current working directory."
        ),
        "next_steps": [
            {
                "action": "pass_scope",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Choose the local project folder Claude Code is allowed to work in.",
            },
            {
                "action": "use_cwd",
                "command": "ardur protect claude-code --scope .",
                "detail": "Use `.` explicitly to protect the current working directory.",
            },
            {
                "action": "create_profile",
                "command": "ardur profile init --template safe-coding --path ARDUR.md",
                "detail": "Create an editable profile that includes a `Protect folder:` line.",
            },
        ],
    }


def _protect_claude_code_identity_invalid_response(condition: str) -> dict[str, object]:
    """Structured response for empty/whitespace ``--agent-id`` or ``--mission``.

    Mirrors the ``protect_scope_invalid`` shape so all ``protect claude-code``
    fail-closed branches share the same envelope. ``next_steps`` use
    placeholder-only commands and details with no local paths or tokens.
    """
    if condition == "protect_agent_id_invalid":
        message = "ardur protect claude-code --agent-id must be a non-empty string after trimming whitespace."
        detail = (
            "An empty or whitespace-only --agent-id was provided. The Mission "
            "Passport subject must be a non-empty identifier after trimming "
            "whitespace; omit the flag to use the default subject."
        )
        next_steps = [
            {
                "action": "pass_agent_id",
                "command": "ardur protect claude-code --scope <your-project> --agent-id <agent-id>",
                "detail": "Provide a non-empty agent subject identifier after trimming whitespace.",
            },
            {
                "action": "omit_agent_id",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --agent-id to use the default subject.",
            },
        ]
    else:  # protect_mission_invalid
        message = "ardur protect claude-code --mission must be a non-empty string after trimming whitespace."
        detail = (
            "An explicitly-provided --mission was empty or whitespace-only. "
            "Pass a non-empty mission string, or omit the flag to use the "
            "selected mode's default mission."
        )
        next_steps = [
            {
                "action": "pass_mission",
                "command": "ardur protect claude-code --scope <your-project> --mission <mission>",
                "detail": "Provide a non-empty mission string after trimming whitespace.",
            },
            {
                "action": "omit_mission",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --mission to use the selected mode's default mission.",
            },
        ]
    return {
        "ok": False,
        "agent": "claude-code",
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": next_steps,
    }


def _protect_claude_code_home_invalid_response() -> dict[str, object]:
    """Structured response for empty/whitespace-only, dangling-symlink, or regular-file ``--home``.

    Mirrors the ``protect_scope_invalid`` / ``protect_agent_id_invalid`` shape
    so all ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local paths
    or tokens. Placed before any ``home.mkdir`` / ``generate_keypair`` /
    ``issue_passport`` / artifact write so no Ardur state is created for an
    invalid home value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_home_invalid",
        "error_code": "protect_home_invalid",
        "condition": "protect_home_invalid",
        "message": "ardur protect claude-code --home must be a non-empty path after trimming whitespace and must not be a dangling symlink or an existing regular file.",
        "detail": (
            "An empty, whitespace-only, dangling-symlink, or regular-file "
            "--home was provided. Pass an explicit Ardur home directory, or "
            "omit --home to use the default home. Empty strings, "
            "whitespace-only values, and unquoted empty environment "
            "variables resolve to the current working directory and are "
            "rejected. A dangling symlink (a symlink whose target does not "
            "exist) looks like it points somewhere but resolves to a "
            "non-existent directory; Ardur would generate real signing "
            "keys and write active_mission.jwt against a directory that "
            "does not exist."
        ),
        "next_steps": [
            {
                "action": "pass_home",
                "command": "ardur protect claude-code --home <ardur-home> --scope <your-project>",
                "detail": "Provide a non-empty Ardur home directory after trimming whitespace.",
            },
            {
                "action": "omit_home",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --home to use the default Ardur home directory.",
            },
            {
                "action": "explicit_cwd",
                "command": "ardur protect claude-code --home . --scope <your-project>",
                "detail": "Use `.` explicitly to place Ardur state in the current working directory.",
            },
        ],
    }


def _protect_claude_code_home_parent_dangling_symlink_response() -> dict[str, object]:
    """Structured response when a PARENT component of ``--home`` is a dangling
    symlink.

    Distinct from ``protect_home_invalid`` (which covers the LEAF) so that
    operators searching logs for parent-path-confusion can grep for the
    specific ``home_dangling_symlink_parent`` condition. Fires for inputs
    like ``--home <dangling-symlink>/child`` where the leaf ``child`` is a
    plain nonexistent path: the existing leaf checks pass, but
    ``Path(...).resolve()`` would follow the symlink and
    ``home.mkdir(parents=True)`` would silently materialise the missing
    target. ``next_steps`` use placeholder-only commands and details with no
    local paths or tokens. Placed before any ``home.mkdir`` /
    ``generate_keypair`` / ``issue_passport`` / artifact write so no Ardur
    state is created for an invalid home value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": HOME_DANGLING_SYMLINK_PARENT_CONDITION,
        "error_code": HOME_DANGLING_SYMLINK_PARENT_CONDITION,
        "condition": HOME_DANGLING_SYMLINK_PARENT_CONDITION,
        "message": (
            "ardur protect claude-code --home path has a parent component "
            "that is a dangling symlink."
        ),
        "detail": (
            "A parent directory in the supplied --home path is a dangling "
            "symlink (a symlink whose target does not exist). Without this "
            "check Ardur resolves the symlink chain, materialises the missing "
            "target, and writes the Ed25519 private key, active_mission.jwt, "
            "state, governance log, and plugin config at a location you did "
            "not type. Remove the dangling symlink or repoint it at a real "
            "directory before retrying."
        ),
        "next_steps": [
            {
                "action": "remove_or_fix_dangling_symlink_parent",
                "command": "ardur protect claude-code --home <ardur-home> --scope <your-project>",
                "detail": (
                    "Remove the dangling symlink in the parent chain or point "
                    "it at a real directory, then retry."
                ),
            },
            {
                "action": "omit_home",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --home to use the default Ardur home directory.",
            },
        ],
    }


def _protect_claude_code_home_parent_not_directory_response() -> dict[str, object]:
    """Structured response when a PARENT component of ``--home`` is an existing
    non-directory (regular file, socket, etc.).

    Distinct from ``protect_home_invalid`` (which covers the LEAF) so that
    operators searching logs for parent-path-confusion can grep for the
    specific ``home_parent_not_directory`` condition. Fires for inputs like
    ``--home <regular-file>/child``: the existing leaf checks pass because
    ``child`` is a plain nonexistent path, but ``home.mkdir(parents=True)``
    would raise ``FileNotFoundError`` / ``NotADirectoryError``. Placed before
    any ``home.mkdir`` / ``generate_keypair`` / ``issue_passport`` /
    artifact write so no Ardur state is created for an invalid home value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": HOME_PARENT_NOT_DIRECTORY_CONDITION,
        "error_code": HOME_PARENT_NOT_DIRECTORY_CONDITION,
        "condition": HOME_PARENT_NOT_DIRECTORY_CONDITION,
        "message": (
            "ardur protect claude-code --home path has a parent component "
            "that is an existing non-directory."
        ),
        "detail": (
            "A parent directory in the supplied --home path already exists "
            "as a regular file or other non-directory. Ardur cannot create "
            "the home tree (keys, active_mission.jwt, state, governance log, "
            "plugin config) inside a file. Move the file aside or choose a "
            "different parent directory before retrying."
        ),
        "next_steps": [
            {
                "action": "move_aside_or_choose_directory_parent",
                "command": "ardur protect claude-code --home <ardur-home> --scope <your-project>",
                "detail": (
                    "Move the existing file in the parent chain aside or "
                    "choose a different parent directory, then retry."
                ),
            },
            {
                "action": "omit_home",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --home to use the default Ardur home directory.",
            },
        ],
    }


def _protect_claude_code_keys_dir_invalid_response() -> dict[str, object]:
    """Structured response for empty/whitespace-only, dangling-symlink, or regular-file ``--keys-dir``.

    Mirrors the ``protect_home_invalid`` / ``protect_scope_invalid`` shape so all
    ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local paths
    or tokens. Placed before any ``mkdir`` / ``generate_keypair`` /
    ``issue_passport`` / artifact write so no Ardur state is created for an
    invalid keys-dir value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_keys_dir_invalid",
        "error_code": "protect_keys_dir_invalid",
        "condition": "protect_keys_dir_invalid",
        "message": "ardur protect claude-code --keys-dir must be a non-empty path after trimming whitespace and must not be a dangling symlink or an existing regular file.",
        "detail": (
            "An empty, whitespace-only, dangling-symlink, or regular-file "
            "--keys-dir was provided. Pass an explicit signing keys "
            "directory, or omit --keys-dir to use the default keys "
            "directory under the Ardur home. Empty strings, "
            "whitespace-only values, and unquoted empty environment "
            "variables resolve to the current working directory and are "
            "rejected, because they silently create real signing keys in "
            "unintended locations. An existing regular file cannot serve "
            "as a signing keys directory and is rejected before any key "
            "generation. A dangling symlink (a symlink whose target does "
            "not exist) looks like it points somewhere but resolves to a "
            "non-existent directory; Ardur would generate real signing "
            "keys against a directory that does not exist."
        ),
        "next_steps": [
            {
                "action": "pass_keys_dir",
                "command": "ardur protect claude-code --keys-dir <keys-dir> --scope <your-project>",
                "detail": "Provide a non-empty signing keys directory after trimming whitespace.",
            },
            {
                "action": "omit_keys_dir",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --keys-dir to use the default keys directory under the Ardur home.",
            },
            {
                "action": "explicit_cwd",
                "command": "ardur protect claude-code --keys-dir . --scope <your-project>",
                "detail": "Use `.` explicitly to place signing keys in the current working directory.",
            },
        ],
    }


def _protect_claude_code_profile_invalid_response() -> dict[str, object]:
    """Structured response for empty/whitespace/directory ``--profile``.

    Mirrors the ``protect_scope_invalid`` / ``protect_home_invalid`` shape
    so all ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local paths
    or tokens. Placed before any ``load_ardur_profile`` / ``generate_keypair`` /
    ``issue_passport`` / artifact write so no Ardur state is created for an
    invalid profile value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_profile_invalid",
        "condition": "protect_profile_invalid",
        "message": "ardur protect claude-code --profile must be a non-empty path to a Markdown file after trimming whitespace.",
        "detail": (
            "An empty, whitespace-only, or directory --profile was provided. "
            "Pass an explicit path to an ARDUR.md profile file, or omit "
            "--profile to use the selected mode's defaults."
        ),
        "next_steps": [
            {
                "action": "create_profile",
                "command": "ardur profile init --template safe-coding --path <profile-file>",
                "detail": "Create an editable profile before using --profile.",
            },
            {
                "action": "use_profile",
                "command": "ardur protect claude-code --profile <profile-file>",
                "detail": "Rerun protection with the profile file after it exists.",
            },
            {
                "action": "omit_profile",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Or configure protection directly for a project folder without a profile.",
            },
        ],
    }


def _protect_claude_code_missing_profile_response() -> dict[str, object]:
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "profile_missing",
        "condition": "profile_missing",
        "message": "Ardur profile file could not be loaded.",
        "detail": "The supplied --profile file was not found.",
        "next_steps": [
            {
                "action": "create_profile",
                "command": "ardur profile init --template safe-coding --path <profile-file>",
                "detail": "Create an editable profile before using --profile.",
            },
            {
                "action": "use_profile",
                "command": "ardur protect claude-code --profile <profile-file>",
                "detail": "Rerun protection with the profile file after it exists.",
            },
            {
                "action": "pass_scope",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Or configure protection directly for a project folder without a profile.",
            },
        ],
    }


def _protect_claude_code_budget_invalid_response() -> dict[str, object]:
    """Structured response for negative ``--max-tool-calls``.

    Mirrors the ``protect_scope_invalid`` / ``protect_home_invalid`` shape
    so all ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local paths
    or tokens. Placed before any ``generate_keypair`` / ``issue_passport`` /
    artifact write so no Ardur state is created for an invalid budget value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_budget_max_tool_calls_invalid",
        "condition": "protect_budget_max_tool_calls_invalid",
        "message": "ardur protect claude-code --max-tool-calls must be zero or a positive integer.",
        "detail": (
            "A negative --max-tool-calls value was provided. Pass zero or a "
            "positive integer, or omit --max-tool-calls to use the default "
            "of 250."
        ),
        "next_steps": [
            {
                "action": "pass_valid_budget",
                "command": "ardur protect claude-code --scope <your-project> --max-tool-calls <non-negative-integer>",
                "detail": "Provide a non-negative integer for --max-tool-calls.",
            },
            {
                "action": "omit_budget",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --max-tool-calls to use the default of 250.",
            },
        ],
    }


def _protect_claude_code_max_duration_invalid_response() -> dict[str, object]:
    """Structured response for non-positive ``--max-duration-s``.

    Mirrors the ``protect_budget_max_tool_calls_invalid`` shape so all
    ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local
    paths or tokens. Placed before any ``generate_keypair`` /
    ``issue_passport`` / artifact write so no Ardur state is created for an
    invalid budget value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_budget_max_duration_invalid",
        "condition": "protect_budget_max_duration_invalid",
        "message": "ardur protect claude-code --max-duration-s must be a positive integer number of seconds.",
        "detail": (
            "A non-positive --max-duration-s value was provided. Pass a "
            "positive integer, or omit --max-duration-s to use the default "
            "of 86400 (24 hours)."
        ),
        "next_steps": [
            {
                "action": "pass_valid_budget",
                "command": "ardur protect claude-code --scope <your-project> --max-duration-s <positive-integer>",
                "detail": "Provide a positive integer for --max-duration-s.",
            },
            {
                "action": "omit_budget",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --max-duration-s to use the default of 86400 (24 hours).",
            },
        ],
    }


def _protect_claude_code_ttl_invalid_response() -> dict[str, object]:
    """Structured response for non-positive ``--ttl-s``.

    Mirrors the ``protect_budget_max_tool_calls_invalid`` shape so all
    ``protect claude-code`` fail-closed branches share the same envelope.
    ``next_steps`` use placeholder-only commands and details with no local
    paths or tokens. Placed before any ``generate_keypair`` /
    ``issue_passport`` / artifact write so no Ardur state is created for an
    invalid TTL value.
    """
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_budget_ttl_invalid",
        "condition": "protect_budget_ttl_invalid",
        "message": "ardur protect claude-code --ttl-s must be a positive integer number of seconds.",
        "detail": (
            "A non-positive --ttl-s value was provided. Pass a positive "
            "integer, or omit --ttl-s to use the --max-duration-s value "
            "as the token TTL."
        ),
        "next_steps": [
            {
                "action": "pass_valid_ttl",
                "command": "ardur protect claude-code --scope <your-project> --ttl-s <positive-integer>",
                "detail": "Provide a positive integer for --ttl-s.",
            },
            {
                "action": "omit_ttl",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit --ttl-s to use the --max-duration-s value as the token TTL.",
            },
        ],
    }


def _protect_claude_code_child_policy_invalid_response(
    code: str,
    *,
    conflict: str | None = None,
) -> dict[str, object]:
    detail = (
        conflict
        or "The child policy registry failed strict private-file or schema validation."
    )
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_child_policy_invalid",
        "error_code": code,
        "condition": "protect_child_policy_invalid",
        "message": "Claude Code child delegation was not configured.",
        "detail": detail,
        "next_steps": [
            {
                "action": "fix_child_policy_registry",
                "command": "chmod 600 <child-policy-file>",
                "detail": (
                    "Use a private regular JSON file with schema_version "
                    "ardur.claude_code.child_policies.v1."
                ),
            },
            {
                "action": "rerun_protection",
                "command": (
                    "ardur protect claude-code --scope <your-project> "
                    "--child-policy-file <child-policy-file>"
                ),
                "detail": (
                    "Validate the registry before issuing a delegation-enabled passport."
                ),
            },
            {
                "action": "disable_child_delegation",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Omit the registry to keep child delegation disabled.",
            },
        ],
    }


def protect_claude_code(args: argparse.Namespace) -> dict[str, object]:
    # Reject empty/whitespace-only --profile before any key generation or
    # profile loading. ``--profile`` is ``type=str`` so an empty or
    # whitespace-only value survives here as-is (previously ``type=Path``
    # normalized ``\"\"`` to ``PosixPath('.')`` which silently resolved to the
    # CWD and caused ``load_ardur_profile`` to ``read_text()`` on a directory,
    # producing an ``IsADirectoryError`` traceback). An explicit ``--profile .``
    # (CWD) is also a directory and must be rejected. Omitting ``--profile``
    # entirely keeps ``args.profile=None`` and is acceptable.
    if isinstance(args.profile, str):
        stripped = args.profile.strip()
        if not stripped:
            return _protect_claude_code_profile_invalid_response()
        profile_path = Path(stripped).expanduser()
        if profile_path.is_dir():
            return _protect_claude_code_profile_invalid_response()
    try:
        profile = load_ardur_profile(args.profile) if args.profile else None
    except (FileNotFoundError, IsADirectoryError):
        return _protect_claude_code_missing_profile_response()
    mode_name = _normalize_protect_mode(
        args.mode or (profile.mode if profile and profile.mode else "safe-coding")
    )
    if mode_name not in CLAUDE_CODE_PROTECT_MODES:
        raise ValueError(f"unsupported Claude Code protection mode: {mode_name}")
    mode = CLAUDE_CODE_PROTECT_MODES[mode_name]
    raw_scope = args.scope
    if raw_scope is None and profile and profile.scope:
        profile_scope = Path(profile.scope).expanduser()
        if profile_scope.is_absolute():
            raw_scope = profile_scope
        else:
            raw_scope = Path(args.profile).expanduser().parent / profile_scope
    if raw_scope is None:
        return _protect_claude_code_missing_scope_response(
            profile_present=bool(args.profile)
        )
    # Reject empty/whitespace-only --scope before any key generation or directory
    # creation. ``args.scope`` is ``type=str`` so an empty or whitespace-only
    # value survives here as-is (previously ``type=Path`` normalized ``""`` to
    # ``PosixPath('.')`` which silently resolved to the CWD and created real
    # signing keys for the wrong directory).
    if isinstance(raw_scope, str) and not raw_scope.strip():
        return _protect_claude_code_scope_invalid_response()
    # Reject --scope pointing to an existing regular file OR a dangling
    # symlink before any key generation or directory creation.  A regular
    # file cannot serve as a project folder and would silently succeed with
    # the old type=Path behaviour.  A dangling symlink (a symlink whose
    # target does not exist) looks like it points somewhere but resolves to
    # a non-existent directory; ``Path.exists()`` returns False for it so
    # the regular-file branch alone is insufficient.  Without this check
    # Ardur resolves the scope to the missing target, generates real signing
    # keys, writes ``active_mission.jwt``, and configures protection against
    # a directory that does not exist.  Non-symlink nonexistent paths and
    # real directories pass through.
    scope_path = Path(raw_scope).expanduser()
    if scope_path.is_symlink() and not scope_path.exists():
        return _protect_claude_code_scope_invalid_response()
    if scope_path.exists() and scope_path.is_file():
        return _protect_claude_code_scope_invalid_response()
    # Reject --scope whose parent chain crosses a dangling symlink or an
    # existing non-directory, before any key generation, JWT issuance, or
    # plugin/hook artifact creation.  Mirrors the ``--home`` and
    # ``--keys-dir`` parent-component walks from ad96e40 and f167304.  A
    # dangling parent symlink is invisible to the leaf-only checks above:
    # ``Path(<dangling>/scope)`` is not itself a symlink, and
    # ``Path.resolve()`` follows the symlink chain to the missing target
    # before the check can see it.  Without this walk Ardur silently
    # resolves the scope through the dangling parent, bakes the resolved
    # path into the JWT ``resource_scope``, and configures protection for
    # a directory that does not exist.  Non-symlink nonexistent parents
    # and real directory parents pass through.
    for parent in scope_path.parents:
        if parent.is_symlink() and not parent.exists():
            return _protect_claude_code_scope_invalid_response()
        if parent.exists() and not parent.is_dir():
            return _protect_claude_code_scope_invalid_response()
    # Reject empty/whitespace-only --agent-id and explicitly-provided
    # empty/whitespace-only --mission before any key generation, Mission
    # Passport JWT issuance, or plugin/hook artifact creation. ``--agent-id``
    # has an argparse default (``local-user:claude-code``) so only an
    # explicitly-passed empty/whitespace string reaches here. ``--mission``
    # defaults to ``None``; reject any explicitly-provided empty or
    # whitespace-only string so that ``--mission ""`` cannot silently create
    # an active mission with keys.
    if isinstance(args.agent_id, str) and not args.agent_id.strip():
        return _protect_claude_code_identity_invalid_response(
            "protect_agent_id_invalid"
        )
    if isinstance(args.mission, str) and not args.mission.strip():
        return _protect_claude_code_identity_invalid_response("protect_mission_invalid")
    # Reject empty/whitespace-only --home before any directory creation or key
    # generation. ``--home`` is ``type=str`` so an empty or whitespace-only
    # value survives here as-is (previously ``type=Path`` normalized ``""`` to
    # ``PosixPath('.')`` which silently resolved to the CWD and created real
    # signing keys + active_mission.jwt in the working directory). An explicit
    # ``--home .`` (CWD) must remain valid, so only reject when the trimmed
    # string is empty. Omitting ``--home`` entirely keeps ``args.home=None``
    # which falls through to ``DEFAULT_HOME`` and is acceptable.
    if isinstance(args.home, str) and not args.home.strip():
        return _protect_claude_code_home_invalid_response()
    # Reject --home pointing to an existing regular file OR a dangling
    # symlink before any key generation or directory creation.  A regular
    # file cannot serve as an Ardur home directory and would traceback with
    # FileExistsError at home.mkdir().  A dangling symlink (a symlink whose
    # target does not exist) looks like it points somewhere but resolves to
    # a non-existent directory; ``Path.exists()`` returns False for it so
    # the regular-file branch alone is insufficient.  Without this check
    # Ardur resolves the home to the missing target, generates real signing
    # keys, writes ``active_mission.jwt``, and configures protection against
    # a directory that does not exist.  Non-symlink nonexistent paths and
    # real directories pass through.
    if args.home:
        home_path = Path(args.home).expanduser()
        if home_path.is_symlink() and not home_path.exists():
            return _protect_claude_code_home_invalid_response()
        if home_path.exists() and home_path.is_file():
            return _protect_claude_code_home_invalid_response()
        # Walk every PARENT component of the un-resolved --home path and
        # reject if any parent is a dangling symlink or an existing
        # non-directory. Without this, ``--home <dangling-symlink>/child``
        # passes the leaf checks above (``child`` is neither a symlink nor a
        # file), ``Path(...).resolve()`` follows the symlink, and
        # ``home.mkdir(parents=True, exist_ok=True)`` silently materialises
        # the missing target — writing the Ed25519 private key,
        # active_mission.jwt, and plugin config at a location the operator
        # did not type. The shared validator raises a HubError carrying the
        # structured-response condition; we translate it into the
        # ``protect claude-code`` envelope so every fail-closed branch on
        # this command shares one response shape.
        try:
            validate_personal_home_path_components(args.home)
        except HubError as exc:
            if exc.code == HOME_DANGLING_SYMLINK_PARENT_CONDITION:
                return _protect_claude_code_home_parent_dangling_symlink_response()
            if exc.code == HOME_PARENT_NOT_DIRECTORY_CONDITION:
                return _protect_claude_code_home_parent_not_directory_response()
            raise
    # Reject empty/whitespace-only --keys-dir before any directory creation or
    # key generation. ``--keys-dir`` is ``type=str`` so an empty or
    # whitespace-only value survives here as-is (previously ``type=Path``
    # normalized ``""`` to ``PosixPath('.')`` which silently resolved to the
    # CWD and created real signing keys there). An explicit ``--keys-dir .``
    # (CWD) must remain valid, so only reject when the trimmed string is
    # empty. Omitting ``--keys-dir`` entirely keeps ``args.keys_dir=None`` and
    # the handler falls back to ``<home>/keys``.
    if isinstance(args.keys_dir, str) and not args.keys_dir.strip():
        return _protect_claude_code_keys_dir_invalid_response()
    # Reject --keys-dir pointing to an existing regular file OR a dangling
    # symlink before any key generation.  A regular file cannot serve as a
    # signing keys directory and would traceback with KeyDirectoryError at
    # generate_keypair().  A dangling symlink (a symlink whose target does
    # not exist) looks like it points somewhere but resolves to a
    # non-existent directory; ``Path.exists()`` returns False for it so the
    # regular-file branch alone is insufficient.  Without this check Ardur
    # resolves the keys-dir to the missing target and proceeds with key
    # generation against a directory that does not exist.  Non-symlink
    # nonexistent paths and real directories pass through.
    if args.keys_dir:
        keys_dir_path = Path(args.keys_dir).expanduser()
        if keys_dir_path.is_symlink() and not keys_dir_path.exists():
            return _protect_claude_code_keys_dir_invalid_response()
        if keys_dir_path.exists() and keys_dir_path.is_file():
            return _protect_claude_code_keys_dir_invalid_response()
        # Reject --keys-dir whose parent chain crosses a dangling symlink or
        # an existing non-directory, before any key generation or mkdir.
        # Mirrors the ``--home`` parent-component walk from ad96e40.  A
        # dangling parent symlink (e.g. ``--keys-dir <dangling>/keys``) is
        # invisible to the leaf-only checks above: ``Path(<dangling>/keys)``
        # is not itself a symlink, and ``Path.resolve()`` follows the symlink
        # chain to the missing target before the check can see it.  Without
        # this walk Ardur silently materialises the missing target via
        # ``mkdir(parents=True)`` inside ``resolve_keys_dir()`` and writes the
        # Ed25519 private key (``passport_private.pem``) at a location the
        # user did not type.  Non-symlink nonexistent parents and real
        # directory parents pass through.
        for parent in keys_dir_path.parents:
            if parent.is_symlink() and not parent.exists():
                return _protect_claude_code_keys_dir_invalid_response()
            if parent.exists() and not parent.is_dir():
                return _protect_claude_code_keys_dir_invalid_response()
    # Reject negative --max-tool-calls before any key generation or directory
    # creation. ``--max-tool-calls`` is ``type=int`` with a default of 250,
    # so only an explicitly-passed negative value reaches here. A negative
    # budget would silently produce a Mission Passport with a negative
    # max_tool_calls claim, which is semantically invalid.
    if args.max_tool_calls < 0:
        return _protect_claude_code_budget_invalid_response()
    # Reject non-positive --max-duration-s before any key generation or
    # directory creation. ``--max-duration-s`` is ``type=int`` with a default
    # of 86400, so only an explicitly-passed non-positive value reaches here.
    # A non-positive budget would silently produce a Mission Passport with a
    # non-positive max_duration_s claim, which is semantically invalid.
    if args.max_duration_s <= 0:
        return _protect_claude_code_max_duration_invalid_response()
    # Reject non-positive --ttl-s before any key generation or directory
    # creation. ``--ttl-s`` is ``type=int`` with a default of None, so only
    # an explicitly-passed non-positive value reaches here. A non-positive TTL
    # would traceback with ``ValueError: ttl_s must be positive`` from
    # ``issue_passport()`` after keys are already generated.
    if args.ttl_s is not None and args.ttl_s <= 0:
        return _protect_claude_code_ttl_invalid_response()
    raw_child_policy = getattr(args, "child_policy_file", None)
    if isinstance(raw_child_policy, str) and not raw_child_policy.strip():
        return _protect_claude_code_child_policy_invalid_response(
            "CHILD_POLICY_UNAVAILABLE"
        )
    child_policy_path: Path | None = None
    child_policies: dict[str, Any] = {}
    if raw_child_policy is not None:
        from .claude_code_children import (
            ClaudeChildBindingError,
            load_claude_child_policy_registry,
        )

        child_policy_input = Path(raw_child_policy).expanduser()
        try:
            child_policies = load_claude_child_policy_registry(child_policy_input)
        except ClaudeChildBindingError as exc:
            return _protect_claude_code_child_policy_invalid_response(exc.code)
        child_policy_path = child_policy_input.resolve()
    scope = Path(raw_scope).expanduser().resolve()
    home = Path(args.home).expanduser().resolve() if args.home else DEFAULT_HOME
    if args.home:
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        _ensure_default_home_dir()
    plugin_dir = Path(args.plugin_dir).expanduser().resolve()
    failed_plugin_checks = [
        check for check in _claude_code_plugin_checks(plugin_dir) if not check["ok"]
    ]
    if failed_plugin_checks:
        return _protect_claude_code_plugin_incomplete_response(failed_plugin_checks)
    invalid_plugin_checks = _claude_code_plugin_content_checks(plugin_dir)
    if invalid_plugin_checks:
        return _protect_claude_code_plugin_invalid_response(invalid_plugin_checks)
    # Validate policy input files before issuing keys/tokens so setup failures
    # remain local, structured, and free of unnecessary generated artifacts.
    try:
        additional_policies = _resolve_protect_policies(args, profile, home)
    except _ProtectPolicyInputError as exc:
        return _protect_policy_input_failure_response(exc)
    if profile and profile.allowed_tools:
        # A profile with an explicit allowlist is authoritative: if the author
        # leaves the blocklist empty, that means "no explicit tool denylist" and
        # should not silently inherit the mode's default denies. The built-in
        # templates still include their blocklists explicitly.
        allowed_tools = list(profile.allowed_tools)
        forbidden_tools = list(profile.forbidden_tools)
    else:
        allowed_tools = list(mode["allowed_tools"])
        forbidden_tools = list(
            profile.forbidden_tools
            if profile and profile.forbidden_tools
            else mode["forbidden_tools"]
        )
    max_tool_calls = (
        profile.max_tool_calls
        if profile and profile.max_tool_calls is not None
        else args.max_tool_calls
    )
    max_duration_s = (
        profile.max_duration_s
        if profile and profile.max_duration_s is not None
        else args.max_duration_s
    )
    if child_policies:
        if "Agent" in forbidden_tools:
            return _protect_claude_code_child_policy_invalid_response(
                "CHILD_POLICY_CONFLICT",
                conflict=(
                    "The selected profile forbids Agent while a child policy registry "
                    "requests child delegation. Remove that conflict or omit the registry."
                ),
            )
        if "*" not in allowed_tools and "Agent" not in allowed_tools:
            allowed_tools.append("Agent")
        largest_child_budget = max(
            int(policy.max_tool_calls) for policy in child_policies.values()
        )
        if max_tool_calls <= largest_child_budget:
            return _protect_claude_code_child_policy_invalid_response(
                "CHILD_BUDGET_DENIED",
                conflict=(
                    "The parent max-tool-calls budget must exceed every configured "
                    "child budget so the Agent dispatch also fits."
                ),
            )
    keys_dir_resolved = (
        Path(args.keys_dir).expanduser().resolve() if args.keys_dir else (home / "keys")
    )
    private_key, public_key = generate_keypair(keys_dir=keys_dir_resolved)
    mission = MissionPassport(
        agent_id=args.agent_id,
        mission=args.mission
        or (profile.mission if profile and profile.mission else mode["mission"]),
        allowed_tools=allowed_tools,
        forbidden_tools=forbidden_tools,
        resource_scope=[str(scope), f"{scope}/*"],
        cwd=str(scope),
        max_tool_calls=max_tool_calls,
        max_duration_s=max_duration_s,
        delegation_allowed=bool(child_policies),
        max_delegation_depth=1 if child_policies else 0,
        additional_policies=additional_policies,
    )
    token = issue_passport(mission, private_key, ttl_s=args.ttl_s or max_duration_s)
    claims = verify_passport(token, public_key)
    # Seed additional policies (Cedar / forbid_rules) into the persistent
    # store so the proxy picks them up at session-start time. Policies are
    # resolved from CLI flags first, then from the profile.
    if additional_policies:
        from vibap.backed_policy_store import FileBackedPolicyStore

        store = FileBackedPolicyStore(home)
        store.put_policies(
            mission_id=str(
                claims.get("mission_id")
                or mission.mission_id
                or derive_mission_id(mission.agent_id, mission.mission)
            ),
            policies=additional_policies,
        )
    active_passport = home / "active_mission.jwt"
    _write_private_text(active_passport, token + "\n")
    hook_python = home / "claude-code-hook-python"
    _write_private_text(hook_python, sys.executable + "\n")
    native_pre_hook_command = install_native_pre_tool_use_command(home=home)
    native_pre_hook_command_expected = resolve_native_pre_tool_use_command_path(home)
    run_environment = f"VIBAP_HOME={shlex.quote(str(home))}"
    if child_policy_path is not None:
        run_environment += (
            f" ARDUR_CC_CHILD_POLICY_FILE={shlex.quote(str(child_policy_path))}"
        )
    run_command = (
        f"{run_environment} claude --plugin-dir {shlex.quote(str(plugin_dir))}"
    )
    return {
        "ok": True,
        "agent": "claude-code",
        "mode": mode_name,
        "profile": str(Path(args.profile).expanduser()) if args.profile else None,
        "scope": str(scope),
        "home": str(home),
        "active_passport": str(active_passport),
        # Matrix-compatible alias for real-world test harnesses and docs that
        # describe this artifact as an active Mission path. Keep the original
        # ``active_passport`` key for existing callers.
        "active_mission_path": str(active_passport),
        "hook_python": str(hook_python),
        "native_pre_hook_command": str(native_pre_hook_command)
        if native_pre_hook_command
        else None,
        "native_pre_hook_command_expected": str(native_pre_hook_command_expected),
        "plugin_dir": str(plugin_dir),
        "child_policy_file": str(child_policy_path) if child_policy_path else None,
        "child_agent_types": sorted(child_policies),
        "run_command": run_command,
        "allowed_tools": allowed_tools,
        "forbidden_tools": forbidden_tools,
        "claims": claims,
    }


def cmd_protect_claude_code(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    result = protect_claude_code(args)
    ok = bool(result.get("ok"))
    if args.json or getattr(args, "output", None) is not None:
        return _handle_output_and_redact(
            args,
            result,
            command="protect_claude_code",
            exit_code=0 if ok else 1,
        )
    if not ok:
        print("Ardur Claude Code protection was not configured.")
        message = result.get("message")
        if message:
            print(str(message))
        detail = result.get("detail")
        if detail:
            print(str(detail))
        _print_report_next_steps(result)
        return 1
    print("Ardur Claude Code protection configured.")
    print(f"mode: {result['mode']}")
    print(f"scope: {result['scope']}")
    print(f"active passport: {result['active_passport']}")
    print(f"run: {result['run_command']}")
    return 0


def _profile_init_existing_profile_response() -> dict[str, object]:
    return {
        "ok": False,
        "error": "profile_exists",
        "condition": "profile_exists",
        "message": "ardur profile init will not overwrite an existing profile without --force.",
        "detail": "Use --force only if you want to replace the current profile, or use the existing profile with protect claude-code.",
        "next_steps": [
            {
                "action": "replace_profile",
                "command": "ardur profile init --path ARDUR.md --force",
                "detail": "Replace the local profile only if you intend to overwrite your current guardrails.",
            },
            {
                "action": "use_existing_profile",
                "command": "ardur protect claude-code --profile ARDUR.md",
                "detail": "Use the existing editable profile when configuring Claude Code protection.",
            },
        ],
    }


def _profile_init_path_invalid_response(
    exc: InvalidProfilePathError,
) -> dict[str, object]:
    condition = "profile_path_invalid"
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Profile path is not a valid Markdown file path.",
        "detail": str(exc),
        "next_steps": [
            {
                "action": "choose_profile_file",
                "command": "ardur profile init --path <profile-file>",
                "detail": (
                    "Use a non-empty Markdown file path with no leading or trailing "
                    "whitespace and no '..' traversal components."
                ),
            },
            {
                "action": "use_profile_file",
                "command": "ardur protect claude-code --profile <profile-file>",
                "detail": "Use the created editable profile when configuring Claude Code protection.",
            },
        ],
    }


def _profile_init_path_failure_response(exc: OSError) -> dict[str, object]:
    if isinstance(exc, IsADirectoryError):
        condition = "profile_path_invalid"
        detail = "The supplied --path points to a directory; choose a Markdown file path such as ARDUR.md."
    else:
        condition = "profile_path_unwritable"
        detail = f"Writing the supplied --path failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Profile path is not a writable Markdown file.",
        "detail": detail,
        "next_steps": [
            {
                "action": "choose_profile_file",
                "command": "ardur profile init --path <profile-file> --force",
                "detail": "Use a writable Markdown file path, not a directory or protected location.",
            },
            {
                "action": "use_profile_file",
                "command": "ardur protect claude-code --profile <profile-file>",
                "detail": "Use the created editable profile when configuring Claude Code protection.",
            },
        ],
    }


def cmd_profile_init(args: argparse.Namespace) -> int:
    path_failure = _path_arg_invalid_failure(args)
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    try:
        path = write_profile_template(
            args.path, template=args.template, force=args.force
        )
    except InvalidProfilePathError as exc:
        result = _profile_init_path_invalid_response(exc)
        if args.json:
            _print_json(result)
        else:
            print("Ardur profile was not created.")
            print(str(result["message"]))
            print(str(result["detail"]))
            _print_report_next_steps(result)
        return 1
    except FileExistsError:
        result = _profile_init_existing_profile_response()
        if args.json:
            _print_json(result)
        else:
            print("Ardur profile was not created.")
            print(str(result["message"]))
            print(str(result["detail"]))
            _print_report_next_steps(result)
        return 1
    except (IsADirectoryError, PermissionError, OSError) as exc:
        result = _profile_init_path_failure_response(exc)
        if args.json:
            _print_json(result)
        else:
            print("Ardur profile was not created.")
            print(str(result["message"]))
            print(str(result["detail"]))
            _print_report_next_steps(result)
        return 1
    result = {
        "ok": True,
        "template": args.template,
        "path": str(path),
        "next_step": f"ardur protect claude-code --profile {path}",
    }
    if args.json:
        _print_json(result)
    else:
        print(f"Created {path}")
        print(result["next_step"])
    return 0


def cmd_doctor_claude_code(args: argparse.Namespace) -> int:
    # Reject empty/whitespace-only --home and --plugin-dir before any
    # diagnostic check. Both args are ``type=str`` so an empty or
    # whitespace-only value survives here as-is (previously ``type=Path``
    # normalized ``""`` to ``PosixPath('.')`` which silently resolved to the
    # CWD and produced misleading diagnostics with corrupted path fragments).
    # An explicit ``--home .`` (CWD) must remain valid, so only reject when the
    # trimmed string is empty. Omitting ``--home`` keeps ``args.home=None``;
    # omitting ``--plugin-dir`` keeps the stringified default plugin dir.
    path_failure = _coerce_report_path_args(
        args,
        command_name="doctor-claude-code",
        command_title="Claude Code doctor",
        specs=(
            ("home", "--home", "home", "doctor_claude_code_home_empty", False),
            (
                "plugin_dir",
                "--plugin-dir",
                "plugin directory",
                "doctor_claude_code_plugin_dir_empty",
                False,
            ),
        ),
    )
    if path_failure is not None:
        _print_json(path_failure)
        return 1
    response = claude_code_doctor(plugin_dir=args.plugin_dir, home=args.home)
    return _handle_output_and_redact(
        args,
        response,
        command="doctor_claude_code",
        exit_code=0 if response.get("ok") else 1,
    )


def _latency_gate_value_failure(
    *,
    condition: str,
    message: str,
    detail: str,
) -> dict[str, object]:
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": [
            {
                "condition": condition,
                "action": "rerun_latency_gate_evaluate",
                "command": (
                    "ardur latency-gate evaluate --reports <reports-dir> "
                    "[--threshold-ms N] [--min-runs N] [--percentile 95] "
                    "[--format json|text]"
                ),
                "detail": (
                    "Provide a directory of latency report JSON files and "
                    "valid positive numeric thresholds. Keep raw local paths "
                    "and tokens out of shared logs."
                ),
            }
        ],
    }


def cmd_latency_gate_evaluate(args: argparse.Namespace) -> int:
    """Load latency reports, run the gate, and print the decision."""

    # ``--reports`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-
    # only values survive parsing and can be rejected explicitly below.
    # ``type=Path`` normalizes ``""`` to ``PosixPath('.')`` (the CWD) which
    # silently masks the empty-argument defect. Same pitfall pattern as
    # --home/--plugin-dir/--keys-dir in other commands.
    reports_value = getattr(args, "reports", None)
    if not isinstance(reports_value, str) or not reports_value.strip():
        failure = _latency_gate_value_failure(
            condition="latency_gate_reports_empty",
            message="latency-gate evaluate --reports must be a non-empty path after trimming whitespace.",
            detail=(
                "The --reports argument is empty or whitespace-only. "
                "Pass an explicit directory of latency report JSON files."
            ),
        )
        _print_json(failure)
        return 1

    threshold_ms = float(args.threshold_ms)
    if not math.isfinite(threshold_ms) or threshold_ms <= 0:
        failure = _latency_gate_value_failure(
            condition="latency_gate_threshold_ms_invalid",
            message="latency-gate evaluate --threshold-ms must be finite and > 0.",
            detail=(
                f"--threshold-ms must be a positive finite number; got {args.threshold_ms!r}."
            ),
        )
        _print_json(failure)
        return 1

    min_runs = int(args.min_runs)
    if min_runs < 1:
        failure = _latency_gate_value_failure(
            condition="latency_gate_min_runs_invalid",
            message="latency-gate evaluate --min-runs must be >= 1.",
            detail=(f"--min-runs must be a positive integer; got {args.min_runs!r}."),
        )
        _print_json(failure)
        return 1

    percentile = int(args.percentile)
    if not (1 <= percentile <= 100):
        failure = _latency_gate_value_failure(
            condition="latency_gate_percentile_invalid",
            message="latency-gate evaluate --percentile must be in 1..100 inclusive.",
            detail=(
                f"--percentile must be an integer from 1 to 100; got {args.percentile!r}."
            ),
        )
        _print_json(failure)
        return 1

    report_dir = Path(reports_value)
    if not report_dir.exists():
        failure = _latency_gate_value_failure(
            condition="latency_gate_reports_dir_not_found",
            message="latency-gate evaluate --reports directory does not exist.",
            detail=(
                "The --reports path does not exist on disk. "
                "Point --reports at a directory of latency report JSON files."
            ),
        )
        _print_json(failure)
        return 1
    if not report_dir.is_dir():
        failure = _latency_gate_value_failure(
            condition="latency_gate_reports_not_directory",
            message="latency-gate evaluate --reports path is not a directory.",
            detail=(
                "The --reports path exists but is not a directory. "
                "Point --reports at a directory of latency report JSON files."
            ),
        )
        _print_json(failure)
        return 1

    try:
        valid_reports, invalid_reports = load_reports_from_directory(report_dir)
    except LatencyGateCliError as exc:
        failure = _latency_gate_value_failure(
            condition="latency_gate_load_failed",
            message=str(exc),
            detail="Report loading failed before the evaluator could run.",
        )
        _print_json(failure)
        return 1

    try:
        protocol = GateProtocol(
            min_independent_runs=min_runs,
            threshold_ms=threshold_ms,
            percentile=percentile,
        )
        decision = run_gate(valid_reports, protocol)
    except (LatencyGateError, LatencyGateCliError) as exc:
        failure = _latency_gate_value_failure(
            condition="latency_gate_protocol_invalid",
            message=str(exc),
            detail="Gate protocol construction or evaluation failed.",
        )
        _print_json(failure)
        return 1

    output_format = args.format
    try:
        rendered = format_gate_output(decision, output_format)
    except LatencyGateCliError as exc:
        failure = _latency_gate_value_failure(
            condition="latency_gate_output_format_invalid",
            message=str(exc),
            detail="Output formatting failed.",
        )
        _print_json(failure)
        return 1

    # Emit a structured top-level envelope so CI can branch on ``ok`` and
    # ``verdict`` without parsing the decision body. The ``decision`` body
    # is the canonical gate output; ``invalid_files`` surfaces loader-level
    # rejections separately so reviewers can see why individual files were
    # dropped without re-scanning the directory.
    if output_format == "json":
        import json as _json

        body = _json.loads(rendered)
        envelope = {
            "ok": True,
            "verdict": decision.verdict,
            "decision": body,
            "invalid_files": invalid_reports,
        }
        # Determine exit code from verdict (0=pass, 1=fail, 2=inconclusive)
        # BEFORE calling _handle_output_and_redact so the file write path
        # preserves the verdict-based exit code.
        if decision.verdict == "pass":
            verdict_exit = 0
        elif decision.verdict == "fail":
            verdict_exit = 1
        else:
            verdict_exit = 2
        return _handle_output_and_redact(
            args, envelope, command="latency_gate_evaluate", exit_code=verdict_exit
        )
    else:
        sys.stdout.write(rendered)
        if invalid_reports:
            sys.stdout.write("\nInvalid report files (not evaluated):\n")
            for entry in invalid_reports:
                sys.stdout.write(f"  {entry['filename']}: {entry['reason']}\n")

    # Exit code: 0 for PASS, 1 for FAIL, 2 for INCONCLUSIVE. This lets CI
    # distinguish "passed the gate" from "failed the gate" from "could not
    # decide" without parsing JSON. All three are successful tool runs (the
    # gate ran correctly); only the verdict differs.
    if decision.verdict == "pass":
        return 0
    if decision.verdict == "fail":
        return 1
    return 2


class _JsonAwareArgumentParser(argparse.ArgumentParser):
    """Argparse parser that honours the ``--json`` contract on argparse errors.

    When ``--json`` is present anywhere in the raw argv, argparse-level
    errors (missing required arguments, ambiguous options, etc.) emit a
    structured JSON payload to stderr instead of the human-readable usage
    block, so JSON consumers always receive machine-readable output.

    Non-JSON behaviour is byte-identical to ``argparse.ArgumentParser``:
    usage text to stderr and ``SystemExit(2)``.

    The ``--json`` flag is detected from the argv passed to ``parse_args``
    (or ``sys.argv`` when none is supplied). Subparsers inherit this class
    automatically via argparse's ``parser_class`` default of ``type(self)``,
    so a missing required argument on any subcommand (for example
    ``ardur evidence correlate --json`` without ``--source-format``) is
    routed through the same JSON path.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        # argparse routes every parse error through ``error()``. Reconstruct
        # the argv actually being parsed (argv passed to ``parse_args`` when
        # provided, otherwise the live ``sys.argv``), so the detection works
        # under both interactive invocation and programmatic ``main(argv)``.
        raw_argv = getattr(self, "_raw_argv", None)
        if raw_argv is None:
            raw_argv = sys.argv[1:]
        if "--json" in raw_argv:
            payload = {
                "ok": False,
                "error": "argument_error",
                "error_code": "argument_error",
                "condition": "argument_error",
                "message": message,
            }
            sys.stderr.write(json.dumps(payload, indent=2) + "\n")
            raise SystemExit(1)
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonAwareArgumentParser(
        prog="ardur",
        description="Ardur governance proxy and mission-passport tooling",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="start the VIBAP proxy HTTP service")
    start.add_argument("--host", default="127.0.0.1", help="bind address")
    start.add_argument("--port", type=int, default=8080, help="listen port")
    start.add_argument(
        "--mission",
        type=str,
        help="optional mission JSON to issue and start immediately",
    )
    start.add_argument(
        "--keys-dir", type=str, help="directory containing VIBAP signing keys"
    )
    start.add_argument("--state-dir", type=str, help="directory for persisted sessions")
    start.add_argument("--log-path", type=str, help="JSONL audit log path")
    start.add_argument(
        "--spiffe-endpoint-socket",
        default=os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
        help=(
            "SPIFFE Workload API socket used to fetch this proxy's SVID; "
            "defaults to SPIFFE_ENDPOINT_SOCKET and is disabled when unset"
        ),
    )
    start.add_argument(
        "--biscuit-peer-trust-bundle",
        default=os.environ.get("ARDUR_BISCUIT_PEER_TRUST_BUNDLE"),
        help=(
            "JSON JWT-SVID trust bundle for Biscuit peer verification; "
            "defaults to ARDUR_BISCUIT_PEER_TRUST_BUNDLE"
        ),
    )
    start.add_argument(
        "--biscuit-peer-trust-domain",
        default=os.environ.get("ARDUR_BISCUIT_PEER_TRUST_DOMAIN"),
        help=(
            "trust domain for a raw SPIRE bundle; defaults to "
            "ARDUR_BISCUIT_PEER_TRUST_DOMAIN"
        ),
    )
    start.add_argument(
        "--biscuit-issuer-public-key",
        default=os.environ.get("ARDUR_BISCUIT_ISSUER_PUBLIC_KEY"),
        help=(
            "PEM Biscuit issuer public key paired with the peer trust bundle; "
            "defaults to ARDUR_BISCUIT_ISSUER_PUBLIC_KEY"
        ),
    )
    start.add_argument(
        "--biscuit-svid-audience",
        default=os.environ.get("ARDUR_BISCUIT_SVID_AUDIENCE", "ardur-proxy"),
        help=(
            "expected peer JWT-SVID audience; defaults to "
            "ARDUR_BISCUIT_SVID_AUDIENCE or ardur-proxy"
        ),
    )
    start.add_argument(
        "--api-token",
        help="Bearer token for clients; VIBAP_API_TOKEN still takes precedence",
    )
    start.add_argument("--tls-cert", type=str, help="TLS certificate PEM file")
    start.add_argument("--tls-key", type=str, help="TLS private key PEM file")
    start.add_argument(
        "--no-tls", action="store_true", help="disable TLS (plain HTTP only)"
    )
    auth_group = start.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--require-auth",
        dest="require_auth",
        action="store_true",
        help="require Bearer token on all endpoints except /health and /healthz (default)",
    )
    auth_group.add_argument(
        "--no-require-auth",
        dest="require_auth",
        action="store_false",
        help="DISABLE Bearer auth — DO NOT USE IN PRODUCTION",
    )
    start.set_defaults(func=cmd_start, require_auth=True)

    issue = subparsers.add_parser("issue", help="issue a mission passport JWT")
    issue.add_argument("--agent-id", required=True, help="agent subject identifier")
    issue.add_argument("--mission", required=True, help="declared mission string")
    issue.add_argument(
        "--allowed-tools", nargs="*", default=[], help="allowed tool names"
    )
    issue.add_argument(
        "--forbidden-tools", nargs="*", default=[], help="forbidden tool names"
    )
    issue.add_argument(
        "--resource-scope",
        nargs="*",
        default=[],
        help="resource patterns; empty grants none, sole '**' explicitly grants all",
    )
    issue.add_argument("--max-tool-calls", default=50, help="max permitted tool calls")
    issue.add_argument(
        "--max-duration-s", default=600, help="max mission duration in seconds"
    )
    issue.add_argument(
        "--delegation-allowed", action="store_true", help="allow one-step delegation"
    )
    issue.add_argument(
        "--max-delegation-depth", default=0, help="delegation depth budget"
    )
    issue.add_argument("--ttl-s", help="override token TTL in seconds")
    issue.add_argument(
        "--keys-dir", type=str, help="directory containing VIBAP signing keys"
    )
    issue.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    issue.add_argument(
        "--output",
        type=str,
        help="atomically write the JSON response to an owner-only file",
    )
    issue.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    issue.set_defaults(func=cmd_issue)

    verify = subparsers.add_parser(
        "verify",
        help="verify an offline receipt journal, mission passport, behavioral attestation, receipt anchor, or receiver attestation",
    )
    verify.add_argument(
        "journal",
        nargs="?",
        type=str,
        help="offline full-evidence bundle, or receipt JSONL with --chain-only",
    )
    verify_input = verify.add_mutually_exclusive_group(required=False)
    verify_input.add_argument("--token", help="passport token to verify")
    verify_input.add_argument(
        "--attestation-token",
        type=str,
        help="behavioral attestation JWT to verify",
    )
    verify_input.add_argument(
        "--anchor-bundle",
        type=str,
        help="portable receipt transparency-anchor JSON bundle",
    )
    verify_input.add_argument(
        "--receiver-envelope",
        type=str,
        help="portable receiver-attestation receipt envelope",
    )
    verify.add_argument(
        "--keys-dir", type=str, help="directory containing VIBAP signing keys"
    )
    verify.add_argument(
        "--receipt-public-key",
        type=str,
        help="trusted receipt-issuer ES256 public key PEM for offline journal verification",
    )
    verify.add_argument(
        "--transparency-log-key",
        type=str,
        help="trusted transparency-log public key PEM for offline anchor verification",
    )
    verify.add_argument(
        "--receiver-public-key",
        type=str,
        help="trusted receiver ES256 public key PEM for offline co-signature verification",
    )
    verify.add_argument(
        "--mcp-request",
        type=str,
        help="optional exact MCP tools/call request JSON for digest comparison",
    )
    verify.add_argument(
        "--mcp-response",
        type=str,
        help="optional exact MCP tools/call response JSON for digest comparison",
    )
    verify.add_argument(
        "--max-registration-delay-s",
        type=int,
        default=86_400,
        help="maximum allowed delay between receipt iat and log integration",
    )
    verify.add_argument(
        "--max-attestation-delay-s",
        type=int,
        default=300,
        help="maximum allowed delay between receipt and receiver co-signature",
    )
    verify.add_argument(
        "--receiver-clock-skew-s",
        type=int,
        default=60,
        help="allowed receiver clock skew relative to the receipt",
    )
    verify.add_argument(
        "--max-bundle-age-s",
        type=int,
        help="reject a bundle whose latest signed receipt is older than this many seconds",
    )
    verify.add_argument(
        "--freshness-clock-skew-s",
        type=int,
        help="allowed future clock skew for --max-bundle-age-s (default: 60)",
    )
    verify.add_argument(
        "--chain-only",
        action="store_true",
        help="explicitly verify receipt signatures and chain only, without external sidecars",
    )
    verify.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows during archival verification",
    )
    verify.add_argument(
        "--json", action="store_true", help="print a machine-readable explorer report"
    )
    verify.add_argument(
        "--html-report",
        type=str,
        help="write a private static HTML explorer report",
    )
    verify.add_argument(
        "--output",
        type=str,
        help="atomically write the JSON explorer report to an owner-only file",
    )
    verify.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    verify.add_argument(
        "--unsafe-show-sensitive",
        action="store_true",
        help="disable default report redaction for explicit local inspection",
    )
    verify.set_defaults(func=cmd_verify)

    evidence = subparsers.add_parser(
        "evidence",
        help="correlate verified receipts with imported runtime evidence",
    )
    evidence_subparsers = evidence.add_subparsers(
        dest="evidence_command", required=True
    )
    evidence_correlate = evidence_subparsers.add_parser(
        "correlate",
        help="verify a receipt journal and emit a redacted correlation report",
    )
    evidence_correlate.add_argument(
        "journal",
        type=str,
        help="signed receipt JSONL journal to verify before correlation",
    )
    evidence_correlate.add_argument(
        "evidence_events",
        metavar="EVENTS",
        type=str,
        help="normalized, Tetragon, or Falco JSONL evidence input",
    )
    evidence_correlate.add_argument(
        "--source-format",
        choices=("normalized", "tetragon", "falco"),
        required=True,
        help="explicit adapter for the JSONL event source",
    )
    evidence_key_source = evidence_correlate.add_mutually_exclusive_group(required=True)
    evidence_key_source.add_argument(
        "--keys-dir",
        type=str,
        help="directory containing the trusted Ardur receipt issuer key",
    )
    evidence_key_source.add_argument(
        "--receipt-public-key",
        type=str,
        help="trusted receipt-issuer ES256 P-256 public key PEM",
    )
    evidence_correlate.add_argument(
        "--correlation-window-s",
        type=int,
        default=30,
        help="maximum receipt/event time difference in seconds (0..3600)",
    )
    evidence_correlate.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows during verification",
    )
    evidence_correlate.add_argument(
        "--format",
        dest="report_format",
        choices=("json", "text"),
        default="json",
        help="redacted report format (default: json)",
    )
    evidence_correlate.add_argument(
        "--output",
        dest="evidence_output",
        type=str,
        help="atomically write an owner-only report instead of printing it",
    )
    evidence_correlate.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    evidence_correlate.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output defaults to JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    evidence_correlate.set_defaults(func=cmd_evidence_correlate)

    telemetry = subparsers.add_parser(
        "telemetry",
        help="export verified governance receipts as redacted telemetry",
    )
    telemetry_subparsers = telemetry.add_subparsers(
        dest="telemetry_command", required=True
    )
    telemetry_export = telemetry_subparsers.add_parser(
        "export",
        help="verify a receipt journal and emit JSONL or OTLP/HTTP traces and logs",
    )
    telemetry_export.add_argument(
        "journal",
        type=str,
        help="signed receipt JSONL journal to verify before export",
    )
    telemetry_key_source = telemetry_export.add_mutually_exclusive_group(required=True)
    telemetry_key_source.add_argument(
        "--keys-dir",
        type=str,
        help="directory containing the trusted Ardur receipt issuer key",
    )
    telemetry_key_source.add_argument(
        "--receipt-public-key",
        type=str,
        help="trusted receipt-issuer ES256 P-256 public key PEM",
    )
    telemetry_export.add_argument(
        "--format",
        dest="export_format",
        choices=("jsonl", "otlp-json"),
        default="jsonl",
        help="local artifact format (default: jsonl)",
    )
    telemetry_export.add_argument(
        "--output",
        dest="telemetry_output",
        type=str,
        help="atomically write an owner-only local artifact instead of stdout",
    )
    telemetry_export.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    telemetry_export.add_argument(
        "--otlp-endpoint",
        help="OTLP/HTTP base URL; remote endpoints require HTTPS",
    )
    telemetry_export.add_argument(
        "--timeout-s",
        type=int,
        default=10,
        help="per-signal OTLP request timeout from 1 to 60 seconds",
    )
    telemetry_export.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows during export",
    )
    telemetry_export.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    telemetry_export.set_defaults(func=cmd_telemetry_export)

    anchor = subparsers.add_parser(
        "anchor",
        help="drain pending receipt anchors outside the governance decision path",
    )
    anchor.add_argument(
        "--receipt-log",
        type=str,
        required=True,
        help="receipt JSONL path whose sibling anchor store should be drained",
    )
    anchor.add_argument(
        "--backend",
        choices=["c2sp-local-v1", "rekor-v1"],
        required=True,
        help="transparency backend used for pending anchors",
    )
    anchor.add_argument(
        "--keys-dir", type=str, help="receipt signing keys (required by Rekor v1)"
    )
    anchor.add_argument(
        "--local-log", type=str, help="self-hosted append-only log JSONL path"
    )
    anchor.add_argument(
        "--log-private-key", type=str, help="self-hosted log Ed25519 private key PEM"
    )
    anchor.add_argument(
        "--origin", help="C2SP checkpoint origin for the self-hosted log"
    )
    anchor.add_argument(
        "--rekor-url",
        default="https://rekor.sigstore.dev",
        help="Rekor base URL (HTTPS required)",
    )
    anchor.add_argument(
        "--allow-insecure-loopback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    anchor.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    anchor.add_argument(
        "--output",
        type=str,
        help="atomically write the JSON response to an owner-only file",
    )
    anchor.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    anchor.set_defaults(func=cmd_anchor)

    receiver_fixture = subparsers.add_parser(
        "receiver-attestation-fixture",
        help="generate a synthetic MCP receiver co-signature evidence bundle",
    )
    receiver_fixture.add_argument(
        "--output",
        type=str,
        required=True,
        help="directory for public fixture artifacts; no private keys are persisted",
    )
    receiver_fixture.set_defaults(func=cmd_receiver_attestation_fixture)

    drp_fixture = subparsers.add_parser(
        "drp-profile-fixture",
        help="generate a synthetic DRP draft-10 profile implementation fixture",
    )
    drp_fixture.add_argument(
        "--output",
        type=str,
        required=True,
        help="directory for public fixture artifacts; no private keys are persisted",
    )
    drp_fixture.set_defaults(func=cmd_drp_profile_fixture)

    offline_fixture = subparsers.add_parser(
        "offline-verification-fixture",
        help="generate a synthetic full-evidence offline verification bundle",
    )
    offline_fixture.add_argument(
        "--output",
        type=str,
        required=True,
        help="directory for public fixture artifacts; no private keys are persisted",
    )
    offline_fixture.set_defaults(func=cmd_offline_verification_fixture)

    attest = subparsers.add_parser(
        "attest", help="issue a behavioral attestation for a saved session"
    )
    attest.add_argument(
        "--session", required=True, help="session identifier / passport jti"
    )
    attest.add_argument(
        "--keys-dir", type=str, help="directory containing VIBAP signing keys"
    )
    attest.add_argument(
        "--state-dir", type=str, help="directory containing persisted sessions"
    )
    attest.add_argument("--log-path", type=str, help="JSONL audit log path")
    attest.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    attest.add_argument(
        "--output",
        type=str,
        help="atomically write the JSON response to an owner-only file",
    )
    attest.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    attest.set_defaults(func=cmd_attest)

    cc_hook = subparsers.add_parser(
        "claude-code-hook",
        help="run the Claude Code hook adapter",
    )
    cc_hook.add_argument(
        "phase",
        choices=["pre", "post", "post-failure", "subagent-start", "subagent-stop"],
        help="hook lifecycle phase to invoke",
    )
    cc_hook.add_argument(
        "--keys-dir",
        type=str,
        help="signing keys directory",
    )
    cc_hook.set_defaults(func=cmd_claude_code_hook)

    cc_report = subparsers.add_parser(
        "claude-code-report",
        help="verify Claude Code hook receipt chains and summarize observability",
    )
    cc_report.add_argument(
        "--home", type=str, help="Ardur home containing claude-code-hook receipts"
    )
    cc_report.add_argument(
        "--chain-dir", type=str, help="explicit Claude Code receipt chain directory"
    )
    cc_report.add_argument("--keys-dir", type=str, help="signing public-key directory")
    cc_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    cc_report.add_argument(
        "--json", action="store_true", help="print machine-readable report"
    )
    cc_report.add_argument("--output", type=str, help="write the JSON report to a file")
    cc_report.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output with stable placeholders",
    )
    cc_report.set_defaults(func=cmd_claude_code_report)

    gemini_hook = subparsers.add_parser(
        "gemini-cli-hook",
        help="run the local-only Gemini CLI hook adapter",
    )
    gemini_hook.add_argument(
        "phase_pos", nargs="?", choices=["pre"], help="hook lifecycle phase"
    )
    gemini_hook.add_argument("--phase", choices=["pre"], help="hook lifecycle phase")
    gemini_hook.add_argument("--keys-dir", type=str, help="signing keys directory")
    gemini_hook.set_defaults(func=cmd_gemini_cli_hook)

    gemini_fixture = subparsers.add_parser(
        "gemini-cli-fixture",
        help="write a local Gemini CLI settings/context fixture and print redacted context",
    )
    gemini_fixture.add_argument(
        "--home",
        type=str,
        help="explicit Gemini home/settings directory to populate; defaults to isolated Ardur local fixture state",
    )
    gemini_fixture.add_argument(
        "--project-dir",
        type=str,
        required=True,
        help="project directory that receives GEMINI.md (required)",
    )
    gemini_fixture.add_argument(
        "--chain-dir", type=str, help="Ardur Gemini receipt chain directory"
    )
    gemini_fixture.add_argument("--keys-dir", type=str, help="signing keys directory")
    gemini_fixture.set_defaults(func=cmd_gemini_cli_fixture)

    gemini_report = subparsers.add_parser(
        "gemini-cli-report",
        help="verify Gemini CLI hook receipt chains and summarize local-only observability",
    )
    gemini_report.add_argument(
        "--home", type=str, help="Gemini/Ardur home used for redaction context"
    )
    gemini_report.add_argument(
        "--chain-dir", type=str, help="explicit Gemini CLI receipt chain directory"
    )
    gemini_report.add_argument(
        "--keys-dir", type=str, help="signing public-key directory"
    )
    gemini_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    gemini_report.add_argument(
        "--json", action="store_true", help="print machine-readable report"
    )
    gemini_report.add_argument(
        "--output", type=str, help="write the JSON report to a file"
    )
    gemini_report.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output with stable placeholders",
    )
    gemini_report.set_defaults(func=cmd_gemini_cli_report)

    codex_event = subparsers.add_parser(
        "codex-app-server-event",
        help="ingest a local Codex app-server/host-event JSON payload and emit an Ardur receipt",
    )
    codex_event.add_argument("--keys-dir", type=str, help="signing keys directory")
    codex_event.set_defaults(func=cmd_codex_app_server_event)

    codex_fixture = subparsers.add_parser(
        "codex-app-server-fixture",
        help="write a local Codex app-server config/schema fixture and print redacted context",
    )
    codex_fixture.add_argument(
        "--home",
        type=str,
        help="explicit Codex home/config directory to populate; defaults to isolated Ardur local fixture state",
    )
    codex_fixture.add_argument(
        "--project-dir",
        type=str,
        required=True,
        help="project directory that receives CODEX.md (required)",
    )
    codex_fixture.add_argument(
        "--chain-dir", type=str, help="Ardur Codex receipt chain directory"
    )
    codex_fixture.add_argument("--keys-dir", type=str, help="signing keys directory")
    codex_fixture.set_defaults(func=cmd_codex_app_server_fixture)

    codex_report = subparsers.add_parser(
        "codex-app-server-report",
        help="verify Codex app-server receipt chains and summarize local-only observability",
    )
    codex_report.add_argument(
        "--home", type=str, help="Codex/Ardur home used for redaction context"
    )
    codex_report.add_argument(
        "--chain-dir",
        type=str,
        help="explicit Codex app-server receipt chain directory",
    )
    codex_report.add_argument(
        "--keys-dir", type=str, help="signing public-key directory"
    )
    codex_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    codex_report.add_argument(
        "--json", action="store_true", help="print machine-readable report"
    )
    codex_report.add_argument(
        "--output", type=str, help="write the JSON report to a file"
    )
    codex_report.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output with stable placeholders",
    )
    codex_report.set_defaults(func=cmd_codex_app_server_report)

    posture = subparsers.add_parser(
        "posture",
        help="derive a local evidence posture index from Ardur artifacts",
    )
    posture_subparsers = posture.add_subparsers(dest="posture_command", required=True)
    posture_scan = posture_subparsers.add_parser(
        "scan",
        help="scan receipt/profile/evidence artifacts into a posture JSON document",
    )
    posture_scan.add_argument(
        "--receipts",
        type=str,
        required=True,
        help="receipt chain directory or receipts.jsonl file",
    )
    posture_scan.add_argument(
        "--keys-dir",
        type=str,
        help="directory containing passport_public.pem for read-only verification",
    )
    posture_scan.add_argument(
        "--profile", type=str, help="optional ARDUR.md profile to digest"
    )
    posture_scan.add_argument(
        "--evidence-bundle",
        type=str,
        help="optional redacted no-key evidence bundle to summarize",
    )
    posture_scan.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    posture_scan.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="output format (default: json)",
    )
    posture_scan.add_argument(
        "--output",
        dest="posture_scan_output",
        type=str,
        help="atomically write an owner-only report instead of printing it",
    )
    posture_scan.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    posture_scan.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output defaults to JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    posture_scan.set_defaults(func=cmd_posture_scan)

    posture_report = posture_subparsers.add_parser(
        "report",
        help="render a posture JSON document as a concise report",
    )
    posture_report.add_argument(
        "--input",
        type=str,
        required=True,
        help="posture JSON produced by ardur posture scan",
    )
    posture_report.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="output format (default: markdown)",
    )
    posture_report.add_argument(
        "--output",
        dest="posture_report_output",
        type=str,
        help="atomically write an owner-only report instead of printing it",
    )
    posture_report.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    posture_report.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output; equivalent to --format json "
        "(accepted for consistency with other commands)",
    )
    posture_report.set_defaults(func=cmd_posture_report)

    preflight = subparsers.add_parser(
        "preflight",
        help="statically inspect tool-server configuration before enablement",
    )
    preflight_subparsers = preflight.add_subparsers(
        dest="preflight_command", required=True
    )
    tool_server_preflight = preflight_subparsers.add_parser(
        "tool-server",
        help="scan strict JSON MCP/tool-server configuration without executing it",
    )
    tool_server_preflight.add_argument(
        "--config",
        type=str,
        required=True,
        help="strict JSON MCP client config or static tool manifest",
    )
    tool_server_preflight.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="report format (default: json)",
    )
    tool_server_preflight.add_argument(
        "--output",
        type=str,
        help="atomically write an owner-only report instead of printing it",
    )
    tool_server_preflight.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in the JSON/file output",
    )
    tool_server_preflight.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="none",
        help=(
            "return exit 2 when this severity or higher is present "
            "(default: none); also applies to config parse errors, so "
            "CI pipelines catch broken configs at the same threshold"
        ),
    )
    tool_server_preflight.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output defaults to JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    tool_server_preflight.set_defaults(func=cmd_tool_server_preflight)

    hub = subparsers.add_parser("hub", help="start the local Ardur Personal Hub")
    hub.add_argument("--host", default=DEFAULT_HUB_HOST, help="bind address")
    hub.add_argument("--port", type=int, default=DEFAULT_HUB_PORT, help="listen port")
    hub.add_argument("--home", type=str, help="Ardur Personal home directory")
    hub.add_argument(
        "--spiffe-endpoint-socket",
        default=os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
        help=(
            "SPIFFE Workload API socket used to fetch this Hub's SVID; "
            "defaults to SPIFFE_ENDPOINT_SOCKET and is disabled when unset"
        ),
    )
    hub.add_argument("--tls-cert", type=str, help="TLS certificate PEM file")
    hub.add_argument("--tls-key", type=str, help="TLS private key PEM file")
    hub.add_argument(
        "--no-tls", action="store_true", help="disable TLS (plain HTTP only)"
    )
    hub.set_defaults(func=cmd_hub)

    setup = subparsers.add_parser("setup", help="configure Ardur Personal on this Mac")
    setup.add_argument("--host", default=DEFAULT_HUB_HOST, help="Hub bind address")
    setup.add_argument("--port", default=DEFAULT_HUB_PORT, help="Hub port")
    setup.add_argument("--home", type=str, help="Ardur Personal home directory")
    setup.add_argument(
        "--rotate-token",
        action="store_true",
        help="generate a new local Hub token instead of reusing the existing install token",
    )
    setup.add_argument(
        "--extension-path",
        type=str,
        default=str(Path("examples/ardur-personal-extension")),
        help="browser extension directory to show in setup output",
    )
    setup.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    setup.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports",
    )
    setup.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the JSON response to an owner-only file "
        "instead of printing it to stdout",
    )
    setup.set_defaults(func=cmd_setup)

    status = subparsers.add_parser("status", help="show Ardur Personal Hub status")
    status.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    status.add_argument(
        "--hub-token", default=None, help="Hub bearer token (defaults to config/env)"
    )
    status.add_argument("--home", type=str, help="Ardur Personal home directory")
    status.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    status.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports",
    )
    status.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the JSON response to an owner-only file "
        "instead of printing it to stdout",
    )
    status.set_defaults(func=cmd_status)

    doctor = subparsers.add_parser("doctor", help="check local Ardur Personal setup")
    doctor.add_argument("--home", type=str, help="Ardur Personal home directory")
    doctor.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    doctor.add_argument(
        "--hub-token", default=None, help="Hub bearer token (defaults to config/env)"
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    doctor.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports",
    )
    doctor.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the JSON response to an owner-only file "
        "instead of printing it to stdout",
    )
    doctor.set_defaults(func=cmd_doctor)

    doctor_cc = subparsers.add_parser(
        "doctor-claude-code", help="check Claude Code plugin and active passport setup"
    )
    doctor_cc.add_argument(
        "--home", type=str, help="Ardur home containing active_mission.jwt"
    )
    doctor_cc.add_argument(
        "--plugin-dir",
        type=str,
        default=str(_default_claude_plugin_dir()),
        help="Claude Code plugin directory",
    )
    doctor_cc.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    doctor_cc.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports",
    )
    doctor_cc.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the JSON response to an owner-only file "
        "instead of printing it to stdout",
    )
    doctor_cc.set_defaults(func=cmd_doctor_claude_code)

    kill_switch = subparsers.add_parser(
        "kill-switch", help="activate/deactivate the emergency kill switch"
    )
    kill_switch.add_argument(
        "--deactivate", action="store_true", help="deactivate the kill switch"
    )
    kill_switch.add_argument(
        "--proxy-url",
        default=None,
        help="proxy base URL (defaults to ARDUR_PROXY_URL env or https://127.0.0.1:8443)",
    )
    kill_switch.add_argument(
        "--api-token",
        default=None,
        help="proxy bearer token (defaults to ARDUR_API_TOKEN env)",
    )
    kill_switch.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    kill_switch.set_defaults(func=cmd_kill_switch)

    uninstall = subparsers.add_parser(
        "uninstall", help="remove Ardur Personal launch files"
    )
    uninstall.add_argument("--home", type=str, help="Ardur Personal home directory")
    uninstall.add_argument(
        "--remove-data",
        action="store_true",
        help="also remove local Ardur Personal evidence and keys",
    )
    uninstall.add_argument(
        "--dry-run",
        action="store_true",
        help="preview uninstall removals without deleting launch files or local data",
    )
    uninstall.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output is always JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    uninstall.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports",
    )
    uninstall.set_defaults(func=cmd_uninstall)

    run = subparsers.add_parser(
        "run",
        help="run a command through Ardur — governed launcher (with --mission/--allowed-tools) "
        "or Ardur Personal Hub streaming (legacy)",
    )
    run.add_argument(
        "--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL (legacy hub path)"
    )
    run.add_argument(
        "--hub-token", default=None, help="Hub bearer token (defaults to config/env)"
    )
    # ``--home`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-only
    # values survive to the handler instead of being normalized to
    # ``Path('.')`` (the CWD) by argparse.  The handler rejects empty/whitespace
    # values before any ``Path()`` conversion or governance execution.
    run.add_argument(
        "--home",
        type=str,
        help="Ardur home directory (ephemeral by default for governance)",
    )
    # Governance-bridge flags. Supplying any of these switches `ardur run` from
    # the legacy hub-streaming path to the zero-setup governance launcher.
    run.add_argument("--mission", help="mission text for the governed agent run")
    run.add_argument(
        "--allowed-tools",
        action="append",
        help="comma-separated allowlist of tools the agent may call (repeatable)",
    )
    run.add_argument(
        "--forbidden-tools",
        action="append",
        help="comma-separated denylist of tools the agent may not call (repeatable)",
    )
    run.add_argument(
        "--max-tool-calls",
        type=int,
        default=None,
        help="maximum governed tool calls for the run (default 250 when governing)",
    )
    run.add_argument(
        "--max-duration-s",
        type=int,
        default=None,
        help="wall-clock budget for the governed run in seconds",
    )
    run.add_argument(
        "--via",
        choices=sorted(VALID_VIA_MODES),
        default=None,
        help="how to route the agent's tool-call governance (default auto-detects Claude Code)",
    )
    run.add_argument(
        "--no-kernel-correlation",
        action="store_true",
        help="skip eBPF daemon/cgroup correlation even when available",
    )
    run.add_argument(
        "--enforce",
        action="store_true",
        help="abort the run if kernel-level BPF policy enforcement cannot be installed "
        "(default: permissive — degrade to hook/proxy governance with a recorded note)",
    )
    resource_scope_group = run.add_mutually_exclusive_group()
    resource_scope_group.add_argument(
        "--resource-scope",
        action="append",
        metavar="PATH",
        help="narrow file access to a path root inside the governed cwd (repeatable; "
        "relative paths resolve against cwd)",
    )
    resource_scope_group.add_argument(
        "--no-resource-scope",
        action="store_true",
        help="explicitly grant all user-space resources while skipping the default "
        "cwd-based kernel file resource_scope (path_allow); use for a mission that "
        "is genuinely network-only, since the seccomp fallback tier "
        "(active when BPF-LSM is unavailable) can only ever enforce network policy — "
        "a mission that also carries a file-scope dimension can never be fully "
        "enforceable on that tier",
    )
    run.add_argument(
        "--json",
        action="store_true",
        help="emit governance run result as JSON to stderr instead of human-readable "
        "summary; stdout stays reserved for the child process output",
    )
    run.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in --json output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports "
        "(governance path only; requires --json)",
    )
    run.add_argument(
        "--output",
        type=str,
        default=None,
        help="write the governance run result JSON to this file "
        "(works with or without --json; useful for CI pipelines that need "
        "a persistent artifact)",
    )
    run.add_argument(
        "command", nargs=argparse.REMAINDER, help="command to run after --"
    )
    run.set_defaults(func=cmd_run)

    desktop = subparsers.add_parser(
        "desktop-observe",
        help="record a Mac desktop app observation through Ardur Personal Hub",
    )
    desktop.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    desktop.add_argument(
        "--hub-token", default=None, help="Hub bearer token (defaults to config/env)"
    )
    desktop.add_argument("--home", type=str, help="Ardur Personal home directory")
    desktop.add_argument("--session-id", help="stable desktop session id")
    desktop.add_argument(
        "--app", help="application name; autodetected on macOS when omitted"
    )
    desktop.add_argument(
        "--title", help="window title; autodetected on macOS when omitted"
    )
    desktop.add_argument(
        "--text",
        help="explicit-consent visible text excerpt to include in the session review",
    )
    desktop.set_defaults(func=cmd_desktop_observe)

    personal_native_host = subparsers.add_parser(
        "personal-native-host",
        help="run the Ardur Personal native messaging bridge",
    )
    personal_native_host.add_argument(
        "--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL"
    )
    personal_native_host.add_argument(
        "--hub-token", default=None, help="Hub bearer token (defaults to config/env)"
    )
    personal_native_host.add_argument(
        "--home", type=str, help="Ardur Personal home directory"
    )
    personal_native_host.add_argument(
        "--once-json",
        type=str,
        help="development mode: process one JSON message file",
    )
    personal_native_host.set_defaults(func=cmd_personal_native_host)

    personal_native_manifest = subparsers.add_parser(
        "personal-native-manifest",
        help="print a native messaging manifest for the Hub bridge",
    )
    personal_native_manifest.add_argument("--host-path", required=True)
    personal_native_manifest.add_argument("--extension-id", required=True)
    personal_native_manifest.add_argument(
        "--browser",
        choices=["chrome", "chrome-for-testing", "chromium", "edge", "firefox"],
        default="chrome",
    )
    personal_native_manifest.set_defaults(func=cmd_personal_native_manifest)

    personal_firewall = subparsers.add_parser(
        "personal-firewall",
        help="run and inspect the conservative local personal action firewall",
    )
    personal_firewall_subparsers = personal_firewall.add_subparsers(
        dest="personal_firewall_command",
        required=True,
    )
    personal_firewall_demo = personal_firewall_subparsers.add_parser(
        "demo",
        help="run a provider-free ASK/DENY and signed-receipt proof",
    )
    personal_firewall_demo.add_argument(
        "--timeout-s",
        type=float,
        default=PERSONAL_FIREWALL_MAX_DEMO_SECONDS,
        help="overall demo deadline in seconds (maximum 60)",
    )
    personal_firewall_demo.add_argument(
        "--temp-parent",
        type=str,
        help="existing directory that receives temporary demo state",
    )
    personal_firewall_demo.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable demo details",
    )
    personal_firewall_demo.set_defaults(func=cmd_personal_firewall_demo)

    profile = subparsers.add_parser(
        "profile",
        help="create and inspect plain Markdown Ardur guardrail profiles",
    )
    profile_subparsers = profile.add_subparsers(dest="profile_command", required=True)
    profile_init = profile_subparsers.add_parser(
        "init",
        help="create an ARDUR.md guardrail profile from a built-in template",
    )
    profile_init.add_argument(
        "--template",
        choices=sorted(PROFILE_TEMPLATES),
        default="read-only",
        help="starter profile to write",
    )
    profile_init.add_argument(
        "--path", type=str, default="ARDUR.md", help="profile file to create"
    )
    profile_init.add_argument(
        "--force", action="store_true", help="replace an existing profile"
    )
    profile_init.add_argument(
        "--json", action="store_true", help="print machine-readable setup details"
    )
    profile_init.set_defaults(func=cmd_profile_init)

    protect = subparsers.add_parser(
        "protect",
        help="configure local Ardur protection for an AI assistant",
    )
    protect_subparsers = protect.add_subparsers(dest="protect_target", required=True)
    protect_cc = protect_subparsers.add_parser(
        "claude-code",
        help="issue an active Mission Passport and print the Claude Code plugin command",
    )
    protect_cc.add_argument(
        "--scope", type=str, help="folder Claude Code is allowed to work in"
    )
    # ``--profile`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-only
    # values survive to the handler instead of being normalized to
    # ``PosixPath('.')`` (the CWD) at parse time. The handler validates the
    # stripped string before any key generation or profile loading.
    protect_cc.add_argument(
        "--profile", type=str, help="Markdown Ardur profile, such as ARDUR.md"
    )
    protect_cc.add_argument(
        "--mode",
        choices=sorted(CLAUDE_CODE_PROTECT_MODES),
        default=None,
        help="plain-English policy template",
    )
    protect_cc.add_argument(
        "--json", action="store_true", help="print machine-readable setup details"
    )
    protect_cc.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in --json output with stable placeholders "
        "so the result is safe to share in CI artifacts or bug reports "
        "(requires --json)",
    )
    # ``--home`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-only
    # values survive to the handler instead of being normalized to
    # ``PosixPath('.')`` (the CWD) at parse time. The handler validates the
    # stripped string before any directory creation or key generation.
    protect_cc.add_argument(
        "--home", type=str, help="Ardur home that receives active_mission.jwt"
    )
    protect_cc.add_argument(
        "--plugin-dir",
        type=str,
        default=str(_default_claude_plugin_dir()),
        help="Claude Code plugin directory",
    )
    # ``--keys-dir`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-
    # only values survive to the handler instead of being normalized to
    # ``PosixPath('.')`` (the CWD) at parse time. The handler validates the
    # stripped string before any directory creation or key generation.
    protect_cc.add_argument("--keys-dir", type=str, help="signing keys directory")
    protect_cc.add_argument(
        "--agent-id", default="local-user:claude-code", help="Mission Passport subject"
    )
    protect_cc.add_argument(
        "--mission", help="override the default mission text for the selected mode"
    )
    protect_cc.add_argument(
        "--max-tool-calls", type=int, default=250, help="maximum governed tool calls"
    )
    protect_cc.add_argument(
        "--max-duration-s",
        type=int,
        default=86400,
        help="mission duration budget in seconds",
    )
    protect_cc.add_argument("--ttl-s", type=int, help="override token TTL in seconds")
    protect_cc.add_argument(
        "--child-policy-file",
        type=str,
        help=(
            "private 0600 JSON registry that enables one level of governed "
            "Agent delegation"
        ),
    )
    protect_cc.add_argument(
        # ``type=str`` (not ``Path``) so an empty or whitespace-only value
        # survives parsing and can be rejected explicitly below. ``type=Path``
        # normalises ``""`` to ``PosixPath(".")`` which silently resolves to the
        # CWD and masks the empty-argument defect.
        "--forbid-rules",
        type=str,
        help="JSON file containing forbid_rules policy specifications",
    )
    protect_cc.add_argument(
        # ``type=str`` (not ``Path``) so an empty or whitespace-only value
        # survives parsing and can be rejected explicitly below. ``type=Path``
        # normalises ``""`` to ``PosixPath(".")`` which silently resolves to the
        # CWD and masks the empty-argument defect.
        "--cedar-policy",
        type=str,
        help="Cedar policy file (.cedar)",
    )
    protect_cc.add_argument(
        # ``type=str`` (not ``Path``) so an empty or whitespace-only value
        # survives parsing and can be rejected explicitly below. ``type=Path``
        # normalises ``""`` to ``PosixPath(".")`` which silently resolves to the
        # CWD and masks the empty-argument defect.
        "--cedar-entities",
        type=str,
        help="Cedar entities JSON file (used with --cedar-policy)",
    )
    protect_cc.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the JSON response to an owner-only file "
        "instead of printing human-readable or JSON output to stdout",
    )
    protect_cc.set_defaults(func=cmd_protect_claude_code)

    latency_gate = subparsers.add_parser(
        "latency-gate",
        help="evaluate a directory of latency reports against the deterministic gate",
    )
    latency_gate_subparsers = latency_gate.add_subparsers(
        dest="latency_gate_command", required=True
    )
    latency_gate_evaluate = latency_gate_subparsers.add_parser(
        "evaluate",
        help="load latency reports from a directory and emit a gate decision",
    )
    # ``--reports`` uses ``type=str`` (not ``type=Path``) so empty/whitespace-
    # only values survive parsing and can be rejected explicitly in the
    # handler. ``type=Path`` normalizes ``""`` to ``PosixPath('.')`` (the CWD)
    # which silently masks the empty-argument defect.
    latency_gate_evaluate.add_argument(
        "--reports",
        type=str,
        required=True,
        help="directory of latency report JSON files to evaluate",
    )
    latency_gate_evaluate.add_argument(
        "--threshold-ms",
        type=float,
        default=10.0,
        help="maximum allowed aggregate p95 latency in ms (default: 10.0)",
    )
    latency_gate_evaluate.add_argument(
        "--min-runs",
        type=int,
        default=3,
        help="minimum number of valid reports for a non-INCONCLUSIVE verdict (default: 3)",
    )
    latency_gate_evaluate.add_argument(
        "--percentile",
        type=int,
        default=95,
        help="percentile rank for the statistical rule, 1..100 (default: 95)",
    )
    latency_gate_evaluate.add_argument(
        "--format",
        "--output-format",
        dest="format",
        choices=("json", "text"),
        default="json",
        help="output format (default: json)",
    )
    latency_gate_evaluate.add_argument(
        "--json",
        action="store_true",
        help="explicitly request JSON output (output defaults to JSON; "
        "this flag is accepted for consistency with other commands)",
    )
    latency_gate_evaluate.add_argument(
        "--redact-paths",
        action="store_true",
        help="replace local absolute paths in JSON/file output with "
        "stable placeholders so the result is safe to share in "
        "CI artifacts or bug reports",
    )
    latency_gate_evaluate.add_argument(
        "--output",
        type=str,
        default=None,
        help="atomically write the gate decision JSON to an owner-only "
        "file instead of printing it to stdout",
    )
    latency_gate_evaluate.set_defaults(func=cmd_latency_gate_evaluate)

    return parser


def verify_main(argv: Sequence[str] | None = None) -> int:
    """Dedicated ``ardur-verify`` console entry point."""

    arguments = sys.argv[1:] if argv is None else list(argv)
    return main(["verify", *arguments])


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    # ``_JsonAwareArgumentParser.error()`` detects ``--json`` from
    # ``_raw_argv`` when set, falling back to ``sys.argv[1:]``. Subparsers do
    # not share the top-level parser's ``_raw_argv``, so for programmatic
    # ``main(argv)`` calls we temporarily mirror ``argv`` into ``sys.argv``.
    # This lets a subparser's ``error()`` (fired by a missing required
    # subcommand argument) honour the ``--json`` contract identically to
    # interactive invocation.
    parser._raw_argv = raw_argv  # type: ignore[attr-defined]
    saved_argv = sys.argv
    sys.argv = ["ardur", *raw_argv]
    try:
        args = parser.parse_args(raw_argv)
    finally:
        sys.argv = saved_argv
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
