"""Receipt-chain observability reports for Ardur Claude Code sessions."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .passport import DEFAULT_HOME, load_report_public_key
from .receipt import verify_chain
from .shareable_redaction import path_aliases, redact_local_paths


_RULE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _root_pairs(mapping: Mapping[str, str | Path | None]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for label, path in mapping.items():
        placeholder = f"<{label}>"
        for alias in path_aliases(path):
            pairs.append((alias, placeholder))
    return sorted(set(pairs), key=lambda item: len(item[0]), reverse=True)


def _shareable_redact(value: Any, *, roots: Mapping[str, str | Path | None]) -> Any:
    return redact_local_paths(value, root_pairs=_root_pairs(roots))


def _is_dispatch_claim(claim: Mapping[str, Any]) -> bool:
    return (
        claim.get("side_effect_class") == "subagent_launch"
        or claim.get("action_class") == "dispatch"
        or claim.get("tool") in {"Agent", "Task"}
    )


def _is_dispatch_launch(claim: Mapping[str, Any]) -> bool:
    return _is_dispatch_claim(claim) and claim.get("reason") != "post-call observation"


def _claude_code_meta(claim: Mapping[str, Any]) -> dict[str, Any]:
    measurements = claim.get("measurements")
    if not isinstance(measurements, dict):
        return {}
    meta = measurements.get("claude_code")
    return dict(meta) if isinstance(meta, dict) else {}


def _empty_report_next_steps() -> list[dict[str, str]]:
    """Deterministic local remediation hints for a report with no receipts."""
    return [
        {
            "condition": "no_claude_code_receipts",
            "action": "configure_claude_code_protection",
            "command": (
                "ardur protect claude-code --scope <your-project> "
                "--home <ardur-home> --plugin-dir <claude-code-plugin>"
            ),
            "detail": (
                "Create a local Mission Passport for the project. The command prints "
                "the Claude Code plugin invocation to run next."
            ),
        },
        {
            "condition": "no_claude_code_receipts",
            "action": "run_claude_code_with_plugin",
            "command": "VIBAP_HOME=<ardur-home> claude --plugin-dir <claude-code-plugin>",
            "detail": (
                "Run a local Claude Code session with the configured plugin; hook "
                "receipts should appear under "
                "<ardur-home>/claude-code-hook/<trace-id>/receipts.jsonl."
            ),
        },
        {
            "condition": "no_claude_code_receipts",
            "action": "rerun_receipt_report",
            "command": "ardur claude-code-report --home <ardur-home>",
            "detail": (
                "Verify the local receipt chains after the run. This report reads "
                "local hook receipts only and does not call live providers or prove "
                "provider-hidden actions."
            ),
        },
    ]


def _is_lifecycle_claim(claim: Mapping[str, Any]) -> bool:
    return str(claim.get("tool", "")) in {"SubagentStart", "SubagentStop"}


def _is_child_tool_claim(claim: Mapping[str, Any]) -> bool:
    if _is_lifecycle_claim(claim):
        return False
    if _is_dispatch_claim(claim):
        return False
    return bool(claim.get("tool"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    records: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _subagents_from_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    subagents: dict[str, dict[str, Any]] = {}
    for record in records:
        child_id = str(record.get("ardur_child_id", "") or "")
        if not child_id:
            continue
        current = subagents.setdefault(
            child_id,
            {
                "ardur_child_id": child_id,
                "claude_agent_id": str(record.get("claude_agent_id", "") or ""),
                "agent_type": str(record.get("agent_type", "") or ""),
                "started_at": None,
                "stopped_at": None,
                "binding_state": "observed_only",
                "binding_states": {},
                "tool_receipt_count": 0,
                "tools": {},
                "violations": 0,
                "attribution_modes": {},
            },
        )
        if record.get("claude_agent_id"):
            current["claude_agent_id"] = str(record["claude_agent_id"])
        if record.get("agent_type"):
            current["agent_type"] = str(record["agent_type"])
        authority_binding = record.get("authority_binding")
        if isinstance(authority_binding, Mapping):
            binding_state = str(authority_binding.get("binding_state", "") or "")
            if binding_state:
                current["binding_state"] = binding_state
                binding_states = dict(current.get("binding_states", {}) or {})
                binding_states[binding_state] = binding_states.get(binding_state, 0) + 1
                current["binding_states"] = dict(sorted(binding_states.items()))
        if record.get("started_at"):
            current["started_at"] = str(record["started_at"])
        if record.get("stopped_at"):
            current["stopped_at"] = str(record["stopped_at"])
    return subagents


def _attribute_child_tool(
    claim: Mapping[str, Any],
    subagents: Mapping[str, dict[str, Any]],
) -> tuple[str | None, str]:
    meta = _claude_code_meta(claim)
    child_id = str(meta.get("ardur_child_id", "") or "")
    authority_binding = meta.get("authority_binding")
    binding_state = (
        str(authority_binding.get("binding_state", "") or "")
        if isinstance(authority_binding, Mapping)
        else ""
    )
    policy_fingerprint = (
        str(authority_binding.get("policy_fingerprint", "") or "")
        if isinstance(authority_binding, Mapping)
        else ""
    )
    if (
        child_id
        and child_id in subagents
        and meta.get("claude_agent_id")
        and binding_state in {"bound", "quarantined"}
        and policy_fingerprint
    ):
        return child_id, "exact"
    return None, "trace_only"


def _merge_attribution_mode(modes: list[str]) -> str:
    if not modes:
        return "trace_only"
    if "ambiguous" in modes:
        return "ambiguous"
    if "trace_only" in modes:
        return "trace_only"
    return "exact"


def _action_summary(claim: Mapping[str, Any]) -> dict[str, Any]:
    verdict = str(claim.get("verdict", ""))
    public_reason = str(claim.get("public_denial_reason", "") or "")
    step_id = str(claim.get("step_id", ""))
    phase = (
        "pre"
        if step_id.endswith(":pre")
        else "post"
        if step_id.endswith(":post")
        else "other"
    )
    if phase == "post":
        explanation = "recorded a post-action result observation"
    elif verdict == "compliant":
        explanation = "allowed by configured policy; the agent's normal permission flow remains in charge"
    elif public_reason == "budget_exhausted":
        explanation = "blocked because the signed session action budget is exhausted"
    elif public_reason:
        explanation = f"blocked by configured policy ({public_reason})"
    else:
        explanation = "blocked because the receipt did not prove a compliant action"
    policies: list[dict[str, str]] = []
    applied_rule = (
        "session_action_budget"
        if public_reason == "budget_exhausted"
        else "configured_policy"
    )
    for item in claim.get("policy_decisions", []):
        if not isinstance(item, Mapping):
            continue
        summary = {
            "backend": str(item.get("backend", "unknown")),
            "decision": str(item.get("decision", "unknown")),
        }
        if summary["backend"] == "forbid_rules":
            candidate = str(item.get("reason", "")).split("(", 1)[0]
            if _RULE_ID_RE.fullmatch(candidate):
                summary["rule_id"] = candidate
                if summary["decision"] == "Deny":
                    applied_rule = candidate
        policies.append(summary)
    return {
        "receipt_id": str(claim.get("receipt_id", "")),
        "timestamp": str(claim.get("timestamp", "")),
        "phase": phase,
        "request": {
            "tool": str(claim.get("tool", "")),
            "action_class": str(claim.get("action_class", "")),
            "resource_family": str(claim.get("resource_family", "")),
            "side_effect_class": str(claim.get("side_effect_class", "")),
        },
        "verdict": verdict,
        "explanation": explanation,
        "applied_rule": applied_rule,
        "policies": policies,
        "budget_delta": dict(claim.get("budget_delta", {}) or {}),
        "budget_remaining": dict(claim.get("budget_remaining", {}) or {}),
    }


def _chain_report(
    *,
    trace_id: str,
    receipt_file: Path,
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    subagent_records = _read_jsonl(receipt_file.parent / "subagents.jsonl")
    subagents_by_child = _subagents_from_records(subagent_records)
    attribution_modes: list[str] = []
    unattributed_tool_receipts: list[dict[str, Any]] = []
    ambiguous_tool_receipts: list[dict[str, Any]] = []
    for claim in claims:
        if not _is_child_tool_claim(claim):
            continue
        child_id, mode = _attribute_child_tool(claim, subagents_by_child)
        attribution_modes.append(mode)
        if child_id:
            subagent = subagents_by_child[child_id]
            subagent["tool_receipt_count"] = (
                int(subagent.get("tool_receipt_count", 0)) + 1
            )
            tools = dict(subagent.get("tools", {}) or {})
            tool = str(claim.get("tool", ""))
            tools[tool] = tools.get(tool, 0) + 1
            subagent["tools"] = dict(sorted(tools.items()))
            if claim.get("verdict") == "violation":
                subagent["violations"] = int(subagent.get("violations", 0)) + 1
            mode_counts = dict(subagent.get("attribution_modes", {}) or {})
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
            subagent["attribution_modes"] = dict(sorted(mode_counts.items()))
            continue
        receipt_ref = {
            "receipt_id": str(claim.get("receipt_id", "")),
            "tool": str(claim.get("tool", "")),
            "tool_use_id": str(_claude_code_meta(claim).get("tool_use_id", "") or ""),
            "attribution": mode,
        }
        if mode == "ambiguous":
            ambiguous_tool_receipts.append(receipt_ref)
        else:
            unattributed_tool_receipts.append(receipt_ref)

    dispatches = [
        {
            "receipt_id": str(claim.get("receipt_id", "")),
            "timestamp": str(claim.get("timestamp", "")),
            "tool": str(claim.get("tool", "")),
            "target": str(claim.get("target", "")),
            "verdict": str(claim.get("verdict", "")),
            "reason": str(claim.get("reason", "")),
            "side_effect_class": str(claim.get("side_effect_class", "")),
        }
        for claim in claims
        if _is_dispatch_claim(claim)
    ]
    dispatch_launches = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] != "post-call observation"
    ]
    dispatch_observations = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] == "post-call observation"
    ]
    first_dispatch_index = next(
        (idx for idx, claim in enumerate(claims) if _is_dispatch_claim(claim)),
        None,
    )
    after_dispatch = (
        claims[first_dispatch_index + 1 :] if first_dispatch_index is not None else []
    )
    return {
        "trace_id": trace_id,
        "receipt_file": str(receipt_file),
        "receipt_count": len(claims),
        "first_timestamp": str(claims[0].get("timestamp", "")) if claims else None,
        "last_timestamp": str(claims[-1].get("timestamp", "")) if claims else None,
        "tools": _counter_dict([str(claim.get("tool", "")) for claim in claims]),
        "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in claims]),
        "action_classes": _counter_dict(
            [str(claim.get("action_class", "")) for claim in claims]
        ),
        "side_effect_classes": _counter_dict(
            [str(claim.get("side_effect_class", "")) for claim in claims]
        ),
        "actions": [_action_summary(claim) for claim in claims],
        "dispatches": dispatches,
        "dispatch_launches": dispatch_launches,
        "dispatch_observations": dispatch_observations,
        "dispatch_receipt_count": len(dispatches),
        "dispatch_launch_count": len(dispatch_launches),
        "dispatch_observation_count": len(dispatch_observations),
        "receipt_count_after_first_dispatch": len(after_dispatch),
        "tools_after_first_dispatch": _counter_dict(
            [str(claim.get("tool", "")) for claim in after_dispatch]
        ),
        "subagent_registry_file": str(receipt_file.parent / "subagents.jsonl"),
        "subagent_registry_records": len(subagent_records),
        "subagents_started": sum(
            1 for record in subagent_records if record.get("event") == "start"
        ),
        "subagents_stopped": sum(
            1 for record in subagent_records if record.get("event") == "stop"
        ),
        "subagents": list(subagents_by_child.values()),
        "per_child_attribution": _merge_attribution_mode(attribution_modes),
        "unattributed_tool_receipts": unattributed_tool_receipts,
        "ambiguous_tool_receipts": ambiguous_tool_receipts,
        "unattributed_tool_receipt_count": len(unattributed_tool_receipts),
        "ambiguous_tool_receipt_count": len(ambiguous_tool_receipts),
    }


def build_claude_code_report(
    *,
    home: Path | None = None,
    chain_dir: Path | None = None,
    keys_dir: Path | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    """Verify Claude Code hook receipt chains and summarize observability.

    Receipt expiry is disabled by default because this command is an evidence
    report: old signed receipts should remain auditable after their runtime
    freshness window has passed.
    """
    resolved_home = (home or DEFAULT_HOME).expanduser().resolve()
    resolved_chain_dir = (
        (chain_dir or (resolved_home / "claude-code-hook")).expanduser().resolve()
    )
    resolved_keys_dir = (keys_dir or (resolved_home / "keys")).expanduser().resolve()
    receipt_files = sorted(resolved_chain_dir.rglob("receipts.jsonl"))
    public_key = load_report_public_key(
        resolved_keys_dir, evidence_present=bool(receipt_files)
    )

    chains: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    for receipt_file in receipt_files:
        tokens = [
            line.strip()
            for line in receipt_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        claims = verify_chain(tokens, public_key, verify_expiry=verify_expiry)
        all_claims.extend(claims)
        trace_id = receipt_file.parent.name
        chains.append(
            _chain_report(trace_id=trace_id, receipt_file=receipt_file, claims=claims)
        )

    dispatch_receipt_count = sum(len(chain["dispatches"]) for chain in chains)
    dispatch_launch_count = sum(chain["dispatch_launch_count"] for chain in chains)
    dispatch_observation_count = sum(
        chain["dispatch_observation_count"] for chain in chains
    )
    subagents_started = sum(int(chain["subagents_started"]) for chain in chains)
    subagents_stopped = sum(int(chain["subagents_stopped"]) for chain in chains)
    child_binding_states = _counter_dict(
        [
            str(subagent.get("binding_state", "observed_only"))
            for chain in chains
            for subagent in chain["subagents"]
        ]
    )
    unattributed_tool_receipt_count = sum(
        int(chain["unattributed_tool_receipt_count"]) for chain in chains
    )
    ambiguous_tool_receipt_count = sum(
        int(chain["ambiguous_tool_receipt_count"]) for chain in chains
    )
    per_child_attribution = _merge_attribution_mode(
        [
            str(chain["per_child_attribution"])
            for chain in chains
            if chain["subagents"] or chain["unattributed_tool_receipts"]
        ]
    )
    roots: dict[str, str | Path | None] = {
        "CLAUDE_CODE_HOME": resolved_home,
        "ARDUR_CLAUDE_CODE_CHAIN": resolved_chain_dir,
        "ARDUR_KEYS": resolved_keys_dir,
    }
    report = {
        "ok": True,
        "home": str(resolved_home),
        "chain_dir": str(resolved_chain_dir),
        "keys_dir": str(resolved_keys_dir),
        "chain_verification": {"ok": True, "verify_expiry": verify_expiry},
        "verification": {
            "command": "ardur claude-code-report --home <ardur-home>",
            "detail": "Re-run the local report to verify signatures and hash links for every receipt chain.",
        },
        "cost_boundary": {
            "enforced_unit": "governed tool calls",
            "monetary_cost": "unavailable_without_signed_adapter_data",
            "detail": (
                "The signed action budget is enforced locally. A dollar-denominated "
                "cap requires trusted cost telemetry from the provider adapter."
            ),
        },
        "chain_count": len(chains),
        "receipt_count": len(all_claims),
        "next_steps": _empty_report_next_steps() if not all_claims else [],
        "totals": {
            "tools": _counter_dict(
                [str(claim.get("tool", "")) for claim in all_claims]
            ),
            "verdicts": _counter_dict(
                [str(claim.get("verdict", "")) for claim in all_claims]
            ),
            "action_classes": _counter_dict(
                [str(claim.get("action_class", "")) for claim in all_claims]
            ),
            "side_effect_classes": _counter_dict(
                [str(claim.get("side_effect_class", "")) for claim in all_claims]
            ),
            "dispatch_count": dispatch_launch_count,
            "dispatch_launch_count": dispatch_launch_count,
            "dispatch_observation_count": dispatch_observation_count,
            "dispatch_receipt_count": dispatch_receipt_count,
            "violation_count": sum(
                1 for claim in all_claims if claim.get("verdict") == "violation"
            ),
            "subagents_started": subagents_started,
            "subagents_stopped": subagents_stopped,
            "child_binding_states": child_binding_states,
            "unattributed_tool_receipt_count": unattributed_tool_receipt_count,
            "ambiguous_tool_receipt_count": ambiguous_tool_receipt_count,
        },
        "coverage": {
            "has_subagent_dispatch": dispatch_launch_count > 0,
            "subagent_launch_count": dispatch_launch_count,
            "subagents_started": subagents_started,
            "subagents_stopped": subagents_stopped,
            "child_binding_states": child_binding_states,
            "per_child_attribution": per_child_attribution,
            "unattributed_tool_receipt_count": unattributed_tool_receipt_count,
            "ambiguous_tool_receipt_count": ambiguous_tool_receipt_count,
            "has_receipts_after_dispatch": any(
                chain["receipt_count_after_first_dispatch"] > 0 for chain in chains
            ),
            "attribution": (
                "exact only when a tool hook's agent_id resolves to the opaque child "
                "authority binding; trace_only when Ardur can prove only parent-trace "
                "membership. Transcript paths and transcript contents are never identity."
            ),
        },
        "chains": chains,
    }
    return _shareable_redact(report, roots=roots)
