from __future__ import annotations

import base64
import copy
import hashlib
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jsonschema import Draft202012Validator

from vibap import cli as cli_module
from vibap import offline_verification as offline
from vibap.canonical_json import canonical_json_bytes
from vibap.offline_verification_fixture import (
    OfflineVerificationFixtureOutputError,
    run_offline_verification_fixture,
)
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt
from vibap.receiver_attestation import (
    MCP_ATTESTATION_META_KEY,
    MCP_RECEIPT_META_KEY,
    ReceiverAttestationShim,
    self_attested_envelope,
)
from vibap.transparency import (
    ANCHORED_BACKEND_KINDS,
    BACKEND_LOCAL_SIGNED,
    BACKEND_REKOR_V1,
    LocalSignedLogBackend,
    RekorV1Backend,
    _hash_leaf,
    _signed_checkpoint,
    pending_anchor_bundle,
)

BUNDLE_SCHEMA_VERSION = offline.BUNDLE_SCHEMA_VERSION
cli_main = cli_module.main
OfflineVerificationError = offline.OfflineVerificationError
load_offline_input = offline.load_offline_input
render_cli_report = offline.render_cli_report
render_html_report = offline.render_html_report
verify_offline_input = offline.verify_offline_input
write_html_report = offline.write_html_report


def test_dedicated_verifier_entry_point_prefixes_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def fake_main(argv: list[str]) -> int:
        observed.append(argv)
        return 19

    monkeypatch.setattr(cli_module, "main", fake_main)

    assert cli_module.verify_main(["fixture.json", "--format", "json"]) == 19
    assert observed == [["verify", "fixture.json", "--format", "json"]]


def _fixture(
    tmp_path: Path,
    *,
    timestamps: tuple[int, ...] = (1_800_000_000, 1_800_000_010, 1_800_000_020),
    budget_remaining: tuple[int, ...] = (9, 8, 7),
    delta_remaining_after: tuple[int | None, ...] = (None, 8, 7),
    bad_parent_at: int | None = None,
    reuse_receipt_as_log_key: bool = False,
) -> dict[str, Any]:
    receipt_key = ec.generate_private_key(ec.SECP256R1())
    receiver_key = ec.generate_private_key(ec.SECP256R1())
    log_key = (
        receipt_key
        if reuse_receipt_as_log_key
        else ed25519.Ed25519PrivateKey.generate()
    )
    log = LocalSignedLogBackend(
        tmp_path / "transparency.jsonl",
        log_key,
        origin="fixture.ardur.dev/offline",
        clock=lambda: timestamps[-1] + 30,
    )
    shim = ReceiverAttestationShim(
        receiver_private_key=receiver_key,
        receipt_public_key=receipt_key.public_key(),
        receiver_id="spiffe://fixture.ardur.dev/tool",
        key_id="fixture-receiver:v1",
    )
    journal: list[dict[str, Any]] = []
    previous_token: str | None = None
    decisions = (Decision.PERMIT, Decision.DENY, Decision.PERMIT)
    for index, (timestamp, decision) in enumerate(
        zip(timestamps, decisions, strict=True)
    ):
        observed = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        secret_target = (
            "https://example.test/items?api_key=fixture-super-secret&view=<script>alert(1)</script>"
            if index == 0
            else f"workspace/item-{index}.txt"
        )
        event = PolicyEvent(
            timestamp=observed,
            step_id=f"step:offline:{index}",
            actor="spiffe://fixture.ardur.dev/agent/reviewer",
            verifier_id="spiffe://fixture.ardur.dev/verifier",
            tool_name="read_file" if index != 1 else "write_file",
            arguments={"path": f"workspace/item-{index}.txt", "index": index},
            action_class="read" if index != 1 else "write",
            target=secret_target,
            resource_family="filesystem",
            side_effect_class="none" if index != 1 else "filesystem_write",
            decision=decision,
            reason=(
                "policy permit token=fixture-policy-secret"
                if decision == Decision.PERMIT
                else "policy denied password=fixture-denial-secret"
            ),
            passport_jti="grant:offline-fixture",
            trace_id="trace:offline-fixture",
            run_nonce="offline_fixture_nonce_0123456789",
            budget_delta=(
                {
                    "operation": "consume",
                    "resource": "tool_calls",
                    "amount": 1,
                    "unit": "invocations",
                    "remaining_after": delta_remaining_after[index],
                }
                if index > 0
                else None
            ),
        )
        parent_hash = (
            hashlib.sha256(previous_token.encode("ascii")).hexdigest()
            if previous_token is not None
            else None
        )
        if bad_parent_at == index:
            parent_hash = "0" * 64
        receipt = build_receipt(
            decision,
            event,
            parent_receipt_hash=parent_hash,
            policy_decisions=[
                {
                    "backend": "native",
                    "decision": "Allow" if decision == Decision.PERMIT else "Deny",
                    "reason": event.reason,
                }
            ],
            budget_remaining={"tool_calls": budget_remaining[index]},
        )
        receipt.iat = timestamp
        receipt.exp = timestamp + 300
        receipt.measurements = {
            "cost_usd": round(0.001 * (index + 1), 3),
            "token_count": 100 * (index + 1),
        }
        token = sign_receipt(receipt, receipt_key)
        anchor = log.submit(
            pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED)
        )
        request = {
            "jsonrpc": "2.0",
            "id": f"fixture-{index}",
            "method": "tools/call",
            "params": {
                "name": event.tool_name,
                "arguments": dict(event.arguments),
                "_meta": {MCP_RECEIPT_META_KEY: token},
            },
        }
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "content": [{"type": "text", "text": f"fixture result {index}"}],
                "isError": decision != Decision.PERMIT,
            },
        }
        receiver_envelope: dict[str, Any]
        if decision == Decision.PERMIT:
            attested = shim.attach_to_mcp_response(
                request=request,
                response=response,
                observed_at=timestamp + 1,
            )
            receiver_envelope = attested["result"]["_meta"][MCP_ATTESTATION_META_KEY]
        else:
            receiver_envelope = self_attested_envelope(token)
        journal.append(
            {
                "receipt_jwt": token,
                "transparency_anchor": anchor,
                "receiver_attestation": receiver_envelope,
            }
        )
        previous_token = token
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "profile": "full-evidence",
        "journal": journal,
    }
    path = tmp_path / "offline-bundle.json"
    path.write_bytes(canonical_json_bytes(bundle) + b"\n")
    return {
        "path": path,
        "bundle": bundle,
        "receipt_key": receipt_key,
        "receiver_key": receiver_key,
        "log_key": log_key,
    }


def _verify(fixture: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return verify_offline_input(
        load_offline_input(fixture["path"]),
        receipt_public_key=fixture["receipt_key"].public_key(),
        log_public_key=fixture["log_key"].public_key(),
        receiver_public_key=fixture["receiver_key"].public_key(),
        **kwargs,
    )


def _rewrite(fixture: dict[str, Any], bundle: dict[str, Any]) -> None:
    fixture["path"].write_bytes(canonical_json_bytes(bundle) + b"\n")


def _write_public_keys(fixture: dict[str, Any], directory: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for role, private_key in (
        ("receipt", fixture["receipt_key"]),
        ("receiver", fixture["receiver_key"]),
        ("log", fixture["log_key"]),
    ):
        path = directory / f"{role}-public.pem"
        path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        paths[role] = path
    return paths


def test_full_bundle_verifies_offline_and_reports_signed_narrowing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)

    def network_forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("offline verification attempted network access")

    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    report = _verify(fixture)
    replayed = _verify(fixture)

    assert report["valid"] is True
    assert replayed["valid"] is True
    assert report["result"] == "verified"
    assert report["verification_mode"] == "offline"
    assert report["revocation_checked"] is False
    assert report["freshness"] == {
        "age_checked": False,
        "max_age_s": None,
        "allowed_future_skew_s": None,
        "latest_receipt_iat": 1_800_000_020,
        "age_s": None,
        "one_time_replay_checked": False,
    }
    assert (
        "offline verification did not enforce receipt age or one-time replay"
        in report["limitations"]
    )
    assert report["summary"] == {
        "receipt_count": 3,
        "permit_count": 2,
        "deny_count": 1,
        "error_count": 0,
        "unknown_count": 0,
        "anchored_count": 3,
        "public_log_protocol_anchored_count": 0,
        "receiver_attested_count": 2,
        "authority_narrowing_steps": [1, 2],
    }
    assert [item["decision"] for item in report["timeline"]] == [
        "PERMIT",
        "DENY",
        "PERMIT",
    ]
    assert report["timeline"][1]["evidence"]["receiver"]["status"] == "not-dispatched"
    assert len(report["trust_roots"]) == 3


def test_opt_in_bundle_age_accepts_boundary_and_rejects_stale_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    latest_iat = 1_800_000_020
    monkeypatch.setattr(offline.time, "time", lambda: latest_iat + 300)

    report = _verify(
        fixture,
        max_bundle_age_s=300,
        freshness_clock_skew_s=60,
    )

    assert report["valid"] is True
    assert report["freshness"] == {
        "age_checked": True,
        "max_age_s": 300,
        "allowed_future_skew_s": 60,
        "latest_receipt_iat": latest_iat,
        "age_s": 300,
        "one_time_replay_checked": False,
    }
    assert (
        "age-bounded freshness does not prevent repeated presentation inside the accepted window"
        in report["limitations"]
    )
    rendered = render_cli_report(report)
    assert "Freshness age checked: true | one-time replay checked: false" in rendered
    assert "Freshness age: 300s | maximum: 300s | allowed future skew: 60s" in rendered

    monkeypatch.setattr(offline.time, "time", lambda: latest_iat + 301)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(
            fixture,
            max_bundle_age_s=300,
            freshness_clock_skew_s=60,
        )
    assert caught.value.code == "bundle_freshness_stale"
    assert caught.value.index == 2


def test_opt_in_bundle_age_bounds_future_clock_skew(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    latest_iat = 1_800_000_020
    monkeypatch.setattr(offline.time, "time", lambda: latest_iat - 60)
    report = _verify(
        fixture,
        max_bundle_age_s=300,
        freshness_clock_skew_s=60,
    )
    assert report["freshness"]["age_s"] == 0

    monkeypatch.setattr(offline.time, "time", lambda: latest_iat - 61)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(
            fixture,
            max_bundle_age_s=300,
            freshness_clock_skew_s=60,
        )
    assert caught.value.code == "bundle_freshness_future"
    assert caught.value.index == 2


@pytest.mark.parametrize(
    ("max_age", "clock_skew"),
    [(-1, 60), (True, 60), (None, 60), (300, -1), (300, True)],
)
def test_bundle_freshness_policy_rejects_invalid_bounds(
    tmp_path: Path, max_age: Any, clock_skew: Any
) -> None:
    fixture = _fixture(tmp_path)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(
            fixture,
            max_bundle_age_s=max_age,
            freshness_clock_skew_s=clock_skew,
        )
    assert caught.value.code == "freshness_policy_invalid"


def test_default_cli_and_html_reports_redact_and_escape(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    report = _verify(fixture)

    cli = render_cli_report(report)
    rendered = render_html_report(report)
    assert "fixture-super-secret" not in cli
    assert "fixture-policy-secret" not in cli
    assert "fixture-denial-secret" not in cli
    assert "[REDACTED]" in cli
    assert "fixture-super-secret" not in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script" not in rendered.lower()
    assert "connect-src 'none'" in rendered
    assert "signed_cost=cost_usd=0.001, token_count=100" in cli
    assert "Freshness age checked: false | one-time replay checked: false" in cli
    assert (
        "Signed receipt age was not checked. One-time replay was not checked."
        in rendered
    )
    assert report["timeline"][0]["evidence"]["transparency"]["anchor_id"] in cli
    assert report["timeline"][0]["evidence"]["receiver"]["attestation_id"] in cli
    assert "cost_usd=0.001, token_count=100" in rendered
    assert report["timeline"][0]["evidence"]["transparency"]["anchor_id"] in rendered
    assert report["timeline"][0]["evidence"]["receiver"]["attestation_id"] in rendered


def test_explicit_unredacted_report_retains_synthetic_values(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    report = _verify(fixture, redact=False)
    assert report["redaction"]["enabled"] is False
    assert "fixture-super-secret" in report["timeline"][0]["target"]
    assert "fixture-policy-secret" in report["timeline"][0]["reason"]


def test_html_report_is_atomic_private_and_rejects_symlink(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    report = _verify(fixture)
    output = tmp_path / "report.html"
    write_html_report(output, report)
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    output.unlink()
    output.symlink_to(tmp_path / "elsewhere.html")
    with pytest.raises(OfflineVerificationError, match="must not be a symlink"):
        write_html_report(output, report)


def test_raw_journal_requires_explicit_chain_only(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    journal = tmp_path / "receipts.jsonl"
    journal.write_text(
        "\n".join(entry["receipt_jwt"] for entry in fixture["bundle"]["journal"])
        + "\n",
        encoding="utf-8",
    )
    loaded = load_offline_input(journal)
    with pytest.raises(OfflineVerificationError) as caught:
        verify_offline_input(
            loaded, receipt_public_key=fixture["receipt_key"].public_key()
        )
    assert caught.value.code == "full_evidence_required"

    report = verify_offline_input(
        loaded,
        receipt_public_key=fixture["receipt_key"].public_key(),
        chain_only=True,
    )
    assert report["result"] == "verified_chain_only"
    assert report["summary"]["anchored_count"] == 0
    assert report["summary"]["receiver_attested_count"] == 0


def test_object_per_line_jsonl_journal_is_supported(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    journal = tmp_path / "receipts-as-objects.jsonl"
    journal.write_text(
        "\n".join(
            json.dumps({"jwt": entry["receipt_jwt"], "source": "fixture"})
            for entry in fixture["bundle"]["journal"]
        )
        + "\n",
        encoding="utf-8",
    )
    report = verify_offline_input(
        load_offline_input(journal),
        receipt_public_key=fixture["receipt_key"].public_key(),
        chain_only=True,
    )
    assert report["summary"]["receipt_count"] == 3


def test_cli_report_neutralizes_terminal_and_bidi_controls(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    report = _verify(fixture, redact=False)
    report["timeline"][0]["reason"] = "safe\x1b[31m red\x07 \u202eevil"
    rendered = render_cli_report(report)
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\u202e" not in rendered
    assert "safe [31m red evil" in rendered


def test_cli_full_bundle_writes_redacted_private_html(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    html_path = tmp_path / "offline-report.html"
    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--transparency-log-key",
                str(keys["log"]),
                "--receiver-public-key",
                str(keys["receiver"]),
                "--html-report",
                str(html_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "Ardur offline verification: VERIFIED" in output
    assert "fixture-super-secret" not in output
    assert html_path.stat().st_mode & 0o777 == 0o600
    assert "fixture-super-secret" not in html_path.read_text(encoding="utf-8")


def test_cli_full_bundle_json_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--transparency-log-key",
                str(keys["log"]),
                "--receiver-public-key",
                str(keys["receiver"]),
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is True
    assert report["summary"]["receipt_count"] == 3
    assert report["redaction"]["enabled"] is True


def test_cli_full_bundle_enforces_opt_in_freshness_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    monkeypatch.setattr(offline.time, "time", lambda: 1_800_000_320)

    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--transparency-log-key",
                str(keys["log"]),
                "--receiver-public-key",
                str(keys["receiver"]),
                "--max-bundle-age-s",
                "300",
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["freshness"] == {
        "age_checked": True,
        "max_age_s": 300,
        "allowed_future_skew_s": 60,
        "latest_receipt_iat": 1_800_000_020,
        "age_s": 300,
        "one_time_replay_checked": False,
    }


def test_cli_freshness_clock_skew_requires_max_bundle_age(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)

    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--freshness-clock-skew-s",
                "60",
            ]
        )
        == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["error"] == "offline_freshness_policy_invalid"


def test_cli_full_bundle_requires_external_log_and_receiver_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--json",
            ]
        )
        == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["error"] == "log_key_required"


def test_cli_raw_journal_chain_only_is_explicit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    journal = tmp_path / "receipts.jsonl"
    journal.write_text(
        "\n".join(entry["receipt_jwt"] for entry in fixture["bundle"]["journal"])
        + "\n",
        encoding="utf-8",
    )
    assert (
        cli_main(
            [
                "verify",
                str(journal),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--chain-only",
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["result"] == "verified_chain_only"
    assert report["assurance_profile"] == "chain-only"


def test_missing_parent_fails_before_sidecar_verification(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    del bundle["journal"][1]
    _rewrite(fixture, bundle)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "receipt_chain_invalid"
    assert "parent_receipt_hash mismatch" in str(caught.value)


def test_validly_signed_broken_parent_hash_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, bad_parent_at=1)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "receipt_chain_invalid"
    assert "parent_receipt_hash mismatch" in str(caught.value)


def test_invalid_receipt_signature_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    token = bundle["journal"][1]["receipt_jwt"]
    bundle["journal"][1]["receipt_jwt"] = "A" + token[1:]
    _rewrite(fixture, bundle)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "receipt_chain_invalid"
    assert "signature/schema invalid" in str(caught.value)


def test_failed_inclusion_proof_is_specific(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    proof = bundle["journal"][1]["transparency_anchor"]["evidence"]["verification"][
        "inclusion_proof"
    ]
    proof["root_hash"] = "0" * 64
    _rewrite(fixture, bundle)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "anchor_verification_failed"
    assert caught.value.index == 1


def test_receiver_substitution_fails_exact_binding(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    bundle["journal"][1]["receiver_attestation"] = copy.deepcopy(
        bundle["journal"][0]["receiver_attestation"]
    )
    _rewrite(fixture, bundle)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "receiver_receipt_mismatch"
    assert caught.value.index == 1


def test_receiver_signature_failure_is_specific(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    attestation = bundle["journal"][2]["receiver_attestation"]["receiver_attestation"]
    token = attestation["statement_jws"]
    header, payload, signature = token.split(".")
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    attestation["statement_jws"] = ".".join((header, payload, signature))
    _rewrite(fixture, bundle)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "receiver_verification_failed"
    assert caught.value.index == 2


def test_missing_sidecar_and_embedded_trust_root_fail_schema(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    missing = copy.deepcopy(fixture["bundle"])
    del missing["journal"][0]["transparency_anchor"]
    _rewrite(fixture, missing)
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(fixture["path"])
    assert caught.value.code == "bundle_schema_invalid"

    embedded = copy.deepcopy(fixture["bundle"])
    embedded["receipt_public_key_pem"] = "untrusted"
    _rewrite(fixture, embedded)
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(fixture["path"])
    assert caught.value.code == "bundle_schema_invalid"


def test_duplicate_json_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":"ardur.offline_verification_bundle.v0.1",'
        '"profile":"full-evidence","profile":"full-evidence","journal":[]}',
        encoding="utf-8",
    )
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(path)
    assert caught.value.code == "duplicate_json_key"


def test_unknown_bundle_schema_is_rejected_directly(tmp_path: Path) -> None:
    path = tmp_path / "unknown-bundle.json"
    path.write_text(
        json.dumps(
            {"schema_version": "ardur.offline_verification_bundle.v9", "journal": []}
        ),
        encoding="utf-8",
    )
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(path)
    assert caught.value.code == "unsupported_bundle_schema"


def test_deeply_nested_json_is_a_controlled_failure(tmp_path: Path) -> None:
    path = tmp_path / "recursive.json"
    nested = "[" * 2_000 + "0" + "]" * 2_000
    path.write_text(
        '{"schema_version":"ardur.offline_verification_bundle.v0.1",'
        f'"profile":"full-evidence","journal":{nested}}}',
        encoding="utf-8",
    )
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(path)
    assert caught.value.code in {"malformed_json", "bundle_schema_invalid"}


def test_bounded_loader_rejects_oversized_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversized.jsonl"
    path.write_text("header.payload.signature\n", encoding="utf-8")
    monkeypatch.setattr(offline, "MAX_INPUT_BYTES", 8)
    with pytest.raises(OfflineVerificationError) as caught:
        load_offline_input(path)
    assert caught.value.code == "input_size_invalid"


def test_timestamp_regression_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path, timestamps=(1_800_000_000, 1_799_999_999, 1_800_000_020)
    )
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "timestamp_regression"


def test_budget_increase_does_not_overclaim_authority_narrowing(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, budget_remaining=(9, 10, 9))
    report = _verify(fixture)

    authority = report["timeline"][1]["authority"]
    assert authority["narrowing_proven"] is False
    assert authority["budget_narrowed"] is False
    assert "remaining budget increased in tool_calls" in "; ".join(authority["why"])


def test_contradictory_signed_budget_fields_do_not_prove_narrowing(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, delta_remaining_after=(None, 7, 7))
    report = _verify(fixture)

    authority = report["timeline"][1]["authority"]
    assert authority["narrowing_proven"] is False
    assert authority["budget_narrowed"] is False
    assert "remaining_after contradicts budget_remaining" in "; ".join(authority["why"])


def test_full_profile_rejects_reused_receipt_and_log_key(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, reuse_receipt_as_log_key=True)
    with pytest.raises(OfflineVerificationError) as caught:
        _verify(fixture)
    assert caught.value.code == "trust_roots_not_distinct"


def test_cli_rejects_mode_specific_options_instead_of_ignoring_them(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert (
        cli_main(["verify", "--token", "header.payload.signature", "--chain-only"]) == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["error"] == "verify_option_invalid"

    assert (
        cli_main(
            [
                "verify",
                "--token",
                "header.payload.signature",
                "--max-bundle-age-s",
                "300",
            ]
        )
        == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["error"] == "verify_option_invalid"

    fixture = _fixture(tmp_path)
    keys = _write_public_keys(fixture, tmp_path)
    request = tmp_path / "request.json"
    request.write_text("{}", encoding="utf-8")
    assert (
        cli_main(
            [
                "verify",
                str(fixture["path"]),
                "--receipt-public-key",
                str(keys["receipt"]),
                "--mcp-request",
                str(request),
            ]
        )
        == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["error"] == "offline_mcp_input_invalid"


def test_no_key_fixture_persists_only_public_verifiable_artifacts(
    tmp_path: Path,
) -> None:
    output = tmp_path / "public-fixture"
    fixture_report = run_offline_verification_fixture(output, now=1_800_000_000)
    assert fixture_report["ok"] is True
    assert fixture_report["private_keys_persisted"] is False
    assert fixture_report["verification"]["result"] == "verified"
    assert fixture_report["verification"]["summary"]["receiver_attested_count"] == 2
    assert sorted(path.name for path in output.iterdir()) == sorted(
        fixture_report["artifacts"]
    )
    persisted = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore") for path in output.iterdir()
    )
    # Assemble PEM sentinels so the repository secret scanner does not mistake
    # these negative assertions for embedded private-key material.
    private_key_marker = "BEGIN " + "PRIVATE" + " KEY"
    ec_private_key_marker = "BEGIN EC " + "PRIVATE" + " KEY"
    assert private_key_marker not in persisted
    assert ec_private_key_marker not in persisted
    assert not any(path.is_dir() for path in output.iterdir())


def test_cli_no_key_fixture_is_immediately_verifiable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "public-fixture"
    assert cli_main(["offline-verification-fixture", "--output", str(output)]) == 0
    fixture_report = json.loads(capsys.readouterr().out)
    assert fixture_report["ok"] is True
    assert (
        cli_main(
            [
                "verify",
                str(output / "offline-verification-v0.1.json"),
                "--receipt-public-key",
                str(output / "offline-verification-v0.1-receipt-public.pem"),
                "--transparency-log-key",
                str(output / "offline-verification-v0.1-log-public.pem"),
                "--receiver-public-key",
                str(output / "offline-verification-v0.1-receiver-public.pem"),
                "--json",
            ]
        )
        == 0
    )
    verification = json.loads(capsys.readouterr().out)
    assert verification["result"] == "verified"
    assert verification["summary"]["receipt_count"] == 3


def test_committed_public_fixture_is_verifiable() -> None:
    root = Path(__file__).resolve().parents[2]
    fixture_dir = root / "docs/specs/fixtures"

    def load_public_key(role: str) -> Any:
        return serialization.load_pem_public_key(
            (fixture_dir / f"offline-verification-v0.1-{role}-public.pem").read_bytes()
        )

    report = offline.verify_offline_path(
        fixture_dir / "offline-verification-v0.1.json",
        receipt_public_key=load_public_key("receipt"),
        log_public_key=load_public_key("log"),
        receiver_public_key=load_public_key("receiver"),
    )

    assert report["result"] == "verified"
    assert report["summary"] == {
        "receipt_count": 3,
        "permit_count": 2,
        "deny_count": 1,
        "error_count": 0,
        "unknown_count": 0,
        "anchored_count": 3,
        "public_log_protocol_anchored_count": 0,
        "receiver_attested_count": 2,
        "authority_narrowing_steps": [1, 2],
    }


def _committed_report_inputs() -> tuple[Path, dict[str, Any]]:
    root = Path(__file__).resolve().parents[2]
    fixture_dir = root / "docs/specs/fixtures"

    def load_public_key(role: str) -> Any:
        return serialization.load_pem_public_key(
            (fixture_dir / f"offline-verification-v0.1-{role}-public.pem").read_bytes()
        )

    return fixture_dir, {
        "receipt_public_key": load_public_key("receipt"),
        "log_public_key": load_public_key("log"),
        "receiver_public_key": load_public_key("receiver"),
        # Mirror run_offline_verification_fixture()'s own call, so this test
        # regenerates the report exactly the way the generator does.
        "max_registration_delay_s": 60,
    }


def test_committed_report_fixture_matches_regenerated_report() -> None:
    """Diff the committed explorer report against freshly generated output.

    This is the drift gate. The committed fixture has already silently fallen
    behind once: ``summary.unknown_count`` is emitted by
    ``verify_offline_input`` but was missing from the checked-in JSON, so an
    external evaluator reading the published artifact could not tell whether
    unknown-verdict receipts were counted or simply not reported.

    ``verified_at`` is the verifier's own wall clock rather than a function of
    the committed bundle, so it is the one field checked for shape instead of
    value. Everything else -- including every timeline entry and every summary
    counter -- must match byte-for-byte after JSON decoding.
    """

    fixture_dir, keys = _committed_report_inputs()
    regenerated = offline.verify_offline_path(
        fixture_dir / "offline-verification-v0.1.json", **keys
    )
    committed = json.loads(
        (fixture_dir / "offline-verification-v0.1-report.json").read_text(
            encoding="utf-8"
        )
    )

    # Pop outside the assert: under ``python -O`` assert statements are stripped,
    # which would leave ``verified_at`` in both dicts and silently turn the
    # comparison below into a wall-clock equality check that can never hold.
    regenerated_verified_at = regenerated.pop("verified_at")
    committed_verified_at = committed.pop("verified_at")
    assert isinstance(regenerated_verified_at, int)
    assert isinstance(committed_verified_at, int)
    assert regenerated == committed


def test_committed_report_fixture_validates_against_public_schema() -> None:
    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "docs/specs/offline-verification-report-v0.1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    committed = json.loads(
        (root / "docs/specs/fixtures/offline-verification-v0.1-report.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(committed)) == []


def test_report_schema_rejects_a_report_missing_unknown_count() -> None:
    """The schema, not just the fixture diff, must reject the observed drift."""

    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "docs/specs/offline-verification-report-v0.1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    committed = json.loads(
        (root / "docs/specs/fixtures/offline-verification-v0.1-report.json").read_text(
            encoding="utf-8"
        )
    )
    del committed["summary"]["unknown_count"]

    errors = list(Draft202012Validator(schema).iter_errors(committed))
    assert errors and "unknown_count" in errors[0].message


def test_report_schema_rejects_a_report_missing_protocol_anchor_count() -> None:
    """A report must state its public-log-protocol anchor count, even when zero."""

    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "docs/specs/offline-verification-report-v0.1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    committed = json.loads(
        (root / "docs/specs/fixtures/offline-verification-v0.1-report.json").read_text(
            encoding="utf-8"
        )
    )
    del committed["summary"]["public_log_protocol_anchored_count"]

    errors = list(Draft202012Validator(schema).iter_errors(committed))
    assert errors and "public_log_protocol_anchored_count" in errors[0].message


def test_self_hosted_anchor_is_labeled_and_never_counts_as_external() -> None:
    """A c2sp-local-v1 anchor must be visibly operator-administered.

    Before this labeling existed, a report anchored by the operator's own
    self-hosted signed log was byte-indistinguishable from one anchored in an
    external log: the evidence block dropped the verified bundle's ``backend``
    and ``anchored_count`` counted both alike, so a gate for
    externally-bounded evidence could be satisfied by operator-held keys.
    """

    fixture_dir, keys = _committed_report_inputs()
    report = offline.verify_offline_path(
        fixture_dir / "offline-verification-v0.1.json", **keys
    )

    for item in report["timeline"]:
        transparency = item["evidence"]["transparency"]
        assert transparency["backend"] == "c2sp-local-v1"
        assert transparency["anchor_class"] == "self-hosted-log"
    assert report["summary"]["anchored_count"] == 3
    assert report["summary"]["public_log_protocol_anchored_count"] == 0
    assert (
        "3 of 3 valid anchors use the self-hosted signed log; a self-hosted "
        "log is operator-administered evidence and does not establish "
        "external anchoring"
    ) in report["limitations"]
    assert any(
        "only as independent as the out-of-band channel" in item
        for item in report["limitations"]
    )

    cli = offline.render_cli_report(report)
    assert "anchor=true [c2sp-local-v1/self-hosted-log]" in cli
    rendered = offline.render_html_report(report)
    assert "anchor backend: c2sp-local-v1 (self-hosted-log)" in rendered
    assert "Public-log protocol" in rendered


def test_rekor_anchor_is_not_presented_as_proof_of_external_anchoring(
    tmp_path: Path,
) -> None:
    """A rekor-v1 anchor built from local keys must not read as external.

    ``backend.kind`` is supplied by the presenter and only selects a
    verification branch. An operator who holds the receipt key and the pinned
    transparency-log key can therefore mint a bundle that declares
    ``rekor-v1`` without any log outside their deployment being contacted --
    the Rekor URL accepts any HTTPS host, and unlike the self-hosted branch
    the checkpoint origin is not pinned. The report must classify the
    mechanism without asserting the deployment.
    """

    receipt_key = ec.generate_private_key(ec.SECP256R1())
    receiver_key = ec.generate_private_key(ec.SECP256R1())
    log_key = ec.generate_private_key(ec.SECP256R1())
    timestamp = 1_800_000_000
    observed = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    event = PolicyEvent(
        timestamp=observed,
        step_id="step:rekor:0",
        actor="spiffe://fixture.ardur.dev/agent/reviewer",
        verifier_id="spiffe://fixture.ardur.dev/verifier",
        tool_name="read_file",
        arguments={"path": "workspace/item-0.txt"},
        action_class="read",
        target="workspace/item-0.txt",
        resource_family="filesystem",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="policy permit",
        passport_jti="grant:rekor-fixture",
        trace_id="trace:rekor-fixture",
        run_nonce="rekor_fixture_nonce_0123456789",
    )
    receipt = build_receipt(Decision.PERMIT, event, parent_receipt_hash=None)
    receipt.iat = timestamp
    receipt.exp = timestamp + 300
    token = sign_receipt(receipt, receipt_key)
    integrated_time = timestamp + 5

    def fake_transport(
        url: str, payload: bytes, timeout: float, max_bytes: int
    ) -> bytes:
        body = canonical_json_bytes(json.loads(payload))
        body_b64 = base64.b64encode(body).decode("ascii")
        root_hash = _hash_leaf(body)
        checkpoint = _signed_checkpoint(
            "rekor.fixture - 1234", 1, root_hash, log_key, signer_name="rekor.fixture"
        )
        set_payload = canonical_json_bytes(
            {
                "body": body_b64,
                "integratedTime": integrated_time,
                "logIndex": 0,
                "logID": "fixture-rekor-log-id",
            }
        )
        return canonical_json_bytes(
            {
                "fixture-entry": {
                    "body": body_b64,
                    "integratedTime": integrated_time,
                    "logID": "fixture-rekor-log-id",
                    "logIndex": 0,
                    "verification": {
                        "inclusionProof": {
                            "checkpoint": checkpoint,
                            "hashes": [],
                            "logIndex": 0,
                            "rootHash": root_hash.hex(),
                            "treeSize": 1,
                        },
                        "signedEntryTimestamp": base64.b64encode(
                            log_key.sign(set_payload, ec.ECDSA(hashes.SHA256()))
                        ).decode("ascii"),
                    },
                }
            }
        )

    anchor = RekorV1Backend(
        "http://127.0.0.1:3000",
        allow_insecure_loopback=True,
        transport=fake_transport,
    ).submit(
        pending_anchor_bundle(token, backend_kind=BACKEND_REKOR_V1),
        receipt_private_key=receipt_key,
    )
    shim = ReceiverAttestationShim(
        receiver_private_key=receiver_key,
        receipt_public_key=receipt_key.public_key(),
        receiver_id="spiffe://fixture.ardur.dev/tool",
        key_id="fixture-receiver:v1",
    )
    request = {
        "jsonrpc": "2.0",
        "id": "rekor-0",
        "method": "tools/call",
        "params": {
            "name": event.tool_name,
            "arguments": dict(event.arguments),
            "_meta": {MCP_RECEIPT_META_KEY: token},
        },
    }
    response = {
        "jsonrpc": "2.0",
        "id": "rekor-0",
        "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
    }
    attested = shim.attach_to_mcp_response(
        request=request, response=response, observed_at=timestamp + 1
    )
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "profile": "full-evidence",
        "journal": [
            {
                "receipt_jwt": token,
                "transparency_anchor": anchor,
                "receiver_attestation": attested["result"]["_meta"][
                    MCP_ATTESTATION_META_KEY
                ],
            }
        ],
    }

    bundle_path = tmp_path / "rekor-bundle.json"
    bundle_path.write_bytes(canonical_json_bytes(bundle) + b"\n")

    report = verify_offline_input(
        load_offline_input(bundle_path),
        receipt_public_key=receipt_key.public_key(),
        log_public_key=log_key.public_key(),
        receiver_public_key=receiver_key.public_key(),
        max_registration_delay_s=60,
    )

    transparency = report["timeline"][0]["evidence"]["transparency"]
    assert transparency["backend"] == BACKEND_REKOR_V1
    assert transparency["anchor_class"] == "public-log-protocol"
    assert report["summary"]["public_log_protocol_anchored_count"] == 1

    # Nothing in the artifact may call this externally anchored, and the
    # presenter-supplied nature of the backend kind must be disclosed.
    limitations = " ".join(report["limitations"])
    assert "declare the rekor-v1 backend" in limitations
    assert "supplied by the presenter" in limitations
    assert "outside the operator's deployment was contacted" in limitations
    assert "only as independent as the out-of-band channel" in limitations
    assert "external-log" not in json.dumps(report)


def test_anchor_class_covers_every_backend_the_verifier_accepts() -> None:
    """Every backend verify_anchor_bundle can emit must carry a class label.

    verify_anchor_bundle rejects unknown backend kinds, so this mapping and
    that check must move together; an anchor backend without a class would
    fail the closed report schema at the return site.
    """

    assert set(offline._ANCHOR_BACKEND_CLASSES) == set(ANCHORED_BACKEND_KINDS)
    assert offline._ANCHOR_BACKEND_CLASSES[BACKEND_LOCAL_SIGNED] == "self-hosted-log"
    assert offline._ANCHOR_BACKEND_CLASSES[BACKEND_REKOR_V1] == "public-log-protocol"


def test_report_schema_is_closed_against_an_unexpected_field() -> None:
    fixture_dir, keys = _committed_report_inputs()
    report = offline.verify_offline_path(
        fixture_dir / "offline-verification-v0.1.json", **keys
    )
    report["timeline"][0]["surprise_field"] = "drift"

    with pytest.raises(OfflineVerificationError) as excinfo:
        offline._validate_report(report)
    assert excinfo.value.code == "report_schema_invalid"


def test_report_schema_accepts_chain_only_and_correlation_paths() -> None:
    """The schema must cover every shape verify_offline_input actually emits."""

    fixture_dir, keys = _committed_report_inputs()
    bundle = fixture_dir / "offline-verification-v0.1.json"

    chain_only = offline.verify_offline_input(
        offline.load_offline_input(bundle),
        receipt_public_key=keys["receipt_public_key"],
        chain_only=True,
        include_correlation_fields=True,
    )
    assert chain_only["result"] == "verified_chain_only"
    assert chain_only["assurance_profile"] == "chain-only"
    assert chain_only["timeline"][0]["evidence"]["receiver"]["status"] == "absent"
    assert "trace_id" in chain_only["timeline"][0]

    unredacted = offline.verify_offline_path(bundle, redact=False, **keys)
    assert unredacted["redaction"]["enabled"] is False
    assert unredacted["freshness"]["one_time_replay_checked"] is False

    # The age-bounded freshness shape (``age_checked`` true, integer
    # ``age_s``/``max_age_s``) cannot be exercised against this fixture -- its
    # receipts are dated 2027, so any age check fails closed as future-dated.
    # That shape is covered by the freshness tests earlier in this module,
    # which now also run through the report schema.


def test_public_and_embedded_report_schemas_are_identical() -> None:
    root = Path(__file__).resolve().parents[2]
    public = json.loads(
        (root / "docs/specs/offline-verification-report-v0.1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    embedded = json.loads(
        (
            root / "python/vibap/_specs/offline_verification_report_v01.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert public == embedded


def test_public_and_embedded_schemas_are_identical() -> None:
    root = Path(__file__).resolve().parents[2]
    public = json.loads(
        (root / "docs/specs/offline-verification-bundle-v0.1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    embedded = json.loads(
        (
            root / "python/vibap/_specs/offline_verification_bundle_v01.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert public == embedded


# --- --output validation (empty / whitespace / existing-file / symlink) ---


def test_offline_fixture_output_existing_regular_file_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_file = tmp_path / "existing-file.txt"
    existing_file.write_text("not a directory", encoding="utf-8")

    code = cli_main(["offline-verification-fixture", "--output", str(existing_file)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_output_not_directory"
    assert report["condition"] == "offline_verification_fixture_output_not_directory"
    assert "[Errno" not in captured.out
    assert str(existing_file) not in captured.out
    assert str(existing_file) not in json.dumps(report)
    assert report["next_steps"]
    assert all(
        "<" in step["command"] and ">" in step["command"]
        for step in report["next_steps"]
    )


def test_offline_fixture_output_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["offline-verification-fixture", "--output", ""])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_output_empty"
    assert report["condition"] == "offline_verification_fixture_output_empty"
    assert report["next_steps"]
    assert not any(tmp_path.iterdir()), "no fixtures written to CWD on empty --output"


def test_offline_fixture_output_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["offline-verification-fixture", "--output", "   "])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_output_empty"
    assert report["condition"] == "offline_verification_fixture_output_empty"
    assert report["next_steps"]
    assert not any(tmp_path.iterdir()), (
        "no fixtures written on whitespace-only --output"
    )


def test_offline_fixture_output_validation_raises_specialized_error(
    tmp_path: Path,
) -> None:
    existing_file = tmp_path / "blocking-file"
    existing_file.write_text("x", encoding="utf-8")

    with pytest.raises(OfflineVerificationFixtureOutputError) as exc_info:
        run_offline_verification_fixture(existing_file)
    assert (
        exc_info.value.condition == "offline_verification_fixture_output_not_directory"
    )
    assert str(existing_file) not in exc_info.value.detail

    with pytest.raises(OfflineVerificationFixtureOutputError) as empty_info:
        run_offline_verification_fixture("")
    assert empty_info.value.condition == "offline_verification_fixture_output_empty"


def test_offline_fixture_output_directory_symlink_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    symlink_dir = tmp_path / "symlink-dir"
    symlink_dir.symlink_to(real_dir)

    code = cli_main(["offline-verification-fixture", "--output", str(symlink_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_output_symlink"
    assert report["condition"] == "offline_verification_fixture_output_symlink"
    assert str(symlink_dir) not in json.dumps(report)


def test_offline_fixture_output_dangling_symlink_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dangling = tmp_path / "dangling-dir"
    dangling.symlink_to(tmp_path / "nonexistent-target")

    code = cli_main(["offline-verification-fixture", "--output", str(dangling)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_output_symlink"
    assert report["condition"] == "offline_verification_fixture_output_symlink"


def test_offline_fixture_output_valid_new_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    new_dir = tmp_path / "fresh-output-dir"

    code = cli_main(["offline-verification-fixture", "--output", str(new_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (new_dir / "offline-verification-v0.1-report.json").is_file()


def test_offline_fixture_output_existing_empty_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_dir = tmp_path / "existing-dir"
    existing_dir.mkdir()

    code = cli_main(["offline-verification-fixture", "--output", str(existing_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (existing_dir / "offline-verification-v0.1-report.json").is_file()


def test_offline_fixture_oserror_does_not_leak_path(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """OSError from fixture generation must not leak raw path/errno into JSON."""
    leak_path = str(tmp_path / "leaked-readonly" / "test.json")

    def raise_oserror(output: object) -> dict:
        raise OSError(13, "Permission denied", leak_path)

    monkeypatch.setattr(
        "vibap.offline_verification_fixture.run_offline_verification_fixture",
        raise_oserror,
    )

    code = cli_main(["offline-verification-fixture", "--output", str(tmp_path)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_failed"
    assert "[Errno" not in captured.out
    assert "[Errno" not in json.dumps(report)
    assert leak_path not in captured.out
    assert leak_path not in json.dumps(report)
    assert "/var/folders" not in json.dumps(report)


def test_offline_fixture_typeerror_does_not_leak_internals(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """TypeError from fixture generation must not leak raw exception text."""
    sentinel = "cannot unpack non-iterable NoneType object"

    def raise_typeerror(output: object) -> dict:
        raise TypeError(sentinel)

    monkeypatch.setattr(
        "vibap.offline_verification_fixture.run_offline_verification_fixture",
        raise_typeerror,
    )

    code = cli_main(["offline-verification-fixture", "--output", str(tmp_path)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_failed"
    assert sentinel not in json.dumps(report)
    assert "NoneType" not in json.dumps(report)


def test_offline_fixture_valueerror_does_not_leak_internals(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ValueError from fixture generation must not leak raw exception text."""
    sentinel = "invalid literal for int() with base 10: 'secret-data'"

    def raise_valueerror(output: object) -> dict:
        raise ValueError(sentinel)

    monkeypatch.setattr(
        "vibap.offline_verification_fixture.run_offline_verification_fixture",
        raise_valueerror,
    )

    code = cli_main(["offline-verification-fixture", "--output", str(tmp_path)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_failed"
    assert sentinel not in json.dumps(report)
    assert "secret-data" not in json.dumps(report)


def test_module_main_oserror_does_not_leak_path(tmp_path: Path) -> None:
    """``python -m vibap.offline_verification_fixture`` OSError sanitization.

    Regression for the module-level ``__main__`` entrypoint: an ``OSError``
    raised during fixture generation (here: ``mkdir`` blocked by a regular
    file on the parent path) must be reported as a constant safe message and
    must never leak ``[Errno ...]`` / raw filesystem paths / ``Traceback``
    into stdout or stderr.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    bad_output = str(blocker / "sub" / "dir")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vibap.offline_verification_fixture",
            "--output",
            bad_output,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is False
    assert report["error"] == "offline_verification_fixture_failed"
    assert report["message"] == "Filesystem error writing fixture output."
    combined = result.stdout + result.stderr
    assert "/var/folders" not in combined
    assert "/tmp/" not in combined
    assert "Errno" not in combined
    assert str(tmp_path) not in combined
    assert str(bad_output) not in combined
