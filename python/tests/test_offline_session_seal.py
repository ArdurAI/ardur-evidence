"""A signed session seal lets the offline verifier detect a journal cut short.

A hash-linked receipt chain exposes a receipt removed from its start or middle,
but a journal truncated after any receipt is still a valid chain. The session
attestation names the final receipt (``receipt_chain_head``); these tests pin
that ``--seal`` turns a truncated or extended journal into a hard failure, and
that a report without a seal says so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap import attestation as attestation_module
from vibap import cli as cli_module
from vibap import offline_verification as offline
from vibap.attestation import issue_attestation
from vibap.passport import issue_passport
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt

BASE_TS = 1_800_000_000


def _receipts(key: ec.EllipticCurvePrivateKey, count: int) -> list[tuple[str, str]]:
    """Return (jwt, receipt_id) pairs forming one hash-linked chain."""

    chain: list[tuple[str, str]] = []
    previous: str | None = None
    for index in range(count):
        timestamp = BASE_TS + 10 * index
        event = PolicyEvent(
            timestamp=datetime.fromtimestamp(timestamp, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            step_id=f"step:seal:{index}",
            actor="spiffe://fixture.ardur.dev/agent/sealer",
            verifier_id="spiffe://fixture.ardur.dev/verifier",
            tool_name="read_file",
            arguments={"path": f"workspace/item-{index}.txt"},
            action_class="read",
            target=f"workspace/item-{index}.txt",
            resource_family="filesystem",
            side_effect_class="none",
            decision=Decision.PERMIT,
            reason="within scope",
            passport_jti="grant:seal-fixture",
            trace_id="trace:seal-fixture",
            run_nonce="seal_fixture_nonce_0123456789",
        )
        receipt = build_receipt(
            Decision.PERMIT,
            event,
            parent_receipt_hash=(
                hashlib.sha256(previous.encode("ascii")).hexdigest()
                if previous is not None
                else None
            ),
            policy_decisions=[
                {"backend": "native", "decision": "Allow", "reason": "within scope"}
            ],
            budget_remaining={"tool_calls": 10 - index},
        )
        receipt.iat = timestamp
        receipt.exp = timestamp + 300
        token = sign_receipt(receipt, key)
        chain.append((token, receipt.receipt_id))
        previous = token
    return chain


def _seal(
    key: ec.EllipticCurvePrivateKey,
    final: tuple[str, str] | None,
    *,
    receipt_id: str | None = None,
) -> str:
    extra: dict[str, Any] = {}
    if final is not None:
        token, final_id = final
        extra["receipt_chain_head"] = {
            "hash_algorithm": "sha-256",
            "receipt_id": receipt_id or final_id,
            "receipt_jwt_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        }
    return issue_attestation(
        passport_jti="grant:seal-fixture",
        agent_id="spiffe://fixture.ardur.dev/agent/sealer",
        mission="session seal fixture",
        events=[],
        permits=3,
        denials=0,
        elapsed_s=1.0,
        private_key=key,
        extra_claims=extra,
    )


def _journal(tmp_path: Path, tokens: list[str], name: str = "receipts.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(tokens) + "\n", encoding="utf-8")
    return path


def _verify(path: Path, key: ec.EllipticCurvePrivateKey, **kwargs: Any) -> dict[str, Any]:
    return offline.verify_offline_input(
        offline.load_offline_input(path),
        receipt_public_key=key.public_key(),
        chain_only=True,
        **kwargs,
    )


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_seal_naming_the_final_receipt_verifies_and_is_reported(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 3)
    report = _verify(
        _journal(tmp_path, [token for token, _ in chain]),
        key,
        session_seal=_seal(key, chain[-1]),
    )

    assert report["session_seal"] == {"checked": True, "chain_head_matches": True}
    assert offline.SESSION_SEAL_ABSENT_LIMITATION not in report["limitations"]
    assert "Session seal: checked" in offline.render_cli_report(report)
    assert "Session seal: checked" in offline.render_html_report(report)


def test_report_without_a_seal_discloses_the_tail_gap(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 3)
    report = _verify(_journal(tmp_path, [token for token, _ in chain]), key)

    assert "session_seal" not in report
    assert offline.SESSION_SEAL_ABSENT_LIMITATION in report["limitations"]


def test_seal_rejects_a_journal_with_its_final_receipt_removed(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 3)
    truncated = _journal(tmp_path, [token for token, _ in chain[:-1]])

    # The gap this closes: without a seal, the shortened journal still verifies.
    assert _verify(truncated, key)["summary"]["receipt_count"] == 2

    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(truncated, key, session_seal=_seal(key, chain[-1]))
    assert caught.value.code == "receipt_chain_head_mismatch"


def test_seal_rejects_a_receipt_appended_after_the_sealed_head(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 3)
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(
            _journal(tmp_path, [token for token, _ in chain]),
            key,
            session_seal=_seal(key, chain[1]),
        )
    assert caught.value.code == "receipt_chain_head_mismatch"


def test_seal_must_name_the_final_receipt_id_as_well_as_its_hash(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 2)
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(
            _journal(tmp_path, [token for token, _ in chain]),
            key,
            session_seal=_seal(key, chain[-1], receipt_id="receipt:someone-else"),
        )
    assert caught.value.code == "receipt_chain_head_mismatch"


def test_seal_without_a_chain_head_is_rejected(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 2)
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(
            _journal(tmp_path, [token for token, _ in chain]),
            key,
            session_seal=_seal(key, None),
        )
    assert caught.value.code == "session_seal_missing_chain_head"


def test_seal_signed_by_another_key_is_rejected(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 2)
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(
            _journal(tmp_path, [token for token, _ in chain]),
            key,
            session_seal=_seal(other, chain[-1]),
        )
    assert caught.value.code == "session_seal_invalid"


def test_old_expired_seal_still_verifies_for_archival_replay(
    tmp_path: Path,
    key: ec.EllipticCurvePrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain = _receipts(key, 2)
    four_hundred_days = 400 * 86_400
    with monkeypatch.context() as patched:
        patched.setattr(
            attestation_module.time,
            "time",
            lambda: float(BASE_TS - four_hundred_days),
        )
        old_seal = _seal(key, chain[-1])
    journal = _journal(tmp_path, [token for token, _ in chain])

    assert _verify(journal, key, session_seal=old_seal)["session_seal"]["checked"]
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(journal, key, session_seal=old_seal, verify_expiry=True)
    assert caught.value.code == "session_seal_invalid"


def test_real_proxy_session_journal_and_seal_verify_together(
    proxy, example_mission, private_key, tmp_path: Path
) -> None:
    """The reference proxy's own receipts log and attestation work with --seal."""

    session = proxy.start_session(issue_passport(example_mission, private_key, ttl_s=60))
    calls = (
        ("read_file", {"path": "README.md"}, Decision.PERMIT),
        ("delete_file", {"path": "README.md"}, Decision.DENY),
        ("analyze", {"input": "q1"}, Decision.PERMIT),
    )
    for tool, arguments, expected in calls:
        decision, _reason = proxy.evaluate_tool_call(session, tool, arguments)
        assert decision == expected
    seal, _claims = proxy.issue_attestation_for_session(
        session.jti, proxy.receipt_private_key
    )
    receipt_key = proxy.receipt_private_key

    report = _verify(proxy.receipts_log_path, receipt_key, session_seal=seal)
    assert report["session_seal"]["chain_head_matches"] is True
    assert report["summary"]["receipt_count"] == 3
    assert report["summary"]["deny_count"] == 1

    lines = proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
    truncated = tmp_path / "proxy-truncated.jsonl"
    truncated.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(offline.OfflineVerificationError) as caught:
        _verify(truncated, receipt_key, session_seal=seal)
    assert caught.value.code == "receipt_chain_head_mismatch"


def test_seal_file_must_hold_exactly_one_token(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    chain = _receipts(key, 1)
    seal = _seal(key, chain[-1])
    single = tmp_path / "seal.jwt"
    single.write_text(seal + "\n", encoding="ascii")
    assert offline.load_session_seal(single) == seal

    double = tmp_path / "two-seals.jwt"
    double.write_text(f"{seal}\n{seal}\n", encoding="ascii")
    with pytest.raises(offline.OfflineVerificationError) as caught:
        offline.load_session_seal(double)
    assert caught.value.code == "session_seal_invalid"


def _cli_inputs(tmp_path: Path, key: ec.EllipticCurvePrivateKey) -> dict[str, Path]:
    chain = _receipts(key, 3)
    public_key = tmp_path / "receipt-public.pem"
    public_key.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    seal = tmp_path / "seal.jwt"
    seal.write_text(_seal(key, chain[-1]) + "\n", encoding="ascii")
    return {
        "key": public_key,
        "seal": seal,
        "full": _journal(tmp_path, [token for token, _ in chain], "full.jsonl"),
        "truncated": _journal(
            tmp_path, [token for token, _ in chain[:-1]], "truncated.jsonl"
        ),
    }


def test_cli_seal_flag_accepts_the_sealed_journal_and_rejects_a_truncated_one(
    tmp_path: Path,
    key: ec.EllipticCurvePrivateKey,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _cli_inputs(tmp_path, key)
    base = ["--chain-only", "--receipt-public-key", str(paths["key"]), "--seal"]

    assert cli_module.main(["verify", str(paths["full"]), *base, str(paths["seal"]), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["session_seal"]["chain_head_matches"] is True

    assert (
        cli_module.main(
            ["verify", str(paths["truncated"]), *base, str(paths["seal"]), "--json"]
        )
        == 1
    )
    failure = json.loads(capsys.readouterr().out)
    assert failure["valid"] is False
    assert "receipt_chain_head_mismatch" in json.dumps(failure)


def test_cli_seal_flag_requires_a_journal(
    tmp_path: Path,
    key: ec.EllipticCurvePrivateKey,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _cli_inputs(tmp_path, key)
    assert (
        cli_module.main(["verify", "--token", "not-a-token", "--seal", str(paths["seal"])])
        == 1
    )
    assert json.loads(capsys.readouterr().out)["error"] == "verify_option_invalid"
