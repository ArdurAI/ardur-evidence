from __future__ import annotations

import base64
import copy
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jsonschema import Draft202012Validator

from vibap.canonical_json import canonical_json_bytes
from vibap.cli import main as cli_main
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import assert_receipt_shaped, build_receipt, sign_receipt
from vibap.transparency import (
    BACKEND_LOCAL_SIGNED,
    BACKEND_REKOR_V1,
    AnchorVerificationError,
    LocalSignedLogBackend,
    RekorV1Backend,
    TransparencyError,
    _hash_leaf,
    _signed_checkpoint,
    anchor_store_for_receipt_log,
    drain_anchor_store,
    load_anchor_bundle,
    pending_anchor_bundle,
    queue_receipt_anchor,
    queue_receipt_anchor_best_effort,
    verify_anchor_bundle,
)


def _signed_receipt(
    *, now: int = 1_800_000_000
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    timestamp = (
        datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    )
    event = PolicyEvent(
        timestamp=timestamp,
        step_id="step:transparency-fixture",
        actor="spiffe://example.test/agent",
        verifier_id="spiffe://example.test/ardur",
        tool_name="read_file",
        arguments={"path": "README.md"},
        action_class="read",
        target="README.md",
        resource_family="filesystem",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="fixture permit",
        passport_jti="passport:transparency-fixture",
        trace_id="trace:transparency-fixture",
        run_nonce="fixture_nonce_0123456789",
    )
    receipt = build_receipt(Decision.PERMIT, event)
    receipt.iat = now
    receipt.exp = now + 300
    return sign_receipt(receipt, private_key), private_key


def test_receipt_sink_queues_one_idempotent_pending_sidecar(tmp_path: Path) -> None:
    token, _ = _signed_receipt()
    receipt_log = tmp_path / "receipts.jsonl"

    first = queue_receipt_anchor(token, receipt_log)
    second = queue_receipt_anchor(token, receipt_log)

    assert first == second
    assert first.parent == anchor_store_for_receipt_log(receipt_log) / "pending"
    bundle = load_anchor_bundle(first)
    assert bundle["status"] == "pending"
    assert bundle["receipt_jwt"] == token
    assert bundle["subject"]["digest"]["value"]


def test_queue_failure_never_escapes_the_governance_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, _ = _signed_receipt()

    def fail_queue(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError("read-only anchor volume")

    monkeypatch.setattr("vibap.transparency.queue_receipt_anchor", fail_queue)
    assert queue_receipt_anchor_best_effort(token, "/read-only/receipts.jsonl") is False


def test_local_signed_log_anchor_verifies_fully_offline(tmp_path: Path) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ed25519.Ed25519PrivateKey.generate()
    backend = LocalSignedLogBackend(
        tmp_path / "operator-log.jsonl",
        log_key,
        origin="operator.example/ardur-receipts",
        clock=lambda: claims["iat"] + 5,
    )

    anchored = backend.submit(
        pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED),
    )
    report = verify_anchor_bundle(
        anchored,
        receipt_public_key=receipt_key.public_key(),
        log_public_key=log_key.public_key(),
        max_registration_delay_s=60,
    )

    assert report["valid"] is True
    assert report["backend"] == BACKEND_LOCAL_SIGNED
    assert report["registration_delay_s"] == 5
    assert report["tree_size"] == 1


def test_changed_receipt_bytes_fail_exact_subject_binding(tmp_path: Path) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ed25519.Ed25519PrivateKey.generate()
    anchored = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        log_key,
        origin="operator.example/log",
        clock=lambda: claims["iat"] + 1,
    ).submit(pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED))
    tampered = copy.deepcopy(anchored)
    tampered["receipt_jwt"] = token[:-1] + ("A" if token[-1] != "A" else "B")

    with pytest.raises(AnchorVerificationError, match="exact receipt JWT"):
        verify_anchor_bundle(
            tampered,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
        )


def test_anchor_identity_and_backend_metadata_are_bound(tmp_path: Path) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ed25519.Ed25519PrivateKey.generate()
    anchored = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        log_key,
        origin="operator.example/log",
        clock=lambda: claims["iat"] + 1,
    ).submit(pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED))

    bad_id = copy.deepcopy(anchored)
    bad_id["anchor_id"] = f"anchor:{'0' * 64}"
    with pytest.raises(AnchorVerificationError, match="anchor id"):
        verify_anchor_bundle(
            bad_id,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
        )

    bad_time = copy.deepcopy(anchored)
    bad_time["anchored_at"] += 1
    with pytest.raises(AnchorVerificationError, match="anchor time"):
        verify_anchor_bundle(
            bad_time,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
        )

    bad_log = copy.deepcopy(anchored)
    bad_log["backend"]["log_id"] = "other.example/log"
    with pytest.raises(AnchorVerificationError, match="backend log id"):
        verify_anchor_bundle(
            bad_log,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
        )


def test_wrong_log_key_and_padded_merkle_path_fail_closed(tmp_path: Path) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ed25519.Ed25519PrivateKey.generate()
    anchored = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        log_key,
        origin="operator.example/log",
        clock=lambda: claims["iat"] + 1,
    ).submit(pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED))

    with pytest.raises(AnchorVerificationError, match="trusted log key"):
        verify_anchor_bundle(
            anchored,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=ed25519.Ed25519PrivateKey.generate().public_key(),
        )

    padded = copy.deepcopy(anchored)
    padded["evidence"]["verification"]["inclusion_proof"]["hashes"].append("00" * 32)
    with pytest.raises(AnchorVerificationError, match="extra sibling"):
        verify_anchor_bundle(
            padded,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
        )


def test_backdated_receipt_fails_configured_registration_window(tmp_path: Path) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ed25519.Ed25519PrivateKey.generate()
    anchored = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        log_key,
        origin="operator.example/log",
        clock=lambda: claims["iat"] + 3_601,
    ).submit(pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED))

    with pytest.raises(AnchorVerificationError, match="maximum registration delay"):
        verify_anchor_bundle(
            anchored,
            receipt_public_key=receipt_key.public_key(),
            log_public_key=log_key.public_key(),
            max_registration_delay_s=3_600,
        )


def test_rekor_hashedrekord_request_and_returned_proof_verify_offline() -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    log_key = ec.generate_private_key(ec.SECP256R1())
    integrated_time = claims["iat"] + 7
    log_id = "fixture-rekor-log-id"

    def fake_transport(
        url: str, payload: bytes, timeout: float, max_bytes: int
    ) -> bytes:
        assert url == "http://127.0.0.1:3000/api/v1/log/entries"
        assert timeout > 0
        assert len(payload) < max_bytes
        proposal = json.loads(payload)
        assert proposal["kind"] == "hashedrekord"
        assert proposal["spec"]["data"]["hash"]["algorithm"] == "sha256"
        body = canonical_json_bytes(proposal)
        body_b64 = base64.b64encode(body).decode("ascii")
        root_hash = _hash_leaf(body)
        checkpoint = _signed_checkpoint(
            "rekor.fixture - 1234",
            1,
            root_hash,
            log_key,
            signer_name="rekor.fixture",
        )
        set_payload = canonical_json_bytes(
            {
                "body": body_b64,
                "integratedTime": integrated_time,
                "logIndex": 0,
                "logID": log_id,
            }
        )
        signed_entry_timestamp = log_key.sign(set_payload, ec.ECDSA(hashes.SHA256()))
        response = {
            "fixture-entry": {
                "body": body_b64,
                "integratedTime": integrated_time,
                "logID": log_id,
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
                        signed_entry_timestamp
                    ).decode("ascii"),
                },
            }
        }
        return canonical_json_bytes(response)

    backend = RekorV1Backend(
        "http://127.0.0.1:3000",
        allow_insecure_loopback=True,
        transport=fake_transport,
    )
    anchored = backend.submit(
        pending_anchor_bundle(token, backend_kind=BACKEND_REKOR_V1),
        receipt_private_key=receipt_key,
    )
    report = verify_anchor_bundle(
        anchored,
        receipt_public_key=receipt_key.public_key(),
        log_public_key=log_key.public_key(),
        max_registration_delay_s=60,
    )

    assert report["valid"] is True
    assert report["backend"] == BACKEND_REKOR_V1
    assert report["registration_delay_s"] == 7


def test_rekor_refuses_invalid_receipt_before_transport() -> None:
    token, receipt_key = _signed_receipt()
    header, payload, signature = token.split(".")
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = ".".join((header, payload, signature))

    def transport_must_not_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("invalid receipt must not reach Rekor transport")

    backend = RekorV1Backend(transport=transport_must_not_run)
    with pytest.raises(
        TransparencyError, match="refusing to submit an invalid receipt"
    ):
        backend.submit(
            pending_anchor_bundle(tampered, backend_kind=BACKEND_REKOR_V1),
            receipt_private_key=receipt_key,
        )


def test_rekor_refuses_unbound_response_before_promotion() -> None:
    token, receipt_key = _signed_receipt()

    def fake_transport(
        url: str, payload: bytes, timeout: float, max_bytes: int
    ) -> bytes:
        del url, timeout, max_bytes
        proposal = json.loads(payload)
        proposal["spec"]["data"]["hash"]["value"] = "0" * 64
        body = canonical_json_bytes(proposal)
        response = {
            "unbound-entry": {
                "body": base64.b64encode(body).decode("ascii"),
                "integratedTime": 1_800_000_001,
                "logID": "fixture-log",
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {
                        "checkpoint": "placeholder",
                        "hashes": [],
                        "logIndex": 0,
                        "rootHash": ("00" * 32),
                        "treeSize": 1,
                    },
                    "signedEntryTimestamp": base64.b64encode(b"placeholder").decode(
                        "ascii"
                    ),
                },
            }
        }
        return canonical_json_bytes(response)

    backend = RekorV1Backend(
        "http://127.0.0.1:3000",
        allow_insecure_loopback=True,
        transport=fake_transport,
    )
    with pytest.raises(AnchorVerificationError, match="digest does not match"):
        backend.submit(
            pending_anchor_bundle(token, backend_kind=BACKEND_REKOR_V1),
            receipt_private_key=receipt_key,
        )


def test_drain_keeps_network_failures_pending_and_moves_successes(
    tmp_path: Path,
) -> None:
    token, receipt_key = _signed_receipt()
    claims = jwt.decode(token, options={"verify_signature": False})
    receipt_log = tmp_path / "receipts.jsonl"
    pending = queue_receipt_anchor(
        token, receipt_log, backend_kind=BACKEND_LOCAL_SIGNED
    )
    store = anchor_store_for_receipt_log(receipt_log)

    class FailingBackend:
        def submit(self, pending_bundle, *, receipt_private_key=None):  # type: ignore[no-untyped-def]
            raise TransparencyError("log unavailable")

    failed = drain_anchor_store(
        store, FailingBackend(), receipt_private_key=receipt_key
    )
    assert failed[0].status == "pending"
    assert pending.exists()

    log_key = ed25519.Ed25519PrivateKey.generate()
    backend = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        log_key,
        origin="operator.example/log",
        clock=lambda: claims["iat"] + 1,
    )
    succeeded = drain_anchor_store(store, backend, receipt_private_key=receipt_key)
    assert succeeded[0].status == "anchored"
    assert not pending.exists()
    assert succeeded[0].path.exists()


def test_local_log_public_key_round_trips_as_standard_pem() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert b"BEGIN PUBLIC KEY" in public_pem


def test_local_backend_fails_explicitly_without_posix_locking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, _ = _signed_receipt()
    backend = LocalSignedLogBackend(
        tmp_path / "log.jsonl",
        ed25519.Ed25519PrivateKey.generate(),
        origin="operator.example/log",
    )
    monkeypatch.setattr(sys.modules["vibap.transparency"], "fcntl", None)

    with pytest.raises(TransparencyError, match="POSIX file locking"):
        backend.submit(pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED))


def test_rekor_cli_requires_existing_key_without_creating_one(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token, _ = _signed_receipt()
    receipt_log = tmp_path / "receipts.jsonl"
    receipt_log.write_text(token + "\n", encoding="utf-8")
    queue_receipt_anchor(token, receipt_log, backend_kind=BACKEND_REKOR_V1)
    missing_keys = tmp_path / "missing-keys"

    assert (
        cli_main(
            [
                "anchor",
                "--receipt-log",
                str(receipt_log),
                "--backend",
                BACKEND_REKOR_V1,
                "--keys-dir",
                str(missing_keys),
                "--rekor-url",
                "https://example.invalid",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().out)
    assert output["error"] == "anchor_submission_failed"
    assert "passport_private.pem is missing" in output["message"]
    assert not missing_keys.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-key mode contract")
def test_rekor_cli_rejects_loose_existing_private_key_before_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token, receipt_key = _signed_receipt()
    receipt_log = tmp_path / "receipts.jsonl"
    receipt_log.write_text(token + "\n", encoding="utf-8")
    queue_receipt_anchor(token, receipt_log, backend_kind=BACKEND_REKOR_V1)
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    private_path = keys_dir / "passport_private.pem"
    private_bytes = receipt_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_path.write_bytes(private_bytes)
    private_path.chmod(0o644)

    assert (
        cli_main(
            [
                "anchor",
                "--receipt-log",
                str(receipt_log),
                "--backend",
                BACKEND_REKOR_V1,
                "--keys-dir",
                str(keys_dir),
                "--rekor-url",
                "https://example.invalid",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().out)
    assert output["error"] == "anchor_submission_failed"
    assert "mode 0600" in output["message"]
    assert private_path.read_bytes() == private_bytes


def test_cli_drains_and_verifies_local_anchor_without_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token, receipt_key = _signed_receipt(now=int(time.time()))
    receipt_log = tmp_path / "receipts.jsonl"
    receipt_log.write_text(token + "\n", encoding="utf-8")
    queue_receipt_anchor(token, receipt_log, backend_kind=BACKEND_LOCAL_SIGNED)

    keys_dir = tmp_path / "receipt-keys"
    keys_dir.mkdir()
    (keys_dir / "passport_public.pem").write_bytes(
        receipt_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    log_key = ed25519.Ed25519PrivateKey.generate()
    log_private_path = tmp_path / "log-private.pem"
    log_public_path = tmp_path / "log-public.pem"
    log_private_path.write_bytes(
        log_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    log_private_path.chmod(0o600)
    log_public_path.write_bytes(
        log_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    assert (
        cli_main(
            [
                "anchor",
                "--receipt-log",
                str(receipt_log),
                "--backend",
                BACKEND_LOCAL_SIGNED,
                "--local-log",
                str(tmp_path / "operator-log.jsonl"),
                "--log-private-key",
                str(log_private_path),
                "--origin",
                "operator.example/ardur",
            ]
        )
        == 0
    )
    anchor_output = json.loads(capsys.readouterr().out)
    assert anchor_output["ok"] is True
    assert anchor_output["anchored"] == 1
    bundle_path = Path(anchor_output["results"][0]["path"])

    assert (
        cli_main(
            [
                "verify",
                "--anchor-bundle",
                str(bundle_path),
                "--keys-dir",
                str(keys_dir),
                "--transparency-log-key",
                str(log_public_path),
                "--max-registration-delay-s",
                "60",
            ]
        )
        == 0
    )
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["valid"] is True
    assert verify_output["backend"] == BACKEND_LOCAL_SIGNED


def test_published_golden_anchor_schema_tamper_and_freshness_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    fixture_dir = root / "docs" / "specs" / "fixtures"
    schema_path = root / "docs" / "specs" / "transparency-anchor-v0.1.schema.json"
    embedded_schema_path = (
        root / "python" / "vibap" / "_specs" / "transparency_anchor_v01.schema.json"
    )
    bundle = json.loads(
        (fixture_dir / "transparency-anchor-v0.1-local.json").read_text(
            encoding="utf-8"
        )
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(bundle)
    assert schema_path.read_bytes() == embedded_schema_path.read_bytes()

    receipt_public_key = serialization.load_pem_public_key(
        (fixture_dir / "transparency-anchor-v0.1-receipt-public.pem").read_bytes()
    )
    log_public_key = serialization.load_pem_public_key(
        (fixture_dir / "transparency-anchor-v0.1-log-public.pem").read_bytes()
    )
    assert isinstance(receipt_public_key, ec.EllipticCurvePublicKey)
    assert isinstance(log_public_key, ed25519.Ed25519PublicKey)
    report = verify_anchor_bundle(
        bundle,
        receipt_public_key=receipt_public_key,
        log_public_key=log_public_key,
        max_registration_delay_s=5,
    )
    assert report["valid"] is True
    assert report["registration_delay_s"] == 5

    tampered = copy.deepcopy(bundle)
    tampered["evidence"]["verification"]["inclusion_proof"]["root_hash"] = "00" * 32
    with pytest.raises(AnchorVerificationError, match="signed checkpoint"):
        verify_anchor_bundle(
            tampered,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
            max_registration_delay_s=5,
        )

    with pytest.raises(AnchorVerificationError, match="maximum registration delay"):
        verify_anchor_bundle(
            bundle,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
            max_registration_delay_s=4,
        )

    unknown_field = copy.deepcopy(bundle)
    unknown_field["unexpected"] = True
    with pytest.raises(AnchorVerificationError, match="schema violation"):
        verify_anchor_bundle(
            unknown_field,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
        )

    control_character = copy.deepcopy(bundle)
    control_character["evidence"]["verification"]["inclusion_proof"]["checkpoint"] = (
        control_character["evidence"]["verification"]["inclusion_proof"][
            "checkpoint"
        ].replace(
            "\n1\n",
            "\n1\t\n",
        )
    )
    with pytest.raises(AnchorVerificationError, match="forbidden control"):
        verify_anchor_bundle(
            control_character,
            receipt_public_key=receipt_public_key,
            log_public_key=log_public_key,
        )


def test_local_backend_refuses_to_anchor_a_non_receipt() -> None:
    """A Merkle leaf cannot be withdrawn, so a non-receipt must never reach one.

    Before this gate the local backend committed any string in ``receipt_jwt``
    to the tree and reported ``anchored``; the resulting bundle was then
    rejected by ``verify_anchor_bundle`` -- dead on arrival, but only after
    the irreversible write. The Rekor backend already refused this
    (test_rekor_refuses_invalid_receipt_before_transport); the two backends
    must not disagree about what is anchorable.
    """

    with tempfile.TemporaryDirectory() as tmp:
        backend = LocalSignedLogBackend(
            Path(tmp) / "log.jsonl",
            ed25519.Ed25519PrivateKey.generate(),
            origin="fixture.local/log",
        )
        with pytest.raises(TransparencyError) as caught:
            backend.submit(
                pending_anchor_bundle("aaa.bbb.ccc", backend_kind=BACKEND_LOCAL_SIGNED)
            )
        assert "refusing to anchor an invalid receipt" in str(caught.value)
        assert not (Path(tmp) / "log.jsonl").exists(), (
            "nothing may be written to the log when submission is refused"
        )


def test_local_backend_still_anchors_a_genuine_receipt_without_any_key() -> None:
    """The structural gate must not break the keyless local-anchoring path."""

    token, _ = _signed_receipt()
    with tempfile.TemporaryDirectory() as tmp:
        backend = LocalSignedLogBackend(
            Path(tmp) / "log.jsonl",
            ed25519.Ed25519PrivateKey.generate(),
            origin="fixture.local/log",
        )
        anchored = backend.submit(
            pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED)
        )
        assert anchored["status"] == "anchored"


def test_local_backend_refuses_a_receipt_signed_by_another_key_when_given_one() -> None:
    """With a receipt public key the gate upgrades from structural to genuine.

    Without a key the backend can only tell that a receipt is well formed. An
    operator who supplies one gets the same guarantee the Rekor path has: a
    receipt from a different issuer is refused before the write.
    """

    token, _ = _signed_receipt()
    stranger = ec.generate_private_key(ec.SECP256R1())
    with tempfile.TemporaryDirectory() as tmp:
        backend = LocalSignedLogBackend(
            Path(tmp) / "log.jsonl",
            ed25519.Ed25519PrivateKey.generate(),
            origin="fixture.local/log",
            receipt_public_key=stranger.public_key(),
        )
        with pytest.raises(TransparencyError) as caught:
            backend.submit(
                pending_anchor_bundle(token, backend_kind=BACKEND_LOCAL_SIGNED)
            )
        assert "InvalidSignature" in str(caught.value)


def test_assert_receipt_shaped_does_not_claim_to_check_signatures() -> None:
    """Pin the honest boundary of the structural gate.

    ``assert_receipt_shaped`` accepts a well-formed receipt regardless of who
    signed it. That is by design -- it exists for backends holding no key --
    and the limit must stay visible, because treating it as verification
    would be the overclaim it was written to avoid.
    """

    token, _ = _signed_receipt()
    claims = assert_receipt_shaped(token)
    assert claims["receipt_id"]

    for junk in ("", "aaa.bbb.ccc", "not-a-jws"):
        with pytest.raises(jwt.PyJWTError):
            assert_receipt_shaped(junk)

    # A corrupted signature is NOT caught here, on purpose: this gate runs
    # where no key is available. Pin it so nobody later mistakes the gate for
    # verification.
    header, payload, signature = token.split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert assert_receipt_shaped(".".join((header, payload, flipped)))

    # A corrupted payload IS caught, because the canonical-payload check
    # recomputes the encoding rather than trusting it.
    with pytest.raises(jwt.PyJWTError):
        assert_receipt_shaped(
            ".".join((header, payload[:-4] + "AAAA", signature))
        )
