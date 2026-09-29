"""Read-only report paths must never create key material.

`load_public_key` auto-creates: it returns `generate_keypair(...)[1]` when
`passport_public.pem` is missing. Three report builders called it, so a
command whose entire job is verifying existing evidence would mint a
*signing* keypair -- private key included -- and then verify against the key
it had just invented. That makes "nothing verified" indistinguishable from
"verified against a key I made up", and it writes a new root of trust into
whatever directory the run happened to resolve.

The fix is deliberately narrower than "always require a key". A fresh install
with no receipts must still get its onboarding report, so the key is required
only when there is evidence to verify. These tests pin all three edges: no
minting ever, onboarding preserved, and fail-closed once evidence exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vibap.claude_code_report import build_claude_code_report
from vibap.codex_app_server_fixture import (
    build_shareable_report as build_codex_report,
)
from vibap.gemini_cli_hook import build_shareable_report as build_gemini_report


def _keys_dir(tmp_path: Path) -> Path:
    keys = tmp_path / "keys"
    keys.mkdir()
    return keys


def _key_files(keys: Path) -> list[str]:
    return sorted(p.name for p in keys.iterdir())


def test_claude_code_report_on_a_fresh_install_mints_no_keys(tmp_path: Path) -> None:
    keys = _keys_dir(tmp_path)

    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "missing-chain",
        keys_dir=keys,
        verify_expiry=False,
    )

    assert report["receipt_count"] == 0
    assert report["next_steps"], "onboarding guidance must survive"
    assert _key_files(keys) == [], "a report path must not create key material"


def test_claude_code_report_fails_closed_when_receipts_exist_without_a_key(
    tmp_path: Path,
) -> None:
    """Evidence with no key is unverifiable, so it must not report success."""

    keys = _keys_dir(tmp_path)
    chain = tmp_path / "claude-code-hook" / "project"
    chain.mkdir(parents=True)
    (chain / "receipts.jsonl").write_text(
        "eyJhbGciOiJFUzI1NiJ9.e30.sig\n", encoding="utf-8"
    )

    with pytest.raises(FileNotFoundError):
        build_claude_code_report(
            home=tmp_path,
            chain_dir=tmp_path / "claude-code-hook",
            keys_dir=keys,
            verify_expiry=False,
        )
    assert _key_files(keys) == [], "failing closed must not leave key material behind"


@pytest.mark.parametrize(
    ("builder", "chain_name"),
    [(build_gemini_report, "gemini-chain"), (build_codex_report, "codex-chain")],
)
def test_adapter_reports_on_a_fresh_install_mint_no_keys(
    tmp_path: Path, builder, chain_name: str
) -> None:
    keys = _keys_dir(tmp_path)

    report = builder(
        home=tmp_path,
        chain_dir=tmp_path / chain_name,
        keys_dir=keys,
        verify_expiry=False,
    )

    assert report["receipt_count"] == 0
    assert _key_files(keys) == []


@pytest.mark.parametrize(
    ("builder", "chain_name"),
    [(build_gemini_report, "gemini-chain"), (build_codex_report, "codex-chain")],
)
def test_adapter_reports_fail_closed_when_chains_exist_without_a_key(
    tmp_path: Path, builder, chain_name: str
) -> None:
    keys = _keys_dir(tmp_path)
    chains = tmp_path / chain_name
    chains.mkdir()
    (chains / "receipts.jsonl").write_text(
        "eyJhbGciOiJFUzI1NiJ9.e30.sig\n", encoding="utf-8"
    )

    with pytest.raises(FileNotFoundError):
        builder(
            home=tmp_path,
            chain_dir=chains,
            keys_dir=keys,
            verify_expiry=False,
        )
    assert _key_files(keys) == []
