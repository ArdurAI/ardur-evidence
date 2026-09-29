from __future__ import annotations

import json
import re
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI path
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = REPO_ROOT / "python"
PYPROJECT = PYTHON_ROOT / "pyproject.toml"
PROXY_SOURCE = PYTHON_ROOT / "vibap" / "proxy.py"
SOURCE_PLUGIN = REPO_ROOT / "plugins" / "claude-code"
PACKAGED_PLUGIN = PYTHON_ROOT / "vibap" / "_plugins" / "claude-code"
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "python-package.yml"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
RELEASE_EVIDENCE = REPO_ROOT / "docs" / "release-evidence-v0.2.0.md"
TESTING_GUIDE = REPO_ROOT / "docs" / "TESTING.md"
VALIDATOR = REPO_ROOT / "scripts" / "validate-python-distribution.py"
SOURCE_SYNC = REPO_ROOT / "site" / "scripts" / "sync_source_docs.py"
BUILD_TOOL_PIN = "build==1.5.0"
PYASN1_SECURITY_FLOOR = "pyasn1>=0.6.4,<0.7"
PYPI_ACTION_SHA = "cef221092ed1bacb1cc03d23a2d87d1d172e277b"
EXPECTED_SUMMARY = "Runtime governance and signed evidence for AI agent tool calls"
PLUGIN_ASSETS = (
    Path(".claude-plugin/plugin.json"),
    Path("hooks/hooks.json"),
    Path("hooks/post_tool_use"),
    Path("hooks/post_tool_use_failure"),
    Path("hooks/pre_tool_use"),
    Path("hooks/subagent_start"),
    Path("hooks/subagent_stop"),
)


def _project_config() -> dict[str, object]:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _validate_changelog_text(changelog: str, expected_version: str) -> None:
    validator = runpy.run_path(str(VALIDATOR))
    validator["validate_changelog_text"](changelog, expected_version)


def test_changelog_has_one_dated_heading_for_the_package_version() -> None:
    expected_version = _project_config()["project"]["version"]

    _validate_changelog_text(CHANGELOG.read_text(encoding="utf-8"), expected_version)


def test_release_build_frontend_uses_non_yanked_pin() -> None:
    config = _project_config()
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert BUILD_TOOL_PIN in config["project"]["optional-dependencies"]["dev"]
    assert BUILD_TOOL_PIN in workflow
    assert "build==1.5.1" not in workflow


def test_version_sensitive_release_claims_have_auditable_evidence() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    evidence = RELEASE_EVIDENCE.read_text(encoding="utf-8")
    normalized_evidence = " ".join(evidence.split())

    assert "docs/release-evidence-v0.2.0.md" in changelog
    for cve in ("CVE-2026-59884", "CVE-2026-59885", "CVE-2026-59886"):
        assert f"https://nvd.nist.gov/vuln/detail/{cve}" in evidence
    assert "https://pypi.org/pypi/build/1.5.0/json" in evidence
    assert "https://pypi.org/pypi/build/1.5.1/json" in evidence
    assert (
        "do not independently attest current advisory or yank metadata"
        in normalized_evidence
    )


def test_dev_extra_and_lock_exclude_vulnerable_pyasn1_releases() -> None:
    config = _project_config()
    lock = tomllib.loads((PYTHON_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_versions = {
        package["name"]: package["version"] for package in lock["package"]
    }

    # pyasn1 is a runtime dependency (spiffe pulls it in); the security floor
    # matters wherever it is declared, so assert on the union rather than on a
    # specific section.
    declared = list(config["project"].get("dependencies", []))
    for extra_requirements in config["project"]["optional-dependencies"].values():
        declared.extend(extra_requirements)
    assert PYASN1_SECURITY_FLOOR in declared
    locked_version = tuple(int(part) for part in locked_versions["pyasn1"].split("."))
    assert (0, 6, 4) <= locked_version < (0, 7)


def test_source_sync_excludes_generated_package_build_directories() -> None:
    source_sync = runpy.run_path(str(SOURCE_SYNC))
    is_public_markdown_path = source_sync["is_public_markdown_path"]

    assert not is_public_markdown_path(
        Path("python/build/lib/vibap/_vendor/rfc8785/UPSTREAM.md")
    )
    assert not is_public_markdown_path(Path("python/dist/generated/README.md"))
    assert is_public_markdown_path(Path("python/vibap/_vendor/rfc8785/UPSTREAM.md"))


def test_testing_guide_only_references_existing_make_targets() -> None:
    documented_targets = set(
        re.findall(
            r"^\s*make\s+([A-Za-z0-9_.-]+)",
            TESTING_GUIDE.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )
    makefile_targets = set(
        re.findall(
            r"^([A-Za-z0-9_.-]+):(?:\s|$)",
            (REPO_ROOT / "Makefile").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )

    assert documented_targets, (
        "TESTING.md must document release validation make targets"
    )
    assert documented_targets <= makefile_targets


@pytest.mark.parametrize(
    ("changelog_template", "error"),
    [
        ("## [Unreleased]\n", "exactly one release heading"),
        (
            "## [Unreleased]\n## [{version}] — 2026-07-22\n"
            "## [{version}] — 2026-07-22\n",
            "exactly one release heading",
        ),
        (
            "## [Unreleased]\n## [{version}] — 2026-02-30\n",
            "not valid ISO YYYY-MM-DD",
        ),
        (
            "## [Unreleased]\n## [9.9.9] — 2026-07-22\n",
            "exactly one release heading",
        ),
        (
            "Prose mentioning ## [Unreleased] is not a heading.\n"
            "## [{version}] — 2026-07-22\n",
            "exactly one Unreleased heading",
        ),
    ],
)
def test_changelog_validator_rejects_invalid_release_headings(
    changelog_template: str, error: str
) -> None:
    expected_version = _project_config()["project"]["version"]
    changelog = changelog_template.format(version=expected_version)

    with pytest.raises(ValueError, match=error):
        _validate_changelog_text(changelog, expected_version)


def test_python_distribution_metadata_is_release_ready() -> None:
    config = _project_config()
    project = config["project"]
    build_system = config["build-system"]

    assert project["name"] == "ardur"
    assert project["description"] == EXPECTED_SUMMARY
    assert project["requires-python"] == ">=3.10"
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert "rfc8785>=0.1.4,<0.2" in project["dependencies"]
    build_requirements = build_system["requires"]
    assert build_requirements
    invalid_build_requirements = [
        requirement
        for requirement in build_requirements
        if re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9._+-]*",
            requirement,
        )
        is None
    ]
    assert not invalid_build_requirements, (
        f"build-system requirements must use exact == pins: {invalid_build_requirements}"
    )
    assert project["urls"] == {
        "Homepage": "https://github.com/ArdurAI/ardur-evidence",
        "Documentation": "https://github.com/ArdurAI/ardur-evidence/tree/main/docs",
        "Repository": "https://github.com/ArdurAI/ardur-evidence",
        "Issues": "https://github.com/ArdurAI/ardur-evidence/issues",
        "Discussions": "https://github.com/ArdurAI/ardur-evidence/discussions",
    }

    package_license = PYTHON_ROOT / "LICENSE"
    assert package_license.read_bytes() == (REPO_ROOT / "LICENSE").read_bytes()

    init_text = (PYTHON_ROOT / "vibap" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', init_text, flags=re.MULTILINE)
    assert match is not None
    assert project["version"] == match.group(1)

    proxy_text = PROXY_SOURCE.read_text(encoding="utf-8")
    proxy_match = re.search(
        r'^API_VERSION = "([^"]+)"$', proxy_text, flags=re.MULTILINE
    )
    assert proxy_match is not None
    assert project["version"] == proxy_match.group(1)


def test_packaged_claude_code_plugin_matches_canonical_source() -> None:
    packaged_files = {
        path.relative_to(PACKAGED_PLUGIN)
        for path in PACKAGED_PLUGIN.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    assert packaged_files == set(PLUGIN_ASSETS)
    for relative_path in PLUGIN_ASSETS:
        source_path = SOURCE_PLUGIN / relative_path
        packaged_path = PACKAGED_PLUGIN / relative_path
        assert packaged_path.read_bytes() == source_path.read_bytes()
        assert stat.S_IMODE(packaged_path.stat().st_mode) == stat.S_IMODE(
            source_path.stat().st_mode
        )


def test_plugin_resolver_uses_packaged_assets_outside_checkout(tmp_path: Path) -> None:
    from vibap.package_assets import claude_code_plugin_dir

    assert claude_code_plugin_dir(tmp_path) == PACKAGED_PLUGIN


def test_distribution_validator_accepts_a_real_sdist_build(tmp_path: Path) -> None:
    expected_version = _project_config()["project"]["version"]
    source = tmp_path / "python-source"
    dist = tmp_path / "dist"
    shutil.copytree(
        PYTHON_ROOT,
        source,
        ignore=shutil.ignore_patterns(
            "build",
            "*.egg-info",
            "__pycache__",
            ".pytest_cache",
        ),
    )
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(dist),
            ".",
        ],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    validate = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "validate-python-distribution.py"),
            "--dist-dir",
            str(dist),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr
    assert f"validated ardur {expected_version}" in validate.stdout


def test_python_publish_workflow_is_tokenless_pinned_and_gated() -> None:
    with PUBLISH_WORKFLOW.open(encoding="utf-8") as handle:
        workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {
        "pull_request",
        "push",
        "release",
        "workflow_dispatch",
    }
    assert workflow["permissions"] == {"contents": "read"}

    jobs = workflow["jobs"]
    required_validation = ["build", "package-smoke", "python-3-9-guard"]
    assert set(jobs) == {
        *required_validation,
        "publish-testpypi",
        "publish-pypi",
    }
    for job_name, environment_name in (
        ("publish-testpypi", "testpypi"),
        ("publish-pypi", "pypi"),
    ):
        job = jobs[job_name]
        assert job["needs"] == required_validation
        assert job["permissions"] == {"id-token": "write"}
        assert job["environment"]["name"] == environment_name

    assert jobs["publish-testpypi"]["if"] == "github.event_name == 'workflow_dispatch'"
    assert jobs["publish-pypi"]["if"] == (
        "github.event_name == 'release' && github.event.release.prerelease == false"
    )

    serialized = json.dumps(workflow)
    assert "PYPI_TOKEN" not in serialized
    assert "password" not in serialized.lower()
    assert "skip-existing" not in serialized

    uses_values = re.findall(r"\buses:\s*([^\s#]+)", PUBLISH_WORKFLOW.read_text())
    assert uses_values
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses_values)
    assert any(value.endswith(f"@{PYPI_ACTION_SHA}") for value in uses_values)
