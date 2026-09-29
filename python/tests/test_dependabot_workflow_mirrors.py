from __future__ import annotations

import runpy
import re
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependabot-workflow-mirrors.yml"
TESTS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync-dependabot-workflow-mirrors.py"
REQUIRED_WORKFLOWS = {
    "codeql.yml",
    "hugo-site.yml",
    "link-check.yml",
    "secret-scan.yml",
    "tests.yml",
    "validate-formats.yml",
}
CHECKOUT_SHA = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"


def _sync_condition_applies(
    condition: str,
    *,
    actor: str,
    author: str,
    head_repo: str,
    repository: str,
    head_ref: str,
) -> bool:
    predicates = {
        "github.actor == 'dependabot[bot]'": actor == "dependabot[bot]",
        "github.event.pull_request.user.login == 'dependabot[bot]'": (
            author == "dependabot[bot]"
        ),
        "github.event.pull_request.head.repo.full_name == github.repository": (
            head_repo == repository
        ),
        "startsWith(github.event.pull_request.head.ref, "
        "'dependabot/github_actions/')": head_ref.startswith(
            "dependabot/github_actions/"
        ),
    }
    terms = [" ".join(term.split()) for term in condition.split("&&")]
    unknown = set(terms) - predicates.keys()
    assert not unknown, f"unsupported sync condition terms: {sorted(unknown)}"
    return all(predicates[term] for term in terms)


def _contains_secret_reference(value: object, *, key: str | None = None) -> bool:
    if isinstance(value, str):
        if key == "secrets" and value == "inherit":
            return True
        return re.search(
            r"\$\{\{[^}]*\bsecrets(?:\s*\.|\s*\[|\s*\)|\s*\}\})",
            value,
            flags=re.IGNORECASE,
        ) is not None
    if isinstance(value, dict):
        if key == "secrets" and value:
            return True
        return any(
            _contains_secret_reference(item, key=str(item_key))
            for item_key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_reference(item) for item in value)
    return False


def _permissions_grant_oidc(permissions: object) -> bool:
    if isinstance(permissions, str):
        return permissions == "write-all"
    if isinstance(permissions, dict):
        return permissions.get("id-token") == "write"
    return False


def _e2e_showcase_applies(
    condition: str,
    *,
    event_name: str,
    ref: str,
    recheck_mode: str,
) -> bool:
    normalized = " ".join(condition.split())
    assert normalized == (
        "(github.event_name != 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main') || "
        "(github.event_name == 'workflow_dispatch' && "
        "inputs.recheck_mode == 'full')"
    )
    return (
        event_name != "workflow_dispatch" and ref == "refs/heads/main"
    ) or (event_name == "workflow_dispatch" and recheck_mode == "full")


def test_mirror_sync_workflow_is_bot_only_and_least_privilege() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"pull_request_target"}
    trigger = workflow["on"]["pull_request_target"]
    assert trigger["types"] == ["opened", "reopened", "synchronize"]
    assert trigger["paths"] == [".github/workflows/*.yml"]
    assert workflow["permissions"] == {"actions": "write", "contents": "write"}

    assert set(workflow["jobs"]) == {"sync"}
    job = workflow["jobs"]["sync"]
    condition = " ".join(job["if"].split())
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in condition
    assert "github.actor" not in condition
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert (
        "startsWith(github.event.pull_request.head.ref, 'dependabot/github_actions/')"
        in condition
    )

    checkout = job["steps"][0]
    assert checkout["uses"] == f"actions/checkout@{CHECKOUT_SHA}"
    assert checkout["with"] == {
        "fetch-depth": "0",
        "ref": "${{ github.event.pull_request.base.sha }}",
    }

    run_blocks = "\n".join(step.get("run", "") for step in job["steps"])
    assert "${{ github.event.pull_request" not in run_blocks
    assert "python3 scripts/sync-dependabot-workflow-mirrors.py" in run_blocks
    assert 'git push origin "HEAD:refs/heads/$HEAD_REF"' in run_blocks
    assert "--force" not in run_blocks

    dispatch = job["steps"][-1]
    assert "if" not in dispatch
    assert set(dispatch["env"]["REQUIRED_WORKFLOWS"].split()) == REQUIRED_WORKFLOWS
    assert dispatch["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert dispatch["env"]["PR_NUMBER"] == "${{ github.event.pull_request.number }}"
    assert dispatch["env"]["RUN_ID"] == "${{ github.run_id }}"
    assert 'git ls-remote origin "refs/heads/$HEAD_REF"' in dispatch["run"]
    assert 'if [ "$remote_sha" != "$expected_sha" ]; then' in dispatch["run"]
    assert (
        'CHECK_REF="dependabot-workflow-mirrors/pr-${PR_NUMBER}-run-${RUN_ID}-'
        '${expected_sha}"' in dispatch["run"]
    )
    assert 'git push origin "$expected_sha:refs/tags/$CHECK_REF"' in dispatch["run"]
    assert 'trap cleanup_check_ref EXIT' in dispatch["run"]
    assert 'gh workflow run "$workflow" --ref "$CHECK_REF"' in dispatch["run"]
    assert 'gh workflow run "$workflow" --ref "$HEAD_REF"' not in dispatch["run"]
    assert "gh run list" in dispatch["run"]
    assert '--workflow "$workflow"' in dispatch["run"]
    assert '--branch "$CHECK_REF"' in dispatch["run"]
    assert '--commit "$expected_sha"' in dispatch["run"]
    assert 'if [ -z "$run_id" ]; then' in dispatch["run"]
    assert 'trap - EXIT' in dispatch["run"]
    assert 'git push origin ":refs/tags/$CHECK_REF"' in dispatch["run"]


def test_sync_runs_for_dependabot_pr_when_human_updates_base() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    condition = workflow["jobs"]["sync"]["if"]
    assert _sync_condition_applies(
        condition,
        actor="maintainer",
        author="dependabot[bot]",
        head_repo="ArdurAI/ardur-evidence",
        repository="ArdurAI/ardur-evidence",
        head_ref="dependabot/github_actions/actions-checkout-7.0.1",
    )


def test_every_dispatched_workflow_is_credential_safe() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        mirror_workflow = yaml.load(handle, Loader=yaml.BaseLoader)
    with TESTS_WORKFLOW.open(encoding="utf-8") as handle:
        tests_workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    dispatch_config = tests_workflow["on"]["workflow_dispatch"]
    assert isinstance(dispatch_config, dict)
    recheck_mode = dispatch_config["inputs"]["recheck_mode"]
    assert recheck_mode["required"] == "true"
    assert recheck_mode["default"] == "full"
    assert recheck_mode["type"] == "choice"
    assert recheck_mode["options"] == ["full", "secretless"]

    dispatch_run = mirror_workflow["jobs"]["sync"]["steps"][-1]["run"]
    assert 'if [ "$workflow" = "tests.yml" ]; then' in dispatch_run
    assert (
        'gh workflow run "$workflow" --ref "$CHECK_REF" '
        "-f recheck_mode=secretless" in dispatch_run
    )

    secret_jobs: set[tuple[str, str]] = set()
    credential_capable_jobs: set[tuple[str, str]] = set()
    for workflow_name in REQUIRED_WORKFLOWS:
        workflow_path = REPO_ROOT / ".github" / "workflows" / workflow_name
        with workflow_path.open(encoding="utf-8") as handle:
            dispatched_workflow = yaml.load(handle, Loader=yaml.BaseLoader)

        assert not _contains_secret_reference(
            dispatched_workflow.get("env", {})
        ), workflow_name
        workflow_permissions = dispatched_workflow.get("permissions", {})
        assert isinstance(workflow_permissions, dict), workflow_name
        assert not _permissions_grant_oidc(workflow_permissions), workflow_name
        for job_name, job in dispatched_workflow["jobs"].items():
            if _contains_secret_reference(job):
                secret_jobs.add((workflow_name, job_name))
            permissions = job.get("permissions", {})
            assert isinstance(permissions, dict), (workflow_name, job_name)
            if job.get("environment") or permissions.get("id-token") == "write":
                credential_capable_jobs.add((workflow_name, job_name))

    assert secret_jobs == {("tests.yml", "e2e-showcase")}
    assert credential_capable_jobs == {("hugo-site.yml", "deploy")}
    with (REPO_ROOT / ".github" / "workflows" / "hugo-site.yml").open(
        encoding="utf-8"
    ) as handle:
        hugo_workflow = yaml.load(handle, Loader=yaml.BaseLoader)
    assert hugo_workflow["jobs"]["deploy"]["if"] == (
        "github.ref == 'refs/heads/main'"
    )

    condition = tests_workflow["jobs"]["e2e-showcase"]["if"]
    assert not _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/dependabot/github_actions/actions-checkout-7.0.1",
        recheck_mode="secretless",
    )
    assert not _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        recheck_mode="secretless",
    )
    assert not _e2e_showcase_applies(
        condition,
        event_name="pull_request",
        ref="refs/pull/406/merge",
        recheck_mode="",
    )
    assert _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/manual-validation",
        recheck_mode="full",
    )


@pytest.mark.parametrize(
    "value",
    [
        "${{secrets.API_KEY}}",
        "${{ secrets['API_KEY'] }}",
        "${{ toJSON(secrets) }}",
        "${{ SECRETS.API_KEY }}",
        "${{ secrets }}",
        {"secrets": "inherit"},
        {"secrets": {"token": "${{ secrets.API_KEY }}"}},
    ],
)
def test_secret_reference_scanner_covers_expression_and_inheritance_forms(
    value: object,
) -> None:
    assert _contains_secret_reference(value)


@pytest.mark.parametrize(
    "permissions",
    [{"id-token": "write"}, "write-all"],
)
def test_permissions_scanner_detects_workflow_level_oidc(
    permissions: object,
) -> None:
    assert _permissions_grant_oidc(permissions)


def test_every_dispatched_workflow_exposes_its_protected_aggregate() -> None:
    for workflow_name in REQUIRED_WORKFLOWS:
        workflow_path = REPO_ROOT / ".github" / "workflows" / workflow_name
        with workflow_path.open(encoding="utf-8") as handle:
            workflow = yaml.load(handle, Loader=yaml.BaseLoader)

        assert "workflow_dispatch" in workflow["on"], workflow_name
        protected_job = Path(workflow_name).stem
        assert protected_job in workflow["jobs"], workflow_name
        job_condition = workflow["jobs"][protected_job].get("if", "")
        assert "github.event_name == 'pull_request'" not in job_condition, workflow_name


def test_change_validator_allows_only_workflow_sources_and_their_mirrors() -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_changed_paths"]

    source = Path(".github/workflows/tests.yml")
    mirror = Path("site/static/repo/.github/workflows/tests.yml")
    assert validator([("M", source)]) == [source]
    assert validator([("M", source), ("M", mirror)]) == [source]


def test_content_validator_allows_only_pinned_action_updates() -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_action_pin_updates"]
    source = Path(".github/workflows/tests.yml")
    base = b"""steps:
  - uses: actions/setup-python@1111111111111111111111111111111111111111  # v6.3.0
  - uses: github/codeql-action/init@2222222222222222222222222222222222222222  # v4.37.0
"""
    head = b"""steps:
  - uses: actions/setup-python@3333333333333333333333333333333333333333  # v7.0.0
  - uses: github/codeql-action/init@4444444444444444444444444444444444444444  # v4.37.7
"""

    validator(source, base, head)


@pytest.mark.parametrize(
    "head",
    [
        b"""steps:
  - uses: attacker/setup-python@3333333333333333333333333333333333333333  # v7.0.0
""",
        b"""steps:
  - uses: actions/setup-python@v7
""",
        b"""steps:
  - uses: actions/setup-python@3333333333333333333333333333333333333333  # v7.0.0
  - run: echo injected
""",
        b"""steps:
  - uses: actions/setup-python@3333333333333333333333333333333333333333  # v7.0.0
if: always()
""",
    ],
)
def test_content_validator_rejects_non_pin_workflow_changes(head: bytes) -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_action_pin_updates"]
    source = Path(".github/workflows/tests.yml")
    base = b"""steps:
  - uses: actions/setup-python@1111111111111111111111111111111111111111  # v6.3.0
"""

    with pytest.raises(ValueError, match="action-pin-only validation"):
        validator(source, base, head)


@pytest.mark.parametrize(
    "changes",
    [
        [("A", Path(".github/workflows/new.yml"))],
        [("M", Path("site/scripts/sync_source_docs.py"))],
        [("M", Path(".github/workflows/tests.yaml"))],
        [("D", Path(".github/workflows/tests.yml"))],
        [("M", Path("site/static/repo/.github/workflows/tests.yml"))],
    ],
)
def test_change_validator_fails_closed_for_unexpected_pr_changes(
    changes: list[tuple[str, Path]],
) -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_changed_paths"]

    with pytest.raises(ValueError, match="Dependabot workflow mirror sync refused"):
        validator(changes)
