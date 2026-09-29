"""Membership tests for the `tests` aggregate job in CI.

`tests` is the aggregate a branch-protection rule points at, so it is the
single job whose failure blocks a merge. Its guarantee is only as good as its
`needs` list and the `require_success` call for each member: drop a job from
`needs`, or drop its `require_success` line while leaving it in `needs`, and a
required gate disappears while every observable stays green -- the aggregate
still reports success, the required context is still present, and the removed
job's own runs still show up in the checks list.

Before this module only `demo-smoke` was pinned (`test_demo_compose.py`), so
seven of the eight members could be silently dropped. These tests pin the whole
membership in both directions: the automation identity that can edit tests
cannot edit `.github/workflows/**`, so a weakening there has to be authored by
a human in a reviewable unit, and these assertions are what make that
weakening visible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"

# Every job the aggregate must gate on. Adding or removing an entry here is a
# deliberate, reviewable act -- which is the point. If CI grows a blocking job,
# this list changes in the same PR.
EXPECTED_BLOCKING_JOBS = (
    "python-lint",
    "go-lint",
    "python",
    "go",
    "go-cve",
    "rwt-phase1",
    "examples-smoke",
    "demo-smoke",
)


def _workflow() -> dict:
    return yaml.safe_load(TESTS_WORKFLOW.read_text(encoding="utf-8"))


def _aggregate_gate_step(workflow: dict) -> dict:
    """Return the aggregate's first step, which holds the require_success calls."""
    return workflow["jobs"]["tests"]["steps"][0]


def test_aggregate_needs_exactly_the_expected_blocking_jobs() -> None:
    """Both directions: no member may be dropped, none added unnoticed."""

    needs = _workflow()["jobs"]["tests"]["needs"]

    assert sorted(needs) == sorted(EXPECTED_BLOCKING_JOBS), (
        "the `tests` aggregate's needs list changed; update "
        "EXPECTED_BLOCKING_JOBS in the same PR and say why in the description"
    )
    # Ordering is not load-bearing for CI, but duplicates would mask a drop.
    assert len(needs) == len(set(needs))


@pytest.mark.parametrize("job", EXPECTED_BLOCKING_JOBS)
def test_every_blocking_job_is_required_by_the_aggregate(job: str) -> None:
    """Each member must be in `needs`, bound to an env var, and asserted on.

    All three are required. A job in `needs` with no `require_success` call is
    awaited and then ignored, which is the failure mode that leaves every
    observable green.
    """

    workflow = _workflow()
    aggregate = workflow["jobs"]["tests"]
    gate = _aggregate_gate_step(workflow)

    assert job in aggregate["needs"], f"{job} is not in the aggregate's needs"

    env_name = job.replace("-", "_").upper()
    # GitHub allows either accessor; hyphenated job ids require the bracket
    # form, so both spellings are legitimate and both must be accepted.
    accepted = {
        f"${{{{ needs['{job}'].result }}}}",
        f"${{{{ needs.{job}.result }}}}",
    }
    assert gate["env"].get(env_name) in accepted, (
        f"{job} has no {env_name} env binding on the aggregate gate step"
    )
    assert f'require_success {job} "${env_name}"' in gate["run"], (
        f"{job} is awaited by the aggregate but never checked with require_success"
    )


def test_every_blocking_job_actually_exists_in_the_workflow() -> None:
    """A `needs` entry naming a job that does not exist would fail the run."""

    workflow = _workflow()
    for job in EXPECTED_BLOCKING_JOBS:
        assert job in workflow["jobs"], f"{job} is required but not defined"


def test_require_success_fails_closed_on_any_non_success_result() -> None:
    """The helper must reject skipped/cancelled, not only failure.

    `if: always()` means a skipped or cancelled dependency still reaches this
    step with a non-success result. Comparing against `success` rather than
    listing failure states is what keeps that fail-closed.
    """

    workflow = _workflow()
    gate = _aggregate_gate_step(workflow)

    # `always()` is what makes the aggregate run even when a dependency failed
    # or was skipped -- without it the gate would itself be skipped and the
    # branch-protection context would never turn red.
    assert "always()" in str(workflow["jobs"]["tests"]["if"])
    assert '[ "$result" != "success" ]' in gate["run"], (
        "require_success must compare against success, so skipped and "
        "cancelled results fail closed too"
    )
    assert "exit 1" in gate["run"]
