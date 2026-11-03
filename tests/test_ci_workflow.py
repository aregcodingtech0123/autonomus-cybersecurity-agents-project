"""Structural checks of .github/workflows/ci.yml.

GitHub Actions cannot be run locally and actionlint was not available, so this only proves the file
parses and keeps the properties the project depends on (least privilege, no rule caching/upload,
pinned actions, the right jobs). It does NOT prove the workflow succeeds on GitHub.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text("utf-8"))


def steps(job: dict) -> list[dict]:
    return job["steps"]


def run_lines(job: dict) -> list[str]:
    return [s["run"] for s in steps(job) if "run" in s]


def test_workflow_parses_and_has_the_two_jobs(doc):
    assert set(doc["jobs"]) == {"lint-test", "docker"}
    triggers = doc.get("on", doc.get(True))  # PyYAML reads the bare key `on` as True
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert "pull_request_target" not in triggers, "never run fork code with write tokens"


def test_least_privilege_and_no_secrets(doc):
    assert doc["permissions"] == {"contents": "read"}
    text = WORKFLOW.read_text("utf-8")
    assert "secrets." not in text and "GITHUB_TOKEN" not in text
    for job in doc["jobs"].values():
        for step in steps(job):
            if "uses" in step and step["uses"].startswith("actions/checkout"):
                assert step["with"]["persist-credentials"] is False


def test_lint_and_test_job_covers_ubuntu_and_windows_without_docker(doc):
    job = doc["jobs"]["lint-test"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "windows-latest"}
    lines = " | ".join(run_lines(job))
    for needed in (
        "uv sync --locked",
        "ruff check",
        "ruff format --check",
        "check_ground_truth.py",
        'pytest -m "not docker"',
    ):
        assert needed in lines, needed


def test_docker_job_builds_images_fetches_rules_fresh_then_runs_the_docker_tests(doc):
    job = doc["jobs"]["docker"]
    assert job["runs-on"] == "ubuntu-latest"
    commands = run_lines(job)
    order = {
        key: next(i for i, c in enumerate(commands) if key in c)
        for key in ("build-images", "rules update", "pytest -m docker")
    }
    assert order["build-images"] < order["pytest -m docker"]
    assert order["rules update"] < order["pytest -m docker"], "rules are fetched inside the job"
    assert any("rm -rf .secaudit/rules" in c for c in commands)
    cleanup = next(s for s in steps(job) if "rm -rf .secaudit/rules" in s.get("run", ""))
    assert cleanup["if"] == "always()"


def test_nothing_caches_or_uploads_anything(doc):
    """Semgrep Rules License v1.0: fetched rules are never redistributed (ADR-001)."""
    for name, job in doc["jobs"].items():
        for step in steps(job):
            uses = step.get("uses", "")
            assert "upload-artifact" not in uses, name
            assert not uses.startswith("actions/cache"), name
            if uses.startswith("astral-sh/setup-uv"):
                assert step["with"]["enable-cache"] is False, name
    assert "upload-artifact" not in WORKFLOW.read_text("utf-8")


def test_actions_are_pinned_to_a_version_and_inputs_are_not_interpolated_into_shell(doc):
    for job in doc["jobs"].values():
        for step in steps(job):
            if "uses" in step:
                assert re.search(r"@(v\d+|[0-9a-f]{40})$", step["uses"]), step["uses"]
    for job in doc["jobs"].values():
        for command in run_lines(job):
            assert "${{" not in command, "no expression interpolation in run: (script injection)"


def test_the_file_says_plainly_that_it_was_not_run(doc):
    header = WORKFLOW.read_text("utf-8").split("name: ci")[0]
    assert "NOT RUN LOCALLY" in header and "Semgrep Rules License" in header
