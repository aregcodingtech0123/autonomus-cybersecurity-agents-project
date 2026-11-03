"""Checks of .github/workflows/ci.yml and .github/dependabot.yml.

GitHub Actions cannot be run locally. This proves the file parses, passes actionlint, and keeps the
properties the project depends on (least privilege, no rule caching/upload, every action pinned to a
commit SHA, the right jobs). It does NOT prove the workflow succeeds on GitHub.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
ACTIONLINT = ROOT / "tools" / "actionlint.py"


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
        assert job["permissions"] == {"contents": "read"}, "every job restates least privilege"
        assert isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] <= 60
        for step in steps(job):
            if "uses" in step and step["uses"].startswith("actions/checkout"):
                assert step["with"]["persist-credentials"] is False
    assert doc["concurrency"]["cancel-in-progress"] is True


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


PINNED = re.compile(r"^([\w.-]+/[\w.-]+)@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)$")


def test_every_third_party_action_is_pinned_to_a_full_commit_sha_with_its_tag_in_a_comment():
    pinned = 0
    for line in WORKFLOW.read_text("utf-8").splitlines():
        match = re.search(r"uses:\s*(\S.*)$", line)
        if match:
            assert PINNED.match(match.group(1).strip()), (
                f"not SHA-pinned with a tag comment: {line}"
            )
            pinned += 1
    assert pinned == 4, "2 jobs x (checkout + setup-uv)"


def test_no_expression_is_interpolated_into_a_shell_command(doc):
    for job in doc["jobs"].values():
        for command in run_lines(job):
            assert "${{" not in command, "no expression interpolation in run: (script injection)"


def test_dependabot_covers_actions_and_uv_but_not_the_digest_pinned_docker_images():
    config = yaml.safe_load(DEPENDABOT.read_text("utf-8"))
    ecosystems = {u["package-ecosystem"]: u for u in config["updates"]}
    assert config["version"] == 2 and set(ecosystems) == {"github-actions", "uv"}
    for update in ecosystems.values():
        assert update["directory"] == "/" and update["schedule"]["interval"] == "weekly"
        assert update["open-pull-requests-limit"] <= 5 and update["cooldown"]["default-days"] >= 1


def run_actionlint(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - our own script and interpreter
        [sys.executable, str(ACTIONLINT), *args], capture_output=True, text=True, timeout=180
    )


def test_actionlint_passes_on_the_workflow():
    done = run_actionlint(str(WORKFLOW))
    assert done.returncode == 0, done.stdout + done.stderr


def test_actionlint_really_fails_on_a_broken_workflow(tmp_path):
    """Positive control: a linter that cannot fail proves nothing."""
    broken = tmp_path / "bad.yml"
    lines = [
        "on: push",
        "jobs:",
        "  j:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: echo ${{ github.nope }}",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          not-an-input: 1",
    ]
    broken.write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
    done = run_actionlint(str(broken))
    assert done.returncode == 1 and "github.nope" in done.stdout


def test_the_actionlint_download_is_pinned_by_checksum():
    source = ACTIONLINT.read_text("utf-8")
    hashes = re.findall(r'"([0-9a-f]{64})"', source)
    assert len(hashes) == 5 and len(set(hashes)) == 5
    assert (
        "does not match the pinned" in source and "https://github.com/rhysd/actionlint/" in source
    )


def test_the_file_says_plainly_that_it_was_not_run(doc):
    header = WORKFLOW.read_text("utf-8").split("name: ci")[0]
    assert "NOT RUN LOCALLY" in header and "Semgrep Rules License" in header


def test_a_download_with_the_wrong_checksum_is_refused_and_nothing_is_installed(
    tmp_path, monkeypatch
):
    import importlib.util

    spec = importlib.util.spec_from_file_location("actionlint_tool", ACTIONLINT)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    monkeypatch.setattr(tool, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(tool, "fetch", lambda url: b"definitely not the real archive")
    with pytest.raises(tool.ActionlintError, match="does not match the pinned"):
        tool.ensure_binary()
    assert not (tmp_path / "cache").exists(), "nothing is written before the hash matches"


def test_the_actionlint_downloader_only_talks_to_the_actionlint_release_url():
    import importlib.util

    spec = importlib.util.spec_from_file_location("actionlint_tool_url", ACTIONLINT)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    with pytest.raises(tool.ActionlintError, match="unexpected URL"):
        tool.fetch("https://evil.example/actionlint.zip")
