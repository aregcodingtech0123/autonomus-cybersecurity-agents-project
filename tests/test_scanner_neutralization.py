"""Empirical matrix (marker docker): plant each candidate mechanism in a copy of the benchmark
target, scan through the REAL orchestrator and sandbox, and require the result count to equal the
baseline. The cases include mechanisms found NOT effective, to pin that down as well.
Results are summarised in docs/PHASE1_NOTES.md."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from secaudit.core.rules import RulesError, load_rules_cache
from secaudit.core.sandbox import ResourceLimits
from secaudit.core.scan import ScanOptions, run_scan

pytestmark = [pytest.mark.docker, pytest.mark.usefixtures("docker_images")]

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "benchmarks" / "targets" / "vuln_python_app"
BASELINE_RAW = REPO / "benchmarks" / "baseline" / "raw"


def put(ws: Path, rel: str, text: str = "x") -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")


def edit(ws: Path, rel: str, old: str, new: str) -> None:
    p = ws / rel
    text = p.read_text(encoding="utf-8")
    assert old in text, f"mutation did not match {rel}: {old!r}"
    p.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


# (tool, id, mutation, path expected in manifest.neutralized_files or None if not effective)
CASES = [
    (
        "bandit",
        "bandit-root",
        lambda w: put(w, ".bandit", "[bandit]\nexclude = ./webshop\nskips = B101,B105\n"),
        ".bandit",
    ),
    (
        "bandit",
        "bandit-nested",
        lambda w: put(w, "webshop/.bandit", "[bandit]\nskips = B608,B324\n"),
        "webshop/.bandit",
    ),
    ("bandit", "bandit-dir-named", lambda w: put(w, ".bandit/x"), ".bandit"),
    (
        "bandit",
        "setup-cfg",
        lambda w: put(w, "setup.cfg", "[bandit]\nexclude = ./webshop\nskips = B101\n"),
        None,
    ),
    (
        "bandit",
        "tox-ini",
        lambda w: put(w, "tox.ini", "[bandit]\nexclude = ./webshop\nskips = B101\n"),
        None,
    ),
    (
        "bandit",
        "pyproject",
        lambda w: put(
            w, "pyproject.toml", "[tool.bandit]\nexclude_dirs=['webshop']\nskips=['B608']\n"
        ),
        None,
    ),
    (
        "bandit",
        "bandit-yaml",
        lambda w: put(w, "bandit.yaml", "skips: [B608, B324]\nexclude_dirs: [webshop]\n"),
        None,
    ),
    (
        "bandit",
        "nosec-comment",
        lambda w: edit(
            w, "webshop/system.py", "text=True)\n    return", "text=True)  #nosec\n    return"
        ),
        None,
    ),
    (
        "semgrep",
        "semgrepignore-nested",
        lambda w: put(w, "webshop/.semgrepignore", "*.py\n"),
        "webshop/.semgrepignore",
    ),
    (
        "semgrep",
        "semgrepignore-root-hostile",
        lambda w: put(w, ".semgrepignore", "*\n"),
        ".semgrepignore",
    ),
    ("semgrep", "semgrepignore-root-dir", lambda w: put(w, ".semgrepignore/k"), ".semgrepignore"),
    (
        "semgrep",
        "semgrepignore-in-tests",
        lambda w: put(w, "tests/.semgrepignore", "*\n"),
        "tests/.semgrepignore",
    ),
    (
        "semgrep",
        "semgrep-settings-dir",
        lambda w: put(w, ".semgrep/settings.yml", "anonymous_user_id: x\n"),
        None,
    ),
    ("semgrep", "gitignore", lambda w: put(w, ".gitignore", "webshop/\n"), None),
    (
        "semgrep",
        "hostile-git-dir",
        lambda w: (
            put(w, ".git/HEAD", "ref: refs/heads/main\n"),
            put(w, ".git/info/exclude", "*.py\n"),
            put(w, ".gitignore", "webshop/\n"),
        ),
        None,
    ),
    (
        "semgrep",
        "nosemgrep-comment",
        lambda w: edit(
            w, "webshop/system.py", "text=True)\n    return", "text=True)  # nosemgrep\n    return"
        ),
        None,
    ),
    (
        "gitleaks",
        "gitleaksignore-root",
        lambda w: put(
            w,
            ".gitleaksignore",
            "config/settings.ini:aws-access-token:7\nconfig/settings.ini:generic-api-key:8\nwebshop/settings.py:stripe-access-token:3\n",
        ),
        ".gitleaksignore",
    ),
    (
        "gitleaks",
        "gitleaksignore-nested",
        lambda w: put(w, "config/.gitleaksignore", "config/settings.ini:aws-access-token:7\n"),
        "config/.gitleaksignore",
    ),
    (
        "gitleaks",
        "gitleaks-toml-root",
        lambda w: put(
            w, ".gitleaks.toml", "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''.*''']\n"
        ),
        ".gitleaks.toml",
    ),
    (
        "gitleaks",
        "gitleaks-toml-nested",
        lambda w: put(w, "config/.gitleaks.toml", "[allowlist]\npaths = ['''.*''']\n"),
        "config/.gitleaks.toml",
    ),
    ("gitleaks", "gitleaks-toml-dir", lambda w: put(w, ".gitleaks.toml/x"), ".gitleaks.toml"),
    (
        "gitleaks",
        "gitleaks-allow-comment",
        lambda w: edit(
            w,
            "webshop/settings.py",
            'VQRgmEuLNsKJ4a0ZkKpFxr11"',
            'VQRgmEuLNsKJ4a0ZkKpFxr11"  # gitleaks:allow',
        ),
        None,
    ),
    (
        "gitleaks",
        "gitignore-listing-secrets",
        lambda w: put(w, ".gitignore", "config/\nwebshop/settings.py\n"),
        None,
    ),
]


@pytest.fixture(scope="module")
def rules_cache():
    try:
        return load_rules_cache()
    except RulesError as exc:
        pytest.fail(str(exc))


def count(path: Path) -> int:
    return len(json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"])


def baseline_count(tool: str) -> int:
    return count(BASELINE_RAW / f"{tool}.sarif")


@pytest.mark.parametrize(
    ("tool", "case_id", "mutate", "expected_neutralized"), CASES, ids=[c[1] for c in CASES]
)
def test_planted_file_cannot_change_results(
    tmp_path, rules_cache, tool, case_id, mutate, expected_neutralized
):
    project = tmp_path / "proj"
    shutil.copytree(TARGET, project)
    mutate(project)
    outcome = run_scan(
        str(project),
        ScanOptions(
            out_root=tmp_path / "audits",
            tools=(tool,),
            resource_limits=ResourceLimits(timeout_s=300),
        ),
        rules=rules_cache,
    )
    entry = outcome.manifest["tools"][tool]
    assert entry["status"] == "completed", entry["detail"]
    artifact = outcome.audit_dir / entry["artifact"]
    assert count(artifact) == baseline_count(tool), f"{case_id} changed the {tool} result count"
    neutralized = outcome.manifest["neutralized_files"]
    if expected_neutralized is not None:
        assert expected_neutralized in neutralized


def test_pip_audit_ignores_hostile_requirements_options(tmp_path):
    project = tmp_path / "proj"
    shutil.copytree(TARGET, project)
    req = project / "requirements.txt"
    req.write_text(
        req.read_text(encoding="utf-8")
        + "--index-url http://127.0.0.1:9/simple\n--extra-index-url http://127.0.0.1:9/x\n"
        + "-r other.txt\n-e .\nevil @ http://127.0.0.1:9/evil.whl\n./local/path\n"
        + "unpinned-evil>=1\n",
        encoding="utf-8",
        newline="\n",
    )
    outcome = run_scan(
        str(project),
        ScanOptions(
            out_root=tmp_path / "audits",
            tools=("pip-audit",),
            resource_limits=ResourceLimits(timeout_s=300),
        ),
    )
    entry = outcome.manifest["tools"]["pip-audit"]
    assert entry["status"] == "completed", entry["detail"]
    reasons = {u["reason"] for u in entry["unresolved"]}
    assert {"include_not_followed", "editable", "url_or_path", "unpinned"} <= reasons
    assert [p["name"] for p in entry["pinned_requirements"]] == ["Flask", "PyYAML", "requests"]
    packages = {
        d["name"].lower()
        for d in json.loads((outcome.audit_dir / entry["artifact"]).read_text(encoding="utf-8"))[
            "dependencies"
        ]
    }
    assert packages == {"flask", "pyyaml", "requests"}, "only the exact pins were audited"


@pytest.mark.parametrize("tool", ["bandit", "semgrep", "gitleaks", "pip-audit"])
def test_images_contain_no_git_so_git_mode_cannot_activate(tool):
    """Semgrep's git-tracked-files mode (and .git/.gitignore tricks) needs a git binary."""
    from secaudit.core import exe
    from secaudit.core.scanners import build_adapters

    adapter = build_adapters((tool,), None)[0]
    done = exe.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            adapter.image,
            "-c",
            "command -v git",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode != 0 and done.stdout.strip() == ""
