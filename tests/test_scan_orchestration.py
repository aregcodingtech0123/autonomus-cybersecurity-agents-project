import json
import tempfile
from pathlib import Path

import pytest

from fakes import Behaviour, FakeExecutor, fake_rules
from secaudit.core.intake import IntakeError, Reason
from secaudit.core.scan import ScanOptions, run_scan
from secaudit.core.scanners.semgrep import SEMGREPIGNORE_BODY, SEMGREPIGNORE_NAME


@pytest.fixture
def sys_tmp(tmp_path, monkeypatch):
    """Redirect the system temp dir so we can assert nothing is left behind."""
    root = tmp_path / "systmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def project(tmp_path):
    src = tmp_path / "myproject"
    src.mkdir()
    (src / "app.py").write_bytes(b"print('x')\n")
    (src / "requirements.txt").write_bytes(b"flask==2.0.1\nrequests>=2\n")
    return src


def scan(project, tmp_path, rules, executor, tools=("bandit", "semgrep", "gitleaks", "pip-audit")):
    return run_scan(
        str(project),
        ScanOptions(out_root=tmp_path / "audits", tools=tools, runner="docker"),
        executor=executor,
        rules=rules,
    )


def test_manifest_and_raw_outputs(project, tmp_path, sys_tmp):
    outcome = scan(project, tmp_path, fake_rules(tmp_path), FakeExecutor())
    audit = outcome.audit_dir
    manifest = json.loads((audit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["audit_id"] == audit.name
    assert manifest["schema_version"] == 1 and manifest["runner"] == "fake"
    assert manifest["tool_order"] == ["bandit", "semgrep", "gitleaks", "pip-audit"]
    assert manifest["summary"] == {"completed": 4, "skipped": 0, "failed": 0}
    assert sorted(p.name for p in (audit / "raw").iterdir()) == [
        "bandit.sarif", "gitleaks.sarif", "pip-audit.json", "semgrep.sarif",
    ]  # fmt: skip
    for name, tool in manifest["tools"].items():
        assert tool["artifact"].startswith("raw/") and "\\" not in tool["artifact"]
        assert tool["command"][0] == name and tool["pinned_version"] and tool["artifact_sha256"]
    assert manifest["tools"]["semgrep"]["ruleset_info"]["rulesets"][0]["name"] == "p/python"
    pip = manifest["tools"]["pip-audit"]
    assert pip["unresolved"][0]["requirement"] == "requests>=2"
    assert pip["pinned_requirements"][0]["name"] == "flask"
    assert manifest["input"]["kind"] == "directory" and manifest["input"]["source"] == "myproject"
    assert manifest["input"]["file_count"] == 2 and len(manifest["input"]["sha256"]) == 64
    assert manifest["workspace_policy_files"] == [SEMGREPIGNORE_NAME]
    blob = json.dumps(manifest)
    assert str(tmp_path) not in blob and str(sys_tmp) not in blob, "no local paths in the manifest"
    assert "\\\\" not in blob


def test_a_failing_tool_does_not_abort_the_others(project, tmp_path, sys_tmp):
    executor = FakeExecutor(behaviours={"bandit": Behaviour(exit_code=2, write=None)})
    outcome = scan(project, tmp_path, fake_rules(tmp_path), executor)
    statuses = {r.tool: r.status for r in outcome.results}
    assert statuses == {"bandit": "failed", "semgrep": "completed", "gitleaks": "completed",
                        "pip-audit": "completed"}  # fmt: skip
    assert outcome.manifest["summary"]["failed"] == 1 and not outcome.tools_ok
    assert outcome.manifest["tools"]["bandit"]["artifact"] is None
    assert "stderr_tail" in outcome.manifest["tools"]["bandit"]


def test_unexpected_exception_in_one_tool_is_contained(project, tmp_path, sys_tmp):
    executor = FakeExecutor(behaviours={"gitleaks": Behaviour(raises=RuntimeError("kaboom"))})
    outcome = scan(project, tmp_path, fake_rules(tmp_path), executor)
    by_tool = {r.tool: r for r in outcome.results}
    assert by_tool["gitleaks"].status == "failed" and "RuntimeError" in by_tool["gitleaks"].detail
    assert by_tool["pip-audit"].status == "completed"


def test_timeout_is_recorded_per_tool(project, tmp_path, sys_tmp):
    executor = FakeExecutor(behaviours={"semgrep": Behaviour(exit_code=None, timed_out=True)})
    outcome = scan(project, tmp_path, fake_rules(tmp_path), executor)
    assert outcome.manifest["tools"]["semgrep"]["status"] == "timeout"
    assert outcome.manifest["tools"]["bandit"]["status"] == "completed"


def test_workspace_is_always_cleaned_up(project, tmp_path, sys_tmp):
    scan(project, tmp_path, fake_rules(tmp_path), FakeExecutor())
    assert list(sys_tmp.iterdir()) == []
    failing = FakeExecutor(behaviours={t: Behaviour(exit_code=2) for t in
                                       ("bandit", "semgrep", "gitleaks", "pip-audit")})  # fmt: skip
    scan(project, tmp_path, fake_rules(tmp_path), failing)
    assert list(sys_tmp.iterdir()) == []


def test_intake_rejection_raises_and_leaves_nothing(tmp_path, sys_tmp):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip at all")
    with pytest.raises(IntakeError) as exc:
        run_scan(str(bad), ScanOptions(out_root=tmp_path / "audits"), executor=FakeExecutor(),
                 rules=fake_rules(tmp_path))  # fmt: skip
    assert exc.value.reason is Reason.INVALID_ARCHIVE
    assert list(sys_tmp.iterdir()) == []
    assert not (tmp_path / "audits").exists()


def test_scan_scope_policy_cannot_be_overridden_by_scanned_code(project, tmp_path, sys_tmp):
    (project / SEMGREPIGNORE_NAME).write_bytes(b"*\n")  # hostile: ignore everything
    executor = FakeExecutor()
    seen = {}
    original = executor.run

    def spy(adapter, prepared, out_dir, command, label):
        if adapter.name == "semgrep" and prepared.src_dir:
            seen["body"] = (prepared.src_dir / SEMGREPIGNORE_NAME).read_text(encoding="utf-8")
        return original(adapter, prepared, out_dir, command, label)

    executor.run = spy
    scan(project, tmp_path, fake_rules(tmp_path), executor, tools=("semgrep",))
    assert seen["body"] == SEMGREPIGNORE_BODY


def test_tool_subset_runs_only_requested_tools(project, tmp_path, sys_tmp):
    executor = FakeExecutor()
    outcome = scan(project, tmp_path, fake_rules(tmp_path), executor, tools=("bandit",))
    assert [r.tool for r in outcome.results] == ["bandit"]
    assert {name for name, _ in executor.calls} == {"bandit"}


def test_missing_rules_cache_fails_only_semgrep(project, tmp_path, sys_tmp, monkeypatch):
    monkeypatch.setenv("SECAUDIT_RULES_DIR", str(tmp_path / "no-rules-here"))
    outcome = run_scan(
        str(project),
        ScanOptions(out_root=tmp_path / "audits", tools=("semgrep", "bandit")),
        executor=FakeExecutor(),
    )
    statuses = {r.tool: r.status for r in outcome.results}
    assert statuses == {"semgrep": "failed", "bandit": "completed"}
    assert "rules update" in outcome.manifest["tools"]["semgrep"]["detail"]


def test_each_tool_gets_its_own_output_directory(project, tmp_path, sys_tmp):
    outs = []
    executor = FakeExecutor()
    original = executor.run

    def spy(adapter, prepared, out_dir, command, label):
        if command != adapter.version_command():
            outs.append(Path(out_dir))
        return original(adapter, prepared, out_dir, command, label)

    executor.run = spy
    scan(project, tmp_path, fake_rules(tmp_path), executor)
    assert len(outs) == len(set(outs)) == 4, "tools must never share a writable output directory"
