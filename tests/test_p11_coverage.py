"""Phase 2A Task 7: coverage model, optional extra tool outputs, and benchmark case P11."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from fakes import SARIF, Behaviour, FakeExecutor, fake_rules
from secaudit.core import evaluation
from secaudit.core.normalize.coverage import (
    bandit_coverage,
    pip_audit_coverage,
    semgrep_coverage,
)
from secaudit.core.normalize.pipeline import normalize_audit
from secaudit.core.scan import ScanOptions, run_scan
from secaudit.core.scanners import SemgrepAdapter, ToolPaths

ROOT = Path(__file__).resolve().parent.parent
TRUTH = ROOT / "benchmarks" / "expected_findings.yaml"
LIMITS = ("limit one", "limit two")


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "p11_generator_under_test", ROOT / "benchmarks" / "p11_generator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- P11 generator


def test_generated_file_is_deterministic_big_enough_and_hash_pinned():
    gen = load_generator()
    data = gen.content()
    assert data == gen.content() and len(data) > 1_000_000, (
        "must exceed Semgrep's 1,000,000-byte limit"
    )
    case = next(c for c in yaml.safe_load(TRUTH.read_text("utf-8"))["cases"] if c["id"] == "P11")
    assert hashlib.sha256(data).hexdigest() == gen.expected_sha256() == case["generated"]["sha256"]
    assert case["line_start"] == gen.vulnerable_line() and case["file"] == gen.RELATIVE_PATH


def test_vulnerable_line_really_holds_the_anchor():
    gen = load_generator()
    lines = gen.render().splitlines()
    assert 'open(request.args.get("f"), "rb")' in lines[gen.vulnerable_line() - 1]
    assert gen.vulnerable_line() > len(lines) - 6, "the vulnerable handler is at the very end"


def test_ensure_creates_repairs_and_is_idempotent(tmp_path):
    gen = load_generator()
    assert gen.ensure(tmp_path) is True
    path = tmp_path / gen.RELATIVE_PATH
    assert path.stat().st_size > 1_000_000 and gen.ensure(tmp_path) is False
    path.write_bytes(b"tampered")
    assert gen.ensure(tmp_path) is True and path.read_bytes() == gen.content()


def test_eval_regenerates_the_file_when_missing(tmp_path):
    truth = evaluation.load_truth(TRUTH)
    assert evaluation.ensure_generated(truth, ROOT, tmp_path) == ["P11"]
    assert evaluation.ensure_generated(truth, ROOT, tmp_path) == []
    assert (tmp_path / "webshop" / "generated_big_module.py").is_file()


def test_the_generated_file_is_git_ignored_and_never_committed():
    ignore = (ROOT / ".gitignore").read_text("utf-8")
    assert "benchmarks/targets/vuln_python_app/webshop/generated_big_module.py" in ignore


# ---------------------------------------------------------------- coverage readers

SEMGREP_DOC = {"paths": {"scanned": ["a.py", "pkg\\b.py", "../escape.py", "/etc/passwd", 5]}}


def test_semgrep_skipped_files_are_derived_from_the_source_tree():
    cov = semgrep_coverage(
        SEMGREP_DOC, LIMITS, ["a.py", "pkg/b.py", "webshop/generated_big_module.py"]
    )
    assert cov.status == "known" and cov.analyzed_files == ("a.py", "pkg/b.py")
    assert [(s.path, s.reason) for s in cov.skipped_files] == [
        (
            "webshop/generated_big_module.py",
            "in the source tree but absent from semgrep paths.scanned",
        )
    ]
    assert cov.limitations == LIMITS, (
        "hostile scanned paths were dropped, declared limitations kept"
    )


def test_semgrep_without_source_cannot_say_what_was_skipped():
    cov = semgrep_coverage(SEMGREP_DOC, LIMITS, None)
    assert (
        cov.status == "known" and cov.skipped_files is None and "skipped files unknown" in cov.note
    )


def test_semgrep_uses_an_explicit_skipped_list_when_present():
    doc = {
        "paths": {
            "scanned": ["a.py"],
            "skipped": [{"path": "big.py", "reason": "too big"}, {"path": "../x"}],
        }
    }
    cov = semgrep_coverage(doc, LIMITS, ["a.py", "big.py", "other.py"])
    assert [(s.path, s.reason) for s in cov.skipped_files] == [("big.py", "too big")]


@pytest.mark.parametrize(
    "doc", [None, [], {}, {"paths": None}, {"paths": {}}, {"paths": {"scanned": "x"}}]
)
def test_semgrep_garbage_is_unknown_not_a_crash(doc):
    cov = semgrep_coverage(doc, LIMITS, ["a.py"])
    assert cov.status == "unknown" and cov.analyzed_files is None


def test_bandit_coverage_reads_metrics_and_errors():
    doc = {
        "metrics": {"_totals": {}, "a.py": {}, "pkg/b.py": {}},
        "errors": [{"filename": "bad.py", "reason": "syntax error"}],
    }
    cov = bandit_coverage(doc, LIMITS)
    assert cov.analyzed_files == ("a.py", "pkg/b.py") and [s.path for s in cov.skipped_files] == [
        "bad.py"
    ]
    assert bandit_coverage({}, LIMITS).status == "unknown"


def test_pip_audit_coverage_comes_from_the_manifest():
    entry = {
        "requirements_files": ["requirements.txt", "dev/requirements.txt"],
        "unresolved": [
            {"file": "requirements.txt", "line": 4, "reason": "unpinned", "requirement": "x>=1"}
        ],
        "pinned_requirements": [{"name": "a"}],
    }
    cov = pip_audit_coverage(entry, LIMITS)
    assert cov.status == "known" and cov.analyzed_files == (
        "dev/requirements.txt",
        "requirements.txt",
    )
    assert [(s.path, s.reason) for s in cov.skipped_files] == [("requirements.txt:4", "unpinned")]
    assert pip_audit_coverage({}, LIMITS).status == "unknown"


# ---------------------------------------------------------------- pipeline integration


def raw_with_semgrep(tmp_path, scanned):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
    (raw / "semgrep.json").write_text(json.dumps({"paths": {"scanned": scanned}}))
    (raw / "bandit.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
    (raw / "gitleaks.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
    return raw


def test_pipeline_surfaces_the_file_semgrep_did_not_analyse(tmp_path):
    source = tmp_path / "src"
    (source / "webshop").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n")
    (source / "webshop" / "generated_big_module.py").write_text("y = 2\n")
    audit = normalize_audit(
        raw_with_semgrep(tmp_path, ["app.py"]), manifest=None, source_root=source
    )
    by_tool = {c.tool: c for c in audit.coverage}
    assert by_tool["semgrep"].status == "known"
    assert [s.path for s in by_tool["semgrep"].skipped_files] == ["webshop/generated_big_module.py"]
    assert by_tool["bandit"].status == "unknown" and "JSON format" in by_tool["bandit"].note
    assert by_tool["gitleaks"].status == "unknown" and "does not report" in by_tool["gitleaks"].note


def test_pipeline_without_source_keeps_coverage_honest(tmp_path):
    audit = normalize_audit(raw_with_semgrep(tmp_path, ["app.py"]), manifest=None, source_root=None)
    semgrep = next(c for c in audit.coverage if c.tool == "semgrep")
    assert semgrep.skipped_files is None and "unknown" in semgrep.note


# ---------------------------------------------------------------- adapter: optional extra output


def test_semgrep_command_writes_the_json_copy_next_to_the_sarif(tmp_path):
    cmd = SemgrepAdapter(fake_rules(tmp_path)).build_command(
        ToolPaths("/src", "/out", "/rules", True)
    )
    assert "--json-output=/out/semgrep.json" in cmd and "--sarif-output=/out/semgrep.sarif" in cmd


def scan_semgrep(tmp_path, behaviour):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    executor = FakeExecutor(behaviours={"semgrep": behaviour})
    return run_scan(
        str(project), ScanOptions(out_root=tmp_path / "audits", tools=("semgrep",)),
        executor=executor, rules=fake_rules(tmp_path),
    )  # fmt: skip


def test_extra_output_is_collected_hashed_and_recorded(tmp_path):
    extra = json.dumps({"paths": {"scanned": ["app.py"]}}).encode()
    outcome = scan_semgrep(
        tmp_path, Behaviour(exit_code=0, write=SARIF.encode(), extra={"semgrep.json": extra})
    )
    entry = outcome.manifest["tools"]["semgrep"]
    assert entry["status"] == "completed"
    assert entry["extra_artifacts"] == [
        {
            "path": "raw/semgrep.json",
            "sha256": hashlib.sha256(extra).hexdigest(),
            "bytes": len(extra),
        }
    ]
    assert (outcome.audit_dir / "raw" / "semgrep.json").read_bytes() == extra


@pytest.mark.parametrize(
    ("extra", "problem"),
    [(None, "was not produced"), ({"semgrep.json": b"not json"}, "not valid JSON")],
)
def test_a_missing_or_malformed_extra_output_never_fails_the_tool(tmp_path, extra, problem):
    outcome = scan_semgrep(tmp_path, Behaviour(exit_code=0, write=SARIF.encode(), extra=extra))
    entry = outcome.manifest["tools"]["semgrep"]
    assert entry["status"] == "completed" and "extra_artifacts" not in entry
    assert any(problem in p for p in entry["extra_output_problems"])
    assert not (outcome.audit_dir / "raw" / "semgrep.json").exists()
