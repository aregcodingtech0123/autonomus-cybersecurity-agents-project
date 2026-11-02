import importlib.util
import textwrap
from pathlib import Path

import pytest

CHECKER_PATH = Path(__file__).resolve().parent.parent / "benchmarks" / "check_ground_truth.py"


@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location("check_ground_truth", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ground_truth_matches_real_files(checker):
    assert checker.check() == []


def test_checker_detects_line_drift(checker, tmp_path):
    """The checker must fail when an anchor no longer sits in the stated line range."""
    doc = checker.DEFAULT_GROUND_TRUTH.read_text(encoding="utf-8")
    drifted = doc.replace(
        "line_start: 13\n    line_end: 13\n    anchor: yaml.load(",
        "line_start: 12\n    line_end: 12\n    anchor: yaml.load(",
    )
    assert drifted != doc
    bad = tmp_path / "expected_findings.yaml"
    bad.write_text(drifted, encoding="utf-8")
    problems = checker.check(bad)
    assert any(p.startswith("P04:") and "anchor" in p for p in problems)


def test_checker_rejects_missing_cases(checker, tmp_path):
    bad = tmp_path / "expected_findings.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            target: benchmarks/targets/vuln_python_app
            cases: []
            """
        ),
        encoding="utf-8",
    )
    assert any("missing planned cases" in p for p in checker.check(bad))
