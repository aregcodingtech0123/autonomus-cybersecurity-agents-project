"""Phase 2C-A: the pre-registered expansion, its checker and the existing-target pin.

Target code is only read and parsed here, never imported or run. Targets are named explicitly and
nothing lists benchmarks/targets, so these tests cannot pick up or scan anything by accident.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
TARGETS = BENCH / "targets"
EXPANSION = BENCH / "expected_findings_expansion.yaml"
STOPWORDS = ("fake", "test", "example", "sample", "dummy", "placeholder")
FORBIDDEN_CALLS = {"eval", "exec", "open", "os.popen", "os.system"}
FORBIDDEN_MODULES = ("httpx", "pickle", "requests", "socket", "subprocess", "tarfile", "urllib")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _forbidden_module_level_calls(source: str) -> list[str]:
    """Calls to dangerous sinks that would run on import; function bodies are skipped."""
    found: list[str] = []
    stack: list[ast.AST] = list(ast.parse(source).body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        if isinstance(node, ast.Call):
            call = _dotted(node.func)
            if call in FORBIDDEN_CALLS or call.split(".")[0] in FORBIDDEN_MODULES:
                found.append(call)
        stack.extend(ast.iter_child_nodes(node))
    return sorted(found)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, BENCH / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    return _load("check_ground_truth")


@pytest.fixture(scope="module")
def doc():
    return yaml.safe_load(EXPANSION.read_text(encoding="utf-8"))


def _mutated(tmp_path: Path, doc: dict, cid: str, **changes) -> Path:
    """A copy of the expansion file where one case has fields changed (None deletes the field)."""
    copy = json.loads(json.dumps(doc))
    for case in copy["cases"]:
        if case["id"] == cid:
            for key, value in changes.items():
                if value is None:
                    case.pop(key, None)
                else:
                    case[key] = value
    path = tmp_path / "expansion.yaml"
    path.write_text(yaml.safe_dump(copy, sort_keys=False), encoding="utf-8")
    return path


def _copy_target(name: str, destination: Path) -> Path:
    def skip(_directory: str, names: list[str]) -> list[str]:
        return [n for n in names if n in ("__pycache__", "generated_big_module.py")]

    shutil.copytree(TARGETS / name, destination / name, ignore=skip)
    return destination / name


# ---------------------------------------------------------------- the real files


def test_expansion_matches_the_real_files(checker):
    assert checker.check_expansion() == []


def test_the_original_ground_truth_still_validates(checker):
    assert checker.check() == []


def test_final_totals_meet_the_brief(doc, checker):
    old = yaml.safe_load(checker.DEFAULT_GROUND_TRUTH.read_text(encoding="utf-8"))["cases"]
    kinds = [c["kind"] for c in doc["cases"] + old]
    assert kinds.count("positive") >= 24
    assert kinds.count("negative") >= 17


def test_gitleaks_detectable_values_avoid_the_stopwords(doc):
    """Positive secrets must stay detectable: Gitleaks' generic rule skips these words."""
    secret_cases = [c for c in doc["cases"] if c["kind"] == "positive" and c["cwe"] == "CWE-798"]
    assert secret_cases
    for case in secret_cases:
        path = TARGETS / case["target"] / case["file"]
        line = path.read_text(encoding="utf-8").splitlines()[case["line_start"] - 1]
        assert "bench_" in line
        value = line[line.index("bench_") :].strip().lower()
        assert not any(word in value for word in STOPWORDS), case["id"]


def test_dead_code_case_really_has_no_caller():
    """P40 is labeled unreachable: no file in its target may mention the module."""
    target = TARGETS / "ops_toolbox"
    module = target / "toolbox" / "legacy_restore.py"
    for path in sorted(target.rglob("*")):
        if path.is_file() and path != module and "__pycache__" not in path.parts:
            assert "legacy_restore" not in path.read_text(encoding="utf-8"), path.name


@pytest.mark.parametrize("name", ["admin_portal", "ops_toolbox", "shop_api"])
def test_target_code_is_inert_at_import(name, checker):
    """Sinks stay inside functions, so importing a target module reaches none of them."""
    for path in checker.target_files(TARGETS / name):
        if path.suffix == ".py":
            source = path.read_text(encoding="utf-8")
            assert _forbidden_module_level_calls(source) == [], path.name


def test_inertness_check_flags_a_module_level_sink():
    source = "import os\nimport requests\nrequests.get('x')\nos.system('x')\nopen('x')\n"
    assert _forbidden_module_level_calls(source) == ["open", "os.system", "requests.get"]
    assert _forbidden_module_level_calls("def f():\n    open('x')\n") == []


# ---------------------------------------------------------------- the existing target stays frozen


def test_existing_target_matches_its_manifest(checker):
    pinned = json.loads(checker.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    assert pinned == checker.existing_target_hashes(TARGETS / "vuln_python_app")
    assert list(pinned) == sorted(pinned)
    assert "webshop/db.py" in pinned


@pytest.mark.parametrize("change", ["modified", "added", "removed"])
def test_checker_rejects_a_changed_existing_target(checker, doc, tmp_path, change):
    root = tmp_path / "targets"
    copy = _copy_target("vuln_python_app", root)
    if change == "modified":
        with (copy / "webshop" / "db.py").open("ab") as handle:
            handle.write(b"# edited\n")
    elif change == "added":
        (copy / "webshop" / "new_module.py").write_bytes(b"")
    else:
        (copy / "webshop" / "db.py").unlink()
    for name in ("admin_portal", "ops_toolbox", "shop_api"):
        _copy_target(name, root)
    problems = checker.check_expansion(targets_root=root)
    assert any(f"existing target file {change}" in p for p in problems)


# ---------------------------------------------------------------- one mutation per failure class


def test_checker_rejects_a_duplicate_id(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "N09", id="N08")
    assert any("N08: duplicate id" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_id_used_in_the_original_file(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P12", id="P01")
    assert any("already used" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_id_gap(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P40", id="P44")
    assert any("without gaps" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_anchor_outside_the_lines(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P16", line_start=9, line_end=9)
    assert any(p.startswith("P16:") and "anchor" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_missing_rationale(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "N10", rationale=None)
    assert any("N10: missing field 'rationale'" in p for p in checker.check_expansion(path))


@pytest.mark.parametrize("cid", ["P12", "N08"])
def test_checker_rejects_a_missing_prior(checker, doc, tmp_path, cid):
    path = _mutated(tmp_path, doc, cid, prior_detectability=None)
    assert any(f"{cid}: missing prior_detectability" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_secrets_prior_of_yes(checker, doc, tmp_path):
    prior = {"sast": "no", "secrets": "yes", "sca": "no"}
    path = _mutated(tmp_path, doc, "P17", prior_detectability=prior)
    assert any("Gitleaks was not run" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_unknown_target(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P12", target="not_a_target")
    assert any("P12: unknown target" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_quota_shortfall(checker, doc, tmp_path):
    copy = json.loads(json.dumps(doc))
    copy["cases"] = [c for c in copy["cases"] if c["kind"] != "masking_probe"]
    path = tmp_path / "expansion.yaml"
    path.write_text(yaml.safe_dump(copy, sort_keys=False), encoding="utf-8")
    assert any("quota not met: 0 new masking_probe" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_target_without_the_banner(checker, tmp_path):
    root = tmp_path / "targets"
    _copy_target("vuln_python_app", root)
    for name in ("admin_portal", "ops_toolbox", "shop_api"):
        _copy_target(name, root)
    (root / "ops_toolbox" / "README.md").write_text("# ops-toolbox\n", encoding="utf-8")
    problems = checker.check_expansion(targets_root=root)
    assert any("ops_toolbox: README.md does not carry the banner" in p for p in problems)


def test_checker_rejects_overlapping_cases(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "M07", line_start=27, line_end=29)
    assert any(
        "M07 and P12 overlap" in p or "P12 and M07 overlap" in p
        for p in (checker.check_expansion(path))
    )


def test_checker_rejects_a_wrong_canary(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "M01", canary="not-in-the-file")
    assert any("M01: canary not found" in p for p in checker.check_expansion(path))


def test_checker_rejects_low_confidence_without_a_doubt(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P39", label_doubt=None)
    assert any("P39: confidence below high" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_dependency_positive_without_advisories(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P18", advisories=None)
    assert any("P18: dependency positive" in p for p in checker.check_expansion(path))


# ---------------------------------------------------------------- the label review


def _case(doc: dict, cid: str) -> dict:
    return next(c for c in doc["cases"] if c["id"] == cid)


def _with_evidence(tmp_path: Path, doc: dict, **changes) -> Path:
    copy = json.loads(json.dumps(doc))
    copy["interpreter_evidence"].update(changes)
    path = tmp_path / "expansion.yaml"
    path.write_text(yaml.safe_dump(copy, sort_keys=False), encoding="utf-8")
    return path


def test_unscored_cases_keep_their_ids_and_carry_no_match(doc):
    unscored = {c["id"]: c for c in doc["cases"] if c["kind"] == "unscored"}
    assert sorted(unscored) == ["N23", "P39"]
    for case in unscored.values():
        assert "match" not in case
        assert case["unscored_reason"].strip() and case["pipeline_expectation"].strip()
    assert "unresolved" in unscored["P39"]["pipeline_expectation"]
    assert "CVE-2026-107784" in unscored["N23"]["unscored_reason"]


@pytest.mark.parametrize("field", ["unscored_reason", "pipeline_expectation"])
def test_checker_rejects_unscored_without_its_fields(checker, doc, tmp_path, field):
    path = _mutated(tmp_path, doc, "P39", **{field: None})
    assert any(f"P39: unscored without {field}" in p for p in checker.check_expansion(path))


def test_checker_rejects_unscored_with_a_match(checker, doc, tmp_path):
    entry = {"file": "requirements.txt", "line_start": 4, "line_end": 4, "classes": ["vuln:*"]}
    path = _mutated(tmp_path, doc, "P39", match=[entry])
    assert any("P39: unscored must not have match" in p for p in checker.check_expansion(path))


def test_checker_rejects_unscored_fields_on_a_scored_case(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P12", unscored_reason="not really")
    assert any("P12: unscored_reason and" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_unscored_case_with_a_bait_prefix(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "I03", kind="unscored")
    assert any("unscored: id prefix" in p for p in checker.check_expansion(path))


def test_expected_miss_reasons_match_the_review(doc):
    reasons = {
        c["id"]: c["expected_miss_reason"] for c in doc["cases"] if "expected_miss_reason" in c
    }
    expected = {f"P{i}": "tool_blind" for i in range(20, 25)}
    assert reasons == {**expected, "P16": "no_rule", "P38": "pipeline_gap"}


def test_checker_requires_a_miss_reason_on_an_all_no_positive(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P16", expected_miss_reason=None)
    assert any("P16: positive with an all-no prior" in p for p in checker.check_expansion(path))


def test_checker_rejects_an_unknown_miss_reason(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P16", expected_miss_reason="unlucky")
    assert any("P16: expected_miss_reason 'unlucky'" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_miss_reason_on_a_detectable_positive(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P12", expected_miss_reason="no_rule")
    assert any("P12: expected_miss_reason is only" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_miss_reason_that_contradicts_tool_blind(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P20", expected_miss_reason="no_rule")
    assert any("P20: expected_miss_reason tool_blind" in p for p in checker.check_expansion(path))


@pytest.mark.parametrize("cid", ["P18", "P19", "P32", "P38", "P39"])
def test_every_sca_case_states_its_reachability(doc, cid):
    assert _case(doc, cid)["context"]["reachability"] in {"not reachable", "not verified"}


def test_checker_rejects_an_sca_case_with_a_bad_reachability(checker, doc, tmp_path):
    context = dict(_case(doc, "P38")["context"], reachability="maybe")
    path = _mutated(tmp_path, doc, "P38", context=context)
    assert any("P38: invalid context.reachability" in p for p in checker.check_expansion(path))


def test_scoring_note_text_is_the_agreed_one(doc, checker):
    for cid in sorted(checker.SCORING_NOTE_CASES):
        assert _case(doc, cid)["scoring_note"] == checker.SCORING_NOTE


def test_checker_requires_the_scoring_note(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P32", scoring_note=None)
    assert any("P32: missing scoring_note" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_changed_scoring_note(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "P32", scoring_note="counts only when exploitable")
    assert any("P32: scoring_note differs" in p for p in checker.check_expansion(path))


def test_p32_records_advisories_for_each_pin_and_keeps_both_lines(doc):
    case = _case(doc, "P32")
    by_package = {}
    for advisory in case["advisories"]:
        by_package.setdefault(advisory["package"], []).append(advisory["id"])
    assert by_package["Flask"] == ["GHSA-68rp-wp8r-4726"]
    assert len(by_package["Werkzeug"]) == 10
    assert (case["line_start"], case["line_end"]) == (2, 3)


@pytest.mark.parametrize("cid", ["P31", "P34", "P36", "P38", "P40"])
def test_review_kept_the_label_and_added_the_assumptions(doc, cid):
    case = _case(doc, cid)
    assert case["kind"] == "positive" and case["confidence_in_label"] == "medium"
    assert "Exploitability assumptions:" in " ".join(case["rationale"].split())


def test_negative_rationales_name_their_enforcing_lines(doc):
    assert "no code execution; DoS risk bounded by the cap" in _case(doc, "N22")["rationale"]
    assert all(f"Line {n}" in _case(doc, "N26")["rationale"] for n in (26, 30, 31))
    assert all(f"ine {n}" in _case(doc, "N17")["rationale"] for n in (53, 61))
    assert all(f"ine {n}" in _case(doc, "N18")["rationale"] for n in (32, 33))


def test_n26_really_has_an_allow_list_and_a_bound_value(doc):
    lines = (
        (TARGETS / "ops_toolbox" / "toolbox" / "report.py").read_text(encoding="utf-8").splitlines()
    )
    assert lines[25].startswith("_REPORT_TABLES = {")
    assert lines[29].strip().startswith("table = _REPORT_TABLES[kind]")
    assert "WHERE total >= ?" in lines[30] and "(min_total,)" in lines[30]


def test_interpreter_range_matches_the_target(doc):
    assert doc["interpreter_evidence"]["required_range"] == ">=3.13.18,<3.14"
    for cid in ("P35", "N23"):
        assert ">=3.13.18,<3.14" in _case(doc, cid)["context"]["notes"]
        assert ">=3.13.18,<3.14" in _case(doc, cid)["rationale"]


def test_checker_rejects_a_range_that_differs_from_the_target(checker, doc, tmp_path):
    path = _with_evidence(tmp_path, doc, required_range=">=3.13.16,<3.14")
    assert any("pyproject.toml declares" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_range_that_allows_the_new_default(checker, doc, tmp_path):
    path = _with_evidence(tmp_path, doc, required_range=">=3.13.18,<3.15")
    assert any("breaks P35" in p for p in checker.check_expansion(path))


def test_checker_rejects_a_floor_below_a_recorded_fix(checker, doc, tmp_path):
    fixes = [*doc["interpreter_evidence"]["fixes"], {"cve": "CVE-X", "fixed_3_13": "3.13.19"}]
    path = _with_evidence(tmp_path, doc, fixes=fixes)
    assert any("floor is below the CVE-X fix" in p for p in checker.check_expansion(path))


def test_checker_rejects_n23_as_negative_while_a_fix_is_missing(checker, doc, tmp_path):
    path = _mutated(tmp_path, doc, "N23", kind="negative")
    assert any("N23 must be unscored" in p for p in checker.check_expansion(path))


def test_checker_asks_to_restore_n23_once_every_fix_is_released(checker, doc, tmp_path):
    fixes = [f for f in doc["interpreter_evidence"]["fixes"] if f["fixed_3_13"] is not None]
    path = _with_evidence(tmp_path, doc, fixes=fixes)
    assert any("N23 must be negative" in p for p in checker.check_expansion(path))
