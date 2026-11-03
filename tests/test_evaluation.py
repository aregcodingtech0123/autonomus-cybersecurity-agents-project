import json
from pathlib import Path

import pytest

from canaries import BENCHMARK_PASSWORD, aws_key_id, aws_secret_key, stripe_test_key_short
from secaudit import cli
from secaudit.core import evaluation
from secaudit.core.models import Audit, RawRef, SecurityFinding, Severity, ToolHit, ToolRun
from secaudit.core.normalize.pipeline import normalize_audit

ROOT = Path(__file__).resolve().parent.parent
BASELINE = Path(__file__).resolve().parent / "fixtures" / "phase1_baseline"
TARGET = ROOT / "benchmarks" / "targets" / "vuln_python_app"
TRUTH = ROOT / "benchmarks" / "expected_findings.yaml"
PLANTED = [
    stripe_test_key_short(),
    BENCHMARK_PASSWORD,
    aws_key_id(),
    aws_secret_key()[:16],
]


def real_metrics(exclude=("P11",)):
    """Evaluate the committed Phase 1 raw outputs (the files in git at the start of Phase 2A)."""
    manifest = json.loads((BASELINE / "manifest.json").read_text("utf-8"))
    audit = normalize_audit(BASELINE / "raw", manifest=manifest, source_root=TARGET)
    return evaluation.evaluate(
        audit, evaluation.load_truth(TRUTH), manifest=manifest, exclude=tuple(exclude)
    )


# ---------------------------------------------------------------- synthetic semantics


def finding(fid, path, start, end, cls, tools=("bandit",), cwes=()):
    ref = RawRef(artifact="raw/x", artifact_sha256="a" * 64, pointer="/runs/0/results/0")
    hits = tuple(
        ToolHit(
            tool=t,
            rule_id=f"{t}-r",
            message="m",
            file_path=path,
            line_start=start,
            line_end=end,
            cwe_ids=cwes,
            raw_ref=ref,
        )
        for t in tools
    )
    return SecurityFinding(
        id=fid, fingerprint=fid, fingerprint_basis="content", title="t", issue_class=cls, file_path=path,
        line_start=start, line_end=end, hits=hits, cwe_ids=cwes, severity=Severity.HIGH, severity_basis="x",
    )  # fmt: skip


def truth_doc(*cases):
    return {"cases": list(cases)}


def pos(cid="P1", file="a.py", start=10, end=12, cwe="CWE-89", **extra):
    return {
        "id": cid,
        "kind": "positive",
        "title": cid,
        "file": file,
        "line_start": start,
        "line_end": end,
        "cwe": cwe,
        **extra,
    }


def neg(cid="N1", file="a.py", start=20, end=21, cwe="CWE-89", **extra):
    return {
        "id": cid,
        "kind": "negative",
        "title": cid,
        "file": file,
        "line_start": start,
        "line_end": end,
        "cwe": cwe,
        **extra,
    }


def run_eval(findings, *cases, exclude=()):
    audit = Audit(
        findings=tuple(findings),
        tool_runs=(ToolRun(tool="bandit", status="completed", raw_results=len(findings)),),
    )
    return evaluation.evaluate(audit, truth_doc(*cases), exclude=exclude)


def test_positive_needs_overlap_and_an_accepted_class():
    m = run_eval([finding("F1", "a.py", 11, 11, "CWE-89", cwes=("CWE-89",))], pos())
    assert m["positives"][0]["detected"] and m["positives"][0]["detected_by"] == ["bandit"]
    wrong_class = run_eval([finding("F1", "a.py", 11, 11, "CWE-79", cwes=("CWE-79",))], pos())
    assert not wrong_class["positives"][0]["detected"]
    assert "not accepted" in wrong_class["unlabeled_findings"][0]["note"], (
        "near miss is surfaced, not hidden"
    )
    assert not run_eval([finding("F1", "b.py", 11, 11, "CWE-89")], pos())["positives"][0][
        "detected"
    ]
    assert not run_eval([finding("F1", "a.py", 13, 14, "CWE-89")], pos())["positives"][0][
        "detected"
    ]


def test_accepted_classes_use_the_reviewed_equivalences_and_match_entries():
    m = run_eval([finding("F1", "a.py", 10, 10, "CWE-798", cwes=("CWE-259",))], pos(cwe="CWE-798"))
    assert m["positives"][0]["detected"], "CWE-259 folds into CWE-798"
    extra = pos(
        match=[{"file": "a.py", "line_start": 10, "line_end": 12, "cwe": ["CWE-89", "CWE-20"]}]
    )
    assert run_eval([finding("F1", "a.py", 10, 10, "CWE-20", cwes=("CWE-20",))], extra)[
        "positives"
    ][0]["detected"]


def test_glob_classes_for_pip_audit():
    case = pos(
        file="requirements.txt",
        start=1,
        end=3,
        cwe=None,
        match=[{"file": "requirements.txt", "line_start": 1, "line_end": 3, "classes": ["vuln:*"]}],
    )
    m = run_eval(
        [finding("F1", "requirements.txt", 2, 2, "vuln:flask@2.0.1", tools=("pip-audit",))], case
    )
    assert m["positives"][0]["detected"] and m["positives"][0]["detected_by"] == ["pip-audit"]


def test_negative_is_flagged_by_any_class_and_lists_tools_and_rules():
    m = run_eval(
        [finding("F1", "a.py", 20, 20, "CWE-703", tools=("bandit", "semgrep"))],
        neg(expected_false_alarms=None),
    )
    n = m["negatives"][0]
    assert (
        not n["clean"]
        and n["flagged_by"] == ["bandit", "semgrep"]
        and n["rules"] == ["bandit:bandit-r", "semgrep:semgrep-r"]
    )
    assert run_eval([finding("F1", "a.py", 30, 30, "CWE-1")], neg())["negatives"][0]["clean"]


def test_unlabeled_findings_are_listed_and_not_counted_as_false_positives():
    m = run_eval([finding("F1", "elsewhere.py", 1, 1, "CWE-1")], pos(), neg())
    assert [u["id"] for u in m["unlabeled_findings"]] == ["F1"]
    assert (
        m["summary"]["negatives"]["flagged"] == []
        and m["summary"]["negatives"]["false_alarm_rate"] == 0.0
    )


def test_exclude_drops_cases_from_all_denominators():
    m = run_eval([], pos("P1"), pos("P2", file="b.py"), exclude=("P2",))
    assert m["summary"]["positives"]["total"] == 1 and m["inputs"]["excluded_cases"] == ["P2"]


def test_empty_audit_has_no_division_by_zero():
    m = run_eval([], pos())
    assert (
        m["summary"]["findings"]["dedup_ratio"] is None
        and m["summary"]["findings"]["evidence_coverage"] is None
    )


def test_findings_in_test_paths_are_counted_not_excluded():
    f = finding("F1", "tests/test_a.py", 1, 1, "CWE-703").model_copy(update={"is_test_path": True})
    m = run_eval([f], pos())
    assert m["findings_in_test_paths"] == ["F1"] and m["summary"]["findings"]["in_test_paths"] == 1


# ---------------------------------------------------------------- the real Phase 1 numbers, reproduced


def test_reproduces_the_phase1_reference_numbers_from_normalized_findings():
    m = real_metrics()
    assert m["summary"]["positives"]["detected"] == 9 and m["summary"]["positives"]["total"] == 11
    assert m["summary"]["positives"]["missed"] == ["P08", "P10"]
    assert m["summary"]["negatives"]["flagged"] == ["N02", "N04", "N05", "N06"]
    assert m["summary"]["negatives"]["total"] == 7


def test_detected_by_matches_the_recorded_phase1_expectations_for_every_case():
    m = real_metrics()
    assert [p["id"] for p in m["positives"] if not p["matches_expectation"]] == []
    assert [n["id"] for n in m["negatives"] if not n["matches_expectation"]] == []
    assert all(b["clean"] for b in m["injection_bait"])


def test_per_tool_raw_vs_finding_counts_and_dedup_ratio():
    t = real_metrics()["per_tool"]
    assert {k: (v["raw_results"], v["unique_hits"]) for k, v in t.items()} == {
        "bandit": (16, 16), "semgrep": (11, 11), "gitleaks": (3, 3), "pip-audit": (16, 8),
    }  # fmt: skip
    assert t["pip-audit"]["findings"] == 3 and t["pip-audit"]["dedup_ratio"] == 5.33
    assert real_metrics()["summary"]["findings"]["evidence_coverage"] == 1.0


def test_the_three_formerly_unlabeled_findings_are_now_labeled_without_moving_the_numbers():
    m = real_metrics()
    assert m["unlabeled_findings"] == [] and m["summary"]["findings"]["unlabeled"] == 0
    p01 = next(p for p in m["positives"] if p["id"] == "P01")
    assert p01["detected_by"] == ["bandit", "semgrep"] and p01["matches_expectation"]
    related = {r["id"]: r for r in m["related_informational"]}
    assert (related["R01"]["related_to"], related["R01"]["rules"]) == ("P06", ["bandit:B403"])
    assert (related["R02"]["related_to"], related["R02"]["rules"]) == ("P05", ["bandit:B404"])
    assert all(r["matches_expectation"] for r in related.values())
    assert m["summary"]["positives"]["total"] == 11 and m["summary"]["positives"]["detected"] == 9
    assert (
        m["summary"]["negatives"]["total"] == 7 and len(m["summary"]["negatives"]["flagged"]) == 4
    )


def test_related_informational_is_labeled_but_neither_detection_nor_false_positive():
    rel = {
        "id": "R1", "kind": "related_informational", "title": "r", "related_to": "P1",
        "file": "a.py", "line_start": 1, "line_end": 1, "cwe": "CWE-502", "observed_by_tools": ["bandit"],
    }  # fmt: skip
    m = run_eval([finding("F1", "a.py", 1, 1, "CWE-502", cwes=("CWE-502",))], pos(), rel)
    assert m["unlabeled_findings"] == []
    assert m["summary"]["positives"]["total"] == 1 and m["summary"]["positives"]["detected"] == 0
    assert (
        m["summary"]["negatives"]["total"] == 0
        and m["summary"]["findings"]["related_informational"] == 1
    )
    assert m["related_informational"][0]["reported_by"] == ["bandit"]
    wrong = run_eval([finding("F1", "a.py", 1, 1, "CWE-1")], pos(), rel)
    assert not wrong["related_informational"][0]["reported"], "only accepted classes are labeled"
    assert [u["id"] for u in wrong["unlabeled_findings"]] == ["F1"]
    assert run_eval([], pos(), rel, exclude=("R1",))["related_informational"] == []


def test_p01_accepts_the_semgrep_cwe704_tag_on_line_21_only():
    case = next(c for c in evaluation.load_cases(evaluation.load_truth(TRUTH)) if c.id == "P01")
    at21 = finding("F1", "webshop/db.py", 21, 21, "CWE-704", cwes=("CWE-704",))
    at22 = finding("F2", "webshop/db.py", 22, 22, "CWE-704", cwes=("CWE-704",))
    assert any(m.overlaps(at21) and m.accepts(at21) for m in case.matches)
    assert not any(m.overlaps(at22) and m.accepts(at22) for m in case.matches)


def test_metrics_are_deterministic_and_secret_free():
    a, b = evaluation.metrics_json(real_metrics()), evaluation.metrics_json(real_metrics())
    assert a == b and "generated_at" not in a
    md = evaluation.render_markdown(real_metrics())
    for secret in PLANTED:
        assert secret not in a and secret not in md


def test_markdown_states_the_unlabeled_rule():
    md = evaluation.render_markdown(real_metrics())
    assert (
        "NOT counted as false positives" in md
        and "**MISSED**" in md
        and "Negatives falsely flagged" in md
    )


# ---------------------------------------------------------------- CLI


def test_cli_eval_works_without_docker_and_writes_both_files(tmp_path, capsys):
    code = cli.main(
        [
            "eval",
            "--from-raw",
            str(BASELINE / "raw"),
            "--source",
            str(TARGET),
            "--out-dir",
            str(tmp_path),
            "--exclude",
            "P11",  # the frozen Phase 1 raw predates P11
        ]
    )
    out = capsys.readouterr().out
    assert code == 0 and "positives detected 9/11" in out and "negatives flagged  4/7" in out
    assert (tmp_path / "metrics_tool_only.json").is_file() and (
        tmp_path / "metrics_tool_only.md"
    ).is_file()
    assert json.loads((tmp_path / "metrics_tool_only.json").read_text("utf-8"))["schema"] == 1


def test_committed_baseline_metrics_match_a_fresh_eval_of_the_committed_raw(tmp_path):
    committed = Path(__file__).resolve().parent.parent / "benchmarks" / "baseline"
    code = cli.main(
        [
            "eval",
            "--from-raw",
            str(committed / "raw"),
            "--source",
            str(TARGET),
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    for name in ("metrics_tool_only.json", "metrics_tool_only.md"):
        assert (tmp_path / name).read_bytes() == (committed / name).read_bytes(), (
            f"{name} is stale: rerun `secaudit eval --from-raw benchmarks/baseline/raw "
            "--source benchmarks/targets/vuln_python_app`"
        )


def test_cli_eval_exclude_flag(tmp_path, capsys):
    cli.main(
        [
            "eval",
            "--from-raw",
            str(BASELINE / "raw"),
            "--source",
            str(TARGET),
            "--out-dir",
            str(tmp_path),
            "--exclude",
            "P11",
            "--exclude",
            "P08",
            "--exclude",
            "N02",
        ]
    )
    assert "positives detected 9/10" in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["--from-raw", "--source", "--ground-truth"])
def test_cli_eval_rejects_missing_paths(tmp_path, capsys, bad):
    args = {
        "--from-raw": str(BASELINE / "raw"),
        "--source": str(TARGET),
        "--ground-truth": str(TRUTH),
    }
    args[bad] = str(tmp_path / "nope")
    argv = ["eval", *[x for kv in args.items() for x in kv], "--out-dir", str(tmp_path / "o")]
    assert cli.main(argv) == cli.EXIT_USAGE and "does not exist" in capsys.readouterr().err


def test_cli_normalize_writes_a_secret_free_findings_json(tmp_path, capsys):
    audit_dir = tmp_path / "audit"
    (audit_dir / "raw").mkdir(parents=True)
    for f in (BASELINE / "raw").iterdir():
        if f.suffix in {".sarif", ".json"} and not f.name.startswith(
            ("pip-audit.no", "semgrep-flask")
        ):
            (audit_dir / "raw" / f.name).write_bytes(f.read_bytes())
    (audit_dir / "manifest.json").write_bytes((BASELINE / "manifest.json").read_bytes())
    code = cli.main(["normalize", str(audit_dir)])
    assert code == 0 and "25 findings from 46 raw results" in capsys.readouterr().out
    text = (audit_dir / "findings.json").read_text("utf-8")
    doc = json.loads(text)
    assert doc["schema_version"] == "2" and len(doc["findings"]) == 25
    assert all(s not in text for s in PLANTED)
    assert doc["findings"][0]["snippet"] is None, (
        "no retained source/ in this audit: no snippets, and it says so"
    )
    assert any("no source available" in w for w in doc["warnings"])


def test_cli_normalize_refuses_a_non_audit_directory(tmp_path, capsys):
    assert cli.main(["normalize", str(tmp_path)]) == cli.EXIT_USAGE
    assert "not an audit directory" in capsys.readouterr().err
