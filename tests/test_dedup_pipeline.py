import hashlib
import json
import random
from pathlib import Path

import pytest

from secaudit.core.models import RawRef, Severity, ToolHit
from secaudit.core.normalize.dedup import build_findings, collapse_identical
from secaudit.core.normalize.pipeline import export_json, normalize_audit

BASELINE = Path(__file__).resolve().parent.parent / "benchmarks" / "baseline"
TARGET = Path(__file__).resolve().parent.parent / "benchmarks" / "targets" / "vuln_python_app"
PLANTED = [
    "bench_n0" "VQRgmEuLNsKJ4a0ZkKpFxr11",
    "not-a-real-password-benchmark-fake",
    "placeholder-not-a-real-password",
    "benc" "h_uoSN55OKIJ9XKt",
    "bench_BvXX7C2JUsDNWW" "hy5PUSWscCmH1w2oxhud",
    "benc" "h_eEA2vGLEXAMPLE",
    "bench_482czv7pDcEQR8" "dwYWxBZZH4EXAMPLEKEY",
]


def hit(
    tool="bandit",
    rule="B608",
    path="app.py",
    start=3,
    end=None,
    cwe=("CWE-89",),
    sev="HIGH",
    n=0,
    **kw,
):
    return ToolHit(
        tool=tool,
        rule_id=rule,
        raw_severity=sev,
        message=kw.pop("message", f"msg {rule}"),
        file_path=path,
        line_start=start,
        line_end=start if end is None else end,
        cwe_ids=cwe,
        raw_ref=RawRef(
            artifact=f"raw/{tool}.sarif", artifact_sha256="a" * 64, pointer=f"/runs/0/results/{n}"
        ),
        **kw,
    )


def findings_of(hits, source=None, gitleaks=None):
    return build_findings(hits, source, gitleaks or {})[0]


# ---------------------------------------------------------------- merge rules


def test_same_file_overlap_and_same_class_merge_across_tools_keeping_all_hits():
    f = findings_of(
        [
            hit("bandit", "B608", start=21),
            hit("semgrep", "sg-sql", start=19, end=22, sev="warning", n=1),
        ]
    )
    assert len(f) == 1 and len(f[0].hits) == 2 and f[0].tools == ("bandit", "semgrep")
    assert (f[0].line_start, f[0].line_end) == (19, 22)


def test_different_classes_on_the_same_line_are_never_merged():
    f = findings_of(
        [hit(cwe=("CWE-89",)), hit("semgrep", "x", cwe=("CWE-704",), sev="warning", n=1)]
    )
    assert len(f) == 2


def test_no_overlap_or_other_file_means_no_merge():
    assert len(findings_of([hit(start=3), hit(start=10, n=1)])) == 2
    assert len(findings_of([hit(path="a.py"), hit(path="b.py", n=1)])) == 2
    assert len(findings_of([hit(start=3, end=5), hit(start=5, end=6, n=1)])) == 1, (
        "touching ranges overlap"
    )
    assert len(findings_of([hit(start=3, end=4), hit(start=5, end=6, n=1)])) == 2


def test_reviewed_equivalence_327_and_328_merge_but_unrelated_classes_do_not():
    assert (
        len(
            findings_of(
                [hit(cwe=("CWE-327",)), hit("semgrep", "m", cwe=("CWE-328",), sev="warning", n=1)]
            )
        )
        == 1
    )
    assert (
        len(
            findings_of(
                [hit(cwe=("CWE-327",)), hit("semgrep", "m", cwe=("CWE-89",), sev="warning", n=1)]
            )
        )
        == 2
    )


def test_rules_without_cwe_only_merge_with_themselves():
    f = findings_of(
        [
            hit(rule="R1", cwe=()),
            hit("semgrep", "R2", cwe=(), n=1),
            hit(rule="R1", cwe=(), n=2, start=3),
        ]
    )
    assert len(f) == 2 and {x.issue_class for x in f} == {"rule:bandit:R1", "rule:semgrep:R2"}


def test_multi_cwe_hits_merge_when_any_class_is_shared():
    f = findings_of(
        [
            hit(cwe=("CWE-79", "CWE-89")),
            hit("semgrep", "x", cwe=("CWE-89", "CWE-20"), sev="warning", n=1),
        ]
    )
    assert len(f) == 1 and f[0].issue_class == "CWE-89"


def test_identical_hits_of_one_tool_collapse():
    kept, collapsed = collapse_identical([hit(n=0), hit(n=1), hit(n=2, start=9)])
    assert len(kept) == 2 and collapsed == 1
    f = findings_of([hit(n=0), hit(n=1)])
    assert len(f) == 1 and len(f[0].hits) == 1


def test_severity_is_the_highest_mapped_one_with_its_basis_and_raw_values_stay_on_hits():
    f = findings_of([hit("bandit", "B608", sev="MEDIUM"), hit("semgrep", "sg", sev="error", n=1)])[
        0
    ]
    assert f.severity is Severity.HIGH and f.severity_basis.startswith("semgrep:sg")
    assert sorted(h.raw_severity for h in f.hits) == ["MEDIUM", "error"]


def test_unknown_severity_stays_unknown_and_warns():
    findings, warnings, _ = build_findings([hit(sev="SEVERE")], None, {})
    assert findings[0].severity is Severity.UNKNOWN and warnings


def pip(rule, n, aliases=(), fixes=("1.2",), pkg="flask", ver="2.0.1", line=1):
    return hit(
        "pip-audit",
        rule,
        path="requirements.txt",
        start=line,
        end=line,
        cwe=(),
        sev=None,
        n=n,
        aliases=aliases,
        fix_versions=fixes,
        package=pkg,
        package_version=ver,
    )


def test_pip_audit_groups_by_package_and_version_unions_aliases_and_keeps_fixes():
    hits = [
        pip("PYSEC-1", 0, ("CVE-1", "PYSEC-1"), ("2.2.5",)),
        pip("PYSEC-1", 1, ("CVE-1", "GHSA-x"), ("2.2.5",)),
        pip("PYSEC-2", 2, ("CVE-2", "PYSEC-2"), ("2.3.2",)),
        pip("PYSEC-9", 3, pkg="requests", ver="2.19.0", line=3),
    ]
    f = findings_of(hits)
    flask = next(x for x in f if x.issue_class == "vuln:flask@2.0.1")
    assert len(f) == 2 and len(flask.hits) == 2, "the duplicate PYSEC-1 entry collapsed"
    assert flask.aliases == ("CVE-1", "CVE-2", "GHSA-x", "PYSEC-1", "PYSEC-2")
    assert flask.fix_versions == ("2.2.5", "2.3.2") and flask.severity is Severity.UNKNOWN
    assert flask.title.startswith("flask 2.0.1 has 2 known vulnerabilities")


def test_pip_audit_never_merges_into_a_sarif_finding_on_the_same_lines():
    f = findings_of(
        [pip("PYSEC-1", 0), hit(path="requirements.txt", start=1, cwe=("CWE-1395",), n=1)]
    )
    assert len(f) == 2


# ---------------------------------------------------------------- fingerprints and ids

SRC = "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n"


def src_tree(tmp_path, text=SRC):
    (tmp_path / "app.py").write_text(text, encoding="utf-8", newline="\n")
    return tmp_path


def fp(tmp_path, text, line, **kw):
    root = src_tree(tmp_path, text)
    return findings_of([hit(path="app.py", start=line, end=line, cwe=("CWE-78",), **kw)], root)[0]


def test_fingerprint_survives_unrelated_line_shifts_and_changes_with_the_flagged_line(tmp_path):
    base = fp(tmp_path, SRC, 5)
    shifted = fp(tmp_path, "# header\n# more\n" + SRC, 7)
    assert base.fingerprint == shifted.fingerprint and base.id == shifted.id
    assert base.fingerprint_basis == "content"
    edited = fp(tmp_path, SRC.replace("os.system(cmd)", "os.system(cmd + ' -x')"), 5)
    assert edited.fingerprint != base.fingerprint
    assert (
        fp(tmp_path, SRC.replace("    return os", "        return   os"), 5).fingerprint
        == base.fingerprint
    ), "whitespace-only edits do not change it"


def test_fingerprint_depends_on_class_and_file(tmp_path):
    root = src_tree(tmp_path)
    (root / "other.py").write_text(SRC, encoding="utf-8")
    a = findings_of([hit(path="app.py", start=5, end=5, cwe=("CWE-78",))], root)[0]
    b = findings_of([hit(path="other.py", start=5, end=5, cwe=("CWE-78",))], root)[0]
    c = findings_of([hit(path="app.py", start=5, end=5, cwe=("CWE-89",))], root)[0]
    assert len({a.fingerprint, b.fingerprint, c.fingerprint}) == 3


def test_fingerprint_is_stable_when_a_secret_is_rotated_and_never_hashes_the_secret(tmp_path):
    old = fp(tmp_path, 'PASSWORD = "hunter2-old-value"\n', 1)
    new = fp(tmp_path, 'PASSWORD = "another-completely-different"\n', 1)
    assert old.fingerprint == new.fingerprint


def test_without_source_the_fingerprint_is_location_based_and_says_so():
    f = findings_of([hit()])[0]
    assert f.fingerprint_basis == "location" and f.snippet is None


def test_equal_fingerprints_get_distinct_stable_ids(tmp_path):
    root = src_tree(tmp_path, "x = os.system(a)\nx = os.system(a)\n")
    f = findings_of(
        [
            hit(path="app.py", start=1, end=1, cwe=("CWE-78",)),
            hit(path="app.py", start=2, end=2, cwe=("CWE-78",), n=1),
        ],
        root,
    )
    assert len(f) == 2 and f[0].fingerprint == f[1].fingerprint and f[0].id != f[1].id


def test_input_order_does_not_matter():
    hits = [hit(start=i, end=i, n=i, path=f"f{i % 3}.py") for i in range(1, 12)]
    reference = [f.model_dump_json() for f in findings_of(hits)]
    for seed in range(5):
        shuffled = hits[:]
        random.Random(seed).shuffle(shuffled)  # noqa: S311 - deterministic test shuffle
        assert [f.model_dump_json() for f in findings_of(shuffled)] == reference


def test_snippet_comes_from_the_source_is_masked_and_bounded(tmp_path):
    root = src_tree(tmp_path, "a = 1\nPASSWORD = 'zzz-secret-value-1234'\nb = 2\n" + "x = 1\n" * 40)
    f = findings_of([hit(path="app.py", start=2, end=2, cwe=("CWE-259",))], root)[0]
    assert "zzz-secret-value-1234" not in f.snippet and "<REDACTED>" in f.snippet
    assert len(f.snippet) <= 1500 and f.snippet.splitlines()[0].startswith("    1 |")


def test_gitleaks_flagged_lines_are_replaced_in_the_snippet(tmp_path):
    root = src_tree(tmp_path, "a = 1\nweird = 'nothing-the-regex-would-catch'\nb = 2\n")
    f = findings_of(
        [
            hit(
                "gitleaks",
                "generic-api-key",
                path="app.py",
                start=2,
                end=2,
                cwe=("CWE-798",),
                sev=None,
            )
        ],
        root,
        gitleaks={"app.py": {2}},
    )[0]
    assert "nothing-the-regex" not in f.snippet and "redacted" in f.snippet


def test_symlink_and_escaping_source_paths_are_not_read(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP SECRET FILE", encoding="utf-8")
    root = tmp_path / "src"
    root.mkdir()
    f = findings_of([hit(path="../outside.txt" if False else "missing.py", start=1, end=1)], root)[
        0
    ]
    assert f.snippet is None and f.fingerprint_basis == "location"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_a.py", True),
        ("pkg/tests/x.py", True),
        ("test_x.py", True),
        ("conftest.py", True),
        ("a/b_test.py", True),
        ("src/app.py", False),
        ("contest.py", False),
        ("latest/app.py", False),
    ],
)
def test_test_paths_are_tagged_but_never_excluded(path, expected, tmp_path):
    f = findings_of([hit(path=path)])
    assert len(f) == 1 and f[0].is_test_path is expected


def test_owasp_category_and_unmapped_cwes():
    f = findings_of([hit(cwe=("CWE-89",)), hit(rule="Z", cwe=("CWE-704",), n=1, start=40, end=40)])
    assert {x.issue_class: x.owasp_2025 for x in f} == {"CWE-89": "A05", "CWE-704": None}


# ---------------------------------------------------------------- the pipeline on the real baseline


def baseline_audit(source=TARGET):
    manifest = json.loads((BASELINE / "manifest.json").read_text("utf-8"))
    return normalize_audit(BASELINE / "raw", manifest=manifest, source_root=source)


def test_pipeline_real_baseline_counts():
    a = baseline_audit()
    runs = {r.tool: (r.raw_results, r.hits, r.unique_hits, r.skipped_results) for r in a.tool_runs}
    assert runs == {
        "bandit": (16, 16, 16, 0),
        "semgrep": (11, 11, 11, 0),
        "gitleaks": (3, 3, 3, 0),
        "pip-audit": (16, 16, 8, 0),
    }
    assert len(a.findings) == 25 and all(f.hits for f in a.findings)
    assert a.audit_id and a.input.kind == "directory" and a.source.retained is True


def test_every_hit_points_back_at_the_right_raw_result_with_the_right_hash():
    a = baseline_audit()
    for finding in a.findings:
        for h in finding.hits:
            data = (BASELINE / h.raw_ref.artifact.replace("raw/", "raw/")).read_bytes()
            assert hashlib.sha256(data).hexdigest() == h.raw_ref.artifact_sha256
            node = json.loads(data)
            for part in h.raw_ref.pointer.split("/")[1:]:
                node = node[int(part)] if part.isdigit() else node[part]
            if h.tool == "pip-audit":
                assert node["id"] == h.rule_id
            else:
                assert node["ruleId"] == h.rule_id


def test_normalizing_twice_is_byte_identical():
    assert export_json(baseline_audit()) == export_json(baseline_audit())


def test_no_planted_secret_appears_anywhere_in_the_derived_export():
    raw_text = (BASELINE / "raw" / "bandit.sarif").read_text("utf-8")
    assert "not-a-real-password-benchmark-fake" in raw_text, "precondition: raw is secret-bearing"
    exported = export_json(baseline_audit())
    for secret in PLANTED:
        assert secret not in exported, secret
    assert "<REDACTED>" in exported


def test_export_has_the_schema_version_and_is_valid_json():
    doc = json.loads(export_json(baseline_audit()))
    assert doc["schema_version"] == "1" and len(doc["findings"]) == 25
    assert all(
        f["triage"] is None and f["risk"] is None and f["remediation"] is None
        for f in doc["findings"]
    )


def test_old_manifest_without_new_fields_produces_warnings_not_errors():
    a = baseline_audit()
    assert any("neutralized_files" in w for w in a.warnings) and any(
        "limitations" in w for w in a.warnings
    )
    assert a.neutralized_files == ()


# ---------------------------------------------------------------- pipeline robustness


def raw_dir(tmp_path, files):
    d = tmp_path / "raw"
    d.mkdir()
    for name, data in files.items():
        (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())
    return d


def test_malformed_missing_and_mismatched_artifacts_become_warnings(tmp_path):
    d = raw_dir(
        tmp_path,
        {
            "bandit.sarif": "{not json",
            "gitleaks.sarif": json.dumps({"version": "2.1.0", "runs": []}),
        },
    )
    a = normalize_audit(d, manifest=None, source_root=None)
    assert a.findings == () and any("not valid JSON" in w for w in a.warnings)
    assert {r.tool: r.status for r in a.tool_runs} == {
        "bandit": "unreadable",
        "gitleaks": "completed",
    }
    assert any("no manifest.json" in w for w in a.warnings)


def test_tools_that_did_not_complete_are_reported_and_not_read(tmp_path):
    d = raw_dir(tmp_path, {})
    manifest = {
        "tool_order": ["bandit", "semgrep"],
        "tools": {
            "bandit": {"status": "failed", "detail": "boom"},
            "semgrep": {"status": "completed"},
        },
    }
    a = normalize_audit(d, manifest=manifest, source_root=None)
    assert {r.tool: r.status for r in a.tool_runs} == {"bandit": "failed", "semgrep": "missing"}
    assert any("bandit: no results read" in w for w in a.warnings)


def test_hash_mismatch_with_the_manifest_is_flagged(tmp_path):
    d = raw_dir(tmp_path, {"gitleaks.sarif": json.dumps({"version": "2.1.0", "runs": []})})
    manifest = {
        "tool_order": ["gitleaks"],
        "tools": {"gitleaks": {"status": "completed", "artifact_sha256": "0" * 64}},
        "neutralized_files": [],
    }
    a = normalize_audit(d, manifest=manifest, source_root=None)
    assert any("hash differs" in w for w in a.warnings)


def test_manifest_fields_flow_into_the_audit(tmp_path):
    d = raw_dir(tmp_path, {"gitleaks.sarif": json.dumps({"version": "2.1.0", "runs": []})})
    manifest = {
        "audit_id": "A1", "runner": "docker", "started_at": "2026-01-01T00:00:00+00:00", "tool_order": ["gitleaks"],
        "neutralized_files": [".bandit", "x/.semgrepignore"],
        "tools": {"gitleaks": {"status": "completed", "version": "8.30.1", "limitations": ["no history", "path allowlist"]}},
        "input": {"kind": "zip", "source": "p.zip", "sha256": "ab", "file_count": 3, "total_bytes": 10, "commit": None},
        "source": {"retained": True, "path": "source", "injected_files": [".semgrepignore"]},
    }  # fmt: skip
    a = normalize_audit(d, manifest=manifest, source_root=None)
    assert a.neutralized_files == (".bandit", "x/.semgrepignore") and a.input.kind == "zip"
    assert (
        a.coverage[0].limitations == ("no history", "path allowlist")
        and a.coverage[0].status == "unknown"
    )
    assert a.source.injected_files == (".semgrepignore",) and a.tool_runs[0].version == "8.30.1"
