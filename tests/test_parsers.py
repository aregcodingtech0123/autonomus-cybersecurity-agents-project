import hashlib
import json
from pathlib import Path

import pytest

from secaudit.core.normalize.pip_audit import parse_pip_audit
from secaudit.core.normalize.sarif import parse_sarif

BASELINE = Path(__file__).resolve().parent / "fixtures" / "phase1_baseline"
RAW = BASELINE / "raw"
PLANTED = [
    "not-a-real-password-benchmark-fake",
    "placeholder-not-a-real-password",
    "bench_n0" "VQRgmEuL",
    "benc" "h_uoSN55OKIJ9XKt",
    "bench_BvXX7C2JUs",
]


def load(name):
    data = (RAW / name).read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def parse(tool, name, version=None):
    doc, sha = load(name)
    return parse_sarif(tool, doc, artifact=f"raw/{name}", sha256=sha, tool_version=version)


# ---------------------------------------------------------------- real files


def test_bandit_real_output():
    out = parse("bandit", "bandit.sarif", "1.9.4")
    assert out.raw_count == 16 and len(out.hits) == 16 and out.skipped == []
    by_rule = {h.rule_id: h for h in out.hits}
    b201 = by_rule["B201"]
    assert (b201.file_path, b201.line_start, b201.cwe_ids, b201.raw_severity) == (
        "dev_server.py", 14, ("CWE-94",), "HIGH",
    )  # fmt: skip
    assert next(h for h in out.hits if h.rule_id == "B608").raw_severity == "MEDIUM", (
        "MEDIUM has no SARIF level; it comes from issue_severity"
    )
    assert all(h.tool_version == "1.9.4" for h in out.hits)


def test_bandit_messages_are_masked_even_though_the_raw_file_holds_the_secret():
    raw_text = (RAW / "bandit.sarif").read_text("utf-8")
    assert "not-a-real-password-benchmark-fake" in raw_text, "precondition: raw is secret-bearing"
    dumped = json.dumps([h.model_dump(mode="json") for h in parse("bandit", "bandit.sarif").hits])
    for secret in PLANTED:
        assert secret not in dumped
    assert "<REDACTED>" in dumped


def test_hits_never_carry_snippet_text():
    for tool, name in (
        ("bandit", "bandit.sarif"),
        ("semgrep", "semgrep.sarif"),
        ("gitleaks", "gitleaks.sarif"),
    ):
        dumped = json.dumps([h.model_dump(mode="json") for h in parse(tool, name).hits])
        assert "snippet" not in dumped and "contextRegion" not in dumped
        assert "hashlib.md5(" not in dumped and "subprocess.run(" not in dumped


def test_semgrep_real_output():
    out = parse("semgrep", "semgrep.sarif")
    assert out.raw_count == 11 and len(out.hits) == 11 and out.skipped == []
    dbg = next(h for h in out.hits if h.rule_id.endswith("debug-enabled"))
    assert dbg.cwe_ids == ("CWE-489",) and dbg.raw_severity == "warning"
    assert dbg.tool_version == "1.183.0", (
        "falls back to the driver version when no manifest version"
    )
    assert all("\\" not in h.file_path and not h.file_path.startswith("/") for h in out.hits)


def test_gitleaks_real_output_and_the_bogus_driver_version_is_ignored():
    out = parse("gitleaks", "gitleaks.sarif")
    assert out.raw_count == 3 and len(out.hits) == 3
    assert {h.rule_id for h in out.hits} == {
        "aws-access-token",
        "generic-api-key",
        "stripe-access-token",
    }
    assert all(h.cwe_ids == ("CWE-798",) for h in out.hits)
    assert all(h.tool_version is None for h in out.hits), "driver says v8.0.0; we never trust it"
    assert parse("gitleaks", "gitleaks.sarif", "8.30.1").hits[0].tool_version == "8.30.1"
    assert out.warnings == []


def test_pip_audit_real_output_is_located_through_the_manifest_pins():
    manifest = json.loads((BASELINE / "manifest.json").read_text("utf-8"))
    pins = manifest["tools"]["pip-audit"]["pinned_requirements"]
    doc, sha = load("pip-audit.json")
    out = parse_pip_audit(
        doc, artifact="raw/pip-audit.json", sha256=sha, tool_version="2.10.1", pins=pins
    )
    assert out.raw_count == len(out.hits) == 16 and out.skipped == []
    lines = {(h.file_path, h.line_start) for h in out.hits}
    assert lines == {("requirements.txt", 1), ("requirements.txt", 2), ("requirements.txt", 3)}
    flask = [h for h in out.hits if h.message.lower().startswith("flask 2.0.1")]
    assert flask and all("CVE-2023-30861" in h.aliases or h.aliases for h in flask)
    assert all(h.cwe_ids == () and h.raw_severity is None for h in out.hits)
    assert all("description" not in h.model_dump() for h in out.hits)


def test_pip_audit_without_a_matching_pin_is_skipped_not_invented():
    doc, sha = load("pip-audit.json")
    out = parse_pip_audit(doc, artifact="a", sha256=sha, tool_version=None, pins=[])
    assert out.hits == [] and len(out.skipped) == 16
    assert {s.reason for s in out.skipped} == {"no_requirement_line"} and out.warnings


# ---------------------------------------------------------------- synthetic edge cases


def sarif(results, rules=None, driver=None):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "t", "rules": rules or [], **(driver or {})}},
                "results": results,
            }
        ],
    }


def result(uri="a.py", start=3, end=3, rule="R1", **kw):
    r = {
        "ruleId": rule,
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start, "endLine": end},
                }
            }
        ],
    }
    r.update(kw)
    return r


def run(doc, tool="semgrep"):
    return parse_sarif(tool, doc, artifact="raw/x.sarif", sha256="0" * 64, tool_version=None)


@pytest.mark.parametrize("doc", [None, [], "text", 5, {}, {"runs": "x"}, {"runs": None}])
def test_non_sarif_input_yields_a_warning_not_a_crash(doc):
    out = run(doc)
    assert out.hits == [] and out.raw_count == 0 and out.warnings


@pytest.mark.parametrize(
    "doc",
    [
        {"runs": []},
        {"runs": [{}]},
        {"runs": [{"tool": {}, "results": []}]},
        {"runs": [5, None, "x"]},
    ],
)
def test_empty_or_odd_runs_are_fine(doc):
    out = run(doc)
    assert out.hits == [] and out.skipped == []


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        ({"locations": []}, "no_location"),
        ({"ruleId": None}, "missing_rule_id"),
        (
            {
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {}}}
                ]
            },
            "no_line",
        ),
        (
            {
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 0},
                        }
                    }
                ]
            },
            "no_line",
        ),
        (
            {
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": "3"},
                        }
                    }
                ]
            },
            "no_line",
        ),
        ({"locations": ["x"]}, "no_location"),
        (
            {
                "locations": [
                    {"physicalLocation": {"artifactLocation": {}, "region": {"startLine": 1}}}
                ]
            },
            "empty_path",
        ),
    ],
)
def test_unusable_results_are_counted_with_a_reason_never_silently_dropped(bad, reason):
    base = result()
    base.update(bad)
    out = run(sarif([base]))
    assert out.hits == [] and out.raw_count == 1
    assert [s.reason for s in out.skipped] == [reason]
    assert out.skipped[0].pointer == "/runs/0/results/0"


@pytest.mark.parametrize(
    "uri", ["../../etc/passwd", "/etc/passwd", "C:\\Windows\\x.py", "a/../../b", "file:///C:/x.py"]
)
def test_hostile_paths_are_dropped_counted_and_warned(uri):
    out = run(sarif([result(uri=uri), result(uri="ok.py")]))
    assert [h.file_path for h in out.hits] == ["ok.py"] and len(out.skipped) == 1
    assert any("outside the source root" in w for w in out.warnings)


def test_very_long_path_and_huge_message_are_bounded():
    out = run(sarif([result(uri="a/" * 3000 + "x.py"), result(uri="ok.py")]))
    assert [h.file_path for h in out.hits] == ["ok.py"] and out.skipped[0].reason == "path_too_long"
    big = result()
    big["message"]["text"] = "A" * 1_000_000
    hit = run(sarif([big])).hits[0]
    assert len(hit.message) <= 500


def test_weird_field_types_never_crash():
    weird = [
        {"ruleId": 5, "message": 7, "locations": 3},
        {
            "ruleId": "R",
            "message": {"text": ["x"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": 9}}}],
        },
        {
            "ruleId": "R",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": True},
                    }
                }
            ],
        },
        "string",
        None,
        42,
        [],
    ]
    out = run(sarif(weird))
    assert out.raw_count == 7 and out.hits == [] and len(out.skipped) == 7


def test_unknown_severity_and_unknown_tool_version_are_kept_as_data():
    out = run(sarif([result(rule="R1", properties={"issue_severity": "SEVERE"})]), tool="bandit")
    hit = out.hits[0]
    assert hit.raw_severity == "SEVERE" and hit.tool_version is None


def test_duplicate_results_are_all_parsed_dedup_happens_later():
    out = run(sarif([result(), result(), result()]))
    assert len(out.hits) == 3 and [h.raw_ref.pointer for h in out.hits] == [
        "/runs/0/results/0", "/runs/0/results/1", "/runs/0/results/2",
    ]  # fmt: skip


def test_rule_resolved_through_ruleindex_and_tags_give_cwe():
    rules = [{"id": "B999", "name": "x", "properties": {"tags": ["external/cwe/cwe-327"]}}]
    r = result(rule=None)
    del r["ruleId"]
    r["ruleIndex"] = 0
    hit = run(sarif([r], rules=rules), tool="bandit").hits[0]
    assert hit.rule_id == "B999" and hit.cwe_ids == ("CWE-327",)


def test_multiple_locations_use_the_first():
    r = result(uri="first.py")
    r["locations"].append(result(uri="second.py")["locations"][0])
    assert run(sarif([r])).hits[0].file_path == "first.py"


def test_unreviewed_gitleaks_rule_is_flagged():
    out = run(sarif([result(rule="brand-new-rule")]), tool="gitleaks")
    assert out.hits[0].cwe_ids == ("CWE-798",) and any("brand-new-rule" in w for w in out.warnings)


def test_pip_audit_garbage():
    for doc in (None, [], {"dependencies": "x"}, {}):
        out = parse_pip_audit(doc, artifact="a", sha256="0" * 64, tool_version=None, pins=[])
        assert out.hits == [] and out.warnings
    out = parse_pip_audit(
        {"dependencies": [{"name": "x", "version": "1", "vulns": [None, "s", {"id": 5}, {"id": "V-1"}]}, 7, None]},
        artifact="a", sha256="0" * 64, tool_version=None, pins=[{"name": "X", "version": "1", "file": "requirements.txt", "line": 4}],
    )  # fmt: skip
    assert len(out.hits) == 1 and out.hits[0].line_start == 4 and out.hits[0].rule_id == "V-1"
    assert out.raw_count == 4 and len(out.skipped) == 3
