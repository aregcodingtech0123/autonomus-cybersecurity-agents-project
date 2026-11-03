"""Phase 2B Task 3: scan post-processing and the findings / report / audit commands."""

from __future__ import annotations

import json
import tempfile
import unicodedata
from pathlib import Path

import pytest

from fakes import FakeExecutor, fake_rules
from secaudit import cli, cli_store
from secaudit.cliout import safe
from secaudit.core.models import (
    Audit,
    AuditInput,
    RawRef,
    SecurityFinding,
    Severity,
    SkippedFile,
    ToolCoverage,
    ToolHit,
    ToolRun,
)
from secaudit.store.convert import IngestRecord
from secaudit.store.db import open_database
from secaudit.store.repo import Repository
from store_helpers import BASELINE_AUDIT_ID, make_audit_dir

HOSTILE = "dir/evil\x1b[2J\x1b]0;pwned\x07‮​name.py"


@pytest.fixture
def populated(tmp_path):
    """<tmp>/audits with the baseline audit ingested; returns (out_root, audit_dir)."""
    out = tmp_path / "audits"
    audit_dir = make_audit_dir(out)
    assert cli.main(["ingest", str(audit_dir)]) == 0
    return out, audit_dir


def run(capfd, *argv):
    code = cli.main([str(a) for a in argv])
    captured = capfd.readouterr()
    return code, captured.out, captured.err


def assert_terminal_safe(text: str) -> None:
    bad = [
        c for c in text if c != "\n" and unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp")
    ]
    assert bad == [], f"control/format characters reached the terminal: {bad!r}"


# ---------------------------------------------------------------- scan does everything


@pytest.fixture
def sys_tmp(tmp_path, monkeypatch):
    root = tmp_path / "systmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def fake_scan(tmp_path, monkeypatch):
    from secaudit.core import scan as scan_mod

    monkeypatch.setattr(scan_mod, "preflight", lambda options, adapters: None)
    real = scan_mod.run_scan
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda source, options: real(
            source, options, executor=FakeExecutor(), rules=fake_rules(tmp_path)
        ),
    )


@pytest.fixture
def project(tmp_path):
    src = tmp_path / "myproject"
    src.mkdir()
    (src / "app.py").write_bytes(b"print('x')\n")
    return src


def test_scan_normalizes_stores_and_writes_the_report(project, tmp_path, sys_tmp, fake_scan, capfd):
    out = tmp_path / "o"
    code, stdout, _err = run(capfd, "scan", project, "--tools", "bandit", "--out", out)
    assert code == 0
    (audit_dir,) = [p for p in out.iterdir() if p.is_dir()]
    assert (audit_dir / "findings.json").is_file() and (audit_dir / "report.html").is_file()
    assert (out / "secaudit.db").is_file()
    assert "findings:" in stdout and "stored (inserted)" in stdout and "source retained" in stdout
    code, listing, _ = run(capfd, "audit", "list", "--out", out)
    assert code == 0 and audit_dir.name in listing


def test_scan_keeps_its_exit_code_semantics_with_post_processing(
    project, tmp_path, sys_tmp, fake_scan, capfd
):
    code, _out, _err = run(capfd, "scan", project, "--tools", "bandit", "--out", tmp_path / "o")
    assert code == cli.EXIT_OK


def test_raw_only_skips_normalization_and_the_database(
    project, tmp_path, sys_tmp, fake_scan, capfd
):
    out = tmp_path / "o"
    code, stdout, _ = run(capfd, "scan", project, "--tools", "bandit", "--out", out, "--raw-only")
    assert code == 0 and "findings:" not in stdout
    (audit_dir,) = [p for p in out.iterdir() if p.is_dir()]
    assert not (audit_dir / "findings.json").exists() and not (out / "secaudit.db").exists()


def test_a_post_processing_failure_keeps_the_audit_and_says_how_to_retry(
    project, tmp_path, sys_tmp, fake_scan, capfd, monkeypatch
):
    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(cli_store, "postprocess_scan", boom)
    code, stdout, err = run(capfd, "scan", project, "--tools", "bandit", "--out", tmp_path / "o")
    assert code == cli.EXIT_ERROR
    assert "post-processing failed" in err and "secaudit normalize" in err
    assert "Traceback" not in stdout + err and "disk on fire" not in stdout + err
    assert [p for p in (tmp_path / "o").iterdir() if p.is_dir()], "raw audit kept"


# ---------------------------------------------------------------- findings


def test_findings_list_defaults_to_the_latest_audit_and_filters(populated, capfd):
    out, _dir = populated
    code, stdout, _ = run(capfd, "findings", "list", "--out", out)
    assert code == 0 and stdout.startswith(f"audit {BASELINE_AUDIT_ID}: 24 finding(s)")
    code, stdout, _ = run(capfd, "findings", "list", "--out", out, "--severity", "high")
    rows = stdout.splitlines()[1:]
    assert code == 0 and rows and all(" HIGH " in row for row in rows)
    code, stdout, _ = run(capfd, "findings", "list", "--out", out, "--tool", "gitleaks")
    assert stdout.startswith(f"audit {BASELINE_AUDIT_ID}: 2 finding(s)")
    code, stdout, _ = run(capfd, "findings", "list", "--out", out, "--audit", BASELINE_AUDIT_ID)
    assert "24 finding(s)" in stdout


def test_findings_list_rejects_bad_input_and_a_missing_database(populated, tmp_path, capfd):
    out, _dir = populated
    with pytest.raises(SystemExit) as exc:
        cli.main(["findings", "list", "--out", str(out), "--severity", "catastrophic"])
    assert exc.value.code == 2
    capfd.readouterr()
    assert run(capfd, "findings", "list", "--out", out, "--audit", "../../x")[0] == cli.EXIT_USAGE
    code, _o, err = run(capfd, "findings", "list", "--out", tmp_path / "nothing")
    assert code == cli.EXIT_USAGE and "no database" in err


def test_findings_show_prints_evidence_with_every_hit(populated, capfd):
    out, _dir = populated
    _c, listing, _ = run(capfd, "findings", "list", "--out", out, "--tool", "pip-audit")
    finding_id = listing.splitlines()[1].split()[0]
    code, stdout, _ = run(capfd, "findings", "show", finding_id, "--out", out)
    assert code == 0
    for needle in (
        "finding F-",
        "severity",
        "evidence:",
        "raw result: raw/pip-audit.json/dependencies",
    ):
        assert needle in stdout
    assert stdout.count("rule ") >= 2, "one evidence entry per advisory"


def test_findings_show_errors(populated, capfd):
    out, _dir = populated
    assert run(capfd, "findings", "show", "F-000000000000", "--out", out)[0] == cli.EXIT_USAGE
    code, _o, err = run(capfd, "findings", "show", "not an id\x1b[2J", "--out", out)
    assert code == cli.EXIT_USAGE and "\x1b" not in err


# ---------------------------------------------------------------- report


def test_report_json_and_html_to_stdout_and_to_a_file(populated, tmp_path, capfd):
    out, _dir = populated
    db = out / "secaudit.db"
    code, stdout, _ = run(capfd, "report", BASELINE_AUDIT_ID, "--format", "json", "--db", db)
    assert code == 0
    document = json.loads(stdout)
    assert document["audit_id"] == BASELINE_AUDIT_ID and len(document["findings"]) == 24
    code, stdout, _ = run(capfd, "report", BASELINE_AUDIT_ID, "--db", db)
    assert code == 0 and "Content-Security-Policy" in stdout and "<script" not in stdout
    target = tmp_path / "r" / "x.html"
    target.parent.mkdir()
    code, stdout, _ = run(capfd, "report", BASELINE_AUDIT_ID, "--db", db, "--out", target)
    assert code == 0 and target.read_text("utf-8").startswith("<!DOCTYPE html>")
    assert run(capfd, "report", "20260101T000000Z-aaaaaaaa", "--db", db)[0] == cli.EXIT_USAGE


def test_report_with_the_ground_truth_lists_related_informational(populated, capfd):
    out, _dir = populated
    truth = Path(__file__).resolve().parent.parent / "benchmarks" / "expected_findings.yaml"
    code, stdout, _ = run(
        capfd, "report", BASELINE_AUDIT_ID, "--db", out / "secaudit.db", "--ground-truth", truth
    )
    assert code == 0 and "R01" in stdout and "R02" in stdout
    missing = run(capfd, "report", BASELINE_AUDIT_ID, "--db", out / "secaudit.db",
                  "--ground-truth", out / "nope.yaml")  # fmt: skip
    assert missing[0] == cli.EXIT_USAGE


def test_report_from_the_database_equals_the_report_scan_wrote(populated, capfd):
    out, audit_dir = populated
    code, stdout, _ = run(capfd, "report", BASELINE_AUDIT_ID, "--db", out / "secaudit.db")
    from secaudit.core.normalize.pipeline import normalize_audit_dir
    from secaudit.report import render_html

    assert code == 0 and stdout == render_html(normalize_audit_dir(audit_dir))


# ---------------------------------------------------------------- audit list / delete


def test_audit_delete_removes_directory_and_database_rows(populated, capfd):
    out, audit_dir = populated
    code, stdout, _ = run(capfd, "audit", "delete", BASELINE_AUDIT_ID, "--out", out)
    assert code == 0 and "directory and database rows" in stdout and not audit_dir.exists()
    assert "0 audit(s)" in run(capfd, "audit", "list", "--out", out)[1]
    assert run(capfd, "audit", "delete", BASELINE_AUDIT_ID, "--out", out)[0] == cli.EXIT_USAGE


def test_audit_delete_cleans_rows_even_if_the_directory_is_already_gone(populated, capfd):
    from secaudit.core.intake import remove_tree

    out, audit_dir = populated
    remove_tree(audit_dir)
    code, stdout, _ = run(capfd, "audit", "delete", BASELINE_AUDIT_ID, "--out", out)
    assert code == 0 and "database rows" in stdout and "directory" not in stdout.split("(")[1]


# ---------------------------------------------------------------- terminal injection


def hostile_audit() -> Audit:
    ref = RawRef(artifact="raw/bandit.sarif", artifact_sha256="a" * 64, pointer="/runs/0/results/0")
    hit = ToolHit(
        tool="bandit", rule_id="B1\x1b[31m", message=f"msg\x1b]0;x\x07 {HOSTILE}",
        file_path=HOSTILE, line_start=2, line_end=2, raw_ref=ref, raw_severity="HIGH\x1b[0m",
    )  # fmt: skip
    finding = SecurityFinding(
        id="F-0123456789ab", fingerprint="f" * 8, fingerprint_basis="content",
        title=f"title {HOSTILE}", issue_class="rule:bandit:B1", file_path=HOSTILE, line_start=2,
        line_end=2, hits=(hit,), severity=Severity.HIGH, severity_basis="b\x1b[1m",
        snippet=f"    2 | {HOSTILE}\n    3 | \x1b[2Jx",
    )  # fmt: skip
    return Audit(
        audit_id="20261103T000000Z-deadbeef", created_at="2026-11-03T00:00:00+00:00",
        runner="docker", input=AuditInput(kind="directory", source=f"proj {HOSTILE}"),
        warnings=(f"warn {HOSTILE}",), findings=(finding,),
        tool_runs=(ToolRun(tool="bandit", status="completed"),),
        coverage=(
            ToolCoverage(
                tool="semgrep", status="known", skipped_files=(SkippedFile(path=HOSTILE, reason=HOSTILE),)
            ),
        ),
    )  # fmt: skip


@pytest.fixture
def hostile_db(tmp_path):
    engine = open_database(tmp_path / "audits" / "secaudit.db")
    Repository(engine).ingest(hostile_audit(), IngestRecord("a" * 64, "b" * 64, "now"))
    engine.dispose()
    return tmp_path / "audits"


@pytest.mark.parametrize(
    "argv",
    [
        ("findings", "list"),
        ("findings", "show", "F-0123456789ab"),
        ("audit", "list"),
        ("report", "20261103T000000Z-deadbeef"),
    ],
    ids=["findings-list", "findings-show", "audit-list", "report-html-stdout"],
)
def test_hostile_file_names_never_reach_the_terminal_as_control_characters(hostile_db, capfd, argv):
    extra = ["--db", hostile_db / "secaudit.db"] if argv[0] == "report" else ["--out", hostile_db]
    code, stdout, stderr = run(capfd, *argv, *extra)
    assert code == 0 and stdout
    assert_terminal_safe(stdout + stderr)
    assert "evil" in stdout, "the readable part of the name is still shown"


def test_the_scan_summary_is_terminal_safe_too(capfd, tmp_path):
    cli_store._print_scan_summary(
        hostile_audit(), tmp_path / HOSTILE.replace("/", "_"), tmp_path / "x.db", "inserted"
    )
    captured = capfd.readouterr()
    assert_terminal_safe(captured.out + captured.err)
    assert "NOT analysed" in captured.out


def test_safe_strips_escape_sequences_bidi_and_control_characters():
    cleaned = safe(HOSTILE)
    assert chr(27) in HOSTILE and chr(0x202E) in HOSTILE, "the fixture really is hostile"
    assert cleaned == "dir/evilname.py"
    assert_terminal_safe(cleaned)
    assert safe("a\nb\rc\td") == "a b c d"
    assert safe("x" * 1000, 20).endswith("...") and len(safe("x" * 1000, 20)) == 20
    assert safe("\x1b]8;;http://evil\x07link\x1b]8;;\x07") == "link", "OSC hyperlinks removed"
