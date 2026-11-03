"""Phase 2B Task 1: SQLite storage, migrations, hash-verified ingest, concurrency, permissions."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlmodel import SQLModel

from secaudit import cli
from secaudit.core import exe
from secaudit.core.models import SCHEMA_VERSION, Audit
from secaudit.core.normalize.pipeline import normalize_audit_dir
from secaudit.store.convert import IngestRecord
from secaudit.store.db import (
    current_revision,
    downgrade_to_base,
    head_revision,
    make_engine,
    open_database,
    secure_database,
    upgrade_to_head,
)
from secaudit.store.ingest import IngestError, ingest_audit_dir, load_audit_dir
from secaudit.store.repo import AuditConflictError, Repository
from store_helpers import BASELINE_AUDIT_ID, make_audit_dir

TABLES = {"schema_version", "audit", "tool_run", "raw_artifact", "finding", "finding_hit"}


@pytest.fixture
def db(tmp_path):
    engine = open_database(tmp_path / "secaudit.db")
    yield engine
    engine.dispose()


@pytest.fixture
def audit_dir(tmp_path):
    return make_audit_dir(tmp_path / "audits")


def count(conn, table):
    return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()  # noqa: S608 - fixed names


def tables(engine):
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


# ---------------------------------------------------------------- migrations


def test_upgrade_from_an_empty_database_creates_every_table_and_seeds_the_schema_row(tmp_path):
    engine = make_engine(tmp_path / "new.db")
    assert tables(engine) == set() and current_revision(engine) is None
    assert upgrade_to_head(engine) is True
    assert tables(engine) == TABLES and current_revision(engine) == head_revision()
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT models_schema FROM schema_version")).scalar()
            == SCHEMA_VERSION
        )
    engine.dispose()


def test_running_upgrade_again_is_a_no_op(db):
    before = current_revision(db)
    assert upgrade_to_head(db) is False and current_revision(db) == before


def test_downgrade_and_upgrade_round_trip(db):
    downgrade_to_base(db)
    assert tables(db) == set()
    assert upgrade_to_head(db) is True and tables(db) == TABLES


def test_migrated_schema_has_no_drift_from_the_orm_tables(db):
    """Migrations are frozen files; this fails the moment the ORM changes without a new revision."""
    with db.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), SQLModel.metadata)
    assert diff == [], f"ORM and migrations disagree: {diff}"


def test_connection_pragmas_wal_busy_timeout_foreign_keys(db):
    with db.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA busy_timeout")).scalar() >= 10_000
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


# ---------------------------------------------------------------- ingest and round trip


def test_ingest_stores_the_baseline_and_it_round_trips_exactly(db, audit_dir):
    repo = Repository(db)
    result = ingest_audit_dir(repo, audit_dir)
    assert (result.status, result.findings, result.hits) == ("inserted", 24, 37)
    stored = repo.get_audit(BASELINE_AUDIT_ID)
    assert stored == normalize_audit_dir(audit_dir), "Audit -> rows -> Audit must lose nothing"
    assert Audit.model_validate_json(stored.model_dump_json()) == stored


def test_raw_artifact_hashes_are_recorded_after_verification(db, audit_dir):
    repo = Repository(db)
    ingest_audit_dir(repo, audit_dir)
    artifacts = {a.path: a for a in repo.raw_artifacts(BASELINE_AUDIT_ID)}
    assert set(artifacts) == {
        "raw/bandit.sarif", "raw/semgrep.sarif", "raw/semgrep.json",
        "raw/gitleaks.sarif", "raw/pip-audit.json",
    }  # fmt: skip
    manifest = json.loads((audit_dir / "manifest.json").read_text("utf-8"))
    assert artifacts["raw/bandit.sarif"].sha256 == manifest["tools"]["bandit"]["artifact_sha256"]
    assert artifacts["raw/semgrep.json"].kind == "extra"


def test_every_pip_audit_advisory_stays_its_own_hit(db, audit_dir):
    repo = Repository(db)
    ingest_audit_dir(repo, audit_dir)
    audit = repo.get_audit(BASELINE_AUDIT_ID)
    pip = [f for f in audit.findings if f.issue_class.startswith("vuln:")]
    assert {(h.package, h.package_version) for f in pip for h in f.hits} == {
        ("flask", "2.0.1"), ("pyyaml", "5.3.1"), ("requests", "2.19.0"),
    }  # fmt: skip
    assert len(pip) == 3 and sum(len(f.hits) for f in pip) == 8
    for f in pip:
        ids = [h.rule_id for h in f.hits]
        assert len(ids) == len(set(ids)), "one hit per advisory, no collapsing across advisories"
        for h in f.hits:
            assert h.rule_id in h.aliases and h.package_version and h.raw_ref.pointer
        assert set(f.aliases) >= {a for h in f.hits for a in h.aliases}
    with db.connect() as conn:  # the same granularity is queryable in SQL, per advisory
        rows = conn.execute(
            text("SELECT rule_id, package, package_version FROM finding_hit WHERE tool='pip-audit'")
        ).all()
    assert len(rows) == 8 and len({r[0] for r in rows}) == 8


def test_reingest_is_idempotent_and_keeps_the_original_ingest_time(db, audit_dir):
    repo = Repository(db)
    first = ingest_audit_dir(repo, audit_dir)
    with db.connect() as conn:
        stamp = conn.execute(text("SELECT ingested_at FROM audit")).scalar()
        counts = [count(conn, t) for t in TABLES]
    second = ingest_audit_dir(repo, audit_dir)
    assert (first.status, second.status) == ("inserted", "unchanged")
    with db.connect() as conn:
        assert conn.execute(text("SELECT ingested_at FROM audit")).scalar() == stamp
        assert [count(conn, t) for t in TABLES] == counts


def test_different_content_for_a_stored_audit_is_refused_unless_replace_is_asked(db, audit_dir):
    repo = Repository(db)
    ingest_audit_dir(repo, audit_dir)
    document = json.loads((audit_dir / "findings.json").read_text("utf-8"))
    document["warnings"] = [*document["warnings"], "edited after the first ingest"]
    (audit_dir / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AuditConflictError):
        ingest_audit_dir(repo, audit_dir)
    assert ingest_audit_dir(repo, audit_dir, replace=True).status == "replaced"
    assert "edited after the first ingest" in repo.get_audit(BASELINE_AUDIT_ID).warnings


def test_equal_fingerprints_in_one_audit_are_stored_with_distinct_ordinals(db, audit_dir):
    audit, _m, fsha, msha, artifacts = load_audit_dir(audit_dir)
    twin = audit.findings[0].model_copy(update={"id": "F-twin00000001"})
    doubled = audit.model_copy(update={"findings": (*audit.findings, twin)})
    repo = Repository(db)
    repo.ingest(doubled, IngestRecord(fsha, msha, "now", artifacts))
    with db.connect() as conn:
        ordinals = conn.execute(
            text("SELECT ordinal FROM finding WHERE fingerprint=:f ORDER BY ordinal"),
            {"f": audit.findings[0].fingerprint},
        ).scalars().all()  # fmt: skip
    already = sum(f.fingerprint == audit.findings[0].fingerprint for f in audit.findings)
    assert already >= 1 and ordinals == list(range(already + 1))
    assert len(repo.get_audit(BASELINE_AUDIT_ID).findings) == 25


def test_deleting_an_audit_cascades_to_every_child_table(db, audit_dir):
    repo = Repository(db)
    ingest_audit_dir(repo, audit_dir)
    assert repo.delete_audit(BASELINE_AUDIT_ID) is True and repo.delete_audit("nope") is False
    with db.connect() as conn:
        assert [count(conn, t) for t in TABLES - {"schema_version"}] == [0] * 5


def test_queries_filter_by_severity_and_tool(db, audit_dir):
    repo = Repository(db)
    ingest_audit_dir(repo, audit_dir)
    everything = repo.list_findings(BASELINE_AUDIT_ID)
    assert len(everything) == 24
    high = repo.list_findings(BASELINE_AUDIT_ID, severity="high")
    assert high and all(f.severity == "HIGH" for f in high)
    gitleaks = repo.list_findings(BASELINE_AUDIT_ID, tool="gitleaks")
    assert len(gitleaks) == 2 and all("gitleaks" in f.tools for f in gitleaks)
    first = everything[0]
    found = repo.find_finding(first.id)
    assert found and found[0] == BASELINE_AUDIT_ID and found[1].id == first.id and found[1].hits
    assert repo.find_finding("F-doesnotexist") is None
    assert [a.audit_id for a in repo.list_audits()] == [BASELINE_AUDIT_ID]


def test_hostile_text_is_stored_as_data_not_as_sql(db, audit_dir):
    audit, _m, fsha, msha, artifacts = load_audit_dir(audit_dir)
    evil = "x'); DROP TABLE finding;--"
    first = audit.findings[0]
    hostile = first.model_copy(update={"title": evil, "snippet": evil})
    repo = Repository(db)
    repo.ingest(audit.model_copy(update={"findings": (hostile, *audit.findings[1:])}),
                IngestRecord(fsha, msha, "now", artifacts))  # fmt: skip
    assert repo.get_audit(BASELINE_AUDIT_ID).findings[0].title == evil
    assert "finding" in tables(db)
    assert repo.list_findings(BASELINE_AUDIT_ID, tool="x' OR '1'='1") == []


# ---------------------------------------------------------------- tampering and malformed input


def test_a_modified_raw_artifact_fails_loudly_and_stores_nothing(db, audit_dir):
    target = audit_dir / "raw" / "bandit.sarif"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(IngestError, match="does not match the manifest sha256") as caught:
        ingest_audit_dir(Repository(db), audit_dir)
    assert "raw/bandit.sarif" in str(caught.value) and caught.value.kind == "rejected"
    with db.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit")).scalar() == 0


def test_a_missing_raw_artifact_is_refused(db, audit_dir):
    (audit_dir / "raw" / "gitleaks.sarif").unlink()
    with pytest.raises(IngestError, match="missing"):
        ingest_audit_dir(Repository(db), audit_dir)


def test_findings_derived_from_other_bytes_than_the_manifest_vouches_for_are_refused(db, audit_dir):
    document = json.loads((audit_dir / "findings.json").read_text("utf-8"))
    document["findings"][0]["hits"][0]["raw_ref"]["artifact_sha256"] = "0" * 64
    (audit_dir / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(IngestError, match="raw_ref sha256 mismatch"):
        ingest_audit_dir(Repository(db), audit_dir)


@pytest.mark.parametrize(
    "bad_path", ["../raw/bandit.sarif", "/etc/passwd", "raw/../manifest.json", "source/app.py"]
)
def test_manifest_artifact_paths_cannot_point_outside_raw(db, audit_dir, bad_path):
    manifest = json.loads((audit_dir / "manifest.json").read_text("utf-8"))
    manifest["tools"]["bandit"]["artifact"] = bad_path
    (audit_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IngestError, match="unacceptable artifact path"):
        ingest_audit_dir(Repository(db), audit_dir)


def test_prerequisites_and_schema_problems_are_reported_not_crashed(db, tmp_path, audit_dir):
    repo = Repository(db)
    with pytest.raises(IngestError, match="not an audit directory") as e1:
        ingest_audit_dir(repo, tmp_path / "empty")
    assert e1.value.kind == "usage"
    (audit_dir / "findings.json").rename(audit_dir / "findings.bak")
    with pytest.raises(IngestError, match="secaudit normalize") as e2:
        ingest_audit_dir(repo, audit_dir)
    assert e2.value.kind == "usage"
    (audit_dir / "findings.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(IngestError, match="does not match the schema"):
        ingest_audit_dir(repo, audit_dir)
    document = json.loads((audit_dir / "findings.bak").read_text("utf-8"))
    document["schema_version"] = "1"
    (audit_dir / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(IngestError, match="schema_version"):
        ingest_audit_dir(repo, audit_dir)
    document["schema_version"] = SCHEMA_VERSION
    document["audit_id"] = "20260101T000000Z-aaaaaaaa"
    (audit_dir / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(IngestError, match="different audits"):
        ingest_audit_dir(repo, audit_dir)


# ---------------------------------------------------------------- CLI and concurrency


def test_cli_ingest_reports_status_and_exit_codes(audit_dir, capsys):
    assert cli.main(["ingest", str(audit_dir)]) == 0
    assert "inserted (24 findings, 37 hits)" in capsys.readouterr().out
    assert cli.main(["ingest", str(audit_dir)]) == 0
    assert "unchanged" in capsys.readouterr().out
    target = audit_dir / "raw" / "pip-audit.json"
    target.write_bytes(target.read_bytes() + b"\n")
    assert cli.main(["ingest", str(audit_dir)]) == 3
    assert "modified after the scan" in capsys.readouterr().err
    assert cli.main(["ingest", str(audit_dir.parent / "missing")]) == 2


def _ingest_process(audit_dir: Path, db: Path) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 - our own interpreter, our own module
        [sys.executable, "-m", "secaudit.cli", "ingest", str(audit_dir), "--db", str(db)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip


def test_two_processes_ingesting_the_same_audit_both_succeed_and_store_it_once(tmp_path):
    audit = make_audit_dir(tmp_path / "audits")
    db_path = tmp_path / "shared.db"
    procs = [_ingest_process(audit, db_path) for _ in range(2)]
    outputs = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], outputs
    states = sorted(re.search(r": (\w+) \(", out).group(1) for out, _err in outputs)
    assert states == ["inserted", "unchanged"]
    engine = make_engine(db_path)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM finding")).scalar() == 24
    finally:
        engine.dispose()


def test_two_processes_ingesting_different_audits_into_one_database(tmp_path):
    a = make_audit_dir(tmp_path / "audits", "20261103T161647Z-68eba1f9")
    b = make_audit_dir(tmp_path / "audits", "20261103T091804Z-16b4cbe7")
    db_path = tmp_path / "shared.db"
    procs = [_ingest_process(a, db_path), _ingest_process(b, db_path)]
    outputs = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], outputs
    engine = make_engine(db_path)
    try:
        repo = Repository(engine)
        assert {s.audit_id for s in repo.list_audits()} == {a.name, b.name}
        assert all(s.findings == 24 for s in repo.list_audits())
        # the same finding id appears in both audits: lookups need (and honour) the audit
        some = repo.list_findings(a.name)[0].id
        assert repo.find_finding(some, b.name)[0] == b.name
        assert repo.find_finding(some)[0] in {a.name, b.name}
    finally:
        engine.dispose()


# ---------------------------------------------------------------- permissions


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits; Windows is covered by the SDDL test")
def test_posix_database_files_are_owner_only(tmp_path):
    engine = open_database(tmp_path / "p.db")
    with engine.begin() as conn:  # make SQLite create the -wal/-shm sidecars
        conn.execute(text("SELECT 1"))
    for name in ("p.db", "p.db-wal", "p.db-shm"):
        if (tmp_path / name).exists():
            assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o600, name
    engine.dispose()


def _sddl(path: Path, scratch: Path) -> str:
    target = scratch / "acl.txt"
    exe.run(["icacls", str(path), "/save", str(target)], capture_output=True, check=True)
    return target.read_bytes().decode("utf-16")


@pytest.mark.skipif(os.name != "nt", reason="icacls/SDDL is Windows-only")
def test_windows_database_file_is_restricted_to_the_current_user_and_still_usable(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    db_path = tmp_path / "w.db"
    engine = open_database(db_path)
    sddl = _sddl(db_path, scratch)
    dacl = re.search(r"D:([A-Z]*)((?:\([^)]*\))*)", sddl)
    assert dacl and "P" in dacl.group(1), sddl
    sids = {ace.split(";")[-1] for ace in re.findall(r"\(([^)]*)\)", dacl.group(2))}
    done = exe.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
    )
    assert sids == {done.stdout.strip().split(",")[1].strip().strip('"')}, sids
    engine.dispose()
    reopened = open_database(db_path)  # an empty ACL would make this fail (the bug this test pins)
    assert tables(reopened) == TABLES
    reopened.dispose()
    assert secure_database(db_path) is True


def test_four_processes_on_two_audits_end_with_each_stored_exactly_once(tmp_path):
    a = make_audit_dir(tmp_path / "audits", "20261103T161647Z-68eba1f9")
    b = make_audit_dir(tmp_path / "audits", "20261103T091804Z-16b4cbe7")
    db_path = tmp_path / "shared.db"
    procs = [_ingest_process(d, db_path) for d in (a, b, a, b)]
    outputs = [p.communicate(timeout=180) for p in procs]
    assert [p.returncode for p in procs] == [0, 0, 0, 0], outputs
    engine = make_engine(db_path)
    try:
        with engine.connect() as conn:
            assert count(conn, "audit") == 2 and count(conn, "finding") == 48
            assert count(conn, "finding_hit") == 74 and count(conn, "raw_artifact") == 10
    finally:
        engine.dispose()
