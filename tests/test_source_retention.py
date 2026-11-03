"""Phase 2A Task 1: the sanitized workspace is kept as <audit>/source/ (read-only, owner-only)."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path

import pytest

from fakes import FakeExecutor, fake_rules
from secaudit import cli
from secaudit.core import exe
from secaudit.core.retention import (
    AuditNotFoundError,
    delete_audit,
    restrict_to_owner,
)
from secaudit.core.scan import ScanOptions, run_scan


@pytest.fixture
def sys_tmp(tmp_path, monkeypatch):
    root = tmp_path / "systmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def project(tmp_path):
    src = tmp_path / "myproject"
    (src / "pkg").mkdir(parents=True)
    (src / "app.py").write_bytes(b"print('x')\n")
    (src / "pkg" / "mod.py").write_bytes(b"y = 1\n")
    (src / ".bandit").write_bytes(b"[bandit]\nskips = B101\n")  # hostile: must not survive
    return src


def scan(project, tmp_path, **kw):
    options = ScanOptions(out_root=tmp_path / "audits", tools=("bandit",), **kw)
    return run_scan(str(project), options, executor=FakeExecutor(), rules=fake_rules(tmp_path))


def is_readonly(path: Path) -> bool:
    if os.name == "nt":
        return bool(os.stat(path).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
    return not os.access(path, os.W_OK) or not (os.stat(path).st_mode & 0o222)


def test_source_is_retained_by_default_and_matches_what_the_scanners_saw(
    project, tmp_path, sys_tmp
):
    outcome = scan(project, tmp_path)
    source = outcome.audit_dir / "source"
    assert (source / "app.py").read_bytes() == b"print('x')\n"
    assert (source / "pkg" / "mod.py").is_file()
    assert not (source / ".bandit").exists(), "the retained copy is the NEUTRALIZED workspace"
    assert (source / ".semgrepignore").is_file()
    info = outcome.manifest["source"]
    assert info == {
        "retained_at_scan": True, "committed": False, "path": "source", "injected_files": [".semgrepignore"], "restricted_to_owner": info["restricted_to_owner"],
    }  # fmt: skip
    assert isinstance(info["restricted_to_owner"], bool)
    assert list(sys_tmp.iterdir()) == [], (
        "temp dirs are still always cleaned; retention is outside them"
    )


def test_retained_files_are_read_only(project, tmp_path, sys_tmp):
    source = scan(project, tmp_path).audit_dir / "source"
    assert is_readonly(source / "app.py") and is_readonly(source / "pkg" / "mod.py")


def test_no_keep_source_deletes_it(project, tmp_path, sys_tmp):
    outcome = scan(project, tmp_path, keep_source=False)
    assert not (outcome.audit_dir / "source").exists()
    assert (
        outcome.manifest["source"]["retained_at_scan"] is False
        and outcome.manifest["source"]["path"] is None
    )
    assert list(sys_tmp.iterdir()) == []


def test_retained_source_does_not_trigger_cleanup_errors(project, tmp_path, sys_tmp):
    """Cleanup still raises loudly for real leftovers, but never for the intentionally kept source."""
    scan(
        project, tmp_path
    )  # would raise CleanupError if the retained dir were treated as a leftover
    scan(project, tmp_path)


def test_manifest_on_disk_carries_the_source_block(project, tmp_path, sys_tmp):
    audit = scan(project, tmp_path).audit_dir
    manifest = json.loads((audit / "manifest.json").read_text("utf-8"))
    assert manifest["source"]["retained_at_scan"] is True and "source" in manifest["source"]["path"]


# ---------------------------------------------------------------- audit delete

AUDIT_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")


def test_delete_removes_a_read_only_tree_on_this_os(project, tmp_path, sys_tmp):
    outcome = scan(project, tmp_path)
    assert is_readonly(outcome.audit_dir / "source" / "app.py")
    assert AUDIT_ID.match(outcome.audit_dir.name)
    delete_audit(tmp_path / "audits", outcome.audit_dir.name)
    assert not outcome.audit_dir.exists()


@pytest.mark.parametrize(
    "bad",
    [
        "../audits",
        "..",
        "/etc",
        "C:\\x",
        "x" * 40,
        "",
        "20260101T000000Z-ZZZZZZZZ",
        "a/b",
        "20260101T000000Z-abcdef12/../x",
    ],
)
def test_delete_refuses_ids_that_are_not_audit_ids(tmp_path, bad):
    (tmp_path / "audits").mkdir()
    with pytest.raises(AuditNotFoundError):
        delete_audit(tmp_path / "audits", bad)


def test_delete_refuses_directories_that_are_not_audits(tmp_path):
    out = tmp_path / "audits"
    (out / "20260101T000000Z-abcdef12").mkdir(parents=True)
    (out / "20260101T000000Z-abcdef12" / "precious.txt").write_text("keep me")
    with pytest.raises(AuditNotFoundError, match="manifest"):
        delete_audit(out, "20260101T000000Z-abcdef12")
    assert (out / "20260101T000000Z-abcdef12" / "precious.txt").exists()


def test_delete_unknown_audit(tmp_path):
    (tmp_path / "audits").mkdir()
    with pytest.raises(AuditNotFoundError):
        delete_audit(tmp_path / "audits", "20260101T000000Z-abcdef12")


def test_cli_audit_delete(project, tmp_path, sys_tmp, capsys):
    outcome = scan(project, tmp_path)
    audit_id = outcome.audit_dir.name
    assert cli.main(["audit", "delete", audit_id, "--out", str(tmp_path / "audits")]) == cli.EXIT_OK
    assert not outcome.audit_dir.exists() and audit_id in capsys.readouterr().out
    assert (
        cli.main(["audit", "delete", audit_id, "--out", str(tmp_path / "audits")]) == cli.EXIT_USAGE
    )
    assert (
        cli.main(["audit", "delete", "../..", "--out", str(tmp_path / "audits")]) == cli.EXIT_USAGE
    )


def test_cli_scan_prints_one_notice_about_the_retained_source(
    project, tmp_path, sys_tmp, capsys, monkeypatch
):
    from secaudit.core import scan as scan_mod

    monkeypatch.setattr(scan_mod, "preflight", lambda options, adapters: None)
    real = scan_mod.run_scan

    def with_fake_executor(source, options):
        return real(source, options, executor=FakeExecutor(), rules=fake_rules(tmp_path))

    monkeypatch.setattr(cli, "run_scan", with_fake_executor)
    code = cli.main(["scan", str(project), "--tools", "bandit", "--out", str(tmp_path / "o")])
    out = capsys.readouterr().out
    notices = [line for line in out.splitlines() if line.startswith("source retained")]
    assert code == 0 and len(notices) == 1
    assert "secrets" in notices[0] and "audit delete" in notices[0]
    cli.main(
        [
            "scan",
            str(project),
            "--tools",
            "bandit",
            "--out",
            str(tmp_path / "o2"),
            "--no-keep-source",
        ]
    )
    assert "source retained" not in capsys.readouterr().out


# ---------------------------------------------------------------- Windows ACL (real icacls, locale independent)


def _sddl(path: Path, scratch: Path) -> str:
    target = scratch / "acl.txt"
    exe.run(["icacls", str(path), "/save", str(target)], capture_output=True, check=True)
    return target.read_bytes().decode("utf-16")


def _current_sid() -> str:
    done = exe.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
    )
    return done.stdout.strip().split(",")[1].strip().strip('"')


@pytest.mark.skipif(
    os.name != "nt",
    reason="icacls/SDDL is Windows-only; POSIX uses 0700/0600 (see test_raw_output_secrecy)",
)
def test_windows_audit_directory_is_restricted_to_the_current_user(project, tmp_path, sys_tmp):
    outcome = scan(project, tmp_path)
    assert outcome.manifest["source"]["restricted_to_owner"] is True
    sddl = _sddl(outcome.audit_dir, tmp_path)
    dacl = re.search(r"D:([A-Z]*)((?:\([^)]*\))*)", sddl)
    assert dacl, sddl
    flags, aces = dacl.group(1), re.findall(r"\(([^)]*)\)", dacl.group(2))
    assert "P" in flags, "inheritance must be removed (protected DACL)"
    sids = {ace.split(";")[-1] for ace in aces}
    assert sids == {_current_sid()}, f"only the current user may have access, got {sids}"
    # A child file must inherit exactly the owner's ACE. (Applying the grant with /T instead leaves
    # files with an EMPTY ACL: the owner could not even read them. That was the first attempt.)
    child = _sddl(outcome.audit_dir / "source" / "app.py", tmp_path)
    child_aces = re.findall(r"\(([^)]*)\)", re.search(r"D:[A-Z]*((?:\([^)]*\))*)", child).group(1))
    assert {a.split(";")[-1] for a in child_aces} == {_current_sid()}, child
    assert (outcome.audit_dir / "source" / "app.py").read_bytes() == b"print('x')\n", (
        "owner can still read"
    )


@pytest.mark.skipif(os.name != "nt", reason="icacls is Windows-only")
def test_restricted_audit_can_still_be_deleted_by_its_owner(project, tmp_path, sys_tmp):
    outcome = scan(project, tmp_path)
    delete_audit(tmp_path / "audits", outcome.audit_dir.name)
    assert not outcome.audit_dir.exists()


def test_restrict_to_owner_reports_false_instead_of_failing_on_a_missing_path(tmp_path):
    assert restrict_to_owner(tmp_path / "does-not-exist") is False


def test_restricting_a_single_file_keeps_it_usable_by_its_owner(tmp_path):
    """The (OI)(CI) grant used for directories leaves a FILE with an empty ACL on Windows."""
    target = tmp_path / "secret.db"
    target.write_bytes(b"data")
    assert restrict_to_owner(target) is True
    assert target.read_bytes() == b"data"
    target.write_bytes(b"more")
    target.unlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_posix_restrict_to_owner_gives_files_0600_and_directories_0700(tmp_path):
    """Found by the first run on a real Linux host: files used to get 0700 (an execute bit)."""
    directory = tmp_path / "d"
    directory.mkdir()
    file = directory / "f.db"
    file.write_bytes(b"x")
    os.chmod(directory, 0o755)
    os.chmod(file, 0o644)
    assert restrict_to_owner(directory) and restrict_to_owner(file)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
