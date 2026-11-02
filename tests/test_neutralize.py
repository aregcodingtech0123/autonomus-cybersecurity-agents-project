"""Reviews #2/#3/#7: files inside the scanned tree must not be able to change scanner behaviour."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from fakes import FakeExecutor, fake_rules
from secaudit.core import neutralize as neutralize_mod
from secaudit.core.intake import IntakeError, Reason
from secaudit.core.neutralize import neutralize_workspace
from secaudit.core.scan import ScanOptions, run_scan
from secaudit.core.scanners.semgrep import SEMGREPIGNORE_BODY, SEMGREPIGNORE_NAME


def put(root: Path, rel: str, text: str = "x") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    put(root, "app.py", "x = 1\n")
    put(root, "setup.cfg", "[bandit]\nskips = B101\n")  # real project config: left alone
    return root


def test_root_policy_file_is_written_and_nothing_recorded_when_absent(ws):
    assert neutralize_workspace(ws) == []
    assert (ws / SEMGREPIGNORE_NAME).read_text(encoding="utf-8") == SEMGREPIGNORE_BODY


@pytest.mark.parametrize(
    "rel",
    [
        ".bandit",
        "pkg/.bandit",
        "a/b/c/.bandit",
        ".gitleaksignore",
        "config/.gitleaksignore",
        ".gitleaks.toml",
        "config/.gitleaks.toml",
        "webshop/.semgrepignore",
        "tests/deep/.semgrepignore",
    ],
)
def test_effective_files_are_removed_at_any_depth(ws, rel):
    put(ws, rel)
    assert rel in neutralize_workspace(ws)
    assert not (ws / rel).exists()


@pytest.mark.parametrize(
    "rel", [".bandit", "pkg/.bandit", ".gitleaksignore", ".gitleaks.toml", "pkg/.semgrepignore"]
)
def test_directory_named_like_a_policy_file_is_removed_too(ws, rel):
    put(ws, f"{rel}/inner/file.txt")
    assert rel in neutralize_workspace(ws)
    assert not (ws / rel).exists()


def test_hostile_root_semgrepignore_is_replaced_and_reported(ws):
    put(ws, SEMGREPIGNORE_NAME, "*\n")
    assert SEMGREPIGNORE_NAME in neutralize_workspace(ws)
    assert (ws / SEMGREPIGNORE_NAME).read_text(encoding="utf-8") == SEMGREPIGNORE_BODY


def test_root_semgrepignore_that_is_a_directory_is_replaced_not_fatal(ws):
    put(ws, f"{SEMGREPIGNORE_NAME}/keep.txt")
    assert SEMGREPIGNORE_NAME in neutralize_workspace(ws)
    assert (ws / SEMGREPIGNORE_NAME).is_file()


def test_names_match_case_insensitively(ws):
    put(ws, "pkg/.BANDIT")
    put(ws, ".GitLeaksIgnore")
    removed = neutralize_workspace(ws)
    assert {"pkg/.BANDIT", ".GitLeaksIgnore"} <= set(removed)


def test_unrelated_files_are_untouched_and_output_is_posix_sorted(ws):
    put(ws, "b/.bandit")
    put(ws, "a/.bandit")
    removed = neutralize_workspace(ws)
    assert removed == sorted(removed) and all("\\" not in r for r in removed)
    assert (ws / "setup.cfg").is_file() and (ws / "app.py").is_file()


def test_failure_to_neutralize_is_a_typed_rejection(ws, monkeypatch):
    put(ws, ".bandit")

    def boom(path):
        raise PermissionError(13, "denied", str(path))

    monkeypatch.setattr(neutralize_mod, "remove_tree", boom)
    monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: boom(self))
    with pytest.raises(IntakeError) as exc:
        neutralize_workspace(ws)
    assert exc.value.reason is Reason.IO_ERROR
    assert str(ws) not in str(exc.value), "no host paths in the message"


# ---------------------------------------------------------------- orchestration wiring


def test_manifest_lists_neutralized_files_and_scan_survives_hostile_names(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "systmp"))
    (tmp_path / "systmp").mkdir()
    project = tmp_path / "proj"
    put(project, "app.py", "x = 1\n")
    put(project, ".bandit", "[bandit]\nskips = B101\n")
    put(project, "pkg/.gitleaksignore", "a:b:1\n")
    put(project, f"{SEMGREPIGNORE_NAME}/dir-instead-of-file.txt")
    outcome = run_scan(
        str(project),
        ScanOptions(out_root=tmp_path / "audits", tools=("bandit", "gitleaks")),
        executor=FakeExecutor(),
        rules=fake_rules(tmp_path),
    )
    manifest = json.loads((outcome.audit_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["neutralized_files"] == [".bandit", ".semgrepignore", "pkg/.gitleaksignore"]
    assert manifest["summary"]["failed"] == 0, "a hostile name must not abort the audit"
    for tool in ("bandit", "gitleaks"):
        assert tool in manifest["tools"]
