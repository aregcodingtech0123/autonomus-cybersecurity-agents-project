"""Review #7: no tracebacks and no host paths on the CLI by default; --debug opts in; log keeps details."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from secaudit import cli
from secaudit.core import scan as scan_mod


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    d = tmp_path / "logs"
    monkeypatch.setenv("SECAUDIT_LOG_DIR", str(d))
    return d


def boom(*args, **kwargs):
    raise RuntimeError(r"boom while reading C:\Users\victim\secret\project\file.py")


def test_unexpected_error_is_one_sanitized_line_and_exit_1(monkeypatch, capsys, tmp_path, log_dir):
    monkeypatch.setattr(cli, "run_scan", boom)
    code = cli.main(["scan", str(tmp_path)])
    out = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "internal error" in out.err and "RuntimeError" in out.err
    assert "Traceback" not in out.err + out.out
    assert "victim" not in out.err + out.out and "boom" not in out.err + out.out
    assert str(tmp_path) not in out.err + out.out
    assert len(out.err.strip().splitlines()) <= 2


def test_traceback_goes_to_a_log_file(monkeypatch, capsys, tmp_path, log_dir):
    monkeypatch.setattr(cli, "run_scan", boom)
    cli.main(["scan", str(tmp_path)])
    logs = list(log_dir.glob("secaudit-*.log"))
    assert len(logs) == 1, "exactly one log file per failure"
    text = logs[0].read_text(encoding="utf-8")
    assert "Traceback" in text and "RuntimeError: boom while reading" in text
    assert logs[0].name in capsys.readouterr().err, (
        "the message must tell the user which log to open"
    )


def test_debug_flag_prints_the_traceback(monkeypatch, capsys, tmp_path, log_dir):
    monkeypatch.setattr(cli, "run_scan", boom)
    code = cli.main(["scan", str(tmp_path), "--debug"])
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert "Traceback" in err and "RuntimeError: boom while reading" in err


def test_debug_flag_is_accepted_before_the_subcommand(monkeypatch, capsys, tmp_path, log_dir):
    monkeypatch.setattr(cli, "run_scan", boom)
    cli.main(["--debug", "scan", str(tmp_path)])
    assert "Traceback" in capsys.readouterr().err


@pytest.fixture
def no_preflight(monkeypatch):
    monkeypatch.setattr(scan_mod, "preflight", lambda options, adapters: None)


@pytest.mark.parametrize("name", ["a?b.py", "a<b.py", "CONOUT$", "x" * 300 + ".py"])
def test_hostile_zip_names_exit_3_without_traceback_or_paths(
    zip_factory, tmp_path, capsys, log_dir, no_preflight, name
):
    archive = zip_factory([{"name": "ok.py", "data": b"1"}, {"name": name, "data": b"x"}])
    code = cli.main(["scan", str(archive), "--tools", "bandit", "--out", str(tmp_path / "o")])
    out = capsys.readouterr()
    assert code == cli.EXIT_INTAKE
    assert "input rejected [unsafe_name]" in out.err
    combined = out.err + out.out
    assert "Traceback" not in combined
    assert str(tmp_path) not in combined and tempfile.gettempdir() not in combined
    assert not (tmp_path / "o").exists(), "a rejected input creates no audit directory"
    assert not log_dir.exists(), "typed rejections are not internal errors"


def test_missing_input_exit_3(tmp_path, capsys, no_preflight, log_dir):
    code = cli.main(
        ["scan", str(tmp_path / "nope"), "--tools", "bandit", "--out", str(tmp_path / "o")]
    )
    assert code == cli.EXIT_INTAKE and "input_not_found" in capsys.readouterr().err


def test_default_log_dir_is_inside_the_ignored_state_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("SECAUDIT_LOG_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert cli.log_directory() == Path(".secaudit") / "logs"
