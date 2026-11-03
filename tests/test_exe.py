"""Review finding #1: external programs must be resolved to trusted absolute paths."""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "secaudit"
IS_WINDOWS = os.name == "nt"
EXT = ".exe" if IS_WINDOWS else ""


def make_exe(directory: Path, name: str = "tool") -> Path:
    """A placeholder 'executable' that is found by the resolver (never actually run)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + EXT)
    path.write_bytes(b"MZ\x00" if IS_WINDOWS else b"#!/bin/sh\n")
    if not IS_WINDOWS:
        path.chmod(0o755)
    return path


@pytest.fixture
def exe_mod():
    from secaudit.core import exe

    exe.clear_cache()
    yield exe
    exe.clear_cache()


def path_env(*dirs) -> str:
    return os.pathsep.join(str(d) for d in dirs)


# ---------------------------------------------------------------- OS-independent resolver tests


def test_resolves_to_absolute_path_on_path(exe_mod, tmp_path):
    good = make_exe(tmp_path / "bin")
    assert exe_mod.resolve("tool", path_env=path_env(tmp_path / "bin"), cwd=tmp_path) == str(good)


def test_cwd_candidate_is_never_returned(exe_mod, tmp_path):
    cwd = tmp_path / "evil"
    make_exe(cwd)
    good = make_exe(tmp_path / "bin")
    got = exe_mod.resolve("tool", path_env=path_env(cwd, tmp_path / "bin"), cwd=cwd)
    assert got == str(good), "a PATH entry equal to the cwd must be skipped"


def test_dot_and_relative_and_empty_path_entries_are_skipped(exe_mod, tmp_path, monkeypatch):
    make_exe(tmp_path / "evil")
    monkeypatch.chdir(tmp_path / "evil")
    good = make_exe(tmp_path / "bin")
    env = os.pathsep.join(["", ".", "evil", str(tmp_path / "bin")])
    assert exe_mod.resolve("tool", path_env=env, cwd=tmp_path / "evil") == str(good)


def test_only_candidate_in_cwd_gives_a_clear_error(exe_mod, tmp_path):
    cwd = tmp_path / "evil"
    make_exe(cwd)
    with pytest.raises(exe_mod.ExecutableNotFound) as exc:
        exe_mod.resolve("tool", path_env=path_env(cwd), cwd=cwd)
    assert "current directory" in str(exc.value) or "untrusted" in str(exc.value)


def test_missing_program_error(exe_mod, tmp_path):
    with pytest.raises(exe_mod.ExecutableNotFound, match="not found"):
        exe_mod.resolve("no-such-tool", path_env=path_env(tmp_path), cwd=tmp_path)


def test_untrusted_roots_are_skipped(exe_mod, tmp_path):
    scanned = tmp_path / "scanned"
    make_exe(scanned / "bin")
    good = make_exe(tmp_path / "bin")
    exe_mod.forbid(scanned)
    env = path_env(scanned / "bin", tmp_path / "bin")
    assert exe_mod.resolve("tool", path_env=env, cwd=tmp_path) == str(good)


def test_untrusted_only_candidate_is_an_error(exe_mod, tmp_path):
    scanned = tmp_path / "scanned"
    make_exe(scanned / "bin")
    exe_mod.forbid(scanned)
    with pytest.raises(exe_mod.ExecutableNotFound):
        exe_mod.resolve("tool", path_env=path_env(scanned / "bin"), cwd=tmp_path)


def test_names_with_separators_must_be_absolute_and_trusted(exe_mod, tmp_path):
    good = make_exe(tmp_path / "bin")
    assert exe_mod.resolve(str(good), path_env="", cwd=tmp_path) == str(good)
    with pytest.raises(exe_mod.ExecutableNotFound):
        exe_mod.resolve(
            os.path.join("sub", "tool"), path_env=path_env(tmp_path / "bin"), cwd=tmp_path
        )
    exe_mod.forbid(tmp_path / "bin")
    with pytest.raises(exe_mod.ExecutableNotFound):
        exe_mod.resolve(str(good), path_env="", cwd=tmp_path)


def test_result_is_cached_per_name_and_cwd(exe_mod, tmp_path):
    make_exe(tmp_path / "bin")
    env = path_env(tmp_path / "bin")
    first = exe_mod.resolve("tool", path_env=env, cwd=tmp_path)
    (tmp_path / "bin" / ("tool" + EXT)).unlink()
    assert exe_mod.resolve("tool", path_env=env, cwd=tmp_path) == first, (
        "resolved once, then cached"
    )
    exe_mod.clear_cache()
    with pytest.raises(exe_mod.ExecutableNotFound):
        exe_mod.resolve("tool", path_env=env, cwd=tmp_path)


@pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only resolver rules")
def test_windows_only_exe_and_com_extensions(exe_mod, tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "tool.bat").write_text("@echo hi")
    (tmp_path / "bin" / "tool.cmd").write_text("@echo hi")
    with pytest.raises(exe_mod.ExecutableNotFound):
        exe_mod.resolve("tool", path_env=path_env(tmp_path / "bin"), cwd=tmp_path)


@pytest.mark.skipif(not IS_WINDOWS, reason="Windows system tools are Windows-only")
@pytest.mark.parametrize("tool", ["taskkill", "icacls", "whoami"])
def test_windows_system_tools_come_from_system32(exe_mod, tool, tmp_path):
    expected = os.path.join(os.environ["SystemRoot"], "System32", tool + ".exe")
    # even when an MSYS-style lookalike earlier on PATH would win (Git for Windows ships /usr/bin/whoami)
    lookalike = tmp_path / "usr_bin"
    lookalike.mkdir()
    (lookalike / f"{tool}.exe").write_bytes(b"MZ\x00")
    got = exe_mod.resolve(tool, path_env=str(lookalike) + os.pathsep + os.environ["PATH"])
    assert os.path.normcase(got) == os.path.normcase(expected)


# ---------------------------------------------------------------- guard: no bare subprocess use


def _under_type_checking(tree: ast.AST, target: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and getattr(node.test, "id", "") == "TYPE_CHECKING":
            if any(child is target for child in ast.walk(node)):
                return True
    return False


def test_no_subprocess_calls_outside_exe_module():
    """Every external program must go through secaudit.core.exe (resolves argv[0])."""
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name == "exe.py" and path.parent.name == "core":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "subprocess"
                and node.attr in {"run", "Popen", "call", "check_call", "check_output", "getoutput"}
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno} subprocess.{node.attr}")
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                bad = [
                    a.name
                    for a in node.names
                    if a.name
                    not in {"DEVNULL", "PIPE", "TimeoutExpired", "Popen", "CompletedProcess"}
                ]
                bad += [
                    a.name
                    for a in node.names
                    if a.name == "Popen" and not _under_type_checking(tree, node)
                ]
                if bad:
                    offenders.append(
                        f"{path.relative_to(SRC)}:{node.lineno} from subprocess import {bad}"
                    )
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "shutil"
                and node.attr == "which"
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno} shutil.which")
    assert offenders == []


# ---------------------------------------------------------------- Windows: planted executables


@pytest.mark.skipif(
    not IS_WINDOWS, reason="current-directory executable search is a Windows behaviour"
)
def test_planted_docker_and_git_in_cwd_are_never_executed(tmp_path):
    """Review #1 reproduction. The env var that disables cwd search is REMOVED for the child."""
    evil = tmp_path / "evil_cwd"
    evil.mkdir()
    system32 = Path(os.environ["SystemRoot"]) / "System32"
    shutil.copy(system32 / "hostname.exe", evil / "docker.exe")  # prints the host name, exit 0
    shutil.copy(system32 / "whoami.exe", evil / "git.exe")  # prints the user name, exit 0
    shutil.copy(system32 / "hostname.exe", evil / "bandit.exe")

    script = textwrap.dedent(
        """
        import os, sys, json
        os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
        from secaudit.core import exe, sandbox
        out = {}
        out["docker_available"] = list(sandbox.docker_available())
        out["docker_path"] = exe.resolve("docker")
        r = exe.run(["git", "--version"], capture_output=True, text=True)
        out["git_stdout"] = r.stdout.strip()
        try:
            exe.resolve("bandit")
            out["bandit"] = "resolved"
        except exe.ExecutableNotFound as e:
            out["bandit"] = "refused"
        print(json.dumps(out))
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "NoDefaultCurrentDirectoryInExePath"}
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=evil,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    import json

    out = json.loads(done.stdout.strip().splitlines()[-1])
    assert str(evil).lower() not in out["docker_path"].lower()
    assert out["git_stdout"].startswith("git version"), "the planted git.exe (whoami) must not run"
    assert out["bandit"] == "refused"
    ok, detail = out["docker_available"]
    if ok:
        assert detail[0].isdigit(), f"the real docker must answer, got {out['docker_available']}"
    else:
        # Daemon not running: the failure must still come from the REAL docker CLI. The planted
        # hostname.exe cannot produce this message (it produced the generic 'docker info failed').
        assert detail != "docker info failed" and "docker" in detail.lower(), out[
            "docker_available"
        ]
