"""Resolve external programs to trusted ABSOLUTE paths; the only place that starts processes.

Why: on Windows, CreateProcess and `shutil.which` search the current directory before PATH, so a
scanned repository that ships `docker.exe` or `git.exe` would run on the host as soon as the user
scans it from inside that folder (review finding #1). We therefore walk PATH ourselves and refuse
the current directory, relative or empty PATH entries, and any registered untrusted root (the
scan input and the workspace). Every subprocess in secaudit goes through `run` / `popen` here;
`tests/test_exe.py` fails if any other module calls `subprocess` or `shutil.which` directly.
"""

from __future__ import annotations

import os
import subprocess

WINDOWS_SYSTEM_TOOLS = frozenset({"taskkill", "icacls", "whoami"})
_WINDOWS_EXTENSIONS = (".exe", ".com")  # never .bat/.cmd: they run through cmd.exe
_cache: dict[tuple, str] = {}
_untrusted: list[str] = []


class ExecutableNotFound(OSError):
    """No trusted executable with that name exists."""


def _norm(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _inside(root: str, candidate: str) -> bool:
    try:
        return os.path.commonpath([root, candidate]) == root
    except ValueError:  # different drives
        return False


def forbid(path: str | os.PathLike[str]) -> None:
    """Never resolve programs located inside this directory (scan input, workspace)."""
    _untrusted.append(_norm(path))
    _cache.clear()


def clear_cache() -> None:
    _cache.clear()


def _untrusted_dir(directory: str, cwd: str) -> str | None:
    real = _norm(directory)
    if real == cwd:
        return "the current directory"
    if any(_inside(root, real) for root in _untrusted):
        return "an untrusted (scanned) directory"
    return None


def _candidates(name: str) -> list[str]:
    if os.name != "nt":
        return [name]
    stem, ext = os.path.splitext(name)
    if ext.lower() in _WINDOWS_EXTENSIONS:
        return [name]
    return [name + e for e in _WINDOWS_EXTENSIONS]


def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and (os.name == "nt" or os.access(path, os.X_OK))


def resolve(
    name: str, *, path_env: str | None = None, cwd: str | os.PathLike[str] | None = None
) -> str:
    """Return the absolute path of `name`, or raise ExecutableNotFound."""
    cwd_real = _norm(cwd if cwd is not None else os.getcwd())
    if path_env is None:
        path_env = os.environ.get("PATH", "")
    key = (name, cwd_real, path_env, tuple(_untrusted))
    if key in _cache:
        return _cache[key]

    stem = name.lower().removesuffix(".exe")
    if os.name == "nt" and stem in WINDOWS_SYSTEM_TOOLS:
        # Git for Windows puts MSYS tools (/usr/bin/whoami, ...) on PATH ahead of System32 and
        # their options differ, so Windows' own tools always come from System32.
        root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        fixed = os.path.join(root, "System32", stem + ".exe")
        if os.path.isfile(fixed):
            _cache[key] = fixed
            return fixed

    rejected: list[str] = []
    has_separator = os.sep in name or (os.altsep is not None and os.altsep in name)
    if has_separator:
        if not os.path.isabs(name):
            raise ExecutableNotFound(f"{name!r}: relative program paths are not accepted")
        reason = _untrusted_dir(os.path.dirname(name), cwd_real)
        if reason and reason != "the current directory":
            raise ExecutableNotFound(f"{name!r} is inside {reason}")
        if _is_executable(name):
            _cache[key] = name
            return name
        raise ExecutableNotFound(f"{name!r} is not an executable file")

    for entry in path_env.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        reason = _untrusted_dir(entry, cwd_real)
        for candidate_name in _candidates(name):
            candidate = os.path.join(entry, candidate_name)
            if not _is_executable(candidate):
                continue
            if reason:
                rejected.append(f"{candidate} ({reason})")
                continue
            _cache[key] = candidate
            return candidate

    # Report a planted cwd copy even when cwd is not on PATH (Windows searches it anyway).
    for candidate_name in _candidates(name):
        planted = os.path.join(cwd_real, candidate_name)
        if os.path.isfile(planted) and not any("current directory" in r for r in rejected):
            rejected.append(f"{planted} (the current directory)")
    if rejected:
        raise ExecutableNotFound(
            f"{name!r} not found in a trusted PATH directory; only found in an untrusted "
            f"location (the current directory or scanned input): {', '.join(rejected)}"
        )
    raise ExecutableNotFound(f"{name!r} not found on PATH")


def _argv(argv):
    argv = list(argv)
    if not argv:
        raise ValueError("empty command")
    argv[0] = resolve(os.fspath(argv[0]))
    return argv


def run(argv, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with argv[0] resolved to a trusted absolute path. Never uses a shell."""
    if kwargs.get("shell"):
        raise ValueError("shell=True is not allowed")
    return subprocess.run(_argv(argv), **kwargs)  # noqa: S603


def popen(argv, **kwargs) -> subprocess.Popen:
    """subprocess.Popen with argv[0] resolved to a trusted absolute path. Never uses a shell."""
    if kwargs.get("shell"):
        raise ValueError("shell=True is not allowed")
    return subprocess.Popen(_argv(argv), **kwargs)  # noqa: S603


__all__ = ["ExecutableNotFound", "clear_cache", "forbid", "popen", "resolve", "run"]
