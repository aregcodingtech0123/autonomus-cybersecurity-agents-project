import hashlib
import os
import stat
import types
from pathlib import Path

import pytest

from secaudit.core import intake as intake_mod
from secaudit.core.intake import (
    DEFAULT_LIMITS,
    IntakeError,
    Reason,
    build_clone_command,
    intake,
    intake_directory,
    intake_git,
    validate_git_url,
)


def make_tree(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_bytes(b"print(1)\n")
    (root / "README.md").write_bytes(b"# hi\n")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_bytes(b"[core]\n")
    return root


# ------------------------------------------------------------------ local directory


def test_directory_copy_metadata_and_git_excluded(tmp_path, ws_parent):
    src = make_tree(tmp_path / "proj")
    result = intake_directory(src, workspace_parent=ws_parent)
    assert result.kind == "directory"
    assert result.file_count == 2
    assert result.total_bytes == len("print(1)\n") + len("# hi\n")
    assert not (result.workspace / ".git").exists()
    assert (result.workspace / "src" / "a.py").read_bytes() == b"print(1)\n"
    assert len(result.input_sha256) == 64
    again = intake_directory(src, workspace_parent=ws_parent)
    assert again.input_sha256 == result.input_sha256  # deterministic tree hash


def test_directory_include_git_is_explicit(tmp_path, ws_parent):
    src = make_tree(tmp_path / "proj")
    result = intake_directory(src, workspace_parent=ws_parent, include_git=True)
    assert (result.workspace / ".git" / "config").exists()
    assert result.file_count == 3


def test_missing_input_rejected(tmp_path, ws_parent):
    with pytest.raises(IntakeError) as exc:
        intake(tmp_path / "nope", workspace_parent=ws_parent)
    assert exc.value.reason is Reason.INPUT_NOT_FOUND


def test_directory_limits_enforced(tmp_path, ws_parent):
    from dataclasses import replace

    src = make_tree(tmp_path / "proj")
    with pytest.raises(IntakeError) as exc:
        intake_directory(
            src, limits=replace(DEFAULT_LIMITS, max_files=1), workspace_parent=ws_parent
        )
    assert exc.value.reason is Reason.TOO_MANY_FILES
    assert list(ws_parent.iterdir()) == []
    with pytest.raises(IntakeError) as exc:
        intake_directory(
            src, limits=replace(DEFAULT_LIMITS, max_file_bytes=3), workspace_parent=ws_parent
        )
    assert exc.value.reason is Reason.FILE_SIZE_EXCEEDED


class _FakeEntry:
    """Stand-in for os.DirEntry: lets us exercise symlink/special-file branches on any OS."""

    def __init__(self, path, mode):
        self.path = str(path)
        self.name = Path(path).name
        self._mode = mode

    def is_dir(self, follow_symlinks=False):
        return stat.S_ISDIR(self._mode)

    def stat(self, follow_symlinks=False):
        return types.SimpleNamespace(st_mode=self._mode)


def _patched_tree(monkeypatch, entries):
    monkeypatch.setattr(intake_mod, "_iter_tree", lambda root, include_git: iter(entries))


@pytest.mark.parametrize("fmt", [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK])
def test_special_files_rejected(tmp_path, ws_parent, monkeypatch, fmt):
    src = tmp_path / "proj"
    src.mkdir()
    _patched_tree(monkeypatch, [("dev", _FakeEntry(src / "dev", fmt | 0o600))])
    with pytest.raises(IntakeError) as exc:
        intake_directory(src, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.SPECIAL_FILE
    assert list(ws_parent.iterdir()) == []


def test_escaping_symlink_rejected(tmp_path, ws_parent, monkeypatch):
    src = tmp_path / "proj"
    src.mkdir()
    _patched_tree(monkeypatch, [("link", _FakeEntry(src / "link", stat.S_IFLNK | 0o777))])
    monkeypatch.setattr(intake_mod, "_is_link", lambda p: True)
    monkeypatch.setattr(intake_mod, "_within", lambda root, cand: False)
    with pytest.raises(IntakeError) as exc:
        intake_directory(src, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.SYMLINK_ESCAPE
    assert list(ws_parent.iterdir()) == []


def test_internal_symlink_is_skipped_not_copied(tmp_path, ws_parent, monkeypatch):
    src = make_tree(tmp_path / "proj")
    link = _FakeEntry(src / "alias", stat.S_IFLNK | 0o777)
    real = _FakeEntry(src / "README.md", stat.S_IFREG | 0o644)
    _patched_tree(monkeypatch, [("alias", link), ("README.md", real)])
    monkeypatch.setattr(intake_mod, "_is_link", lambda p: p.endswith("alias"))
    result = intake_directory(src, workspace_parent=ws_parent)
    assert result.skipped == ("symlink:alias",)
    assert not (result.workspace / "alias").exists()


def _can_symlink(tmp_path) -> bool:
    try:
        os.symlink(tmp_path, tmp_path / "probe-link")
    except (OSError, NotImplementedError):
        return False
    (tmp_path / "probe-link").unlink()
    return True


def test_real_symlink_escape_rejected(tmp_path, ws_parent):
    if not _can_symlink(tmp_path):
        pytest.skip("this OS account may not create symlinks (Windows needs Developer Mode)")
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    src = make_tree(tmp_path / "proj")
    os.symlink(secret, src / "leak.txt")
    with pytest.raises(IntakeError) as exc:
        intake_directory(src, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.SYMLINK_ESCAPE


# ------------------------------------------------------------------ git URL validation


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("file:///etc/passwd", Reason.GIT_URL_SCHEME),
        ("file://C:/repo", Reason.GIT_URL_SCHEME),
        ("ssh://git@github.com/org/repo.git", Reason.GIT_URL_SCHEME),
        ("git://github.com/org/repo.git", Reason.GIT_URL_SCHEME),
        ("http://github.com/org/repo.git", Reason.GIT_URL_SCHEME),
        ("git@github.com:org/repo.git", Reason.GIT_URL_SCHEME),
        ("/srv/git/repo", Reason.GIT_URL_SCHEME),
        ("../repo", Reason.GIT_URL_SCHEME),
        ("C:\\repos\\x", Reason.GIT_URL_SCHEME),
        ("--upload-pack=evil", Reason.GIT_URL_SCHEME),
        ("ext::sh -c evil", Reason.GIT_URL_INVALID),
        ("https://github.com/org/repo .git", Reason.GIT_URL_INVALID),
        ("https://github.com/org/repo\n.git", Reason.GIT_URL_INVALID),
        ("https://user:pass@github.com/org/repo.git", Reason.GIT_CREDENTIALS_IN_URL),
        ("https://token@github.com/org/repo.git", Reason.GIT_CREDENTIALS_IN_URL),
        ("https://127.0.0.1/org/repo.git", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://[::1]/org/repo.git", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://169.254.169.254/latest", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://localhost/org/repo.git", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://evil.example.com/org/repo.git", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://github.com.evil.example/org/repo.git", Reason.GIT_HOST_NOT_ALLOWED),
        ("https://github.com:8443/org/repo.git", Reason.GIT_URL_INVALID),
        ("https://github.com/org/repo.git?x=1", Reason.GIT_URL_INVALID),
        ("https://github.com/", Reason.GIT_URL_INVALID),
        ("", Reason.GIT_URL_INVALID),
    ],
)
def test_git_url_rejections(url, reason):
    with pytest.raises(IntakeError) as exc:
        validate_git_url(url)
    assert exc.value.reason is reason


def test_valid_git_url_is_canonicalised():
    assert validate_git_url("https://GitHub.com/octocat/Hello-World.git") == (
        "https://github.com/octocat/Hello-World.git"
    )
    assert validate_git_url("https://github.com:443/octocat/Hello-World").startswith(
        "https://github.com/"
    )


def test_dispatcher_sends_urlish_inputs_to_git_validation(ws_parent):
    for bad in ("file:///etc/passwd", "git@github.com:org/repo.git", "ssh://github.com/a/b"):
        with pytest.raises(IntakeError) as exc:
            intake(bad, workspace_parent=ws_parent)
        assert exc.value.reason is Reason.GIT_URL_SCHEME


def test_clone_command_is_hardened(tmp_path):
    cmd = build_clone_command("https://github.com/o/r.git", tmp_path / "d", tmp_path / "hooks")
    joined = " ".join(cmd)
    assert cmd[0] == "git"
    for needle in (
        f"core.hooksPath={tmp_path / 'hooks'}",
        "protocol.file.allow=never",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "core.symlinks=false",
        "http.followRedirects=false",
        "credential.helper=",
        "--depth 1",
        "--no-recurse-submodules",
        "--single-branch",
    ):
        assert needle in joined, needle
    assert cmd[-3] == "--", "URL must come after -- so it can never be parsed as an option"
    assert cmd[-2] == "https://github.com/o/r.git"


def test_git_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    env = intake_mod._git_env(tmp_path)
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    assert env["HOME"] == str(tmp_path)
    for leaked in ("GIT_SSH_COMMAND", "GIT_DIR", "GITHUB_TOKEN"):
        assert leaked not in env


def test_git_intake_removes_dot_git_and_scratch(ws_parent, monkeypatch, tmp_path):
    """Drive intake_git with a fake clone so no network or git binary behaviour is involved."""
    scratch_before = set(Path(os.environ.get("TEMP", "/tmp")).glob("secaudit-clone-*"))

    def fake_clone(argv, env, dest, limits):
        make_tree(dest)
        (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

    monkeypatch.setattr(intake_mod, "_run_clone", fake_clone)
    monkeypatch.setattr(intake_mod, "_git_head", lambda repo, env: "a" * 40)
    monkeypatch.setattr(intake_mod.shutil, "which", lambda name: "git")
    result = intake_git("https://github.com/o/r.git", workspace_parent=ws_parent)
    assert result.kind == "git"
    assert result.commit == "a" * 40
    assert not (result.workspace / ".git").exists()
    assert result.file_count == 2
    assert result.input_sha256 == hashlib.sha256(b"https://github.com/o/r.git").hexdigest()
    assert set(Path(os.environ.get("TEMP", "/tmp")).glob("secaudit-clone-*")) == scratch_before


def test_git_clone_failure_is_typed_and_cleans_up(ws_parent, monkeypatch):
    def failing_clone(argv, env, dest, limits):
        raise IntakeError(Reason.GIT_CLONE_TIMEOUT, "slow")

    monkeypatch.setattr(intake_mod, "_run_clone", failing_clone)
    monkeypatch.setattr(intake_mod.shutil, "which", lambda name: "git")
    with pytest.raises(IntakeError) as exc:
        intake_git("https://github.com/o/r.git", workspace_parent=ws_parent)
    assert exc.value.reason is Reason.GIT_CLONE_TIMEOUT
    assert list(ws_parent.iterdir()) == []


def test_git_unavailable(ws_parent, monkeypatch):
    monkeypatch.setattr(intake_mod.shutil, "which", lambda name: None)
    with pytest.raises(IntakeError) as exc:
        intake_git("https://github.com/o/r.git", workspace_parent=ws_parent)
    assert exc.value.reason is Reason.GIT_UNAVAILABLE


@pytest.mark.network
def test_real_clone_of_small_public_repo(ws_parent):
    result = intake_git("https://github.com/octocat/Hello-World.git", workspace_parent=ws_parent)
    assert not (result.workspace / ".git").exists()
    assert result.file_count >= 1
    assert result.commit and len(result.commit) == 40


# ------------------------------------------------------------------ clone time / size limits


def _clone_limits(**kw):
    from dataclasses import replace

    return replace(DEFAULT_LIMITS, **kw)


def test_clone_time_limit_kills_the_process(tmp_path):
    import sys
    import time

    started = time.monotonic()
    with pytest.raises(IntakeError) as exc:
        intake_mod._run_clone(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            dict(os.environ),
            tmp_path / "dest",
            _clone_limits(git_clone_timeout_s=1.0),
        )
    assert exc.value.reason is Reason.GIT_CLONE_TIMEOUT
    assert time.monotonic() - started < 30


def test_clone_size_limit_kills_the_process(tmp_path):
    import sys

    dest = tmp_path / "dest"
    script = (
        "import pathlib, time\n"
        f"d = pathlib.Path({str(dest)!r}); d.mkdir()\n"
        "(d / 'big.bin').write_bytes(b'x' * 200000)\n"
        "time.sleep(60)\n"
    )
    with pytest.raises(IntakeError) as exc:
        intake_mod._run_clone(
            [sys.executable, "-c", script],
            dict(os.environ),
            dest,
            _clone_limits(git_clone_max_bytes=50_000, git_clone_timeout_s=60.0),
        )
    assert exc.value.reason is Reason.GIT_CLONE_TOO_LARGE


def test_clone_failure_reports_git_stderr(tmp_path):
    import sys

    with pytest.raises(IntakeError) as exc:
        intake_mod._run_clone(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('fatal: repository not found'); sys.exit(128)",
            ],
            dict(os.environ),
            tmp_path / "dest",
            DEFAULT_LIMITS,
        )
    assert (
        exc.value.reason is Reason.GIT_CLONE_FAILED and "repository not found" in exc.value.detail
    )
