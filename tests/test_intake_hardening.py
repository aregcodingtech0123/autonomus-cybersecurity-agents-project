"""Reviews #6, #7, #11, #12: hardlinks, untyped errors, long/invalid names, reserved names, TOCTOU."""

from __future__ import annotations

import errno
import os
import textwrap
from pathlib import Path

import pytest

from canaries import ini_secret
from linux_probe import run_linux
from secaudit.core import intake as intake_mod
from secaudit.core.intake import (
    DEFAULT_LIMITS,
    IntakeError,
    Reason,
    intake_directory,
    intake_zip,
)

# ---------------------------------------------------------------- #6 hardlinks


def _tree(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "app.py").write_bytes(b"x = 1\n")
    return root


def test_hardlink_to_a_file_outside_the_input_is_rejected(tmp_path, ws_parent):
    outside = tmp_path / "victim_credentials.txt"
    outside.write_bytes(b"aws_secret_access_key = " + ini_secret().encode() + b"\n")
    proj = _tree(tmp_path / "proj")
    os.link(outside, proj / "config.txt")
    assert os.stat(proj / "config.txt").st_nlink == 2
    with pytest.raises(IntakeError) as exc:
        intake_directory(proj, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.HARDLINK
    assert list(ws_parent.iterdir()) == [], "nothing may be left behind"
    assert str(tmp_path) not in str(exc.value), "no host paths in the message"


def test_two_hardlinked_files_inside_the_input_are_rejected_not_silently_hidden(
    tmp_path, ws_parent
):
    proj = _tree(tmp_path / "proj")
    os.link(proj / "app.py", proj / "copy.py")
    with pytest.raises(IntakeError) as exc:
        intake_directory(proj, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.HARDLINK


LINUX_HARDLINK = textwrap.dedent(
    """
    import json, os
    from pathlib import Path
    from secaudit.core.intake import IntakeError, intake_directory, intake_zip
    os.makedirs("/h/proj"); os.makedirs("/h/ws")
    Path("/h/victim").write_text("secret")
    Path("/h/proj/app.py").write_text("x=1")
    os.link("/h/victim", "/h/proj/config.txt")
    try:
        intake_directory(Path("/h/proj"), workspace_parent=Path("/h/ws")); out = "ACCEPTED"
    except IntakeError as e:
        out = e.reason.value
    print(json.dumps({"hardlink": out, "leftover": os.listdir("/h/ws")}))
    """
)


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
def test_hardlink_rejected_on_linux_too():
    result = run_linux(LINUX_HARDLINK)
    assert result.returncode == 0, result.stderr
    assert result.json() == {"hardlink": "hardlink", "leftover": []}


# ---------------------------------------------------------------- #7 names, long paths, typed errors


@pytest.mark.parametrize("char", list('<>"|?*'))
def test_windows_invalid_characters_are_a_typed_rejection(zip_factory, ws_parent, char):
    path = zip_factory([{"name": "ok.py", "data": b"1"}, {"name": f"a{char}b.py", "data": b"x"}])
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.UNSAFE_NAME
    assert list(ws_parent.iterdir()) == []


def test_overlong_component_is_rejected_on_every_os(zip_factory, ws_parent):
    path = zip_factory([{"name": "d" * 300 + ".py", "data": b"x"}])
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.UNSAFE_NAME


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH applies to Windows only")
def test_entry_that_exceeds_windows_max_path_once_joined_is_rejected(zip_factory, ws_parent):
    """237 characters: passes the 240-character name limit but not MAX_PATH once joined to the workspace."""
    name = "/".join(["d" * 50] * 4) + "/" + "f" * 30 + ".py"
    assert len(name) <= DEFAULT_LIMITS.max_path_length
    with pytest.raises(IntakeError) as exc:
        intake_zip(zip_factory([{"name": name, "data": b"x"}]), workspace_parent=ws_parent)
    assert exc.value.reason is Reason.UNSAFE_NAME
    assert list(ws_parent.iterdir()) == []


@pytest.mark.parametrize(
    ("os_name", "length", "ok"),
    [
        ("nt", 200, True),
        ("nt", 259, True),
        ("nt", 260, False),
        ("posix", 4000, True),
        ("posix", 5000, False),
    ],
)
def test_total_path_length_rule(os_name, length, ok):
    target = "x" * length
    if ok:
        intake_mod._check_path_length(target, os_name=os_name)
    else:
        with pytest.raises(IntakeError) as exc:
            intake_mod._check_path_length(target, os_name=os_name)
        assert exc.value.reason is Reason.UNSAFE_NAME


def test_any_oserror_during_zip_extraction_is_typed(zip_factory, ws_parent, monkeypatch):
    path = zip_factory([{"name": "a.py", "data": b"x"}])

    def disk_full(self, *a, **k):
        raise OSError(errno.ENOSPC, "No space left on device", str(self))

    monkeypatch.setattr(Path, "open", disk_full)
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.IO_ERROR
    assert str(ws_parent) not in str(exc.value) and "No space" not in str(exc.value)
    monkeypatch.undo()
    assert list(ws_parent.iterdir()) == []


def test_any_oserror_during_directory_copy_is_typed_without_paths(tmp_path, ws_parent, monkeypatch):
    proj = _tree(tmp_path / "proj")
    real_open = os.open

    def deny(path, flags, *a, **k):
        if str(path).endswith("app.py"):
            raise OSError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", deny)
    with pytest.raises(IntakeError) as exc:
        intake_directory(proj, workspace_parent=ws_parent)
    monkeypatch.undo()
    assert exc.value.reason is Reason.IO_ERROR
    assert str(tmp_path) not in str(exc.value)
    assert list(ws_parent.iterdir()) == []
