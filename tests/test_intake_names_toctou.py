"""Reviews #11 and #12: reserved device names and the check-to-open race."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secaudit.core.intake import IntakeError, Reason, intake_directory, intake_zip


def _tree(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "app.py").write_bytes(b"x = 1\n")
    return root


# ---------------------------------------------------------------- #11 reserved device names


@pytest.mark.parametrize(
    "name",
    ["CONIN$", "CONOUT$", "COM¹.txt", "LPT²", "CON .txt", "AUX .py", "con", "Nul.txt",
     "COM0", "COM9.log", "LPT9", "LPT³.dat", "prn.", "CLOCK$"],
)  # fmt: skip
def test_reserved_windows_device_names_are_rejected(zip_factory, ws_parent, name):
    path = zip_factory([{"name": "ok.py", "data": b"1"}, {"name": name, "data": b"x"}])
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.UNSAFE_NAME
    assert list(ws_parent.iterdir()) == []


@pytest.mark.parametrize(
    "name", ["console.py", "communicate.py", "COM10.txt", "lpt.py", "aux2.txt", "connector.py"]
)
def test_names_that_merely_resemble_reserved_ones_are_accepted(zip_factory, ws_parent, name):
    result = intake_zip(zip_factory([{"name": name, "data": b"x"}]), workspace_parent=ws_parent)
    assert (result.workspace / name).is_file()


# ---------------------------------------------------------------- #12 TOCTOU


def test_file_swapped_between_check_and_open_is_detected(tmp_path, ws_parent, monkeypatch):
    """Deterministic race: after the lstat the file is replaced by a different file."""
    proj = _tree(tmp_path / "proj")
    other = tmp_path / "other.txt"
    other.write_bytes(b"attacker controlled\n")
    target = proj / "app.py"
    real_open = os.open

    def swapping_open(path, flags, *a, **k):
        if str(path).endswith("app.py"):
            os.replace(other, path)  # a different inode now lives at the path
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", swapping_open)
    with pytest.raises(IntakeError) as exc:
        intake_directory(proj, workspace_parent=ws_parent)
    monkeypatch.undo()
    assert exc.value.reason is Reason.CHANGED_DURING_INTAKE
    assert target.exists()
    assert list(ws_parent.iterdir()) == []
