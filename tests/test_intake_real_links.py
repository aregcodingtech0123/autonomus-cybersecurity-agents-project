"""Review test-quality items: REAL links and special files, not stubs.

Windows: real junctions (no admin needed). Linux semantics (symlinks, FIFOs, devices, sockets) run in a
Linux container via tests/linux_probe.py, because this development host cannot create them.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from linux_probe import run_linux
from secaudit.core import exe
from secaudit.core.intake import IntakeError, Reason, intake_directory

# ---------------------------------------------------------------- Windows junctions


def _junction(link: Path, target: Path) -> None:
    done = exe.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        pytest.fail(f"could not create a junction: {done.stdout}{done.stderr}")


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions exist on Windows only")
def test_real_junction_escaping_the_input_is_rejected(tmp_path, ws_parent):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "id_rsa").write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_bytes(b"x = 1\n")
    _junction(proj / "linked", outside)
    assert not os.path.islink(proj / "linked"), (
        "precondition: a junction is NOT reported as a symlink"
    )
    with pytest.raises(IntakeError) as exc:
        intake_directory(proj, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.SYMLINK_ESCAPE
    assert list(ws_parent.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions exist on Windows only")
def test_real_junction_inside_the_input_is_skipped_not_followed(tmp_path, ws_parent):
    proj = tmp_path / "proj"
    (proj / "real").mkdir(parents=True)
    (proj / "real" / "mod.py").write_bytes(b"x = 1\n")
    _junction(proj / "alias", proj / "real")
    result = intake_directory(proj, workspace_parent=ws_parent)
    assert result.skipped == ("symlink:alias",)
    assert not (result.workspace / "alias").exists()
    assert result.file_count == 1, "the real directory is copied once, the junction not at all"


# ---------------------------------------------------------------- Linux: real symlinks and special files

SCRIPT = textwrap.dedent(
    """
    import json, os, socket, stat
    from pathlib import Path
    from secaudit.core.intake import IntakeError, intake_directory

    def case(name, build):
        base = Path("/h") / name
        proj, ws = base / "proj", base / "ws"
        proj.mkdir(parents=True); ws.mkdir()
        (proj / "app.py").write_text("x = 1\\n")
        build(proj)
        try:
            r = intake_directory(proj, workspace_parent=ws)
            return {"result": "accepted", "skipped": list(r.skipped), "files": r.file_count,
                    "copied": sorted(p.name for p in r.workspace.iterdir())}
        except IntakeError as e:
            return {"result": e.reason.value, "leftover": sorted(os.listdir(ws))}

    Path("/h/secret.txt").write_text("top secret")
    out = {}
    out["escape_file"] = case("c1", lambda p: os.symlink("/h/secret.txt", p / "leak.txt"))
    out["escape_dir"] = case("c2", lambda p: os.symlink("/h", p / "home"))
    out["escape_relative"] = case("c3", lambda p: os.symlink("../../secret.txt", p / "up.txt"))
    out["dangling_outside"] = case("c4", lambda p: os.symlink("/nonexistent/place", p / "dangling"))
    out["internal_file"] = case("c5", lambda p: os.symlink("app.py", p / "alias.py"))
    def loop(p):
        os.symlink("b", p / "a"); os.symlink("a", p / "b")
    out["loop"] = case("c6", loop)
    out["fifo"] = case("c7", lambda p: os.mkfifo(p / "pipe"))
    out["char_device"] = case("c8", lambda p: os.mknod(p / "null", stat.S_IFCHR | 0o600, os.makedev(1, 3)))
    def sock(p):
        s = socket.socket(socket.AF_UNIX); s.bind(str(p / "sock")); s.close()
    out["unix_socket"] = case("c9", sock)
    print(json.dumps(out))
    """
)


@pytest.fixture(scope="module")
def linux_cases():
    result = run_linux(SCRIPT)
    assert result.returncode == 0, result.stderr
    return result.json()


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
class TestRealLinuxLinks:
    @pytest.mark.parametrize(
        "case", ["escape_file", "escape_dir", "escape_relative", "dangling_outside"]
    )
    def test_symlinks_leaving_the_input_reject_the_whole_input(self, linux_cases, case):
        assert linux_cases[case] == {"result": "symlink_escape", "leftover": []}

    @pytest.mark.parametrize("case", ["internal_file", "loop"])
    def test_internal_symlinks_are_skipped_and_never_recreated(self, linux_cases, case):
        got = linux_cases[case]
        assert got["result"] == "accepted" and got["files"] == 1
        assert got["copied"] == ["app.py"], "only the regular file arrives in the workspace"
        assert got["skipped"] and all(s.startswith("symlink:") for s in got["skipped"])

    @pytest.mark.parametrize("case", ["fifo", "char_device", "unix_socket"])
    def test_special_files_reject_the_input(self, linux_cases, case):
        assert linux_cases[case] == {"result": "special_file", "leftover": []}
