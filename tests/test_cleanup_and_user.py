"""Review #5: cleanup must never chmod through a symlink and must fail loudly on leftovers.
Review #5 fix (a): on POSIX the container runs as the host uid:gid (never root)."""

from __future__ import annotations

import textwrap

import pytest

from linux_probe import run_linux
from secaudit.core import sandbox

# ---------------------------------------------------------------- container user selection (no Docker)


@pytest.mark.parametrize(
    ("os_name", "uid", "gid", "expected"),
    [
        ("posix", 1000, 1000, "1000:1000"),
        ("posix", 501, 20, "501:20"),
        (
            "posix",
            0,
            0,
            "10001:10001",
        ),  # never run the scanner as root, even if the host user is root
        ("posix", 1000, 0, "1000:1000"),
        ("nt", None, None, "10001:10001"),  # bind mounts ignore uid on Docker Desktop for Windows
    ],
)
def test_container_user_selection(os_name, uid, gid, expected):
    assert sandbox.container_user(os_name=os_name, uid=uid, gid=gid) == expected


def test_container_user_is_never_root_for_any_input():
    for uid in (0, 1, 999, 1000, 65534):
        user = sandbox.container_user(os_name="posix", uid=uid, gid=0)
        assert not user.startswith("0:") and user.split(":")[0] != "0"


def test_command_builder_uses_the_selected_user(tmp_path, monkeypatch):
    src, out = tmp_path / "s", tmp_path / "o"
    src.mkdir()
    out.mkdir()
    monkeypatch.setattr(sandbox, "container_user", lambda **kw: "1234:5678")
    spec = sandbox.ContainerSpec(
        image="secaudit/bandit:1.9.4",
        command=("bandit",),
        output_dir=out,
        inputs=(sandbox.Mount(src, "/src"),),
        workdir="/src",
    ).with_name("t")
    argv = sandbox.build_docker_command(spec)
    assert argv[argv.index("--user") + 1] == "1234:5678"


# ---------------------------------------------------------------- cleanup in a Linux container

SCRIPT = textwrap.dedent(
    """
    import json, os
    from pathlib import Path
    from secaudit.core.intake import remove_tree

    def as_user(uid, fn):
        pid = os.fork()
        if pid == 0:
            os.setgid(uid); os.setuid(uid)
            try: fn()
            finally: os._exit(0)
        os.waitpid(pid, 0)

    def mode(p): return oct(os.lstat(p).st_mode & 0o777)
    r = {}
    os.makedirs("/h/res"); os.chmod("/h/res", 0o777)

    # --- Scenario A: the reviewer's attack. A compromised scanner (uid 10001) leaves a symlink to a
    #     host file inside a read-only directory in its output; the host user (uid 1000) cleans up.
    os.makedirs("/h/a/out"); os.chmod("/h/a", 0o755); os.chmod("/h/a/out", 0o777)
    Path("/h/a/victim").write_text("host file\\n"); os.chown("/h/a/victim", 1000, 1000); os.chmod("/h/a/victim", 0o600)
    def attack():
        os.mkdir("/h/a/out/d"); os.symlink("/h/a/victim", "/h/a/out/d/link"); os.chmod("/h/a/out/d", 0o555)
    as_user(10001, attack)
    r["a_victim_before"] = mode("/h/a/victim")
    # run in-process as uid 1000 via fork + pipe-free json file
    def clean_a_proc():
        out = {}
        try: remove_tree(Path("/h/a/out"))
        except BaseException as e: out["raised"] = type(e).__name__; out["msg"] = str(e)
        Path("/h/res/a.json").write_text(json.dumps(out))
    as_user(1000, clean_a_proc)
    res = json.loads(Path("/h/res/a.json").read_text())
    r["a_raised"] = res.get("raised"); r["a_msg"] = res.get("msg", "")
    r["a_victim_after"] = mode("/h/a/victim")
    r["a_leftover"] = sorted(os.listdir("/h/a/out")) if os.path.exists("/h/a/out") else []

    # --- Scenario B: ordinary read-only tree owned by the cleaning user is removed completely.
    os.makedirs("/h/b/out/sub"); Path("/h/b/out/sub/f").write_text("x"); Path("/h/b/out/g").write_text("y")
    os.chmod("/h/b/out/sub/f", 0o444); os.chmod("/h/b/out/sub", 0o555); os.chmod("/h/b/out/g", 0o444)
    for p in ("/h/b", "/h/b/out"): os.chown(p, 1000, 1000)
    for root, dirs, files in os.walk("/h/b/out"):
        for n in dirs + files: os.chown(os.path.join(root, n), 1000, 1000)
    def clean_b():
        out = {}
        try: remove_tree(Path("/h/b/out"))
        except BaseException as e: out["raised"] = type(e).__name__
        out["gone"] = not os.path.lexists("/h/b/out")
        Path("/h/res/b.json").write_text(json.dumps(out))
    as_user(1000, clean_b)
    r["b"] = json.loads(Path("/h/res/b.json").read_text())

    # --- Scenario C: a symlink INSIDE the tree to an outside file is removed; the target is untouched.
    os.makedirs("/h/c/out"); Path("/h/c/target").write_text("t"); os.chmod("/h/c/target", 0o640)
    os.symlink("/h/c/target", "/h/c/out/lnk")
    os.chown("/h/c", 1000, 1000); os.chown("/h/c/out", 1000, 1000)
    def clean_c():
        out = {}
        try: remove_tree(Path("/h/c/out"))
        except BaseException as e: out["raised"] = type(e).__name__
        out["gone"] = not os.path.lexists("/h/c/out")
        Path("/h/res/c.json").write_text(json.dumps(out))
    as_user(1000, clean_c)
    r["c"] = json.loads(Path("/h/res/c.json").read_text())
    r["c_target_mode"] = mode("/h/c/target")
    print(json.dumps(r))
    """
)


@pytest.fixture(scope="module")
def linux_cleanup():
    result = run_linux(SCRIPT)
    assert result.returncode == 0, result.stderr
    return result.json()


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
class TestCleanupInLinux:
    def test_cleanup_never_chmods_through_a_symlink(self, linux_cleanup):
        assert linux_cleanup["a_victim_before"] == "0o600"
        assert linux_cleanup["a_victim_after"] == "0o600", "victim file permissions were changed"

    def test_unremovable_leftovers_fail_loudly(self, linux_cleanup):
        assert linux_cleanup["a_raised"] == "CleanupError"
        assert linux_cleanup["a_leftover"] == ["d"]
        assert "d" in linux_cleanup["a_msg"]

    def test_read_only_tree_of_the_same_user_is_fully_removed(self, linux_cleanup):
        assert linux_cleanup["b"] == {"gone": True}

    def test_inner_symlink_is_removed_and_target_untouched(self, linux_cleanup):
        assert linux_cleanup["c"] == {"gone": True}
        assert linux_cleanup["c_target_mode"] == "0o640"
