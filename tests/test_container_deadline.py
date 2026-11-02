"""Review #13: a killed secaudit process must not leave an unbounded container behind."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time

import pytest

from secaudit.core.executors import list_managed_containers, pid_alive, reap_stale_containers
from secaudit.core.sandbox import (
    ContainerSpec,
    Mount,
    ResourceLimits,
    build_docker_command,
    kill_container,
)

# ---------------------------------------------------------------- builder (no Docker)


@pytest.fixture
def spec(tmp_path):
    src, out = tmp_path / "s", tmp_path / "o"
    src.mkdir()
    out.mkdir()
    return ContainerSpec(
        image="secaudit/bandit:1.9.4",
        command=("bandit", "-r", "."),
        output_dir=out,
        inputs=(Mount(src, "/src"),),
        workdir="/src",
        limits=ResourceLimits(timeout_s=30),
    ).with_name("t")


def test_command_is_wrapped_in_an_inner_timeout_longer_than_the_host_timeout(spec):
    argv = build_docker_command(spec)
    at = argv.index(spec.image)
    assert argv[at + 1 : at + 5] == ["timeout", "-k", "5", "40"]
    assert argv[at + 5 :] == ["bandit", "-r", "."]


def test_containers_are_labelled_with_owner_pid_and_start_time(spec):
    argv = build_docker_command(spec)
    labels = [argv[i + 1] for i, t in enumerate(argv) if t == "--label"]
    assert f"org.secaudit.owner-pid={os.getpid()}" in labels
    started = [x for x in labels if x.startswith("org.secaudit.started=")]
    assert len(started) == 1 and abs(int(started[0].split("=")[1]) - time.time()) < 60


def test_pid_alive():
    assert pid_alive(os.getpid())
    child = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603
    child.wait()
    assert not pid_alive(child.pid)
    assert not pid_alive(0) and not pid_alive(-5)


# ---------------------------------------------------------------- real containers

CHILD = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from secaudit.core.sandbox import ContainerSpec, Mount, ResourceLimits, run_container
    src, out, namefile, timeout_s = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), float(sys.argv[4])
    spec = ContainerSpec(
        image="secaudit/bandit:1.9.4",
        command=("python", "-c", "import time; time.sleep(600)"),
        output_dir=out, inputs=(Mount(src, "/src"),), workdir="/src",
        limits=ResourceLimits(timeout_s=timeout_s),
    ).with_name("orphan")
    namefile.write_text(spec.name)
    run_container(spec)
    """
)


def _start_parent(tmp_path, timeout_s):
    src, out = tmp_path / "s", tmp_path / "o"
    src.mkdir(exist_ok=True)
    out.mkdir(exist_ok=True)
    namefile = tmp_path / f"name-{timeout_s}.txt"
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", CHILD, str(src), str(out), str(namefile), str(timeout_s)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not namefile.exists():
        time.sleep(0.2)
    name = namefile.read_text()
    while time.monotonic() < deadline and name not in list_managed_containers(name):
        time.sleep(0.3)
    assert name in list_managed_containers(name), "container never started"
    return parent, name


def _wait_gone(name, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not list_managed_containers(name):
            return True
        time.sleep(1)
    return False


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
class TestOrphans:
    def test_container_survives_a_killed_parent_then_the_reaper_removes_it(self, tmp_path):
        parent, name = _start_parent(tmp_path, timeout_s=300)
        try:
            parent.kill()  # SIGKILL / TerminateProcess: no cleanup code can run
            parent.wait()
            time.sleep(1)
            assert name in list_managed_containers(name), (
                "precondition: the orphan is still running"
            )
            removed = reap_stale_containers()
            assert name in removed
            assert _wait_gone(name, 30), "the reaper must remove containers whose owner is dead"
        finally:
            kill_container(name)

    def test_reaper_leaves_containers_of_live_owners_alone(self, tmp_path):
        parent, name = _start_parent(tmp_path, timeout_s=300)
        try:
            assert name not in reap_stale_containers(), "the owner process is alive"
            assert name in list_managed_containers(name)
        finally:
            parent.kill()
            parent.wait()
            kill_container(name)

    def test_orphan_stops_by_itself_via_the_inner_timeout(self, tmp_path):
        parent, name = _start_parent(tmp_path, timeout_s=3)  # inner deadline = 3 + 10 s
        try:
            parent.kill()
            parent.wait()
            assert _wait_gone(name, 60), (
                "the in-container `timeout` must end the orphan without any reaper"
            )
        finally:
            kill_container(name)

    def test_inner_timeout_does_not_disturb_a_normal_run(self, tmp_path):
        from secaudit.core.sandbox import run_container

        src, out = tmp_path / "s2", tmp_path / "o2"
        src.mkdir()
        out.mkdir()
        spec = ContainerSpec(
            image="secaudit/bandit:1.9.4",
            command=("python", "-c", "import sys; print('ok'); sys.exit(1)"),
            output_dir=out,
            inputs=(Mount(src, "/src"),),
            workdir="/src",
        ).with_name("normal")
        result = run_container(spec)
        assert result.exit_code == 1 and result.stdout.strip() == "ok" and not result.timed_out
        assert result.argv[result.argv.index("secaudit/bandit:1.9.4") + 1] == "timeout"
