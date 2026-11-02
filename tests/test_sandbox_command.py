"""Sandbox command builder + runner logic, verified with a fake runner (no Docker needed)."""

import sys

import pytest

from secaudit.core.sandbox import (
    CommandOutcome,
    ContainerSpec,
    Mount,
    NetworkPolicy,
    ResourceLimits,
    SandboxError,
    build_docker_command,
    container_user,
    run_container,
    subprocess_runner,
)


@pytest.fixture
def dirs(tmp_path):
    src, out, rules = tmp_path / "src", tmp_path / "out", tmp_path / "rules"
    for d in (src, out, rules):
        d.mkdir()
    return src, out, rules


@pytest.fixture
def spec(dirs):
    src, out, _ = dirs
    return ContainerSpec(
        image="secaudit/bandit:1.9.4",
        command=("bandit", "-r", "."),
        output_dir=out,
        inputs=(Mount(src, "/src"),),
        env={"HOME": "/tmp"},
        workdir="/src",
    ).with_name("test")


def value_after(argv, flag):
    return argv[argv.index(flag) + 1]


def test_every_mandatory_flag_is_present(spec):
    argv = build_docker_command(spec)
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv
    assert "--read-only" in argv
    assert value_after(argv, "--pull") == "never"
    assert value_after(argv, "--network") == "none"
    assert value_after(argv, "--cap-drop") == "ALL"
    assert value_after(argv, "--security-opt") == "no-new-privileges"
    user = value_after(argv, "--user")
    assert user == container_user() and not user.startswith("0:"), "non-root --user is mandatory"
    assert value_after(argv, "--pids-limit") == "256"
    assert value_after(argv, "--memory") == "1g"
    assert value_after(argv, "--memory-swap") == "1g"
    assert float(value_after(argv, "--cpus")) == 2.0
    assert value_after(argv, "--tmpfs").startswith("/tmp:rw,noexec,nosuid,size=")
    assert value_after(argv, "--workdir") == "/src"
    mounts = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--mount"]
    src_mount = next(m for m in mounts if "target=/src" in m)
    out_mount = next(m for m in mounts if "target=/out" in m)
    assert src_mount.endswith(",readonly"), "source must be mounted read-only"
    assert "readonly" not in out_mount, "output is the one writable mount"
    image_at = argv.index("secaudit/bandit:1.9.4")
    assert argv[image_at + 1 : image_at + 5] == ["timeout", "-k", "5", "610"], (
        "in-container deadline (timeout_s + 10)"
    )
    assert argv[-3:] == ["bandit", "-r", "."], "the tool command comes last"


def test_forbidden_options_are_never_produced(spec, dirs):
    _, out, rules = dirs
    full = ContainerSpec(
        spec.image, spec.command, out, (*spec.inputs, Mount(rules, "/rules")), NetworkPolicy.EGRESS_ONLY,
        {"HOME": "/tmp"}, spec.limits, spec.name, "/src",
    )  # fmt: skip
    for candidate in (spec, full):
        argv = build_docker_command(candidate)
        text = " ".join(argv)
        assert "docker.sock" not in text
        assert "--privileged" not in argv
        assert "host" not in [argv[i + 1] for i, t in enumerate(argv) if t == "--network"]
        for forbidden in ("--pid", "--ipc", "--uts", "--cap-add", "--device", "-v", "--volume",
                          "--env-file", "--userns", "--security-opt=seccomp=unconfined"):  # fmt: skip
            assert forbidden not in argv, forbidden
        opts = [argv[i + 1] for i, t in enumerate(argv) if t == "--security-opt"]
        assert opts == ["no-new-privileges"], "no seccomp/apparmor weakening"
        envs = [argv[i + 1] for i, t in enumerate(argv) if t == "--env"]
        assert all("=" in e for e in envs), "no bare --env KEY passthrough from the host"


def test_egress_policy_only_changes_the_network_flag(spec):
    none_argv = build_docker_command(spec)
    egress = ContainerSpec(
        spec.image, spec.command, spec.output_dir, spec.inputs, NetworkPolicy.EGRESS_ONLY,
        spec.env, spec.limits, spec.name, spec.workdir,
    )  # fmt: skip
    egress_argv = build_docker_command(egress)
    diff = [(a, b) for a, b in zip(none_argv, egress_argv, strict=True) if a != b]
    assert diff == [("none", "bridge")]


def test_host_network_cannot_even_be_expressed():
    with pytest.raises(ValueError):
        NetworkPolicy("host")


@pytest.mark.parametrize(
    ("env", "why"),
    [
        ({"AWS_SECRET_ACCESS_KEY": "x"}, "not allow-listed"),
        ({"PATH": "/usr/bin"}, "not allow-listed"),
        ({"HOME": "a\nb"}, "newline"),
    ],
)
def test_env_allowlist_enforced(spec, env, why):
    bad = ContainerSpec(spec.image, spec.command, spec.output_dir, spec.inputs, env=env,
                        name=spec.name, workdir=spec.workdir)  # fmt: skip
    with pytest.raises(SandboxError):
        build_docker_command(bad)


def test_invalid_images_names_and_commands_rejected(spec):
    base = dict(command=spec.command, output_dir=spec.output_dir, inputs=spec.inputs, name=spec.name,
                workdir=spec.workdir)  # fmt: skip
    for image in ("alpine; rm -rf /", "-v /:/host alpine", "--privileged", "", "UPPER/case"):
        with pytest.raises(SandboxError):
            build_docker_command(ContainerSpec(image=image, **base))
    with pytest.raises(SandboxError):
        build_docker_command(ContainerSpec(image=spec.image, **{**base, "command": ()}))
    with pytest.raises(SandboxError):
        build_docker_command(ContainerSpec(image=spec.image, **{**base, "name": "bad name; x"}))
    with pytest.raises(SandboxError):
        build_docker_command(ContainerSpec(image=spec.image, **{**base, "name": ""}))


def test_mount_source_validation(tmp_path, spec):
    def with_src(path, out=None, read_only=True, target="/src"):
        return ContainerSpec(spec.image, spec.command, out or spec.output_dir,
                             (Mount(path, target, read_only),), name=spec.name,
                             workdir="/tmp")  # fmt: skip

    for name in ("a,b", "it's", "docker.sock"):
        bad = tmp_path / name
        bad.mkdir()
        with pytest.raises(SandboxError):
            build_docker_command(with_src(bad))
    with pytest.raises(SandboxError):
        build_docker_command(with_src(tmp_path / "does-not-exist"))
    with pytest.raises(SandboxError):
        build_docker_command(with_src(__import__("pathlib").Path("relative/dir")))
    with pytest.raises(SandboxError, match="read-only"):
        build_docker_command(with_src(tmp_path / "src", read_only=False))
    with pytest.raises(SandboxError, match="mount target"):
        build_docker_command(with_src(tmp_path / "src", target="/etc"))


def test_output_mount_must_not_overlap_inputs(tmp_path, dirs, spec):
    src, _, _ = dirs
    nested_out = src / "out"
    nested_out.mkdir()
    bad = ContainerSpec(spec.image, spec.command, nested_out, (Mount(src, "/src"),), name=spec.name,
                        workdir="/src")  # fmt: skip
    with pytest.raises(SandboxError, match="overlap"):
        build_docker_command(bad)
    same = ContainerSpec(spec.image, spec.command, src, (Mount(src, "/src"),), name=spec.name,
                         workdir="/src")  # fmt: skip
    with pytest.raises(SandboxError, match="overlap"):
        build_docker_command(same)


def test_workdir_src_requires_a_source_mount(spec):
    bad = ContainerSpec(
        spec.image, spec.command, spec.output_dir, (), name=spec.name, workdir="/src"
    )
    with pytest.raises(SandboxError, match="workdir"):
        build_docker_command(bad)


# ------------------------------------------------------------------ run_container with a fake runner


class FakeRunner:
    def __init__(self, outcome=None, raises=None):
        self.outcome = outcome or CommandOutcome(0)
        self.raises = raises
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout_s, max_capture, max_stream, on_kill=None):
        self.calls.append(list(argv))
        if argv[1] == "run":
            if self.raises:
                raise self.raises
            if (self.outcome.timed_out or self.outcome.output_limit_exceeded) and on_kill:
                on_kill()
            return self.outcome
        return CommandOutcome(0)

    def docker_verbs(self):
        return [c[1] for c in self.calls]


def test_nonzero_exit_is_data_not_an_error(spec):
    runner = FakeRunner(CommandOutcome(1, b"found things", b"warn"))
    result = run_container(spec, runner=runner)
    assert result.exit_code == 1 and not result.timed_out
    assert result.stdout == "found things"
    assert runner.docker_verbs() == ["run"], "no kill on a normal completion (--rm cleans up)"
    assert result.argv[1] == "run" and result.container_name == spec.name


def test_timeout_kills_the_container_by_name(spec):
    runner = FakeRunner(CommandOutcome(None, timed_out=True))
    result = run_container(spec, runner=runner)
    assert result.timed_out and result.exit_code is None
    assert ["docker", "kill", spec.name] in runner.calls
    assert ["docker", "rm", "-f", spec.name] in runner.calls


def test_output_flood_kills_the_container(spec):
    runner = FakeRunner(CommandOutcome(None, output_limit_exceeded=True))
    result = run_container(spec, runner=runner)
    assert result.output_limit_exceeded
    assert ["docker", "kill", spec.name] in runner.calls


def test_exception_during_run_still_kills_container(spec):
    runner = FakeRunner(raises=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        run_container(spec, runner=runner)
    assert ["docker", "kill", spec.name] in runner.calls


def test_run_requires_a_named_spec(spec):
    unnamed = ContainerSpec(spec.image, spec.command, spec.output_dir, spec.inputs, workdir="/src")
    with pytest.raises(SandboxError):
        run_container(unnamed, runner=FakeRunner())


# ------------------------------------------------------------------ the real subprocess runner


def test_subprocess_runner_caps_capture_and_reports_truncation():
    outcome = subprocess_runner(
        [sys.executable, "-c", "print('x' * 100000)"],
        timeout_s=30, max_capture=100, max_stream=10_000_000,
    )  # fmt: skip
    assert outcome.exit_code == 0
    assert len(outcome.stdout) == 100 and outcome.stdout_truncated


def test_subprocess_runner_times_out_and_invokes_kill_hook():
    killed = []
    outcome = subprocess_runner(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        timeout_s=1, max_capture=100, max_stream=1000, on_kill=lambda: killed.append(1),
    )  # fmt: skip
    assert outcome.timed_out and outcome.exit_code is None and killed


def test_subprocess_runner_kills_output_flood():
    killed = []
    outcome = subprocess_runner(
        [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536); sys.stdout.flush()"],
        timeout_s=60, max_capture=100, max_stream=300_000, on_kill=lambda: killed.append(1),
    )  # fmt: skip
    assert outcome.output_limit_exceeded and killed


def test_limits_defaults_are_conservative():
    limits = ResourceLimits()
    assert limits.pids <= 512 and limits.timeout_s <= 900 and limits.max_capture_bytes <= 256 * 1024
