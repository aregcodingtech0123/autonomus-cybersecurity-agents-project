"""Run exactly one scanner container with a fixed, restrictive set of Docker flags.

`build_docker_command` is a pure function (argument list, never a shell string) so tests can
assert every mandatory flag. `run_container` executes it with a wall-clock timeout, kills the
*container* by name on timeout (not just the docker client), and caps captured output.

Mandatory flags (always present): --rm, --pull never, --read-only, --tmpfs /tmp,
--cap-drop ALL, --security-opt no-new-privileges, --user (non-root), --pids-limit, --memory,
--memory-swap, --cpus, --network none unless an adapter explicitly asks for egress-only,
source mounted read-only at /src, a SEPARATE writable output mount at /out.
Never produced: docker.sock mounts, --privileged, host networking/PID/IPC, env passthrough.
"""

from __future__ import annotations

import enum
import re
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

from secaudit.core import exe

NON_ROOT_USER = "10001:10001"
MANAGED_LABEL = "org.secaudit.managed=true"
SRC_TARGET = "/src"
RULES_TARGET = "/rules"
OUT_TARGET = "/out"
ALLOWED_INPUT_TARGETS = frozenset({SRC_TARGET, RULES_TARGET})
# Only these environment variable names may be set, and only with explicit values.
ALLOWED_ENV = frozenset(
    {
        "HOME",
        "TMPDIR",
        "LANG",
        "XDG_CACHE_HOME",
        "PYTHONDONTWRITEBYTECODE",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
    }
)
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$")
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$")
_UNSAFE_PATH_CHARS = re.compile(r"[,\"'\n\r\x00]")


class SandboxError(ValueError):
    """The requested container spec violates the sandbox policy (nothing was started)."""


class NetworkPolicy(enum.StrEnum):
    NONE = "none"
    EGRESS_ONLY = "bridge"  # default bridge: outbound only, no published ports


@dataclass(frozen=True)
class ResourceLimits:
    pids: int = 256
    memory: str = "1g"
    cpus: float = 2.0
    tmpfs_size: str = "256m"
    timeout_s: float = 600.0
    max_capture_bytes: int = 64 * 1024
    max_stream_bytes: int = 8 * 1024 * 1024  # kill the container if it floods output beyond this


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class ContainerSpec:
    image: str
    command: tuple[str, ...]
    output_dir: Path
    inputs: tuple[Mount, ...] = ()
    network: NetworkPolicy = NetworkPolicy.NONE
    env: Mapping[str, str] = field(default_factory=dict)
    limits: ResourceLimits = ResourceLimits()
    name: str = ""
    workdir: str = "/tmp"

    def with_name(self, label: str) -> ContainerSpec:
        """Copy of this spec with a unique container name `secaudit-<label>-<random>`."""
        return replace(self, name=f"secaudit-{label}-{uuid.uuid4().hex[:8]}")


@dataclass(frozen=True)
class CommandOutcome:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_limit_exceeded: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class RunResult:
    argv: tuple[str, ...]
    container_name: str
    exit_code: int | None
    duration_s: float
    timed_out: bool
    output_limit_exceeded: bool
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    output_dir: Path


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        max_capture: int,
        max_stream: int,
        on_kill: Callable[[], None] | None = None,
    ) -> CommandOutcome: ...


# --------------------------------------------------------------------------- command builder


def _check_mount_source(path: Path) -> str:
    text = str(path)
    if not path.is_absolute():
        raise SandboxError(f"mount source must be absolute: {text!r}")
    if _UNSAFE_PATH_CHARS.search(text):
        raise SandboxError(f"mount source contains characters unsafe for --mount: {text!r}")
    if "docker.sock" in text.lower() or "docker_engine" in text.lower():
        raise SandboxError("the Docker socket must never be mounted")
    if path.is_symlink() or not path.is_dir():
        raise SandboxError(f"mount source must be an existing real directory: {text!r}")
    return text


def _overlaps(a: Path, b: Path) -> bool:
    a, b = a.resolve(), b.resolve()
    return a == b or a in b.parents or b in a.parents


def build_docker_command(spec: ContainerSpec, docker: str = "docker") -> list[str]:
    if not spec.name or not _NAME_RE.match(spec.name):
        raise SandboxError(f"invalid container name {spec.name!r}")
    if not _IMAGE_RE.match(spec.image):
        raise SandboxError(f"invalid image reference {spec.image!r}")
    if not spec.command or any(not isinstance(c, str) or "\x00" in c for c in spec.command):
        raise SandboxError("command must be a non-empty argument list of strings")
    if not isinstance(spec.network, NetworkPolicy):
        raise SandboxError("network must be a NetworkPolicy (host networking is not available)")
    for key, value in spec.env.items():
        if key not in ALLOWED_ENV:
            raise SandboxError(f"environment variable {key!r} is not in the allowlist")
        if "\n" in value or "\x00" in value:
            raise SandboxError(f"environment variable {key!r} has an illegal value")
    seen_targets: set[str] = set()
    for mount in spec.inputs:
        if mount.target not in ALLOWED_INPUT_TARGETS or mount.target in seen_targets:
            raise SandboxError(f"unsupported or duplicate mount target {mount.target!r}")
        if not mount.read_only:
            raise SandboxError("input mounts must be read-only")
        seen_targets.add(mount.target)
    if spec.workdir not in ("/tmp", SRC_TARGET) or (
        spec.workdir == SRC_TARGET and SRC_TARGET not in seen_targets
    ):
        raise SandboxError(f"unsupported workdir {spec.workdir!r}")
    out = Path(spec.output_dir)
    out_text = _check_mount_source(out)
    for mount in spec.inputs:
        if _overlaps(out, mount.source):
            raise SandboxError("the output mount must not overlap any input mount")

    limits = spec.limits
    argv = [
        docker, "run",
        "--rm",
        "--pull", "never",
        "--name", spec.name,
        "--label", MANAGED_LABEL,
        "--network", spec.network.value,
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", NON_ROOT_USER,
        "--pids-limit", str(limits.pids),
        "--memory", limits.memory,
        "--memory-swap", limits.memory,
        "--cpus", f"{limits.cpus:g}",
        "--workdir", spec.workdir,
    ]  # fmt: skip
    for mount in spec.inputs:
        src = _check_mount_source(mount.source)
        argv += ["--mount", f"type=bind,source={src},target={mount.target},readonly"]
    argv += ["--mount", f"type=bind,source={out_text},target={OUT_TARGET}"]
    for key in sorted(spec.env):
        argv += ["--env", f"{key}={spec.env[key]}"]
    argv += [spec.image, *spec.command]
    return argv


# --------------------------------------------------------------------------- execution


def _drain(
    stream, sink: bytearray, state: dict, max_capture: int, max_stream: int, key: str, on_flood
):
    total = 0
    for chunk in iter(lambda: stream.read(8192), b""):
        total += len(chunk)
        room = max_capture - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > room:
            state[f"{key}_truncated"] = True
        if total > max_stream and not state.get("flood"):
            state["flood"] = True
            on_flood()


def subprocess_runner(
    argv: Sequence[str],
    *,
    timeout_s: float,
    max_capture: int,
    max_stream: int,
    on_kill: Callable[[], None] | None = None,
) -> CommandOutcome:
    """Real process execution: argument list, no shell, stdin closed, bounded capture."""
    proc = exe.popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    state: dict = {}
    out_buf, err_buf = bytearray(), bytearray()

    def flood() -> None:
        if on_kill:
            on_kill()
        proc.kill()

    threads = [
        threading.Thread(
            target=_drain,
            args=(proc.stdout, out_buf, state, max_capture, max_stream, "stdout", flood),
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(proc.stderr, err_buf, state, max_capture, max_stream, "stderr", flood),
            daemon=True,
        ),
    ]  # fmt: skip
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        if on_kill:
            on_kill()
        proc.kill()
        proc.wait()
    except BaseException:
        if on_kill:
            on_kill()
        proc.kill()
        raise
    for t in threads:
        t.join(timeout=10)
    return CommandOutcome(
        exit_code=None if timed_out else proc.returncode,
        stdout=bytes(out_buf),
        stderr=bytes(err_buf),
        timed_out=timed_out,
        output_limit_exceeded=bool(state.get("flood")),
        stdout_truncated=bool(state.get("stdout_truncated")),
        stderr_truncated=bool(state.get("stderr_truncated")),
    )


def kill_container(
    name: str, runner: CommandRunner = subprocess_runner, docker: str = "docker"
) -> None:
    """Kill and remove a container by name (best effort, never raises)."""
    for argv in ([docker, "kill", name], [docker, "rm", "-f", name]):
        try:
            runner(argv, timeout_s=30, max_capture=4096, max_stream=65536)
        except Exception:  # noqa: BLE001, S110 - cleanup must not mask the real error
            pass


def run_container(
    spec: ContainerSpec,
    *,
    runner: CommandRunner = subprocess_runner,
    docker: str = "docker",
) -> RunResult:
    """Run one container. A non-zero exit code is data, not an error (adapters judge it)."""
    if not spec.name:
        raise SandboxError("spec has no container name; use spec.with_name(tool)")
    argv = build_docker_command(spec, docker)
    limits = spec.limits
    started = time.monotonic()
    killed = False

    def on_kill() -> None:
        nonlocal killed
        killed = True
        kill_container(spec.name, runner, docker)

    try:
        outcome = runner(
            argv,
            timeout_s=limits.timeout_s,
            max_capture=limits.max_capture_bytes,
            max_stream=limits.max_stream_bytes,
            on_kill=on_kill,
        )
    except BaseException:
        kill_container(spec.name, runner, docker)
        raise
    if outcome.timed_out or outcome.output_limit_exceeded or killed:
        kill_container(spec.name, runner, docker)  # idempotent; guarantees nothing is left running
    return RunResult(
        argv=tuple(argv),
        container_name=spec.name,
        exit_code=outcome.exit_code,
        duration_s=round(time.monotonic() - started, 3),
        timed_out=outcome.timed_out,
        output_limit_exceeded=outcome.output_limit_exceeded,
        stdout=outcome.stdout.decode("utf-8", "replace"),
        stderr=outcome.stderr.decode("utf-8", "replace"),
        stdout_truncated=outcome.stdout_truncated,
        stderr_truncated=outcome.stderr_truncated,
        output_dir=Path(spec.output_dir),
    )


def docker_available(docker: str = "docker") -> tuple[bool, str]:
    """(reachable, detail). Uses `docker info`; never raises."""
    try:
        done = exe.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=30, check=False, stdin=subprocess.DEVNULL,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker CLI not usable: {exc}"
    if done.returncode != 0:
        return False, (done.stderr.strip().splitlines() or ["docker info failed"])[-1]
    return True, done.stdout.strip()
