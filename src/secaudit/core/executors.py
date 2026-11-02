"""Executors: where an adapter's command actually runs (sandboxed container, or native)."""

from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
import time
from pathlib import Path

from secaudit.core import exe
from secaudit.core.sandbox import (
    RULES_TARGET,
    SRC_TARGET,
    CommandRunner,
    ContainerSpec,
    Mount,
    NetworkPolicy,
    ResourceLimits,
    kill_container,
    run_container,
    subprocess_runner,
)
from secaudit.core.scanners.base import ExecOutcome, Prepared, ScannerAdapter, ToolPaths


class DockerExecutor:
    """Runs each command in its own locked-down container (see core/sandbox.py)."""

    kind = "docker"

    def __init__(
        self,
        *,
        runner: CommandRunner = subprocess_runner,
        limits: ResourceLimits | None = None,
        docker: str = "docker",
        name_prefix: str = "",
    ) -> None:
        self.runner = runner
        self.limits = limits or ResourceLimits()
        self.docker = docker
        self.name_prefix = name_prefix

    def paths(self, prepared: Prepared, out_dir: Path) -> ToolPaths:
        return ToolPaths(
            src=SRC_TARGET,
            out="/out",
            rules=RULES_TARGET if prepared.rules_dir else None,
            sandboxed=True,
        )

    def run(
        self,
        adapter: ScannerAdapter,
        prepared: Prepared,
        out_dir: Path,
        command: list[str],
        label: str,
    ) -> ExecOutcome:
        inputs: list[Mount] = []
        if prepared.src_dir is not None:
            inputs.append(Mount(prepared.src_dir, SRC_TARGET))
        if prepared.rules_dir is not None:
            inputs.append(Mount(prepared.rules_dir, RULES_TARGET))
        has_inputs = bool(inputs)
        spec = ContainerSpec(
            image=adapter.image,
            command=tuple(command),
            output_dir=out_dir,
            inputs=tuple(inputs),
            # Only a real scan may use an adapter's network policy; version probes never do.
            network=adapter.network_policy if has_inputs else NetworkPolicy.NONE,
            env=dict(adapter.env),
            limits=self.limits,
            workdir=adapter.workdir if prepared.src_dir is not None else "/tmp",
        ).with_name(f"{self.name_prefix}{label}")
        result = run_container(spec, runner=self.runner, docker=self.docker)
        display = list(result.argv)
        replacements = [(spec.name, "<container>"), (str(out_dir), "<out>")]
        if prepared.src_dir is not None:
            replacements.append((str(prepared.src_dir), "<src>"))
        if prepared.rules_dir is not None:
            replacements.append((str(prepared.rules_dir), "<rules>"))
        for old, new in replacements:
            display = [token.replace(old, new) for token in display]
        return ExecOutcome(
            exit_code=result.exit_code,
            duration_s=result.duration_s,
            timed_out=result.timed_out,
            output_limit_exceeded=result.output_limit_exceeded,
            stdout=result.stdout,
            stderr=result.stderr,
            sandbox_command=tuple(display),
        )


class NativeExecutor:
    """Runs tools directly on the host. NO isolation: development only, trusted code only."""

    kind = "native"

    def __init__(self, timeout_s: float = 600.0) -> None:
        self.timeout_s = timeout_s

    def paths(self, prepared: Prepared, out_dir: Path) -> ToolPaths:
        return ToolPaths(
            src=str(prepared.src_dir or out_dir),
            out=str(out_dir),
            rules=str(prepared.rules_dir) if prepared.rules_dir else None,
            sandboxed=False,
            sep=os.sep,
        )

    def run(
        self,
        adapter: ScannerAdapter,
        prepared: Prepared,
        out_dir: Path,
        command: list[str],
        label: str,
    ) -> ExecOutcome:
        executable = exe.resolve(command[0])  # raises ExecutableNotFound (an OSError)
        cwd = prepared.src_dir if (prepared.src_dir and adapter.workdir == SRC_TARGET) else out_dir
        env = {
            k: os.environ[k]
            for k in ("PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG")
            if k in os.environ
        }
        env.update({"HOME": tempfile.gettempdir(), "USERPROFILE": tempfile.gettempdir()})
        env.update({k: v for k, v in adapter.env.items() if k != "HOME"})
        started = time.monotonic()
        try:
            done = exe.run(
                [executable, *command[1:]], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=self.timeout_s, check=False,
            )  # fmt: skip
        except subprocess.TimeoutExpired:
            return ExecOutcome(None, round(time.monotonic() - started, 3), True, False, "", "",
                               ("native", *command))  # fmt: skip
        return ExecOutcome(
            done.returncode,
            round(time.monotonic() - started, 3),
            False,
            False,
            done.stdout.decode("utf-8", "replace")[:65536],
            done.stderr.decode("utf-8", "replace")[:65536],
            ("native", *command),
        )


def image_exists(image: str, docker: str = "docker") -> bool:
    done = exe.run(
        [docker, "image", "inspect", image], capture_output=True, check=False,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    return done.returncode == 0


def list_managed_containers(name_filter: str = "", docker: str = "docker") -> list[str]:
    """Names of all secaudit-managed containers (running or not), optionally name-filtered."""
    argv = [docker, "ps", "-a", "--filter", "label=org.secaudit.managed=true"]
    if name_filter:
        argv += ["--filter", f"name={name_filter}"]
    argv += ["--format", "{{.Names}}"]
    done = exe.run(
        argv, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL
    )  # fmt: skip
    return [line for line in done.stdout.splitlines() if line.strip()]


STALE_AFTER_S = 24 * 3600  # guards against a recycled owner pid keeping a container alive forever


def pid_alive(pid: int) -> bool:
    """Is a process with this pid running? (posix: signal 0; Windows: OpenProcess)"""
    if pid <= 0:
        return False
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists, owned by someone else
        return True
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    process_query_limited_information, still_active, access_denied = 0x1000, 259, 5
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return ctypes.get_last_error() == access_denied or kernel32.GetLastError() == access_denied
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def reap_stale_containers(docker: str = "docker", *, now: float | None = None) -> list[str]:
    """Remove secaudit containers whose owning secaudit process is gone (or that are very old).

    Containers carry `org.secaudit.owner-pid` and `org.secaudit.started` labels. Best effort:
    never raises. Returns the names that were removed.
    """
    fmt = '{{.Names}}|{{.Label "org.secaudit.owner-pid"}}|{{.Label "org.secaudit.started"}}'
    try:
        done = exe.run(
            [docker, "ps", "-a", "--filter", "label=org.secaudit.managed=true", "--format", fmt],
            capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL, timeout=60,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return []
    current = now if now is not None else time.time()
    removed: list[str] = []
    for line in done.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3 or not parts[0]:
            continue
        name, pid_text, started_text = parts
        if not pid_text.isdigit():
            continue  # unlabelled (older) container: not ours to judge
        pid = int(pid_text)
        old = started_text.isdigit() and current - int(started_text) > STALE_AFTER_S
        if pid != os.getpid() and (old or not pid_alive(pid)):
            kill_container(name, docker=docker)
            removed.append(name)
    return removed
