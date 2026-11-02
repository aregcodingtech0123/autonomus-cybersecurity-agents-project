"""Adapter base class and the generic "run one adapter" procedure.

Adapters build commands and judge completion. They never parse or normalize findings:
the only thing inspected in a result file is that it is well-formed JSON/SARIF (Phase 2 does
the real parsing).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from secaudit.core.sandbox import NetworkPolicy, output_dir_mode

MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
STDERR_TAIL_CHARS = 2000


class AdapterUnavailable(RuntimeError):
    """The adapter cannot run in the current setup (e.g. no rules cache)."""


class ArtifactError(ValueError):
    """The tool's result file is missing or malformed."""


@dataclass(frozen=True)
class ToolPaths:
    """Where the tool should find its inputs/outputs: container paths or host paths."""

    src: str
    out: str
    rules: str | None
    sandboxed: bool
    sep: str = "/"

    def out_file(self, name: str) -> str:
        return f"{self.out}{self.sep}{name}"

    def rules_file(self, name: str) -> str:
        assert self.rules is not None  # noqa: S101
        return f"{self.rules}{self.sep}{name}"


@dataclass(frozen=True)
class Prepared:
    """Result of adapter.prepare(): what to mount, or why to skip."""

    src_dir: Path | None = None
    rules_dir: Path | None = None
    skip_reason: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ExecOutcome:
    exit_code: int | None
    duration_s: float
    timed_out: bool
    output_limit_exceeded: bool
    stdout: str
    stderr: str
    sandbox_command: tuple[str, ...]  # display form: host paths replaced by placeholders


class Executor(Protocol):
    kind: str

    def paths(self, prepared: Prepared, out_dir: Path) -> ToolPaths: ...

    def run(
        self,
        adapter: ScannerAdapter,
        prepared: Prepared,
        out_dir: Path,
        command: list[str],
        label: str,
    ) -> ExecOutcome: ...


@dataclass(frozen=True)
class RawScanResult:
    tool: str
    version: str  # version reported by the tool itself, else the pinned version
    pinned_version: str
    command: tuple[str, ...]
    exit_code: int | None
    raw_artifact_path: Path | None
    duration_s: float
    status: str  # completed | failed | timeout | skipped
    detail: str = ""
    artifact_sha256: str | None = None
    sandbox_command: tuple[str, ...] = ()
    network: str = "none"
    stderr_tail: str = ""
    extra: dict = field(default_factory=dict)


class ScannerAdapter:
    name: str
    version: str  # pinned
    output_filename: str
    artifact_kind: str  # "sarif" | "json"
    completed_exit_codes: frozenset[int] = frozenset({0, 1})
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    workdir: str = "/src"
    env: dict[str, str] = {"HOME": "/tmp"}  # noqa: RUF012 - read-only class constant

    @property
    def image(self) -> str:
        return f"secaudit/{self.name}:{self.version}"

    def prepare(self, workspace: Path, staging: Path) -> Prepared:
        return Prepared(src_dir=workspace)

    def build_command(self, paths: ToolPaths) -> list[str]:
        raise NotImplementedError

    def version_command(self) -> list[str]:
        return [self.name, "--version"]

    def parse_version(self, text: str) -> str | None:
        match = re.search(r"\d+\.\d+\.\d+", text)
        return match.group(0) if match else None

    def validate_artifact(self, data: bytes) -> None:
        try:
            doc = json.loads(data)
        except ValueError as exc:
            raise ArtifactError(f"result is not valid JSON: {exc}") from exc
        if self.artifact_kind == "sarif":
            if not (
                isinstance(doc, dict)
                and str(doc.get("version", "")).startswith("2.")
                and isinstance(doc.get("runs"), list)
            ):
                raise ArtifactError("result is not a SARIF 2.x document")
        elif not (isinstance(doc, dict) and isinstance(doc.get("dependencies"), list)):
            raise ArtifactError("result is not a pip-audit JSON document")


def _lstat_regular(path: Path) -> os.stat_result | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def run_adapter(
    adapter: ScannerAdapter,
    workspace: Path,
    *,
    work_dir: Path,
    raw_dir: Path,
    executor: Executor,
    label: str,
) -> RawScanResult:
    """Prepare, run and judge one adapter. Never raises for tool problems."""
    from secaudit.core.sandbox import SandboxError  # local: keeps imports light for adapters

    def result(status: str, detail: str = "", **kw) -> RawScanResult:
        return RawScanResult(
            tool=adapter.name,
            version=kw.pop("version", adapter.version),
            pinned_version=adapter.version,
            command=kw.pop("command", ()),
            exit_code=kw.pop("exit_code", None),
            raw_artifact_path=kw.pop("raw_artifact_path", None),
            duration_s=kw.pop("duration_s", 0.0),
            status=status,
            detail=detail,
            network=adapter.network_policy.value,
            **kw,
        )

    staging = work_dir / f"{adapter.name}-stage"
    out_dir = work_dir / f"{adapter.name}-out"
    staging.mkdir(parents=True)
    make_output_dir(out_dir)
    try:
        prepared = adapter.prepare(workspace, staging)
    except AdapterUnavailable as exc:
        return result("failed", f"unavailable: {exc}")
    if prepared.skip_reason:
        return result("skipped", prepared.skip_reason, extra=prepared.extra)

    try:
        reported = _probe_version(adapter, executor, work_dir, label)
        command = adapter.build_command(executor.paths(prepared, out_dir))
        outcome = executor.run(adapter, prepared, out_dir, command, label)
    except SandboxError as exc:
        return result("failed", f"sandbox policy violation: {exc}", extra=prepared.extra)
    except OSError as exc:
        return result("failed", f"could not start tool: {exc}", extra=prepared.extra)

    common = {
        "version": reported or adapter.version,
        "command": tuple(command),
        "exit_code": outcome.exit_code,
        "duration_s": outcome.duration_s,
        "sandbox_command": outcome.sandbox_command,
        "stderr_tail": outcome.stderr[-STDERR_TAIL_CHARS:],
        "extra": {**prepared.extra, **_version_note(adapter, reported)},
    }
    if outcome.timed_out:
        return result("timeout", "wall-clock timeout; container killed", **common)
    if outcome.output_limit_exceeded:
        return result("failed", "tool flooded its output stream; container killed", **common)
    if outcome.exit_code not in adapter.completed_exit_codes:
        return result("failed", f"exit code {outcome.exit_code} is not a completed state", **common)

    source = out_dir / adapter.output_filename
    st = _lstat_regular(source)
    if st is None:
        return result("failed", "no regular result file was produced", **common)
    if st.st_size > MAX_ARTIFACT_BYTES:
        return result("failed", f"result file larger than {MAX_ARTIFACT_BYTES} bytes", **common)
    data = source.read_bytes()
    try:
        adapter.validate_artifact(data)
    except ArtifactError as exc:
        return result("failed", str(exc), **common)
    raw_dir.mkdir(parents=True, exist_ok=True)
    destination = raw_dir / adapter.output_filename
    shutil.copyfile(source, destination)
    make_private(destination)
    return result(
        "completed",
        raw_artifact_path=destination,
        artifact_sha256=hashlib.sha256(data).hexdigest(),
        **common,
    )


def _version_note(adapter: ScannerAdapter, reported: str | None) -> dict:
    if reported is None:
        return {"version_check": "tool did not report a parsable version"}
    if reported != adapter.version:
        return {"version_check": f"MISMATCH: pinned {adapter.version}, tool reports {reported}"}
    return {}


def _probe_version(
    adapter: ScannerAdapter, executor: Executor, work_dir: Path, label: str
) -> str | None:
    probe_out = work_dir / f"{adapter.name}-version"
    make_output_dir(probe_out)
    outcome = executor.run(
        adapter, Prepared(), probe_out, adapter.version_command(), f"{label}-ver"
    )
    if outcome.exit_code != 0 or outcome.timed_out:
        return None
    return adapter.parse_version(outcome.stdout + "\n" + outcome.stderr)


def make_private(path: Path) -> None:
    """Owner-only permissions (0700 dir / 0600 file) on POSIX; chmod only, bytes untouched.

    Raw scanner outputs are SECRET-BEARING (Bandit embeds source lines verbatim). Windows has no
    stdlib equivalent, so nothing is applied there (documented, not faked).
    """
    if os.name == "posix":
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def make_output_dir(path: Path) -> None:
    """Create a per-tool output directory the unprivileged container user can write to."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, output_dir_mode())
