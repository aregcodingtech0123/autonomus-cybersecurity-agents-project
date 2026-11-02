"""Scan orchestration: intake -> run adapters -> audit directory with manifest.json.

A failing tool never aborts the others; its status goes into the manifest. The temporary
workspace and any containers are always cleaned up, even on failure or timeout.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from secaudit import __version__
from secaudit.core import exe
from secaudit.core.executors import (
    DockerExecutor,
    NativeExecutor,
    image_exists,
    list_managed_containers,
)
from secaudit.core.intake import DEFAULT_LIMITS, IntakeLimits, IntakeResult, intake, remove_tree
from secaudit.core.neutralize import neutralize_workspace
from secaudit.core.rules import RulesCache, RulesError, load_rules_cache
from secaudit.core.sandbox import ResourceLimits, docker_available, kill_container
from secaudit.core.scanners import (
    TOOL_NAMES,
    RawScanResult,
    ScannerAdapter,
    build_adapters,
    run_adapter,
)
from secaudit.core.scanners.base import Executor, make_private
from secaudit.core.scanners.semgrep import SEMGREPIGNORE_NAME

MANIFEST_SCHEMA_VERSION = 1


class ScanEnvironmentError(RuntimeError):
    """The environment cannot run the requested scan (Docker down, image missing, ...)."""


@dataclass(frozen=True)
class ScanOptions:
    out_root: Path
    tools: tuple[str, ...] = TOOL_NAMES
    runner: str = "docker"  # "docker" | "native"
    limits: IntakeLimits = DEFAULT_LIMITS
    include_git: bool = False
    rules_dir: Path | None = None
    resource_limits: ResourceLimits = ResourceLimits()
    docker: str = "docker"


@dataclass
class ScanOutcome:
    audit_dir: Path
    manifest: dict
    results: list[RawScanResult] = field(default_factory=list)

    @property
    def tools_ok(self) -> bool:
        return all(r.status in ("completed", "skipped") for r in self.results)


def preflight(options: ScanOptions, adapters: list[ScannerAdapter]) -> None:
    """Fail early and clearly when the Docker runner cannot work."""
    if options.runner != "docker":
        return
    ok, detail = docker_available(options.docker)
    if not ok:
        raise ScanEnvironmentError(
            f"Docker daemon is not reachable ({detail}). Start Docker Desktop and retry, "
            "or use --runner native with --i-trust-this-code for trusted code."
        )
    missing = [a.image for a in adapters if not image_exists(a.image, options.docker)]
    if missing:
        raise ScanEnvironmentError(
            f"scanner image(s) not built: {', '.join(missing)}. Run `secaudit build-images`."
        )


def _new_audit_id() -> str:
    return f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"


def _display_source(source: str, kind: str) -> str:
    return source if kind == "git" else Path(source).name


def build_manifest(
    *,
    audit_id: str,
    started_at: str,
    finished_at: str,
    runner: str,
    source: str,
    intake_result: IntakeResult,
    results: list[RawScanResult],
    audit_dir: Path,
    neutralized_files: list[str] | None = None,
) -> dict:
    """Assemble manifest.json content. All paths are POSIX-style and relative to the audit dir."""
    tools: dict[str, dict] = {}
    for r in results:
        extra = dict(r.extra)
        entry = {
            "status": r.status,
            "detail": r.detail,
            "pinned_version": r.pinned_version,
            "version": r.version,
            "command": list(r.command),
            "sandbox_command": list(r.sandbox_command),
            "network": r.network,
            "exit_code": r.exit_code,
            "duration_s": r.duration_s,
            "artifact": (
                r.raw_artifact_path.relative_to(audit_dir).as_posix()
                if r.raw_artifact_path
                else None
            ),
            "artifact_sha256": r.artifact_sha256,
        }
        if r.status != "completed" and r.stderr_tail:
            entry["stderr_tail"] = r.stderr_tail
        for key in (
            "rules",
            "requirements_files",
            "pinned_requirements",
            "unresolved",
            "version_check",
        ):
            if key in extra:
                entry[{"rules": "ruleset_info"}.get(key, key)] = extra[key]
        tools[r.tool] = entry
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "audit_id": audit_id,
        "secaudit_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "runner": runner,
        "input": {
            "kind": intake_result.kind,
            "source": _display_source(source, intake_result.kind),
            "sha256": intake_result.input_sha256,
            "file_count": intake_result.file_count,
            "total_bytes": intake_result.total_bytes,
            "commit": intake_result.commit,
            "skipped_entries": list(intake_result.skipped),
        },
        "workspace_policy_files": [SEMGREPIGNORE_NAME],
        "neutralized_files": list(neutralized_files or []),
        "tool_order": [r.tool for r in results],
        "tools": tools,
        "summary": {
            "completed": sum(r.status == "completed" for r in results),
            "skipped": sum(r.status == "skipped" for r in results),
            "failed": sum(r.status in ("failed", "timeout") for r in results),
        },
    }


def run_scan(
    source: str,
    options: ScanOptions,
    *,
    executor: Executor | None = None,
    rules: RulesCache | None = None,
) -> ScanOutcome:
    """Run a full audit. Raises IntakeError for rejected input; tool problems go in the manifest."""
    audit_id = _new_audit_id()
    short = audit_id.rsplit("-", 1)[1]
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    temp_root = Path(tempfile.mkdtemp(prefix="secaudit-"))
    executor = executor or (
        DockerExecutor(
            limits=options.resource_limits, docker=options.docker, name_prefix=f"{short}-"
        )
        if options.runner == "docker"
        else NativeExecutor(timeout_s=options.resource_limits.timeout_s)
    )
    try:
        wanted_rules = "semgrep" in options.tools
        if rules is None and wanted_rules:
            try:
                rules = load_rules_cache(options.rules_dir)
            except RulesError:
                rules = None  # the adapter reports "unavailable" with a clear instruction
        adapters = build_adapters(options.tools, rules)
        if executor.kind == "docker":
            preflight(options, adapters)

        if os.path.exists(source):
            exe.forbid(source)  # programs inside the scanned input are never run
        intake_result = intake(
            source,
            limits=options.limits,
            workspace_parent=temp_root / "ws",
            include_git=options.include_git,
        )
        exe.forbid(intake_result.workspace)
        neutralized_files = neutralize_workspace(intake_result.workspace)

        audit_dir = options.out_root / audit_id
        raw_dir = audit_dir / "raw"
        raw_dir.mkdir(parents=True)
        make_private(audit_dir)
        make_private(raw_dir)
        work_dir = temp_root / "work"
        work_dir.mkdir()

        results: list[RawScanResult] = []
        for adapter in adapters:
            try:
                results.append(
                    run_adapter(
                        adapter,
                        intake_result.workspace,
                        work_dir=work_dir,
                        raw_dir=raw_dir,
                        executor=executor,
                        label=adapter.name,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one tool must never abort the others
                results.append(
                    RawScanResult(
                        tool=adapter.name,
                        version=adapter.version,
                        pinned_version=adapter.version,
                        command=(),
                        exit_code=None,
                        raw_artifact_path=None,
                        duration_s=0.0,
                        status="failed",
                        detail=f"unexpected error: {type(exc).__name__}",
                        network=adapter.network_policy.value,
                    )
                )
        manifest = build_manifest(
            audit_id=audit_id,
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
            runner=executor.kind,
            source=source,
            intake_result=intake_result,
            results=results,
            audit_dir=audit_dir,
            neutralized_files=neutralized_files,
        )
        (audit_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        make_private(audit_dir / "manifest.json")
        return ScanOutcome(audit_dir, manifest, results)
    finally:
        remove_tree(temp_root)
        if executor.kind == "docker":
            _sweep_containers(f"secaudit-{short}-", options.docker)


def _sweep_containers(name_prefix: str, docker: str) -> None:
    """Belt and braces: remove any container of this audit that is somehow still around."""
    try:
        for name in list_managed_containers(name_prefix, docker):
            kill_container(name, docker=docker)
    except Exception:  # noqa: BLE001, S110 - cleanup must never mask the real outcome
        pass
