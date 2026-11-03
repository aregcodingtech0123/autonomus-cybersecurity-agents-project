"""Test doubles shared by adapter, orchestration and CLI tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from secaudit.core.rules import RulesCache
from secaudit.core.scanners.base import ExecOutcome, Prepared, ScannerAdapter, ToolPaths

SARIF = json.dumps(
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}
)
PIP_AUDIT_JSON = json.dumps({"dependencies": [], "fixes": []})


@dataclass
class Behaviour:
    exit_code: int | None = 1
    write: bytes | None = None  # bytes to write as the tool's output file; None = write nothing
    timed_out: bool = False
    flood: bool = False
    raises: Exception | None = None
    reported_version: str | None = None  # what `--version` prints; None = pinned
    extra: dict[str, bytes] | None = None  # additional output files to write next to the main one


@dataclass
class FakeExecutor:
    kind: str = "fake"
    behaviours: dict[str, Behaviour] = field(default_factory=dict)
    calls: list[tuple[str, list[str]]] = field(default_factory=list)
    seen_workspaces: dict[str, Path] = field(default_factory=dict)

    def paths(self, prepared: Prepared, out_dir: Path) -> ToolPaths:
        return ToolPaths(
            src="/src", out=out_dir.as_posix(), rules="/rules" if prepared.rules_dir else None,
            sandboxed=True,
        )  # fmt: skip

    def run(
        self,
        adapter: ScannerAdapter,
        prepared: Prepared,
        out_dir: Path,
        command: list[str],
        label: str,
    ) -> ExecOutcome:
        self.calls.append((adapter.name, list(command)))
        if command == adapter.version_command():
            behaviour = self.behaviours.get(adapter.name, Behaviour())
            version = behaviour.reported_version or adapter.version
            return ExecOutcome(0, 0.0, False, False, f"{adapter.name} {version}\n", "", ("fake",))
        behaviour = self.behaviours.get(adapter.name)
        if behaviour is None:
            behaviour = Behaviour(
                exit_code=1,
                write=(PIP_AUDIT_JSON if adapter.artifact_kind == "json" else SARIF).encode(),
            )
        if behaviour.raises:
            raise behaviour.raises
        if prepared.src_dir is not None:
            self.seen_workspaces[adapter.name] = prepared.src_dir
        if behaviour.write is not None:
            (out_dir / adapter.output_filename).write_bytes(behaviour.write)
        for name, data in (behaviour.extra or {}).items():
            (out_dir / name).write_bytes(data)
        return ExecOutcome(
            None if behaviour.timed_out else behaviour.exit_code,
            0.01,
            behaviour.timed_out,
            behaviour.flood,
            "",
            "boom: something went wrong" if behaviour.exit_code not in (0, 1) else "",
            ("fake", *command),
        )


def fake_rules(tmp_path: Path) -> RulesCache:
    snapshot = tmp_path / "rules-snapshot"
    snapshot.mkdir(exist_ok=True)
    entries = tuple(
        {
            "ruleset": f"p/{n}",
            "url": f"https://x/{n}",
            "file": f"p-{n}.yaml",
            "sha256": "0" * 64,
            "bytes": 1,
        }
        for n in ("python", "flask")
    )
    return RulesCache(snapshot, "20260101T000000Z", "2026-01-01T00:00:00+00:00", entries)
