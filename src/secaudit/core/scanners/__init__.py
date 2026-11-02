"""Scanner adapters (Phase 1: run tools and collect raw results; no normalization)."""

from secaudit.core.rules import RulesCache
from secaudit.core.scanners.bandit import BanditAdapter
from secaudit.core.scanners.base import (
    AdapterUnavailable,
    ArtifactError,
    ExecOutcome,
    Executor,
    Prepared,
    RawScanResult,
    ScannerAdapter,
    ToolPaths,
    run_adapter,
)
from secaudit.core.scanners.gitleaks import GitleaksAdapter
from secaudit.core.scanners.pip_audit import PipAuditAdapter
from secaudit.core.scanners.semgrep import SemgrepAdapter

TOOL_NAMES = ("bandit", "semgrep", "gitleaks", "pip-audit")


def build_adapters(names: tuple[str, ...], rules: RulesCache | None) -> list[ScannerAdapter]:
    registry: dict[str, ScannerAdapter] = {
        "bandit": BanditAdapter(),
        "semgrep": SemgrepAdapter(rules),
        "gitleaks": GitleaksAdapter(),
        "pip-audit": PipAuditAdapter(),
    }
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(
            f"unknown tool(s): {', '.join(unknown)}; choose from {', '.join(TOOL_NAMES)}"
        )
    return [registry[n] for n in names]


__all__ = [
    "TOOL_NAMES",
    "AdapterUnavailable",
    "ArtifactError",
    "BanditAdapter",
    "ExecOutcome",
    "Executor",
    "GitleaksAdapter",
    "PipAuditAdapter",
    "Prepared",
    "RawScanResult",
    "ScannerAdapter",
    "SemgrepAdapter",
    "ToolPaths",
    "build_adapters",
    "run_adapter",
]
