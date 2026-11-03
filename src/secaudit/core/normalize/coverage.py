"""Coverage model: what did each tool actually look at?

A tool that does not report its analysed/skipped files gets an explicit `unknown`, never a guessed
"complete". Declared limitations from manifest.json are always carried along. Optional coverage
artifacts (Semgrep `--json-output`, Bandit JSON) are read when the scan produced them.
"""

from __future__ import annotations

import json
from pathlib import Path

from secaudit.core.models import SkippedFile, ToolCoverage
from secaudit.core.normalize.paths import normalize_source_path

MAX_FILES_LISTED = 5000


def _paths(values: object) -> tuple[list[str], int]:
    good: list[str] = []
    dropped = 0
    for value in values if isinstance(values, list) else []:
        path, _why = normalize_source_path(value if isinstance(value, str) else None)
        if path is None:
            dropped += 1
        else:
            good.append(path)
    return sorted(set(good))[:MAX_FILES_LISTED], dropped


def semgrep_coverage(doc: object, limitations: tuple[str, ...]) -> ToolCoverage:
    """Semgrep's JSON output lists `paths.scanned` and `paths.skipped` (with reasons)."""
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        return unknown_coverage("semgrep", limitations, "semgrep JSON has no paths.scanned")
    scanned, _dropped = _paths(paths["scanned"])
    skipped: list[SkippedFile] = []
    for entry in paths.get("skipped") or []:
        if isinstance(entry, dict):
            path, _why = normalize_source_path(entry.get("path"))
            if path:
                reason = entry.get("reason")
                skipped.append(
                    SkippedFile(path=path, reason=reason[:80] if isinstance(reason, str) else None)
                )
    return ToolCoverage(
        tool="semgrep",
        status="known",
        analyzed_files=tuple(scanned),
        skipped_files=tuple(sorted(skipped, key=lambda s: s.path)[:MAX_FILES_LISTED]),
        limitations=limitations,
    )


def bandit_coverage(doc: object, limitations: tuple[str, ...]) -> ToolCoverage:
    """Bandit's JSON `metrics` has one entry per analysed file; `errors` lists files it skipped."""
    if not isinstance(doc, dict) or not isinstance(doc.get("metrics"), dict):
        return unknown_coverage("bandit", limitations, "bandit JSON has no metrics")
    analysed, _d = _paths([k for k in doc["metrics"] if k != "_totals"])
    skipped: list[SkippedFile] = []
    for err in doc.get("errors") or []:
        if isinstance(err, dict):
            path, _why = normalize_source_path(err.get("filename"))
            if path:
                reason = err.get("reason")
                skipped.append(
                    SkippedFile(path=path, reason=reason[:80] if isinstance(reason, str) else None)
                )
    return ToolCoverage(
        tool="bandit",
        status="known",
        analyzed_files=tuple(analysed),
        skipped_files=tuple(sorted(skipped, key=lambda s: s.path)),
        limitations=limitations,
    )


def unknown_coverage(tool: str, limitations: tuple[str, ...], note: str) -> ToolCoverage:
    return ToolCoverage(tool=tool, status="unknown", limitations=limitations, note=note)


def load_optional_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
