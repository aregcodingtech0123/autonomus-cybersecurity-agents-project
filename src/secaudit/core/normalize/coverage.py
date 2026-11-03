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


def semgrep_coverage(
    doc: object, limitations: tuple[str, ...], source_files: list[str] | None = None
) -> ToolCoverage:
    """Semgrep's JSON lists `paths.scanned`. Its `paths.skipped` is absent in this output mode, so
    skipped files are derived: files that exist in the retained source tree but are NOT in `scanned`
    (this is how a >1 MB file Semgrep silently ignores becomes visible)."""
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        return unknown_coverage("semgrep", limitations, "semgrep JSON has no paths.scanned")
    scanned, _dropped = _paths(paths["scanned"])
    skipped: list[SkippedFile] = []
    listed = paths.get("skipped")
    if isinstance(listed, list):
        for entry in listed:
            if isinstance(entry, dict):
                path, _why = normalize_source_path(entry.get("path"))
                if path:
                    reason = entry.get("reason")
                    skipped.append(
                        SkippedFile(
                            path=path, reason=reason[:80] if isinstance(reason, str) else None
                        )
                    )
    elif source_files is not None:
        seen = set(scanned)
        skipped = [
            SkippedFile(path=p, reason="in the source tree but absent from semgrep paths.scanned")
            for p in sorted(set(source_files) - seen)[:MAX_FILES_LISTED]
        ]
    return ToolCoverage(
        tool="semgrep",
        status="known",
        analyzed_files=tuple(scanned),
        skipped_files=tuple(sorted(skipped, key=lambda s: s.path)[:MAX_FILES_LISTED])
        if (isinstance(listed, list) or source_files is not None)
        else None,
        limitations=limitations,
        note=None
        if (isinstance(listed, list) or source_files is not None)
        else "no source to diff against: skipped files unknown",
    )


def pip_audit_coverage(entry: dict, limitations: tuple[str, ...]) -> ToolCoverage:
    """pip-audit coverage is known from the manifest: files read, lines left unresolved."""
    files = tuple(sorted(f for f in entry.get("requirements_files", []) if isinstance(f, str)))
    if not files and not entry.get("pinned_requirements"):
        return unknown_coverage("pip-audit", limitations, "manifest lists no requirements files")
    unresolved = [
        SkippedFile(path=f"{u.get('file')}:{u.get('line')}", reason=str(u.get("reason"))[:60])
        for u in entry.get("unresolved", [])
        if isinstance(u, dict)
    ]
    return ToolCoverage(
        tool="pip-audit",
        status="known",
        analyzed_files=files,
        skipped_files=tuple(unresolved),
        limitations=limitations,
        note="exact pins only; skipped entries are requirement lines that were not audited",
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
