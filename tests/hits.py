"""Tiny file+line lookups over raw scanner output (test helper; NOT finding normalization)."""

from __future__ import annotations

import json
import re
from pathlib import Path

Hit = tuple[str, int, int]  # (posix file path, start line, end line)


def _clean(uri: str) -> str:
    path = uri.replace("\\", "/")
    for prefix in ("file:///src/", "/src/", "./"):
        if path.startswith(prefix):
            path = path[len(prefix) :]
    return path


def sarif_hits(path: Path) -> list[Hit]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    hits: list[Hit] = []
    for run in doc["runs"]:
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                physical = loc["physicalLocation"]
                region = physical.get("region", {})
                start = region.get("startLine", 1)
                hits.append(
                    (
                        _clean(physical["artifactLocation"]["uri"]),
                        start,
                        region.get("endLine", start),
                    )
                )
    return hits


def pip_audit_hits(
    path: Path, requirements_text: str, requirements_file: str = "requirements.txt"
) -> list[Hit]:
    """pip-audit has no locations: map each vulnerable package to its pin line in requirements."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    vulnerable = {
        d["name"].lower().replace("_", "-") for d in doc["dependencies"] if d.get("vulns")
    }
    hits: list[Hit] = []
    for number, line in enumerate(requirements_text.splitlines(), start=1):
        match = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==", line)
        if match and match.group(1).lower().replace("_", "-") in vulnerable:
            hits.append((requirements_file, number, number))
    return hits


def tool_hits(tool: str, raw_dir: Path, requirements_text: str) -> list[Hit]:
    if tool == "pip-audit":
        return pip_audit_hits(raw_dir / "pip-audit.json", requirements_text)
    return sarif_hits(raw_dir / f"{tool}.sarif")


def overlaps(hits: list[Hit], file: str, start: int, end: int) -> bool:
    return any(f == file and s <= end and e >= start for f, s, e in hits)
