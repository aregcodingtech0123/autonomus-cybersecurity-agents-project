"""pip-audit JSON reader. pip-audit has no line numbers: each vulnerable package is located through
the exact pin recorded in manifest.json (`pinned_requirements`) or, without a manifest, parsed from
the requirements files of the retained source. The vulnerability `description` (free text from an
advisory database) is never copied; only ids, aliases and fix versions are."""

from __future__ import annotations

import re
from pathlib import Path

from secaudit.core.models import RawRef, SkippedResult, ToolHit
from secaudit.core.normalize.masking import mask_message, sanitize
from secaudit.core.normalize.paths import normalize_source_path
from secaudit.core.normalize.sarif import ParseResult, _dict, _list, _text
from secaudit.core.scanners.pip_audit import find_requirements_files, parse_requirements


def canonical_name(name: str) -> str:
    """PEP 503 normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pins_from_source(source_root: Path | None) -> list[dict]:
    """Fallback when no manifest is available: parse requirements files in the retained source."""
    if source_root is None or not source_root.is_dir():
        return []
    texts: dict[str, str] = {}
    for path in find_requirements_files(source_root):
        try:
            texts[path.relative_to(source_root).as_posix()] = path.read_text(
                "utf-8", errors="replace"
            )
        except OSError:
            continue
    return parse_requirements(texts)[0]


def _strings(value: object, limit: int = 80) -> tuple[str, ...]:
    return tuple(sorted({s for v in _list(value) if (s := _text(v, limit))}))


def parse_pip_audit(
    doc: object, *, artifact: str, sha256: str, tool_version: str | None, pins: list[dict]
) -> ParseResult:
    out = ParseResult()
    if not isinstance(doc, dict) or not isinstance(doc.get("dependencies"), list):
        out.warnings.append("pip-audit: artifact is not a pip-audit JSON document")
        return out
    index: dict[tuple[str, str], list[dict]] = {}
    for pin in pins:
        if (
            isinstance(pin, dict)
            and isinstance(pin.get("name"), str)
            and isinstance(pin.get("version"), str)
        ):
            index.setdefault((canonical_name(pin["name"]), pin["version"]), []).append(pin)
    extra_locations = 0
    skipped_deps = 0
    for d_index, dep in enumerate(doc["dependencies"]):
        dep = _dict(dep)
        name, version = _text(dep.get("name"), 100), _text(dep.get("version"), 60)
        if dep.get("skip_reason"):
            skipped_deps += 1
        for v_index, vuln in enumerate(_list(dep.get("vulns"))):
            pointer = f"/dependencies/{d_index}/vulns/{v_index}"
            out.raw_count += 1
            try:
                vuln = _dict(vuln)
                vuln_id = _text(vuln.get("id"), 120)
                if not (name and version and vuln_id):
                    raise ValueError("missing name, version or id")
                located = sorted(
                    index.get((canonical_name(name), version), []),
                    key=lambda p: (str(p.get("file")), int(p.get("line", 0))),
                )
                if not located:
                    out.skipped.append(
                        SkippedResult(
                            tool="pip-audit", pointer=pointer, reason="no_requirement_line"
                        )
                    )
                    continue
                extra_locations += len(located) - 1
                path, why = normalize_source_path(located[0].get("file"))
                line = located[0].get("line")
                if path is None or not isinstance(line, int) or line < 1:
                    out.skipped.append(
                        SkippedResult(
                            tool="pip-audit", pointer=pointer, reason=why or "bad_pin_line"
                        )
                    )
                    continue
                aliases = tuple(sorted(set(_strings(vuln.get("aliases"))) | {vuln_id}))
                fixes = _strings(vuln.get("fix_versions"), 60)
                text = f"{name} {version} is affected by {vuln_id}" + (
                    f"; fixed in {', '.join(fixes)}" if fixes else ""
                )
                out.hits.append(
                    ToolHit(
                        tool="pip-audit",
                        tool_version=tool_version,
                        rule_id=vuln_id,
                        rule_name=mask_message(f"Known vulnerability in {name}", 200),
                        raw_severity=None,
                        message=mask_message(text),
                        file_path=path,
                        line_start=line,
                        line_end=line,
                        cwe_ids=(),
                        aliases=aliases,
                        fix_versions=fixes,
                        package=name,
                        package_version=version,
                        raw_ref=RawRef(artifact=artifact, artifact_sha256=sha256, pointer=pointer),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - hostile input must never crash normalization
                out.skipped.append(
                    SkippedResult(
                        tool="pip-audit",
                        pointer=pointer,
                        reason=f"malformed_result:{type(exc).__name__}",
                    )
                )
    if extra_locations:
        out.warnings.append(
            f"pip-audit: {extra_locations} vulnerable pin(s) also appear on other requirement "
            "lines (the first is used)"
        )
    if skipped_deps:
        out.warnings.append(
            f"pip-audit: {skipped_deps} dependency(ies) were skipped by pip-audit itself"
        )
    if any(r.reason == "no_requirement_line" for r in out.skipped):
        out.warnings.append(
            "pip-audit: some vulnerable packages could not be located in a requirements file"
        )
    return out


__all__ = ["canonical_name", "parse_pip_audit", "pins_from_source", "sanitize"]
