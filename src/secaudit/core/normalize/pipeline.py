"""normalize_audit(): raw artifacts + manifest + retained source -> Audit (findings included).

Inputs are untrusted: unreadable or malformed artifacts, hash mismatches and missing manifest fields
become WARNINGS on the Audit; nothing here raises on bad tool output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaudit.core.models import (
    Audit,
    AuditInput,
    SkippedResult,
    SourceInfo,
    ToolCoverage,
    ToolHit,
    ToolRun,
)
from secaudit.core.normalize.coverage import (
    bandit_coverage,
    load_optional_json,
    pip_audit_coverage,
    semgrep_coverage,
    unknown_coverage,
)
from secaudit.core.normalize.dedup import build_findings, collapse_identical
from secaudit.core.normalize.owasp import load_owasp_map
from secaudit.core.normalize.pip_audit import parse_pip_audit, pins_from_source
from secaudit.core.normalize.sarif import ParseResult, parse_sarif

ARTIFACTS = {
    "bandit": "bandit.sarif",
    "semgrep": "semgrep.sarif",
    "gitleaks": "gitleaks.sarif",
    "pip-audit": "pip-audit.json",
}
COVERAGE_ARTIFACTS = {"semgrep": "semgrep.json", "bandit": "bandit.json"}
DID_NOT_RUN = {"failed", "timeout", "skipped"}


def _str_list(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _source_files(source_root: Path | None, limit: int = 20_000) -> list[str] | None:
    """POSIX-relative files in the retained source tree (bounded), or None without source."""
    if source_root is None or not Path(source_root).is_dir():
        return None
    files: list[str] = []
    root = Path(source_root)
    for path in root.rglob("*"):
        if len(files) >= limit:
            break
        if path.is_file() and not path.is_symlink():
            files.append(path.relative_to(root).as_posix())
    return sorted(files)


def normalize_audit(
    raw_dir: Path,
    *,
    manifest: dict | None,
    source_root: Path | None,
) -> Audit:
    raw_dir = Path(raw_dir)
    warnings: list[str] = []
    manifest = manifest if isinstance(manifest, dict) else None
    manifest_tools = (
        manifest.get("tools", {}) if manifest and isinstance(manifest.get("tools"), dict) else {}
    )
    if manifest is None:
        warnings.append(
            "no manifest.json: tool versions, limitations and neutralized files are unknown"
        )
    else:
        for key in ("neutralized_files",):
            if key not in manifest:
                warnings.append(
                    f"manifest has no {key!r} (audit produced before the Phase 1 remediation)"
                )

    order = _str_list(manifest.get("tool_order")) if manifest else ()
    tools = [t for t in order if t in ARTIFACTS] or [
        t for t, f in ARTIFACTS.items() if (raw_dir / f).is_file()
    ]

    all_hits: list[ToolHit] = []
    skipped_all: list[SkippedResult] = []
    runs: list[ToolRun] = []
    coverage: list[ToolCoverage] = []
    for tool in tools:
        entry = manifest_tools.get(tool, {}) if isinstance(manifest_tools.get(tool), dict) else {}
        limitations = _str_list(entry.get("limitations"))
        if manifest and not limitations:
            warnings.append(f"{tool}: manifest declares no limitations (older audit)")
        status = entry.get("status", "completed") if manifest else "completed"
        filename = ARTIFACTS[tool]
        path = raw_dir / filename
        base = dict(
            tool=tool,
            version=entry.get("version") if isinstance(entry.get("version"), str) else None,
            pinned_version=entry.get("pinned_version")
            if isinstance(entry.get("pinned_version"), str)
            else None,
            exit_code=entry.get("exit_code") if isinstance(entry.get("exit_code"), int) else None,
            detail=str(entry.get("detail", ""))[:200],
            unresolved_requirements=tuple(
                u for u in entry.get("unresolved", []) if isinstance(u, dict)
            )
            if isinstance(entry.get("unresolved"), list)
            else (),
        )
        note = {
            "bandit": "bandit lists analysed files only in its JSON format; no second run is made",
            "gitleaks": "gitleaks does not report which files it scanned",
        }.get(tool, "tool does not report analysed files")
        coverage.append(unknown_coverage(tool, limitations, note))
        if status in DID_NOT_RUN or not path.is_file():
            if status not in DID_NOT_RUN:
                status = "missing"
            warnings.append(f"{tool}: no results read (status: {status})")
            runs.append(ToolRun(status=str(status)[:20], **base))
            continue
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        declared = entry.get("artifact_sha256")
        if isinstance(declared, str) and declared != sha:
            warnings.append(
                f"{tool}: artifact hash differs from the manifest (file modified after the scan?)"
            )
        try:
            doc = json.loads(data)
        except ValueError:
            warnings.append(f"{tool}: artifact is not valid JSON")
            runs.append(
                ToolRun(
                    status="unreadable", artifact=f"raw/{filename}", artifact_sha256=sha, **base
                )
            )
            continue
        artifact = f"raw/{filename}"
        version = base["version"]
        if tool == "pip-audit":
            pins = entry.get("pinned_requirements")
            pins = pins if isinstance(pins, list) and pins else pins_from_source(source_root)
            parsed: ParseResult = parse_pip_audit(
                doc, artifact=artifact, sha256=sha, tool_version=version, pins=pins
            )
        else:
            parsed = parse_sarif(tool, doc, artifact=artifact, sha256=sha, tool_version=version)
        unique, _collapsed = collapse_identical(parsed.hits)
        runs.append(
            ToolRun(
                status=str(status)[:20],
                artifact=artifact,
                artifact_sha256=sha,
                raw_results=parsed.raw_count,
                hits=len(parsed.hits),
                unique_hits=len(unique),
                skipped_results=len(parsed.skipped),
                **base,
            )
        )
        all_hits.extend(parsed.hits)
        skipped_all.extend(parsed.skipped)
        warnings.extend(parsed.warnings)
        extra = COVERAGE_ARTIFACTS.get(tool)
        if extra and (raw_dir / extra).is_file():
            cov_doc = load_optional_json(raw_dir / extra)
            if tool == "semgrep":
                coverage[-1] = semgrep_coverage(cov_doc, limitations, _source_files(source_root))
            else:
                coverage[-1] = bandit_coverage(cov_doc, limitations)
        if tool == "pip-audit" and entry:
            coverage[-1] = pip_audit_coverage(entry, limitations)

    gitleaks_lines: dict[str, set[int]] = {}
    for hit in all_hits:
        if hit.tool == "gitleaks":
            gitleaks_lines.setdefault(hit.file_path, set()).update(
                range(hit.line_start, hit.line_end + 1)
            )
    findings, finding_warnings, _ = build_findings(all_hits, source_root, gitleaks_lines)
    warnings.extend(w for w in finding_warnings if w not in warnings)
    if source_root is None:
        warnings.append(
            "no source available: snippets are omitted and fingerprints are location-based"
        )
    if any(f.fingerprint_basis == "location" for f in findings) and source_root is not None:
        warnings.append(
            "some findings could not be read from the source: location-based fingerprint"
        )

    owasp = load_owasp_map()
    unmapped = sorted(
        {c for f in findings for c in f.cwe_ids if owasp.category(c) is None},
        key=lambda c: int(c.split("-")[1]),
    )
    inp = manifest.get("input", {}) if manifest and isinstance(manifest.get("input"), dict) else {}
    src = manifest.get("source") if manifest and isinstance(manifest.get("source"), dict) else None
    injected = (
        _str_list(src.get("injected_files"))
        if src
        else _str_list(manifest.get("workspace_policy_files") if manifest else None)
    )
    return Audit(
        audit_id=manifest.get("audit_id")
        if manifest and isinstance(manifest.get("audit_id"), str)
        else None,
        secaudit_version=manifest.get("secaudit_version")
        if manifest and isinstance(manifest.get("secaudit_version"), str)
        else None,
        created_at=manifest.get("started_at")
        if manifest and isinstance(manifest.get("started_at"), str)
        else None,
        runner=manifest.get("runner")
        if manifest and isinstance(manifest.get("runner"), str)
        else None,
        input=AuditInput(
            **{k: inp.get(k) for k in AuditInput.model_fields if isinstance(inp.get(k), (str, int))}
        ),
        source=SourceInfo(
            retained=source_root is not None,
            path=src.get("path") if src and isinstance(src.get("path"), str) else None,
            injected_files=injected,
        ),
        neutralized_files=_str_list(manifest.get("neutralized_files")) if manifest else (),
        tool_runs=tuple(runs),
        coverage=tuple(coverage),
        warnings=tuple(dict.fromkeys(warnings)),
        skipped_results=tuple(skipped_all),
        unmapped_cwes=tuple(unmapped),
        findings=tuple(findings),
    )


def normalize_audit_dir(audit_dir: Path) -> Audit:
    """An audit directory as written by `secaudit scan`: manifest.json, raw/, optional source/."""
    audit_dir = Path(audit_dir)
    try:
        manifest = json.loads((audit_dir / "manifest.json").read_bytes())
    except (OSError, ValueError):
        manifest = None
    source = audit_dir / "source"
    return normalize_audit(
        audit_dir / "raw", manifest=manifest, source_root=source if source.is_dir() else None
    )


def export_json(audit: Audit) -> str:
    """Deterministic, versioned JSON export (field order is the model's)."""
    return audit.model_dump_json(indent=2) + "\n"
