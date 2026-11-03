"""The boundary between the pydantic core models and the ORM rows (conversion both ways).

`core/models.py` never imports the ORM; this module is where an `Audit` becomes rows and back, so a
move to another database is a driver change, not a model change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secaudit.core.models import (
    Audit,
    AuditInput,
    Confidence,
    RawRef,
    SecurityFinding,
    Severity,
    SkippedResult,
    SourceInfo,
    ToolCoverage,
    ToolHit,
    ToolRun,
)
from secaudit.store.orm import AuditRow, FindingHitRow, FindingRow, RawArtifactRow, ToolRunRow


@dataclass(frozen=True)
class ArtifactRecord:
    """A raw artifact whose sha256 was verified against the manifest."""

    tool: str
    path: str
    sha256: str
    size_bytes: int | None
    kind: str  # "primary" | "extra"


@dataclass(frozen=True)
class IngestRecord:
    """Facts about the ingest itself (not part of the normalized Audit)."""

    findings_sha256: str
    manifest_sha256: str
    ingested_at: str
    artifacts: tuple[ArtifactRecord, ...] = ()


@dataclass
class AuditRows:
    audit: AuditRow
    tool_runs: list[ToolRunRow] = field(default_factory=list)
    artifacts: list[RawArtifactRow] = field(default_factory=list)
    findings: list[FindingRow] = field(default_factory=list)
    hits: list[FindingHitRow] = field(default_factory=list)


def audit_to_rows(audit: Audit, record: IngestRecord) -> AuditRows:
    if not audit.audit_id:
        raise ValueError("an audit without an audit_id cannot be stored")
    aid = audit.audit_id
    rows = AuditRows(
        audit=AuditRow(
            audit_id=aid,
            schema_version=audit.schema_version,
            secaudit_version=audit.secaudit_version,
            created_at=audit.created_at,
            runner=audit.runner,
            input_kind=audit.input.kind,
            input_source=audit.input.source,
            input_sha256=audit.input.sha256,
            input_file_count=audit.input.file_count,
            input_total_bytes=audit.input.total_bytes,
            input_commit=audit.input.commit,
            source_retained_at_scan=audit.source.retained_at_scan,
            source_committed=audit.source.committed,
            source_available=audit.source.available,
            source_path=audit.source.path,
            injected_files=list(audit.source.injected_files),
            neutralized_files=list(audit.neutralized_files),
            warnings=list(audit.warnings),
            skipped_results=[s.model_dump(mode="json") for s in audit.skipped_results],
            unmapped_cwes=list(audit.unmapped_cwes),
            coverage=[c.model_dump(mode="json") for c in audit.coverage],
            findings_sha256=record.findings_sha256,
            manifest_sha256=record.manifest_sha256,
            ingested_at=record.ingested_at,
        )
    )
    for position, run in enumerate(audit.tool_runs):
        data = run.model_dump(mode="json")
        rows.tool_runs.append(ToolRunRow(audit_id=aid, position=position, **data))
    for art in record.artifacts:
        rows.artifacts.append(
            RawArtifactRow(
                audit_id=aid,
                path=art.path,
                tool=art.tool,
                kind=art.kind,
                sha256=art.sha256,
                size_bytes=art.size_bytes,
            )
        )
    seen: dict[str, int] = {}
    for position, finding in enumerate(audit.findings):
        ordinal = seen.get(finding.fingerprint, 0)
        seen[finding.fingerprint] = ordinal + 1
        rows.findings.append(
            FindingRow(
                audit_id=aid,
                id=finding.id,
                position=position,
                fingerprint=finding.fingerprint,
                ordinal=ordinal,
                fingerprint_basis=finding.fingerprint_basis,
                title=finding.title,
                issue_class=finding.issue_class,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                cwe_ids=list(finding.cwe_ids),
                owasp_2025=finding.owasp_2025,
                severity=finding.severity.value,
                severity_basis=finding.severity_basis,
                confidence=finding.confidence.value,
                snippet=finding.snippet,
                is_test_path=finding.is_test_path,
                aliases=list(finding.aliases),
                fix_versions=list(finding.fix_versions),
                status=finding.status,
            )
        )
        for hit_position, hit in enumerate(finding.hits):
            rows.hits.append(
                FindingHitRow(
                    audit_id=aid,
                    finding_id=finding.id,
                    position=hit_position,
                    tool=hit.tool,
                    tool_version=hit.tool_version,
                    rule_id=hit.rule_id,
                    rule_name=hit.rule_name,
                    raw_severity=hit.raw_severity,
                    confidence=hit.confidence.value,
                    message=hit.message,
                    file_path=hit.file_path,
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    cwe_ids=list(hit.cwe_ids),
                    aliases=list(hit.aliases),
                    fix_versions=list(hit.fix_versions),
                    package=hit.package,
                    package_version=hit.package_version,
                    raw_artifact=hit.raw_ref.artifact,
                    raw_artifact_sha256=hit.raw_ref.artifact_sha256,
                    raw_pointer=hit.raw_ref.pointer,
                )
            )
    return rows


def hit_from_row(row: FindingHitRow) -> ToolHit:
    return ToolHit(
        tool=row.tool,
        tool_version=row.tool_version,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        raw_severity=row.raw_severity,
        confidence=Confidence(row.confidence),
        message=row.message,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        cwe_ids=tuple(row.cwe_ids),
        aliases=tuple(row.aliases),
        fix_versions=tuple(row.fix_versions),
        package=row.package,
        package_version=row.package_version,
        raw_ref=RawRef(
            artifact=row.raw_artifact,
            artifact_sha256=row.raw_artifact_sha256,
            pointer=row.raw_pointer,
        ),
    )


def finding_from_row(row: FindingRow, hits: list[FindingHitRow]) -> SecurityFinding:
    return SecurityFinding(
        id=row.id,
        fingerprint=row.fingerprint,
        fingerprint_basis=row.fingerprint_basis,
        title=row.title,
        issue_class=row.issue_class,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        hits=tuple(hit_from_row(h) for h in sorted(hits, key=lambda h: h.position)),
        cwe_ids=tuple(row.cwe_ids),
        owasp_2025=row.owasp_2025,
        severity=Severity(row.severity),
        severity_basis=row.severity_basis,
        confidence=Confidence(row.confidence),
        snippet=row.snippet,
        is_test_path=row.is_test_path,
        aliases=tuple(row.aliases),
        fix_versions=tuple(row.fix_versions),
        status=row.status,
    )


def rows_to_audit(rows: AuditRows) -> Audit:
    a = rows.audit
    hits_by_finding: dict[str, list[FindingHitRow]] = {}
    for hit in rows.hits:
        hits_by_finding.setdefault(hit.finding_id, []).append(hit)
    runs = []
    for run in sorted(rows.tool_runs, key=lambda r: r.position):
        runs.append(
            ToolRun(
                tool=run.tool,
                status=run.status,
                version=run.version,
                pinned_version=run.pinned_version,
                exit_code=run.exit_code,
                artifact=run.artifact,
                artifact_sha256=run.artifact_sha256,
                raw_results=run.raw_results,
                hits=run.hits,
                unique_hits=run.unique_hits,
                skipped_results=run.skipped_results,
                detail=run.detail,
                unresolved_requirements=tuple(run.unresolved_requirements),
            )
        )
    return Audit(
        schema_version=a.schema_version,
        audit_id=a.audit_id,
        secaudit_version=a.secaudit_version,
        created_at=a.created_at,
        runner=a.runner,
        input=AuditInput(
            kind=a.input_kind,
            source=a.input_source,
            sha256=a.input_sha256,
            file_count=a.input_file_count,
            total_bytes=a.input_total_bytes,
            commit=a.input_commit,
        ),
        source=SourceInfo(
            retained_at_scan=a.source_retained_at_scan,
            committed=a.source_committed,
            available=a.source_available,
            path=a.source_path,
            injected_files=tuple(a.injected_files),
        ),
        neutralized_files=tuple(a.neutralized_files),
        tool_runs=tuple(runs),
        coverage=tuple(ToolCoverage.model_validate(c) for c in a.coverage),
        warnings=tuple(a.warnings),
        skipped_results=tuple(SkippedResult.model_validate(s) for s in a.skipped_results),
        unmapped_cwes=tuple(a.unmapped_cwes),
        findings=tuple(
            finding_from_row(f, hits_by_finding.get(f.id, []))
            for f in sorted(rows.findings, key=lambda f: f.position)
        ),
    )
