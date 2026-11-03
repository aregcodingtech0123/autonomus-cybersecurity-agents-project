"""Repository: the only code that talks to the database. Pydantic models in, pydantic models out.

Statements are built with the SQLAlchemy expression API, never by formatting strings. Every write
runs in one transaction that holds the write lock from the start (see db.write_engine); reads use
plain deferred transactions.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, delete, func
from sqlmodel import Session, select

from secaudit.core.models import Audit, SecurityFinding
from secaudit.store.convert import (
    AuditRows,
    IngestRecord,
    audit_to_rows,
    finding_from_row,
    rows_to_audit,
)
from secaudit.store.db import write_engine
from secaudit.store.orm import (
    AuditRow,
    FindingHitRow,
    FindingRow,
    RawArtifactRow,
    SchemaVersionRow,
    ToolRunRow,
)


class AuditConflictError(Exception):
    """The audit id is already stored with different content (and replace was not requested)."""


@dataclass(frozen=True)
class IngestResult:
    audit_id: str
    status: str  # "inserted" | "unchanged" | "replaced"
    findings: int
    hits: int


@dataclass(frozen=True)
class AuditSummary:
    audit_id: str
    created_at: str | None
    runner: str | None
    input_source: str | None
    findings: int
    ingested_at: str


@dataclass(frozen=True)
class FindingSummary:
    audit_id: str
    id: str
    severity: str
    issue_class: str
    title: str
    file_path: str
    line_start: int
    line_end: int
    owasp_2025: str | None
    is_test_path: bool
    tools: tuple[str, ...]


class Repository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # ---------------------------------------------------------------- writes

    def ingest(self, audit: Audit, record: IngestRecord, *, replace: bool = False) -> IngestResult:
        rows = audit_to_rows(audit, record)
        aid = rows.audit.audit_id
        with Session(write_engine(self._engine)) as session, session.begin():
            existing = session.get(AuditRow, aid)
            status = "inserted"
            if existing is not None:
                same = (
                    existing.findings_sha256 == record.findings_sha256
                    and existing.manifest_sha256 == record.manifest_sha256
                )
                if same:
                    return IngestResult(aid, "unchanged", len(rows.findings), len(rows.hits))
                if not replace:
                    raise AuditConflictError(
                        f"audit {aid} is already stored with different content "
                        "(findings.json or manifest.json changed); use --replace to overwrite"
                    )
                session.exec(delete(AuditRow).where(AuditRow.audit_id == aid))
                session.flush()
                status = "replaced"
            session.add(rows.audit)
            session.flush()  # parents first: foreign keys are enforced
            session.add_all(rows.tool_runs)
            session.add_all(rows.artifacts)
            session.add_all(rows.findings)
            session.flush()
            session.add_all(rows.hits)
            self._stamp_schema(session, audit.schema_version)
        return IngestResult(aid, status, len(rows.findings), len(rows.hits))

    @staticmethod
    def _stamp_schema(session: Session, models_schema: str) -> None:
        row = session.get(SchemaVersionRow, 1)
        if row is not None and row.models_schema != models_schema:
            raise AuditConflictError(
                f"database holds schema {row.models_schema}, audit uses {models_schema}"
            )

    def delete_audit(self, audit_id: str) -> bool:
        """Remove an audit and everything under it (foreign keys cascade). True if it existed."""
        with Session(write_engine(self._engine)) as session, session.begin():
            result = session.exec(delete(AuditRow).where(AuditRow.audit_id == audit_id))
            return bool(result.rowcount)

    # ---------------------------------------------------------------- reads

    def has_audit(self, audit_id: str) -> bool:
        with Session(self._engine) as session:
            return session.get(AuditRow, audit_id) is not None

    def get_audit(self, audit_id: str) -> Audit | None:
        with Session(self._engine) as session:
            audit_row = session.get(AuditRow, audit_id)
            if audit_row is None:
                return None
            rows = AuditRows(
                audit=audit_row,
                tool_runs=list(
                    session.exec(select(ToolRunRow).where(ToolRunRow.audit_id == audit_id))
                ),
                findings=list(
                    session.exec(select(FindingRow).where(FindingRow.audit_id == audit_id))
                ),
                hits=list(
                    session.exec(select(FindingHitRow).where(FindingHitRow.audit_id == audit_id))
                ),
            )
            return rows_to_audit(rows)

    def list_audits(self) -> list[AuditSummary]:
        with Session(self._engine) as session:
            counts = dict(
                session.exec(
                    select(FindingRow.audit_id, func.count()).group_by(FindingRow.audit_id)
                ).all()
            )
            audits = session.exec(
                select(AuditRow).order_by(AuditRow.created_at.desc(), AuditRow.audit_id.desc())
            ).all()
            return [
                AuditSummary(
                    a.audit_id,
                    a.created_at,
                    a.runner,
                    a.input_source,
                    counts.get(a.audit_id, 0),
                    a.ingested_at,
                )
                for a in audits
            ]

    def latest_audit_id(self) -> str | None:
        audits = self.list_audits()
        return audits[0].audit_id if audits else None

    def raw_artifacts(self, audit_id: str) -> list[RawArtifactRow]:
        with Session(self._engine) as session:
            return list(
                session.exec(select(RawArtifactRow).where(RawArtifactRow.audit_id == audit_id))
            )

    def list_findings(
        self,
        audit_id: str,
        *,
        severity: str | None = None,
        tool: str | None = None,
    ) -> list[FindingSummary]:
        with Session(self._engine) as session:
            query = select(FindingRow).where(FindingRow.audit_id == audit_id)
            if severity:
                query = query.where(FindingRow.severity == severity.upper())
            if tool:
                query = query.where(
                    FindingRow.id.in_(
                        select(FindingHitRow.finding_id).where(
                            FindingHitRow.audit_id == audit_id, FindingHitRow.tool == tool
                        )
                    )
                )
            findings = session.exec(query.order_by(FindingRow.position)).all()
            tools: dict[str, set[str]] = {}
            for finding_id, hit_tool in session.exec(
                select(FindingHitRow.finding_id, FindingHitRow.tool).where(
                    FindingHitRow.audit_id == audit_id
                )
            ):
                tools.setdefault(finding_id, set()).add(hit_tool)
            return [
                FindingSummary(
                    audit_id=f.audit_id,
                    id=f.id,
                    severity=f.severity,
                    issue_class=f.issue_class,
                    title=f.title,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    owasp_2025=f.owasp_2025,
                    is_test_path=f.is_test_path,
                    tools=tuple(sorted(tools.get(f.id, ()))),
                )
                for f in findings
            ]

    def find_finding(
        self, finding_id: str, audit_id: str | None = None
    ) -> tuple[str, SecurityFinding] | None:
        """(audit_id, finding). Ids repeat across audits (they hash content), so without an
        audit the most recent audit containing the id wins."""
        with Session(self._engine) as session:
            query = select(FindingRow).where(FindingRow.id == finding_id)
            if audit_id:
                query = query.where(FindingRow.audit_id == audit_id)
            candidates = session.exec(query).all()
            if not candidates:
                return None
            order = {a.audit_id: n for n, a in enumerate(self.list_audits())}
            row = min(candidates, key=lambda r: order.get(r.audit_id, len(order)))
            hits = list(
                session.exec(
                    select(FindingHitRow).where(
                        FindingHitRow.audit_id == row.audit_id,
                        FindingHitRow.finding_id == row.id,
                    )
                )
            )
            return row.audit_id, finding_from_row(row, hits)
