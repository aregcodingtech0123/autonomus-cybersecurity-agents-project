"""ORM tables. The ONLY module that imports SQLModel; `core/models.py` stays free of ORM imports.

Everything stored here is DERIVED data (findings.json + manifest.json): masked snippets, rule ids,
locations, hashes of raw artifacts. Raw scanner output is never stored. Column text that came from
scanned content ([UNTRUSTED] in core/models.py) is plain data: nothing here builds SQL from it.

Every change to a table needs an Alembic revision (store/migrations/versions) and passes the drift
test in tests/test_store_migrations.py, which compares the migrated schema with this metadata.
"""

from sqlalchemy import JSON, Column, ForeignKeyConstraint, Index, UniqueConstraint
from sqlmodel import Field, SQLModel


def json_column() -> Column:
    """A fresh NOT NULL JSON column (a Column instance cannot be shared between tables)."""
    return Column(JSON, nullable=False)


class SchemaVersionRow(SQLModel, table=True):
    """One row: which findings.json schema version the stored rows follow."""

    __tablename__ = "schema_version"

    id: int = Field(default=1, primary_key=True)
    models_schema: str
    applied_at: str


class AuditRow(SQLModel, table=True):
    __tablename__ = "audit"

    audit_id: str = Field(primary_key=True)
    schema_version: str
    secaudit_version: str | None = None
    created_at: str | None = None
    runner: str | None = None
    input_kind: str | None = None
    input_source: str | None = None
    input_sha256: str | None = None
    input_file_count: int | None = None
    input_total_bytes: int | None = None
    input_commit: str | None = None
    source_retained_at_scan: bool | None = None
    source_committed: bool = False
    source_available: bool = False
    source_path: str | None = None
    injected_files: list = Field(default_factory=list, sa_column=json_column())
    neutralized_files: list = Field(default_factory=list, sa_column=json_column())
    warnings: list = Field(default_factory=list, sa_column=json_column())
    skipped_results: list = Field(default_factory=list, sa_column=json_column())
    unmapped_cwes: list = Field(default_factory=list, sa_column=json_column())
    coverage: list = Field(default_factory=list, sa_column=json_column())
    findings_sha256: str
    manifest_sha256: str
    ingested_at: str


class ToolRunRow(SQLModel, table=True):
    __tablename__ = "tool_run"
    __table_args__ = (ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),)

    audit_id: str = Field(primary_key=True)
    tool: str = Field(primary_key=True)
    position: int
    status: str
    version: str | None = None
    pinned_version: str | None = None
    exit_code: int | None = None
    artifact: str | None = None
    artifact_sha256: str | None = None
    raw_results: int = 0
    hits: int = 0
    unique_hits: int = 0
    skipped_results: int = 0
    detail: str = ""
    unresolved_requirements: list = Field(default_factory=list, sa_column=json_column())


class RawArtifactRow(SQLModel, table=True):
    """A raw scanner file whose sha256 was VERIFIED at ingest time (the bytes are not stored)."""

    __tablename__ = "raw_artifact"
    __table_args__ = (ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),)

    audit_id: str = Field(primary_key=True)
    path: str = Field(primary_key=True)
    tool: str
    kind: str  # "primary" (the tool's result file) or "extra" (e.g. semgrep.json for coverage)
    sha256: str
    size_bytes: int | None = None


class FindingRow(SQLModel, table=True):
    __tablename__ = "finding"
    __table_args__ = (
        ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),
        # Equal fingerprints are legal (identical code twice in a file); `ordinal` tells them apart.
        UniqueConstraint("audit_id", "fingerprint", "ordinal", name="uq_finding_fingerprint"),
        Index("ix_finding_fingerprint", "fingerprint"),
        Index("ix_finding_audit_severity", "audit_id", "severity"),
    )

    audit_id: str = Field(primary_key=True)
    id: str = Field(primary_key=True)
    position: int
    fingerprint: str
    ordinal: int
    fingerprint_basis: str
    title: str
    issue_class: str
    file_path: str
    line_start: int
    line_end: int
    cwe_ids: list = Field(default_factory=list, sa_column=json_column())
    owasp_2025: str | None = None
    severity: str
    severity_basis: str
    confidence: str
    snippet: str | None = None
    is_test_path: bool = False
    aliases: list = Field(default_factory=list, sa_column=json_column())
    fix_versions: list = Field(default_factory=list, sa_column=json_column())
    status: str = "open"


class FindingHitRow(SQLModel, table=True):
    """1:1 with ToolHit. pip-audit: one row per advisory, even though the finding is per package."""

    __tablename__ = "finding_hit"
    __table_args__ = (
        ForeignKeyConstraint(
            ["audit_id", "finding_id"],
            ["finding.audit_id", "finding.id"],
            ondelete="CASCADE",
        ),
        Index("ix_finding_hit_finding", "audit_id", "finding_id"),
        Index("ix_finding_hit_package", "package", "package_version"),
    )

    id: int | None = Field(default=None, primary_key=True)
    audit_id: str
    finding_id: str
    position: int
    tool: str
    tool_version: str | None = None
    rule_id: str
    rule_name: str | None = None
    raw_severity: str | None = None
    confidence: str
    message: str
    file_path: str
    line_start: int
    line_end: int
    cwe_ids: list = Field(default_factory=list, sa_column=json_column())
    aliases: list = Field(default_factory=list, sa_column=json_column())
    fix_versions: list = Field(default_factory=list, sa_column=json_column())
    package: str | None = None
    package_version: str | None = None
    raw_artifact: str
    raw_artifact_sha256: str
    raw_pointer: str
