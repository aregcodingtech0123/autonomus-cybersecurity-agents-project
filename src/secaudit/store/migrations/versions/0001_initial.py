"""initial schema: schema_version, audit, tool_run, raw_artifact, finding, finding_hit

Hand-written and FROZEN: never edit a released revision, add a new one. The drift test in
tests/test_store.py fails if the ORM tables and the migrated schema disagree.

Revision ID: 0001
Revises: (none)
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# findings.json schema version the first release of the database understands
MODELS_SCHEMA = "2"


def _json() -> sa.JSON:
    return sa.JSON()


def upgrade() -> None:
    schema_version = op.create_table(
        "schema_version",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("models_schema", sa.String(), nullable=False),
        sa.Column("applied_at", sa.String(), nullable=False),
    )
    op.bulk_insert(
        schema_version, [{"id": 1, "models_schema": MODELS_SCHEMA, "applied_at": "initial"}]
    )

    op.create_table(
        "audit",
        sa.Column("audit_id", sa.String(), primary_key=True),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("secaudit_version", sa.String()),
        sa.Column("created_at", sa.String()),
        sa.Column("runner", sa.String()),
        sa.Column("input_kind", sa.String()),
        sa.Column("input_source", sa.String()),
        sa.Column("input_sha256", sa.String()),
        sa.Column("input_file_count", sa.Integer()),
        sa.Column("input_total_bytes", sa.Integer()),
        sa.Column("input_commit", sa.String()),
        sa.Column("source_retained_at_scan", sa.Boolean()),
        sa.Column("source_committed", sa.Boolean(), nullable=False),
        sa.Column("source_available", sa.Boolean(), nullable=False),
        sa.Column("source_path", sa.String()),
        sa.Column("injected_files", _json(), nullable=False),
        sa.Column("neutralized_files", _json(), nullable=False),
        sa.Column("warnings", _json(), nullable=False),
        sa.Column("skipped_results", _json(), nullable=False),
        sa.Column("unmapped_cwes", _json(), nullable=False),
        sa.Column("coverage", _json(), nullable=False),
        sa.Column("findings_sha256", sa.String(), nullable=False),
        sa.Column("manifest_sha256", sa.String(), nullable=False),
        sa.Column("ingested_at", sa.String(), nullable=False),
    )

    op.create_table(
        "tool_run",
        sa.Column("audit_id", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("version", sa.String()),
        sa.Column("pinned_version", sa.String()),
        sa.Column("exit_code", sa.Integer()),
        sa.Column("artifact", sa.String()),
        sa.Column("artifact_sha256", sa.String()),
        sa.Column("raw_results", sa.Integer(), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("unique_hits", sa.Integer(), nullable=False),
        sa.Column("skipped_results", sa.Integer(), nullable=False),
        sa.Column("detail", sa.String(), nullable=False),
        sa.Column("unresolved_requirements", _json(), nullable=False),
        sa.PrimaryKeyConstraint("audit_id", "tool"),
        sa.ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),
    )

    op.create_table(
        "raw_artifact",
        sa.Column("audit_id", sa.String(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer()),
        sa.PrimaryKeyConstraint("audit_id", "path"),
        sa.ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),
    )

    op.create_table(
        "finding",
        sa.Column("audit_id", sa.String(), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("fingerprint_basis", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("issue_class", sa.String(), nullable=False),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("cwe_ids", _json(), nullable=False),
        sa.Column("owasp_2025", sa.String()),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("severity_basis", sa.String(), nullable=False),
        sa.Column("confidence", sa.String(), nullable=False),
        sa.Column("snippet", sa.String()),
        sa.Column("is_test_path", sa.Boolean(), nullable=False),
        sa.Column("aliases", _json(), nullable=False),
        sa.Column("fix_versions", _json(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("audit_id", "id"),
        sa.ForeignKeyConstraint(["audit_id"], ["audit.audit_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("audit_id", "fingerprint", "ordinal", name="uq_finding_fingerprint"),
    )
    op.create_index("ix_finding_fingerprint", "finding", ["fingerprint"])
    op.create_index("ix_finding_audit_severity", "finding", ["audit_id", "severity"])

    op.create_table(
        "finding_hit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("audit_id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("tool_version", sa.String()),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_name", sa.String()),
        sa.Column("raw_severity", sa.String()),
        sa.Column("confidence", sa.String(), nullable=False),
        sa.Column("message", sa.String(), nullable=False),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("cwe_ids", _json(), nullable=False),
        sa.Column("aliases", _json(), nullable=False),
        sa.Column("fix_versions", _json(), nullable=False),
        sa.Column("package", sa.String()),
        sa.Column("package_version", sa.String()),
        sa.Column("raw_artifact", sa.String(), nullable=False),
        sa.Column("raw_artifact_sha256", sa.String(), nullable=False),
        sa.Column("raw_pointer", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["audit_id", "finding_id"], ["finding.audit_id", "finding.id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_finding_hit_finding", "finding_hit", ["audit_id", "finding_id"])
    op.create_index("ix_finding_hit_package", "finding_hit", ["package", "package_version"])


def downgrade() -> None:
    op.drop_table("finding_hit")
    op.drop_table("finding")
    op.drop_table("raw_artifact")
    op.drop_table("tool_run")
    op.drop_table("audit")
    op.drop_table("schema_version")
