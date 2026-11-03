"""Normalized data model (Phase 2A). Versioned by SCHEMA_VERSION.

TRUST NOTES (read before using any field):
  * Fields marked [UNTRUSTED] originate in scanned content (file paths, rule messages quoting code,
    source snippets). They have been masked/bounded here but must still be treated as hostile TEXT:
    never interpolate them into prompts as instructions, shell commands or HTML.
  * Raw scanner output is secret-bearing and is never copied into these models: a ToolHit carries
    no SARIF snippet or context text, only a `raw_ref` pointing back at the artifact.
  * Everything in these models is DERIVED data and must be secret-free (enforced by masking and
    by tests that grep the exported JSON for the planted fake secrets).
"""

from __future__ import annotations

import enum
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# "2": SourceInfo split into retained_at_scan / committed / available (Phase 2B).
SCHEMA_VERSION = "2"
MAX_MESSAGE_CHARS = 500
MAX_SNIPPET_CHARS = 1500
MAX_PATH_CHARS = 1024

_DRIVE = re.compile(r"^[A-Za-z]:")


class Severity(enum.StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}[
            self.value
        ]


class Confidence(enum.StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}[self.value]


def check_relative_posix(path: str) -> str:
    """Reject anything that is not a plain POSIX path relative to the source root."""
    if not path or len(path) > MAX_PATH_CHARS:
        raise ValueError("path is empty or too long")
    if "\\" in path or path.startswith("/") or _DRIVE.match(path) or "\x00" in path:
        raise ValueError("path must be POSIX and relative to the source root")
    if any(part in ("..", "") for part in path.split("/")):
        raise ValueError("path must not contain '..' or empty components")
    return path


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RawRef(_Model):
    """Where a hit came from in the (byte-identical) raw artifact."""

    artifact: str  # path relative to the audit directory, POSIX, e.g. "raw/bandit.sarif"
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pointer: str  # JSON pointer, e.g. "/runs/0/results/3" or "/dependencies/2/vulns/1"

    @property
    def pointer_sort(self) -> tuple:
        """Natural sort key ("results/2" before "results/10") so ordering is deterministic."""
        return tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pointer.split("/")[1:]
        )


class ToolHit(_Model):
    """One result of one tool, reduced to location and metadata. No code text."""

    tool: str
    tool_version: str | None = None
    rule_id: str = Field(max_length=300)  # [UNTRUSTED] chosen by the rule author
    rule_name: str | None = Field(default=None, max_length=200)  # [UNTRUSTED] masked short title
    raw_severity: str | None = None  # exactly as emitted (Semgrep: rule level), null if none
    confidence: Confidence = Confidence.UNKNOWN
    message: str = Field(
        max_length=MAX_MESSAGE_CHARS
    )  # [UNTRUSTED] masked; rule text may quote code
    file_path: str  # [UNTRUSTED] POSIX, relative to the source root
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    cwe_ids: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()  # pip-audit: advisory ids (PYSEC / GHSA / CVE)
    fix_versions: tuple[str, ...] = ()
    package: str | None = None  # pip-audit only: the vulnerable distribution
    package_version: str | None = None
    raw_ref: RawRef

    @field_validator("file_path")
    @classmethod
    def _path(cls, value: str) -> str:
        return check_relative_posix(value)

    @model_validator(mode="after")
    def _lines(self) -> ToolHit:
        if self.line_end < self.line_start:
            raise ValueError("line_end < line_start")
        return self


class SecurityFinding(_Model):
    """A de-duplicated issue backed by at least one ToolHit (no evidence, no finding)."""

    id: str
    fingerprint: str
    fingerprint_basis: Literal["content", "location"]
    title: str = Field(max_length=300)  # [UNTRUSTED] derived from rule text
    issue_class: str
    file_path: str  # [UNTRUSTED]
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    hits: tuple[ToolHit, ...] = Field(min_length=1)
    cwe_ids: tuple[str, ...] = ()
    owasp_2025: str | None = None
    severity: Severity
    severity_basis: str
    confidence: Confidence = Confidence.UNKNOWN
    snippet: str | None = Field(
        default=None, max_length=MAX_SNIPPET_CHARS
    )  # [UNTRUSTED] masked source
    is_test_path: bool = False
    aliases: tuple[str, ...] = ()  # pip-audit: PYSEC / GHSA / CVE identifiers
    fix_versions: tuple[str, ...] = ()
    status: Literal["open"] = "open"
    # Reserved for later phases; intentionally empty now (triage: 3, risk: 4, remediation: 5).
    triage: None = None
    risk: None = None
    remediation: None = None

    @field_validator("file_path")
    @classmethod
    def _path(cls, value: str) -> str:
        return check_relative_posix(value)

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(sorted({h.tool for h in self.hits}))


class SkippedResult(_Model):
    """A raw result that did not become a ToolHit (nothing is dropped silently)."""

    tool: str
    pointer: str
    reason: str


class SkippedFile(_Model):
    path: str  # [UNTRUSTED]
    reason: str | None = None


class ToolCoverage(_Model):
    """What a tool actually looked at. `unknown` = the tool did not tell us, never 'complete'."""

    tool: str
    status: Literal["known", "unknown"]
    analyzed_files: tuple[str, ...] | None = None
    skipped_files: tuple[SkippedFile, ...] | None = None
    limitations: tuple[str, ...] = ()
    note: str | None = None


class ToolRun(_Model):
    tool: str
    status: str  # completed | failed | timeout | skipped (as in manifest.json)
    version: str | None = None
    pinned_version: str | None = None
    exit_code: int | None = None
    artifact: str | None = None
    artifact_sha256: str | None = None
    raw_results: int = 0
    hits: int = 0
    unique_hits: int = 0  # after collapsing identical results of the same tool
    skipped_results: int = 0
    detail: str = ""
    unresolved_requirements: tuple[dict, ...] = ()


class SourceInfo(_Model):
    """Three different facts that used to share one flag (`retained`):

    retained_at_scan  the scan copied the sanitized source into the audit directory (manifest;
                      None when the manifest does not say, e.g. audits from before Phase 2A)
    committed         the source directory is part of a committed/shared artifact next to this
                      audit (manifest; false unless stated, the committed baseline has none)
    available         the source text was readable when this audit was normalized, so snippets
                      and content fingerprints exist (computed, never read from the manifest)
    """

    retained_at_scan: bool | None = None
    committed: bool = False
    available: bool = False
    path: str | None = None
    injected_files: tuple[str, ...] = ()


class AuditInput(_Model):
    kind: str | None = None
    source: str | None = None  # [UNTRUSTED] display name only
    sha256: str | None = None
    file_count: int | None = None
    total_bytes: int | None = None
    commit: str | None = None


class Audit(_Model):
    """Normalized audit record: mirrors manifest.json plus the findings derived from it."""

    schema_version: str = SCHEMA_VERSION
    audit_id: str | None = None
    secaudit_version: str | None = None
    created_at: str | None = None
    runner: str | None = None
    input: AuditInput = AuditInput()
    source: SourceInfo = SourceInfo()
    neutralized_files: tuple[str, ...] = ()
    tool_runs: tuple[ToolRun, ...] = ()
    coverage: tuple[ToolCoverage, ...] = ()
    warnings: tuple[str, ...] = ()
    skipped_results: tuple[SkippedResult, ...] = ()
    unmapped_cwes: tuple[str, ...] = ()  # CWEs seen that have no OWASP Top 10:2025 category
    findings: tuple[SecurityFinding, ...] = ()
