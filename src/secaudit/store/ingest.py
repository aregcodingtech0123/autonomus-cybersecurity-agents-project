"""`secaudit ingest`: findings.json + manifest.json -> database rows, raw hashes verified first.

DATA FLOW RULE: the rows are built only from findings.json and manifest.json. Raw scanner files are
opened for exactly one purpose here: computing their sha256 and comparing it with the manifest and
with every hit's `raw_ref`. A mismatch means the raw output was modified after the scan (or the
findings were produced from different bytes), and nothing is written.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from secaudit.core.models import SCHEMA_VERSION, Audit
from secaudit.core.retention import AUDIT_ID_RE
from secaudit.store.convert import ArtifactRecord, IngestRecord
from secaudit.store.repo import IngestResult, Repository

MAX_FINDINGS_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_ARTIFACT_PATH = re.compile(r"^raw/[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class IngestError(Exception):
    """Ingest refused. `kind`: "usage" (missing prerequisite) or "rejected" (bad/tampered data)."""

    def __init__(self, message: str, kind: str = "rejected") -> None:
        super().__init__(message)
        self.kind = kind


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise IngestError(f"{path.name} not found in the audit directory", "usage")
        if path.stat().st_size > limit:
            raise IngestError(f"{path.name} is larger than {limit} bytes")
        return path.read_bytes()
    except OSError as exc:
        raise IngestError(f"cannot read {path.name} ({type(exc).__name__})", "usage") from exc


def _sha256_file(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _declared_artifacts(manifest: dict) -> list[tuple[str, str, str, str]]:
    """(tool, path, sha256, kind) for every raw file the manifest vouches for."""
    tools = manifest.get("tools")
    if not isinstance(tools, dict):
        raise IngestError("manifest.json has no 'tools' table")
    declared: list[tuple[str, str, str, str]] = []
    for tool, entry in tools.items():
        if not isinstance(entry, dict):
            raise IngestError(f"manifest entry for {tool!r} is malformed")
        if entry.get("artifact") is not None:
            declared.append((tool, entry["artifact"], entry.get("artifact_sha256"), "primary"))
        extras = entry.get("extra_artifacts") or []
        if not isinstance(extras, list):
            raise IngestError(f"manifest extra_artifacts for {tool!r} is malformed")
        for extra in extras:
            if not isinstance(extra, dict):
                raise IngestError(f"manifest extra_artifacts for {tool!r} is malformed")
            declared.append((tool, extra.get("path"), extra.get("sha256"), "extra"))
    return declared


def verify_raw_artifacts(audit_dir: Path, manifest: dict) -> tuple[ArtifactRecord, ...]:
    """Hash every declared raw file and compare. Raises IngestError on any mismatch."""
    records: list[ArtifactRecord] = []
    for tool, path, declared_sha, kind in _declared_artifacts(manifest):
        if not isinstance(path, str) or not _ARTIFACT_PATH.match(path):
            raise IngestError(f"manifest names an unacceptable artifact path for {tool!r}")
        if not isinstance(declared_sha, str) or not _SHA256.match(declared_sha):
            raise IngestError(f"manifest has no valid sha256 for {path}")
        file = audit_dir / path
        if file.is_symlink() or not file.is_file():
            raise IngestError(f"raw artifact {path} listed in the manifest is missing")
        actual, size = _sha256_file(file)
        if actual != declared_sha:
            raise IngestError(
                f"raw artifact {path} does not match the manifest sha256 "
                f"(expected {declared_sha[:12]}..., found {actual[:12]}...): "
                "the raw output was modified after the scan; nothing was stored"
            )
        records.append(ArtifactRecord(tool, path, actual, size, kind))
    return tuple(records)


def _check_hits_point_at_verified_files(audit: Audit, records: tuple[ArtifactRecord, ...]) -> None:
    verified = {r.path: r.sha256 for r in records}
    for finding in audit.findings:
        for hit in finding.hits:
            expected = verified.get(hit.raw_ref.artifact)
            if expected is None:
                raise IngestError(
                    f"finding {finding.id} cites {hit.raw_ref.artifact}, "
                    "which the manifest does not list"
                )
            if hit.raw_ref.artifact_sha256 != expected:
                raise IngestError(
                    f"finding {finding.id} was derived from different bytes than "
                    f"{hit.raw_ref.artifact} has now (raw_ref sha256 mismatch); nothing was stored"
                )


def load_audit_dir(audit_dir: Path) -> tuple[Audit, dict, str, str, tuple[ArtifactRecord, ...]]:
    """Validate an audit directory: (audit, manifest, findings sha, manifest sha, artifacts)."""
    audit_dir = Path(audit_dir)
    if not audit_dir.is_dir() or not (audit_dir / "manifest.json").is_file():
        raise IngestError("not an audit directory (no manifest.json)", "usage")
    manifest_bytes = _read_bounded(audit_dir / "manifest.json", MAX_MANIFEST_BYTES)
    if not (audit_dir / "findings.json").is_file():
        raise IngestError(
            "no findings.json in the audit directory; run `secaudit normalize <audit_dir>` first",
            "usage",
        )
    findings_bytes = _read_bounded(audit_dir / "findings.json", MAX_FINDINGS_BYTES)
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise IngestError("manifest.json is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise IngestError("manifest.json is not a JSON object")
    try:
        audit = Audit.model_validate_json(findings_bytes)
    except ValidationError as exc:
        raise IngestError(
            f"findings.json does not match the schema ({exc.error_count()} problem(s)); "
            "re-run `secaudit normalize`"
        ) from exc
    if audit.schema_version != SCHEMA_VERSION:
        raise IngestError(
            f"findings.json has schema_version {audit.schema_version!r}; this release reads "
            f"{SCHEMA_VERSION!r}. Re-run `secaudit normalize`."
        )
    if not audit.audit_id or not AUDIT_ID_RE.match(audit.audit_id):
        raise IngestError("findings.json carries no valid audit_id")
    if manifest.get("audit_id") != audit.audit_id:
        raise IngestError("findings.json and manifest.json describe different audits")
    artifacts = verify_raw_artifacts(audit_dir, manifest)
    _check_hits_point_at_verified_files(audit, artifacts)
    return (
        audit,
        manifest,
        hashlib.sha256(findings_bytes).hexdigest(),
        hashlib.sha256(manifest_bytes).hexdigest(),
        artifacts,
    )


def ingest_audit_dir(repo: Repository, audit_dir: Path, *, replace: bool = False) -> IngestResult:
    audit, _manifest, findings_sha, manifest_sha, artifacts = load_audit_dir(audit_dir)
    record = IngestRecord(
        findings_sha256=findings_sha,
        manifest_sha256=manifest_sha,
        ingested_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        artifacts=artifacts,
    )
    return repo.ingest(audit, record, replace=replace)
