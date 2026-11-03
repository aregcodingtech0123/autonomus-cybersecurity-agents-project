"""CLI commands that work on stored audits: ingest, post-scan processing, findings, report, audit.

Everything printed that originates in scanned content (paths, titles, rule text, snippets, input
names) goes through `cliout.safe` first, so a hostile file name cannot drive the terminal. Data
comes from the database / findings.json / manifest.json only; raw scanner files are read for
their sha256 (ingest) and nothing else.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from pathlib import Path

from secaudit.cliout import safe
from secaudit.core import evaluation
from secaudit.core.intake import CleanupError
from secaudit.core.models import Audit, SecurityFinding
from secaudit.core.normalize.pipeline import export_json, normalize_audit_dir
from secaudit.core.retention import AUDIT_ID_RE, AuditNotFoundError, delete_audit
from secaudit.exitcodes import EXIT_CLEANUP, EXIT_INTAKE, EXIT_OK, EXIT_USAGE
from secaudit.report import render_html
from secaudit.report.render import related_informational_items
from secaudit.store.db import DB_FILENAME, open_database, secure_database
from secaudit.store.ingest import IngestError, ingest_audit_dir
from secaudit.store.repo import AuditConflictError, Repository

FINDING_ID_RE = re.compile(r"^F-[0-9a-f]{12}$")
FINDINGS_FILENAME = "findings.json"
REPORT_FILENAME = "report.html"


def db_path(args: argparse.Namespace) -> Path:
    return args.db if getattr(args, "db", None) else Path(args.out) / DB_FILENAME


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    if os.name == "posix":
        path.chmod(0o600)


def _open_existing(args: argparse.Namespace):
    """The engine of an existing database; prints an error and returns None if there is none."""
    path = db_path(args)
    if not path.is_file():
        print(
            f"error: no database at {safe(path.as_posix())}; "
            "run `secaudit scan` or `secaudit ingest` first",
            file=sys.stderr,
        )
        return None
    return open_database(path)


# ---------------------------------------------------------------- ingest and post-scan processing


def cmd_ingest(args: argparse.Namespace) -> int:
    audit_dir = args.audit_dir
    path = args.db or audit_dir.resolve().parent / DB_FILENAME
    engine = open_database(path, restrict_parent=args.db is None)
    try:
        result = ingest_audit_dir(Repository(engine), audit_dir, replace=args.replace)
    except IngestError as exc:
        print(f"error: {safe(exc)}", file=sys.stderr)
        return EXIT_USAGE if exc.kind == "usage" else EXIT_INTAKE
    except AuditConflictError as exc:
        print(f"error: {safe(exc)}", file=sys.stderr)
        return EXIT_INTAKE
    finally:
        engine.dispose()
    secure_database(path, restrict_parent=args.db is None)
    print(
        f"audit {safe(result.audit_id)}: {result.status} "
        f"({result.findings} findings, {result.hits} hits) in {safe(path.name)}"
    )
    return EXIT_OK


def postprocess_scan(audit_dir: Path, path: Path, *, restrict_parent: bool) -> Audit:
    """normalize -> findings.json -> ingest (hash-verified) -> report.html, then print a summary."""
    audit = normalize_audit_dir(audit_dir)
    _write_private(audit_dir / FINDINGS_FILENAME, export_json(audit))
    engine = open_database(path, restrict_parent=restrict_parent)
    try:
        result = ingest_audit_dir(Repository(engine), audit_dir)
    finally:
        engine.dispose()
    secure_database(path, restrict_parent=restrict_parent)
    _write_private(audit_dir / REPORT_FILENAME, render_html(audit))
    _print_scan_summary(audit, audit_dir, path, result.status)
    return audit


def _print_scan_summary(audit: Audit, audit_dir: Path, path: Path, status: str) -> None:
    raw_total = sum(r.raw_results for r in audit.tool_runs)
    by_severity = Counter(f.severity.value for f in audit.findings)
    breakdown = ", ".join(f"{name} {n}" for name, n in by_severity.most_common())
    print(
        f"findings: {len(audit.findings)} from {raw_total} raw results"
        + (f" ({breakdown})" if breakdown else "")
    )
    unknown = [c.tool for c in audit.coverage if c.status == "unknown"]
    if unknown:
        print(f"coverage unknown for: {', '.join(safe(t) for t in unknown)} (see the report)")
    skipped = [
        f"{c.tool}: {len(c.skipped_files)} file(s)" for c in audit.coverage if c.skipped_files
    ]
    if skipped:
        print(f"files NOT analysed: {safe('; '.join(skipped))}")
    if audit.warnings:
        print(f"{len(audit.warnings)} warning(s); see {REPORT_FILENAME}")
    print(
        f"stored ({status}) in {safe(path.as_posix())}; wrote "
        f"{safe((audit_dir / FINDINGS_FILENAME).as_posix())} and "
        f"{safe((audit_dir / REPORT_FILENAME).as_posix())}"
    )


# ---------------------------------------------------------------- findings


def _check_audit_id(value: str | None) -> bool:
    if value is not None and not AUDIT_ID_RE.match(value):
        print("error: not a valid audit id (expected YYYYMMDDTHHMMSSZ-xxxxxxxx)", file=sys.stderr)
        return False
    return True


def cmd_findings_list(args: argparse.Namespace) -> int:
    if not _check_audit_id(args.audit):
        return EXIT_USAGE
    engine = _open_existing(args)
    if engine is None:
        return EXIT_USAGE
    try:
        repo = Repository(engine)
        audit_id = args.audit or repo.latest_audit_id()
        if audit_id is None or not repo.has_audit(audit_id):
            print("error: no such audit in the database", file=sys.stderr)
            return EXIT_USAGE
        rows = repo.list_findings(audit_id, severity=args.severity, tool=args.tool)
    finally:
        engine.dispose()
    print(f"audit {audit_id}: {len(rows)} finding(s)")
    for row in rows:
        location = f"{row.file_path}:{row.line_start}"
        print(
            f"{row.id}  {row.severity:<8} {safe(location, 60):<44} "
            f"{safe(','.join(row.tools), 30):<26} {safe(row.title, 70)}"
        )
    return EXIT_OK


def _print_finding(audit_id: str, finding: SecurityFinding) -> None:
    f = finding
    location = f"{f.file_path}:{f.line_start}" + (
        f"-{f.line_end}" if f.line_end != f.line_start else ""
    )
    print(f"finding {f.id} in audit {audit_id}")
    print(f"  severity    {f.severity.value} (basis: {safe(f.severity_basis)})")
    print(f"  confidence  {f.confidence.value}")
    cwes = safe(", ".join(f.cwe_ids) or "-")
    print(f"  issue       {safe(f.issue_class)}  CWE: {cwes}  OWASP 2025: {f.owasp_2025 or '-'}")
    print(f"  location    {safe(location)}{'  (test code)' if f.is_test_path else ''}")
    print(f"  title       {safe(f.title)}")
    print(f"  tools       {safe(', '.join(f.tools))}")
    print(f"  fingerprint {f.fingerprint} ({f.fingerprint_basis})")
    if f.aliases:
        print(f"  advisories  {safe(', '.join(f.aliases))}")
    if f.fix_versions:
        print(f"  fixed in    {safe(', '.join(f.fix_versions))}")
    if f.snippet:
        print("  snippet (masked):")
        for line in f.snippet.split("\n"):
            print(f"    {safe(line, 240)}")
    print("  evidence:")
    for hit in f.hits:
        print(
            f"    - {safe(hit.tool)} {safe(hit.tool_version or '')} rule {safe(hit.rule_id)}"
            f"  raw severity: {safe(hit.raw_severity or 'none')}"
            f"  confidence: {hit.confidence.value}"
        )
        print(f"        {safe(hit.message, 400)}")
        print(f"        raw result: {safe(hit.raw_ref.artifact)}{safe(hit.raw_ref.pointer)}")


def cmd_findings_show(args: argparse.Namespace) -> int:
    if not _check_audit_id(args.audit):
        return EXIT_USAGE
    if not FINDING_ID_RE.match(args.finding_id):
        print("error: not a finding id (expected F- and 12 hex digits)", file=sys.stderr)
        return EXIT_USAGE
    engine = _open_existing(args)
    if engine is None:
        return EXIT_USAGE
    try:
        found = Repository(engine).find_finding(args.finding_id, args.audit)
    finally:
        engine.dispose()
    if found is None:
        print("error: no such finding", file=sys.stderr)
        return EXIT_USAGE
    _print_finding(*found)
    return EXIT_OK


# ---------------------------------------------------------------- report, audit list / delete


def cmd_report(args: argparse.Namespace) -> int:
    if not _check_audit_id(args.audit_id):
        return EXIT_USAGE
    engine = _open_existing(args)
    if engine is None:
        return EXIT_USAGE
    try:
        audit = Repository(engine).get_audit(args.audit_id)
    finally:
        engine.dispose()
    if audit is None:
        print("error: no such audit in the database", file=sys.stderr)
        return EXIT_USAGE
    if args.format == "json":
        text = export_json(audit)
    else:
        related = None
        if args.ground_truth:
            if not args.ground_truth.is_file():
                print("error: --ground-truth file does not exist", file=sys.stderr)
                return EXIT_USAGE
            related = related_informational_items(audit, evaluation.load_truth(args.ground_truth))
        text = render_html(audit, related=related)
    if args.out:
        _write_private(args.out, text)
        print(f"wrote {safe(args.out.as_posix())}")
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.flush()
    return EXIT_OK


def cmd_audit_list(args: argparse.Namespace) -> int:
    engine = _open_existing(args)
    if engine is None:
        return EXIT_USAGE
    try:
        audits = Repository(engine).list_audits()
    finally:
        engine.dispose()
    print(f"{len(audits)} audit(s)")
    for a in audits:
        print(
            f"{a.audit_id}  {safe(a.created_at or 'unknown', 25):<25} "
            f"{safe(a.runner or '-', 8):<8} "
            f"{a.findings:>4} findings  {safe(a.input_source or '-', 60)}"
        )
    return EXIT_OK


def cmd_audit_delete(args: argparse.Namespace) -> int:
    """Remove the audit directory (raw output, retained source) and its database rows."""
    removed_dir = removed_rows = False
    try:
        delete_audit(args.out, args.audit_id)
        removed_dir = True
    except AuditNotFoundError as exc:
        missing = exc
    except CleanupError as exc:
        print(f"cleanup failed, delete these leftovers manually: {safe(exc)}", file=sys.stderr)
        return EXIT_CLEANUP
    path = db_path(args)
    if AUDIT_ID_RE.match(args.audit_id) and path.is_file():
        engine = open_database(path)
        try:
            removed_rows = Repository(engine).delete_audit(args.audit_id)
        finally:
            engine.dispose()
    if not (removed_dir or removed_rows):
        print(f"error: {safe(missing)}", file=sys.stderr)
        return EXIT_USAGE
    parts = [p for p, ok in (("directory", removed_dir), ("database rows", removed_rows)) if ok]
    print(f"deleted audit {args.audit_id} ({' and '.join(parts)})")
    return EXIT_OK
