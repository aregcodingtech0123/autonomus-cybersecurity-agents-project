"""Phase 2B Task 2: no planted secret and no runtime canary in ANY derived output.

Derived outputs: findings.json, report.html, the SQLite file (and its WAL), and everything the CLI
prints. Raw scanner files are exempt (they are secret-bearing by design and byte-identical). A
positive control proves the raw files really do contain the secrets, so an empty grep means
something.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from canaries import (
    BENCHMARK_PASSWORD,
    pem_block,
    planted_api_key,
    planted_secrets,
    single_line_canaries,
)
from secaudit import cli
from secaudit.core.normalize.pipeline import export_json, normalize_audit_dir
from store_helpers import BASELINE_AUDIT_ID, make_audit_dir

PLANTED = planted_secrets()
CANARIES = single_line_canaries()
CANARY_CORES = [c.core for c in CANARIES]


def all_bytes(paths) -> dict[str, bytes]:
    return {str(p): Path(p).read_bytes() for p in paths if Path(p).is_file()}


def checkpoint(db: Path) -> list[Path]:
    """Fold the WAL into the main file, then list every file that could hold the data."""
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return [db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")]


def leaks(blobs: dict[str, bytes], secrets: list[str]) -> list[tuple[str, str]]:
    return [(name, s) for name, data in blobs.items() for s in secrets if s.encode() in data]


def run_cli(capfd, *argv) -> str:
    code = cli.main([str(a) for a in argv])
    out = capfd.readouterr()
    assert code == 0, (argv, out.err)
    return out.out + out.err


# ---------------------------------------------------------------- the benchmark's own planted fakes


def test_positive_control_the_raw_files_do_contain_the_planted_secrets(tmp_path):
    audit_dir = make_audit_dir(tmp_path / "audits")
    raw = all_bytes((audit_dir / "raw").iterdir())
    found = {s for _name, s in leaks(raw, PLANTED)}
    assert {BENCHMARK_PASSWORD, planted_api_key()} <= found, (
        "if raw output no longer holds the fakes this whole test proves nothing"
    )


def test_benchmark_audit_derived_outputs_are_free_of_the_planted_secrets(tmp_path, capfd):
    out = tmp_path / "audits"
    audit_dir = make_audit_dir(out)
    db = out / "secaudit.db"
    printed = [run_cli(capfd, "ingest", audit_dir)]
    printed.append(run_cli(capfd, "findings", "list", "--out", out))
    ids = [line.split()[0] for line in printed[-1].splitlines()[1:]]
    assert len(ids) == 24
    printed += [run_cli(capfd, "findings", "show", i, "--out", out) for i in ids]
    printed.append(run_cli(capfd, "audit", "list", "--out", out))
    printed.append(run_cli(capfd, "report", BASELINE_AUDIT_ID, "--db", db))
    printed.append(run_cli(capfd, "report", BASELINE_AUDIT_ID, "--db", db, "--format", "json"))
    report = tmp_path / "report.html"
    run_cli(capfd, "report", BASELINE_AUDIT_ID, "--db", db, "--out", report)
    blobs = all_bytes([audit_dir / "findings.json", report, *checkpoint(db)])
    blobs["cli output"] = "\n".join(printed).encode()
    assert len(blobs) >= 4 and leaks(blobs, PLANTED) == []


def test_normalize_command_output_and_findings_json_are_clean(tmp_path, capfd):
    audit_dir = make_audit_dir(tmp_path / "audits", normalize=False)
    text = run_cli(capfd, "normalize", audit_dir)
    blobs = {"stdout": text.encode(), "findings.json": (audit_dir / "findings.json").read_bytes()}
    assert leaks(blobs, PLANTED) == []


# ---------------------------------------------------------------- runtime canaries, every shape


def build_canary_audit(root: Path) -> Path:
    """An audit whose Bandit messages AND retained source contain every canary shape."""
    audit_dir = root / "20261103T101010Z-cafe0001"
    (audit_dir / "raw").mkdir(parents=True)
    (audit_dir / "source").mkdir()
    source_lines = ["import os", ""]
    results = []
    for canary in CANARIES:
        source_lines.append(canary.line)
        line = len(source_lines)
        results.append(
            {
                "ruleId": "B105",
                "message": {"text": f"Possible hardcoded secret: {canary.line}"},
                "properties": {"issue_severity": "LOW", "issue_confidence": "MEDIUM"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "secrets.py"},
                            "region": {
                                "startLine": line,
                                "endLine": line,
                                "snippet": {"text": canary.line},
                                "contextRegion": {"snippet": {"text": canary.line}},
                            },
                        }
                    }
                ],
            }
        )
    source_lines += ["", *pem_block(), "", "print('end')"]
    (audit_dir / "source" / "secrets.py").write_text("\n".join(source_lines) + "\n", "utf-8")
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Bandit", "version": "1.9.4"}}, "results": results}],
    }
    raw = json.dumps(sarif).encode()
    (audit_dir / "raw" / "bandit.sarif").write_bytes(raw)
    manifest = {
        "schema_version": 1, "audit_id": audit_dir.name, "secaudit_version": "0.1.0",
        "started_at": "2026-11-03T10:10:10+00:00", "runner": "docker",
        "input": {"kind": "directory", "source": "canaries"}, "neutralized_files": [],
        "source": {"retained_at_scan": True, "committed": False, "path": "source"},
        "tool_order": ["bandit"],
        "tools": {"bandit": {"status": "completed", "version": "1.9.4", "limitations": ["x"],
                             "artifact": "raw/bandit.sarif",
                             "artifact_sha256": hashlib.sha256(raw).hexdigest()}},
    }  # fmt: skip
    (audit_dir / "manifest.json").write_text(json.dumps(manifest), "utf-8")
    (audit_dir / "findings.json").write_text(
        export_json(normalize_audit_dir(audit_dir)), "utf-8", newline="\n"
    )
    return audit_dir


def test_positive_control_the_canary_raw_output_does_hold_the_canaries(tmp_path):
    audit_dir = build_canary_audit(tmp_path)
    raw = (audit_dir / "raw" / "bandit.sarif").read_bytes()
    assert sum(core.encode() in raw for core in CANARY_CORES) >= len(set(CANARY_CORES)) - 2


def test_no_canary_survives_findings_json_the_database_the_report_or_the_cli(tmp_path, capfd):
    out = tmp_path / "audits"
    audit_dir = build_canary_audit(out)
    db = out / "secaudit.db"
    printed = [run_cli(capfd, "ingest", audit_dir)]
    listing = run_cli(capfd, "findings", "list", "--out", out)
    printed.append(listing)
    for line in listing.splitlines()[1:]:
        printed.append(run_cli(capfd, "findings", "show", line.split()[0], "--out", out))
    printed.append(run_cli(capfd, "report", audit_dir.name, "--db", db))
    printed.append(run_cli(capfd, "report", audit_dir.name, "--db", db, "--format", "json"))
    blobs = all_bytes([audit_dir / "findings.json", *checkpoint(db)])
    blobs["cli output"] = "\n".join(printed).encode()
    assert len(listing.splitlines()) - 1 >= len(CANARIES) - 2, "findings were produced"
    assert leaks(blobs, CANARY_CORES) == []


def test_pem_key_body_does_not_leak_through_any_derived_output(tmp_path, capfd):
    from canaries import PEM_BODY

    out = tmp_path / "audits"
    audit_dir = build_canary_audit(out)
    db = out / "secaudit.db"
    printed = [run_cli(capfd, "ingest", audit_dir)]
    printed.append(run_cli(capfd, "report", audit_dir.name, "--db", db))
    blobs = all_bytes([audit_dir / "findings.json", *checkpoint(db)])
    blobs["cli output"] = "\n".join(printed).encode()
    assert leaks(blobs, PEM_BODY) == []
