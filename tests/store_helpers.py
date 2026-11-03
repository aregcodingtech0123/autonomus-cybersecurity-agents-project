"""Build real audit directories (manifest + raw + findings.json [+ source]) for storage/report tests.

They are made from the COMMITTED baseline: its raw outputs, its manifest and the benchmark target as
the retained source, so the data is the real 24-finding audit (25 before ADR-002), not a hand-made stand-in.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from secaudit.core.normalize.pipeline import export_json, normalize_audit_dir

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "benchmarks" / "baseline"
TARGET = ROOT / "benchmarks" / "targets" / "vuln_python_app"
BASELINE_AUDIT_ID = "20261103T161647Z-68eba1f9"


def make_audit_dir(
    out_root: Path,
    audit_id: str = BASELINE_AUDIT_ID,
    *,
    with_source: bool = True,
    normalize: bool = True,
) -> Path:
    """<out_root>/<audit_id>/ with the baseline's raw files and manifest (audit id rewritten)."""
    audit_dir = Path(out_root) / audit_id
    shutil.copytree(BASELINE / "raw", audit_dir / "raw")
    manifest = json.loads((BASELINE / "manifest.json").read_text("utf-8"))
    manifest["audit_id"] = audit_id
    (audit_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if with_source:
        shutil.copytree(TARGET, audit_dir / "source", ignore=shutil.ignore_patterns("__pycache__"))
    if normalize:
        audit = normalize_audit_dir(audit_dir)
        (audit_dir / "findings.json").write_text(export_json(audit), encoding="utf-8", newline="\n")
    return audit_dir
