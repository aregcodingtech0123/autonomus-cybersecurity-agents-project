"""Regenerate benchmarks/baseline/ from a REAL sandboxed container scan. Scripted, no manual steps.

    uv run python benchmarks/regenerate_baseline.py [--allow-rules-change]

What it does (ADR-003, docs/DECISIONS.md):

1. Generates the git-ignored P11 module (benchmarks/p11_generator.py) so the scan sees 16 files.
2. Runs `secaudit scan` with the Docker runner on benchmarks/targets/vuln_python_app into a
   temporary output root. The source copy is retained, as for every canonical baseline, so the
   manifest records `source.retained_at_scan: true` and `source.committed: false`.
3. Refuses to continue unless every tool completed and the Semgrep rule snapshot equals the one the
   committed manifest records (pass --allow-rules-change to accept a new snapshot on purpose).
4. Replaces benchmarks/baseline/raw/ with byte copies of the scan's raw outputs and copies the
   scan's manifest.json; then verifies every recorded artifact hash against the copied bytes.
5. Runs `secaudit eval` to rewrite metrics_tool_only.{json,md}, which pins the ground-truth hash and
   the raw artifact hashes.
6. Deletes the temporary audit and prints per-tool result counts.

Raw outputs are never edited. Anything that differs between two runs (audit id, timestamps,
durations, container labels) differs only because it was a different run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REPO = BENCH.parent
TARGET = BENCH / "targets" / "vuln_python_app"
BASELINE = BENCH / "baseline"
RAW_FILES = ("bandit.sarif", "semgrep.sarif", "semgrep.json", "gitleaks.sarif", "pip-audit.json")

sys.path.insert(0, str(BENCH))
from p11_generator import ensure as ensure_p11  # noqa: E402

from secaudit import cli  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rulesets(manifest: dict) -> list[tuple[str, str]]:
    info = manifest["tools"]["semgrep"].get("ruleset_info") or {}
    return sorted((r["name"], r["sha256"]) for r in info.get("rulesets", []))


def _run(argv: list[str]) -> None:
    code = cli.main(argv)
    if code != 0:
        raise SystemExit(f"`secaudit {' '.join(argv[:1])}` failed with exit code {code}")


def result_counts(raw: Path) -> dict[str, int]:
    counts = {}
    for tool in ("bandit", "semgrep", "gitleaks"):
        doc = json.loads((raw / f"{tool}.sarif").read_text("utf-8"))
        counts[tool] = sum(len(run.get("results", [])) for run in doc["runs"])
    audit = json.loads((raw / "pip-audit.json").read_text("utf-8"))
    counts["pip-audit"] = sum(len(d.get("vulns", [])) for d in audit["dependencies"])
    return counts


def verify_hashes(manifest: dict, baseline: Path) -> None:
    for name, tool in manifest["tools"].items():
        artifact = tool.get("artifact")
        if artifact:
            got = _sha256(baseline / artifact)
            if got != tool["artifact_sha256"]:
                raise SystemExit(f"{name}: {artifact} does not match its recorded hash")
        for extra in tool.get("extra_artifacts", []):
            if _sha256(baseline / extra["path"]) != extra["sha256"]:
                raise SystemExit(f"{name}: {extra['path']} does not match its recorded hash")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--allow-rules-change", action="store_true")
    args = parser.parse_args(argv)

    old_manifest = json.loads((BASELINE / "manifest.json").read_text("utf-8"))
    old_counts = result_counts(BASELINE / "raw")
    ensure_p11(TARGET)

    with tempfile.TemporaryDirectory(
        prefix="secaudit-baseline-", ignore_cleanup_errors=True
    ) as tmp:
        out = Path(tmp) / "audits"
        _run(["scan", str(TARGET), "--runner", "docker", "--out", str(out), "--raw-only"])
        (audit_dir,) = [p for p in out.iterdir() if p.is_dir()]
        manifest_text = (audit_dir / "manifest.json").read_text("utf-8")
        manifest = json.loads(manifest_text)

        failed = {
            n: t["status"] for n, t in manifest["tools"].items() if t["status"] != "completed"
        }
        if failed:
            raise SystemExit(f"not every tool completed: {failed}")
        if _rulesets(manifest) != _rulesets(old_manifest) and not args.allow_rules_change:
            raise SystemExit(
                "Semgrep rule snapshot differs from the committed baseline; "
                "rerun with --allow-rules-change if that is intended"
            )
        source = manifest["source"]
        if not (source.get("retained_at_scan") is True and source.get("committed") is False):
            raise SystemExit(f"unexpected source record in the manifest: {source}")
        if tmp in manifest_text or tmp.replace("\\", "/") in manifest_text:
            raise SystemExit("the manifest records a host path; refusing to commit it")

        raw_dir = BASELINE / "raw"
        for stale in raw_dir.iterdir():
            stale.unlink()
        for name in RAW_FILES:
            shutil.copyfile(audit_dir / "raw" / name, raw_dir / name)
        shutil.copyfile(audit_dir / "manifest.json", BASELINE / "manifest.json")
        verify_hashes(manifest, BASELINE)
        _run(["audit", "delete", manifest["audit_id"], "--out", str(out)])

    _run(["eval", "--from-raw", str(raw_dir), "--source", str(TARGET)])
    new_counts = result_counts(raw_dir)
    print(f"baseline regenerated: audit {manifest['audit_id']}")
    for tool, n in new_counts.items():
        note = "" if n == old_counts.get(tool) else f"   (was {old_counts.get(tool)})"
        print(f"  {tool:<10} {n:>3} results{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
