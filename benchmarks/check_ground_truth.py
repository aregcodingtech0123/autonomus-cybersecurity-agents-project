"""Validate benchmarks/expected_findings.yaml against the real benchmark target files.

Checks, per case: the file exists inside the target, the 1-indexed line range lies within the
file, and the `anchor` substring occurs inside that range. Also checks schema, id uniqueness
and that the full planned case set (P01-P10, N01-N06, I01-I02) is present.

Usage: python benchmarks/check_ground_truth.py   (exit code 1 on any problem)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

BENCH_DIR = Path(__file__).resolve().parent
DEFAULT_GROUND_TRUTH = BENCH_DIR / "expected_findings.yaml"
REPO_ROOT = BENCH_DIR.parent

KINDS = {"positive", "negative", "injection_bait"}
KIND_PREFIX = {"positive": "P", "negative": "N", "injection_bait": "I"}
TOOLS = {"semgrep", "bandit", "gitleaks", "pip-audit"}
REQUIRED = ("id", "title", "kind", "file", "line_start", "line_end", "anchor", "notes")
CWE_RE = re.compile(r"^CWE-\d+$")
EXPECTED_IDS = (
    {f"P{i:02d}" for i in range(1, 11)}
    | {"P08b"}
    | {f"N{i:02d}" for i in range(1, 8)}
    | {f"I{i:02d}" for i in range(1, 3)}
)


def check(path: Path = DEFAULT_GROUND_TRUTH) -> list[str]:
    """Return a list of human-readable problems; empty means the ground truth is valid."""
    problems: list[str] = []
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list):
        return [f"{path}: top level must be a mapping with a 'cases' list"]

    target = (REPO_ROOT / str(doc.get("target", ""))).resolve()
    if not target.is_dir():
        return [f"target directory does not exist: {doc.get('target')!r}"]

    seen: set[str] = set()
    for index, case in enumerate(doc["cases"]):
        cid = case.get("id", f"<case #{index}>")
        problems.extend(f"{cid}: {msg}" for msg in _check_case(case, target))
        if cid in seen:
            problems.append(f"{cid}: duplicate id")
        seen.add(cid)

    missing = EXPECTED_IDS - seen
    if missing:
        problems.append(f"missing planned cases: {sorted(missing)}")
    unexpected = seen - EXPECTED_IDS
    if unexpected:
        problems.append(f"unplanned case ids: {sorted(unexpected)}")
    return problems


def _check_case(case: dict, target: Path) -> list[str]:
    problems = [f"missing field '{f}'" for f in REQUIRED if f not in case]
    if problems:
        return problems

    kind = case["kind"]
    if kind not in KINDS:
        return [f"invalid kind {kind!r}"]
    if not str(case["id"]).startswith(KIND_PREFIX[kind]):
        problems.append(f"id prefix does not match kind {kind!r}")

    if case.get("cwe") is not None and not CWE_RE.match(str(case["cwe"])):
        problems.append(f"malformed cwe {case['cwe']!r}")
    for key in ("expected_detecting_tools", "observed_false_alarms"):
        unknown = set(case.get(key) or []) - TOOLS
        if unknown:
            problems.append(f"unknown tools in {key}: {sorted(unknown)}")
    if kind != "positive" and case.get("expected_detecting_tools"):
        problems.append("only positive cases may list expected_detecting_tools")
    if kind != "negative" and case.get("observed_false_alarms"):
        problems.append("only negative cases may list observed_false_alarms")

    file_path = (target / case["file"]).resolve()
    if not file_path.is_relative_to(target):
        return [*problems, f"file escapes target directory: {case['file']!r}"]
    if not file_path.is_file():
        return [*problems, f"file does not exist: {case['file']!r}"]

    lines = file_path.read_text(encoding="utf-8").splitlines()
    start, end = case["line_start"], case["line_end"]
    if not (isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= len(lines)):
        return [
            *problems,
            f"line range {start}-{end} invalid for {case['file']} ({len(lines)} lines)",
        ]

    window = "\n".join(lines[start - 1 : end])
    if case["anchor"] not in window:
        problems.append(f"anchor {case['anchor']!r} not found in {case['file']}:{start}-{end}")
    return problems


def main() -> int:
    problems = check()
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"ground truth OK: {DEFAULT_GROUND_TRUTH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
