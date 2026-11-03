"""Tool-only detection metrics: normalized findings vs benchmarks/expected_findings.yaml.

Matching rules (docs/PHASE2_DESIGN.md section 7):
  * positive: DETECTED iff some finding overlaps a `match` range (same file, overlapping lines) AND
    its issue class is accepted; `detected_by` is the union of tools behind those findings;
  * negative / injection bait: FLAGGED iff ANY finding overlaps its range, whatever the class;
  * a finding that supports no positive and lies in no negative range is UNLABELED: listed for
    manual labeling, never counted as a false positive.
No timestamps are written, so the same inputs always give byte-identical metrics files.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

from secaudit.core.models import Audit, SecurityFinding
from secaudit.core.normalize.cwe import issue_class_for_cwe, normalize_cwe

METRICS_SCHEMA = 1


@dataclass(frozen=True)
class Match:
    file: str
    start: int
    end: int
    classes: frozenset[str]
    patterns: tuple[str, ...]

    def overlaps(self, f: SecurityFinding) -> bool:
        return f.file_path == self.file and f.line_start <= self.end and f.line_end >= self.start

    def accepts(self, f: SecurityFinding) -> bool:
        have = finding_classes(f)
        return bool(have & self.classes) or any(
            fnmatch.fnmatchcase(c, p) for c in have for p in self.patterns
        )


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    title: str
    matches: tuple[Match, ...]
    expected_tools: frozenset[str]
    expected_false_alarms: frozenset[str]


def finding_classes(f: SecurityFinding) -> set[str]:
    return {f.issue_class} | {issue_class_for_cwe(c) for c in f.cwe_ids}


def _folded(values: object) -> frozenset[str]:
    items = [values] if isinstance(values, str) else list(values or [])
    out: set[str] = set()
    for item in items:
        cwe = normalize_cwe(str(item))
        out.add(issue_class_for_cwe(cwe) if cwe else str(item))
    return frozenset(out)


def _split_classes(values: list[str]) -> tuple[frozenset[str], tuple[str, ...]]:
    patterns = tuple(v for v in values if "*" in v)
    plain = frozenset(_folded([v for v in values if "*" not in v]))
    return plain, patterns


def load_cases(truth: dict, exclude: tuple[str, ...] = ()) -> list[Case]:
    cases: list[Case] = []
    for raw in truth.get("cases", []):
        if raw["id"] in exclude:
            continue
        entries = raw.get("match") or [
            {
                "file": raw["file"],
                "line_start": raw["line_start"],
                "line_end": raw["line_end"],
                "cwe": raw.get("cwe"),
            }
        ]
        matches = []
        for entry in entries:
            classes, patterns = _split_classes(list(entry.get("classes") or []))
            matches.append(
                Match(
                    file=entry["file"],
                    start=int(entry["line_start"]),
                    end=int(entry["line_end"]),
                    classes=classes | _folded(entry.get("cwe")),
                    patterns=patterns,
                )
            )
        cases.append(
            Case(
                id=raw["id"],
                kind=raw["kind"],
                title=raw["title"],
                matches=tuple(matches),
                expected_tools=frozenset(raw.get("expected_detecting_tools") or []),
                expected_false_alarms=frozenset(raw.get("observed_false_alarms") or []),
            )
        )
    return cases


def ensure_generated(truth: dict, repo_root: Path, source_root: Path) -> list[str]:
    """Regenerate deterministic generated benchmark files (e.g. P11's >1 MB module) when missing."""
    made: list[str] = []
    for raw in truth.get("cases", []):
        spec = raw.get("generated")
        if not spec:
            continue
        module_path = repo_root / spec["generator"]
        loader = importlib.util.spec_from_file_location(
            "secaudit_generated_" + raw["id"], module_path
        )
        if loader is None or loader.loader is None:
            raise FileNotFoundError(f"generator for {raw['id']} not found: {spec['generator']}")
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
        if module.ensure(source_root):
            made.append(raw["id"])
    return made


def _finding_row(f: SecurityFinding) -> dict:
    return {
        "id": f.id,
        "file": f.file_path,
        "lines": [f.line_start, f.line_end],
        "class": f.issue_class,
        "severity": f.severity.value,
        "tools": list(f.tools),
        "rules": sorted({f"{h.tool}:{h.rule_id}" for h in f.hits}),
        "is_test_path": f.is_test_path,
    }


def evaluate(
    audit: Audit,
    truth: dict,
    *,
    manifest: dict | None = None,
    exclude: tuple[str, ...] = (),
    inputs: dict | None = None,
) -> dict:
    cases = load_cases(truth, exclude)
    findings = list(audit.findings)
    labeled: set[str] = set()
    near_miss: dict[str, list[str]] = defaultdict(list)

    positives, negatives, baits = [], [], []
    for case in cases:
        supporting: list[SecurityFinding] = []
        overlapping: list[SecurityFinding] = []
        for m in case.matches:
            for f in findings:
                if m.overlaps(f):
                    overlapping.append(f)
                    if case.kind == "positive":
                        if m.accepts(f):
                            supporting.append(f)
                        else:
                            near_miss[f.id].append(
                                f"overlaps {case.id} but class {f.issue_class} is not accepted"
                            )
        supporting = sorted({f.id: f for f in supporting}.values(), key=lambda f: f.id)
        overlapping = sorted({f.id: f for f in overlapping}.values(), key=lambda f: f.id)
        if case.kind == "positive":
            tools = sorted({t for f in supporting for t in f.tools})
            labeled.update(f.id for f in supporting)
            positives.append(
                {
                    "id": case.id,
                    "title": case.title,
                    "detected": bool(supporting),
                    "detected_by": tools,
                    "expected_detecting_tools": sorted(case.expected_tools),
                    "matches_expectation": set(tools) == set(case.expected_tools),
                    "findings": [f.id for f in supporting],
                }
            )
        else:
            tools = sorted({t for f in overlapping for t in f.tools})
            labeled.update(f.id for f in overlapping)
            row = {
                "id": case.id,
                "title": case.title,
                "clean": not overlapping,
                "flagged_by": tools,
                "rules": sorted({f"{h.tool}:{h.rule_id}" for f in overlapping for h in f.hits}),
                "findings": [f.id for f in overlapping],
            }
            if case.kind == "negative":
                row["expected_false_alarms"] = sorted(case.expected_false_alarms)
                row["matches_expectation"] = set(tools) == set(case.expected_false_alarms)
                negatives.append(row)
            else:
                baits.append(row)

    unlabeled = []
    for f in findings:
        if f.id in labeled:
            continue
        row = _finding_row(f)
        row["note"] = (
            "; ".join(sorted(set(near_miss.get(f.id, []))))
            or "no ground-truth case covers this location"
        )
        unlabeled.append(row)

    pos_total = len(positives)
    pos_hit = sum(p["detected"] for p in positives)
    neg_total = len(negatives)
    neg_flagged = sum(not n["clean"] for n in negatives)

    per_tool: dict[str, dict] = {}
    for run in audit.tool_runs:
        in_findings = [f for f in findings if run.tool in f.tools]
        per_tool[run.tool] = {
            "status": run.status,
            "version": run.version,
            "raw_results": run.raw_results,
            "hits": run.hits,
            "unique_hits": run.unique_hits,
            "skipped_results": run.skipped_results,
            "findings": len(in_findings),
            "dedup_ratio": round(run.raw_results / len(in_findings), 2) if in_findings else None,
            "positives_detected": sum(run.tool in p["detected_by"] for p in positives),
            "negatives_flagged": sum(run.tool in n["flagged_by"] for n in negatives),
        }
    total_raw = sum(r.raw_results for r in audit.tool_runs)
    complete = [f for f in findings if f.hits and all(h.raw_ref.artifact_sha256 for h in f.hits)]
    test_findings = [f for f in findings if f.is_test_path]
    rules = {}
    if manifest:
        info = (manifest.get("tools", {}).get("semgrep", {}) or {}).get("ruleset_info")
        if isinstance(info, dict):
            rules = {"fetch_id": info.get("fetch_id"), "rulesets": info.get("rulesets")}

    return {
        "schema": METRICS_SCHEMA,
        "kind": "tool_only_baseline",
        "inputs": {
            "audit_id": audit.audit_id,
            "excluded_cases": sorted(exclude),
            "tool_versions": {r.tool: r.version for r in audit.tool_runs},
            "semgrep_rules": rules,
            **(inputs or {}),
        },
        "summary": {
            "positives": {
                "total": pos_total,
                "detected": pos_hit,
                "missed": [p["id"] for p in positives if not p["detected"]],
                "detection_rate": round(pos_hit / pos_total, 4) if pos_total else None,
            },
            "negatives": {
                "total": neg_total,
                "clean": neg_total - neg_flagged,
                "flagged": [n["id"] for n in negatives if not n["clean"]],
                "false_alarm_rate": round(neg_flagged / neg_total, 4) if neg_total else None,
            },
            "findings": {
                "total": len(findings),
                "raw_results": total_raw,
                "dedup_ratio": round(total_raw / len(findings), 2) if findings else None,
                "unlabeled": len(unlabeled),
                "in_test_paths": len(test_findings),
                "evidence_coverage": round(len(complete) / len(findings), 4) if findings else None,
            },
        },
        "per_tool": per_tool,
        "positives": sorted(positives, key=lambda r: r["id"]),
        "negatives": sorted(negatives, key=lambda r: r["id"]),
        "injection_bait": sorted(baits, key=lambda r: r["id"]),
        "unlabeled_findings": unlabeled,
        "findings_by_severity": dict(sorted(Counter(f.severity.value for f in findings).items())),
        "findings_by_owasp_2025": dict(
            sorted(Counter(f.owasp_2025 or "unmapped" for f in findings).items())
        ),
        "findings_in_test_paths": sorted(f.id for f in test_findings),
        "unmapped_cwes": list(audit.unmapped_cwes),
        "coverage": [c.model_dump(mode="json") for c in audit.coverage],
        "neutralized_files": list(audit.neutralized_files),
        "warnings": list(audit.warnings),
        "skipped_results": len(audit.skipped_results),
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_truth(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def metrics_json(metrics: dict) -> str:
    return json.dumps(metrics, indent=2, sort_keys=True) + "\n"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_markdown(m: dict) -> str:
    s = m["summary"]
    p, n, f = s["positives"], s["negatives"], s["findings"]
    out = [
        "# Tool-only baseline metrics",
        "",
        "Generated by `secaudit eval` from normalized findings. No LLM involved. Deterministic: same raw files "
        "and ground truth give the same file.",
        "",
        f"- Audit: `{m['inputs'].get('audit_id')}`; tools: "
        + ", ".join(f"{t} {v}" for t, v in m["inputs"]["tool_versions"].items()),
        f"- Ground truth sha256: `{m['inputs'].get('ground_truth_sha256', 'n/a')}`; excluded cases: "
        + (", ".join(m["inputs"]["excluded_cases"]) or "none"),
        "",
        "## Summary",
        "",
        f"- **Positives detected: {p['detected']}/{p['total']}** ({_pct(p['detection_rate'])}); "
        f"missed by every tool: {', '.join(p['missed']) or 'none'}",
        f"- **Negatives falsely flagged: {len(n['flagged'])}/{n['total']}** ({_pct(n['false_alarm_rate'])}): "
        f"{', '.join(n['flagged']) or 'none'}",
        f"- Findings: {f['total']} from {f['raw_results']} raw results (dedup ratio {f['dedup_ratio']}); "
        f"{f['unlabeled']} unlabeled, {f['in_test_paths']} in test paths; evidence coverage {_pct(f['evidence_coverage'])}",
        "",
        "## Per case: positives",
        "",
        "| Case | Detected | Detected by | Expected (Phase 1 baseline) |",
        "|---|---|---|---|",
    ]
    for r in m["positives"]:
        mark = "" if r["matches_expectation"] else " (differs)"
        out.append(
            f"| {r['id']} | {'yes' if r['detected'] else '**MISSED**'} | {', '.join(r['detected_by']) or '-'} "
            f"| {', '.join(r['expected_detecting_tools']) or '-'}{mark} |"
        )
    out += [
        "",
        "## Per case: negatives (should be clean)",
        "",
        "| Case | Result | Flagged by | Rules |",
        "|---|---|---|---|",
    ]
    for r in m["negatives"]:
        out.append(
            f"| {r['id']} | {'clean' if r['clean'] else '**flagged**'} | {', '.join(r['flagged_by']) or '-'} "
            f"| {', '.join(r['rules']) or '-'} |"
        )
    if m["injection_bait"]:
        out += ["", "## Injection bait (scanners should not react)", ""]
        out += [
            f"- {r['id']}: {'clean' if r['clean'] else 'flagged by ' + ', '.join(r['flagged_by'])}"
            for r in m["injection_bait"]
        ]
    out += [
        "",
        "## Per tool: raw results vs findings",
        "",
        "| Tool | Status | Raw results | Unique hits | Findings containing it | Raw/finding | Positives detected | Negatives flagged |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for tool, t in m["per_tool"].items():
        out.append(
            f"| {tool} | {t['status']} | {t['raw_results']} | {t['unique_hits']} | {t['findings']} "
            f"| {t['dedup_ratio']} | {t['positives_detected']} | {t['negatives_flagged']} |"
        )
    out += [
        "",
        f"## Unlabeled findings ({len(m['unlabeled_findings'])}): for manual labeling, NOT counted as false positives",
        "",
    ]
    out += ["| Finding | Location | Class | Severity | Tools | Note |", "|---|---|---|---|---|---|"]
    for u in m["unlabeled_findings"]:
        out.append(
            f"| {u['id']} | {u['file']}:{u['lines'][0]}-{u['lines'][1]} | {u['class']} | {u['severity']} "
            f"| {', '.join(u['tools'])} | {u['note']} |"
        )
    out += ["", "## Coverage and warnings", ""]
    for c in m["coverage"]:
        out.append(
            f"- {c['tool']}: coverage **{c['status']}**"
            + (f" ({c['note']})" if c.get("note") else "")
        )
        out += [f"  - limitation: {lim}" for lim in c["limitations"]]
    out += [
        f"- neutralized files: {', '.join(m['neutralized_files']) or 'none'}",
        f"- CWEs without an OWASP Top 10:2025 category: {', '.join(m['unmapped_cwes']) or 'none'}",
    ]
    out += [f"- warning: {w}" for w in m["warnings"]]
    return "\n".join(out) + "\n"
