"""Deduplication, merging and fingerprints. Every rule here is documented in docs/PHASE2_DESIGN.md.

a) identical hits of one tool (same rule, file, lines) collapse;
b) cross-rule / cross-tool merge ONLY with the same file, overlapping lines AND a shared issue
   class (equal CWE, or a reviewed equivalence); different classes are NEVER merged;
c) pip-audit: one finding per (package, version), advisories unioned, fix versions kept;
d) a merged finding keeps ALL its hits; severity = the highest mapped one, with `severity_basis`;
e) fingerprint = sha256(schema tag | issue_class | file | masked text of the flagged lines);
f) deterministic everywhere (stable sort keys), so re-normalizing yields identical ids.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from secaudit.core.models import (
    Confidence,
    SecurityFinding,
    Severity,
    ToolHit,
)
from secaudit.core.normalize.cwe import issue_class_for_cwe
from secaudit.core.normalize.masking import mask_message
from secaudit.core.normalize.owasp import owasp_category
from secaudit.core.normalize.pip_audit import canonical_name
from secaudit.core.normalize.severity_map import map_severity
from secaudit.core.normalize.snippets import flagged_text, is_test_path, make_snippet

# Names the fingerprint ALGORITHM, not the export schema: a SCHEMA_VERSION bump must not change ids.
FINGERPRINT_TAG = "secaudit-fp-v1"


def hit_classes(hit: ToolHit) -> frozenset[str]:
    """Issue classes of a hit: equivalence-folded CWEs, else one rule-specific class."""
    if hit.tool == "pip-audit" and hit.package:
        return frozenset({f"vuln:{canonical_name(hit.package)}@{hit.package_version}"})
    if hit.cwe_ids:
        return frozenset(issue_class_for_cwe(c) for c in hit.cwe_ids)
    return frozenset({f"rule:{hit.tool}:{hit.rule_id}"})


def _class_key(cls: str) -> tuple[int, int, str]:
    if cls.startswith("CWE-") and cls[4:].isdigit():
        return (0, int(cls[4:]), cls)
    return (1, 0, cls)


def collapse_identical(hits: list[ToolHit]) -> tuple[list[ToolHit], int]:
    """Rule (a). Keeps the first occurrence (lowest pointer); returns (kept, collapsed_count)."""
    position: dict[tuple, int] = {}
    kept: list[ToolHit] = []
    for hit in sorted(hits, key=lambda h: (h.tool, h.raw_ref.pointer_sort, h.rule_id)):
        key = (
            hit.tool,
            hit.rule_id,
            hit.file_path,
            hit.line_start,
            hit.line_end,
            hit.package,
            hit.package_version,
        )
        if key in position:
            first = kept[position[key]]
            aliases = tuple(sorted(set(first.aliases) | set(hit.aliases)))
            fixes = tuple(sorted(set(first.fix_versions) | set(hit.fix_versions)))
            if (aliases, fixes) != (first.aliases, first.fix_versions):
                kept[position[key]] = first.model_copy(
                    update={"aliases": aliases, "fix_versions": fixes}
                )
            continue
        position[key] = len(kept)
        kept.append(hit)
    return kept, len(hits) - len(kept)


@dataclass
class _Cluster:
    file_path: str
    start: int
    end: int
    classes: frozenset[str]
    hits: list[ToolHit] = field(default_factory=list)


def cluster_hits(hits: list[ToolHit]) -> list[_Cluster]:
    """Rules (b) and (c). Greedy, deterministic (hits are processed in a fixed order)."""
    clusters: list[_Cluster] = []
    ordered = sorted(
        hits,
        key=lambda h: (
            h.file_path,
            h.line_start,
            h.line_end,
            h.tool,
            h.rule_id,
            h.raw_ref.pointer_sort,
        ),
    )
    for hit in ordered:
        classes = hit_classes(hit)
        target = None
        for cluster in clusters:
            if cluster.file_path != hit.file_path:
                continue
            if hit.tool == "pip-audit" or any(h.tool == "pip-audit" for h in cluster.hits):
                if classes == cluster.classes:  # same (package, version)
                    target = cluster
                    break
                continue
            if (
                hit.line_start <= cluster.end
                and hit.line_end >= cluster.start
                and classes & cluster.classes
            ):
                target = cluster
                break
        if target is None:
            clusters.append(_Cluster(hit.file_path, hit.line_start, hit.line_end, classes, [hit]))
        else:
            target.hits.append(hit)
            target.start = min(target.start, hit.line_start)
            target.end = max(target.end, hit.line_end)
            target.classes = target.classes & classes  # narrowing keeps later merges conservative
    return clusters


def _best_hit(hits: list[ToolHit]) -> tuple[ToolHit, Severity, str, str | None]:
    best, best_sev, best_basis, best_warn = None, Severity.UNKNOWN, "", None
    for hit in sorted(hits, key=lambda h: (h.tool, h.rule_id, h.raw_ref.pointer_sort)):
        sev, basis, warn = map_severity(hit.tool, raw=hit.raw_severity)
        if best is None or sev.rank > best_sev.rank:
            best, best_sev, best_basis, best_warn = (
                hit,
                sev,
                f"{hit.tool}:{hit.rule_id} ({basis})",
                warn,
            )
    if best is None:  # unreachable: clusters always hold >= 1 hit
        raise ValueError("empty cluster")
    return best, best_sev, best_basis, best_warn


def _title(hit: ToolHit, hits: list[ToolHit]) -> str:
    if hit.tool == "pip-audit":
        advisories = len({h.rule_id for h in hits})
        return f"{hit.package} {hit.package_version} has {advisories} known vulnerabilit" + (
            "y" if advisories == 1 else "ies"
        )
    sentence = hit.message.split(". ")[0].strip() or hit.rule_name or hit.rule_id
    return mask_message(sentence, 200)


def build_findings(
    hits: list[ToolHit],
    source_root: Path | None,
    gitleaks_lines: dict[str, set[int]],
) -> tuple[list[SecurityFinding], list[str], int]:
    """Cluster hits into findings. Returns (findings, warnings, collapsed_identical_hits)."""
    kept, collapsed = collapse_identical(hits)
    warnings: list[str] = []
    drafts = []
    for cluster in cluster_hits(kept):
        chits = cluster.hits
        best, severity, basis, warn = _best_hit(chits)
        if warn and warn not in warnings:
            warnings.append(warn)
        classes = sorted(cluster.classes or hit_classes(best), key=_class_key)
        issue_class = classes[0]
        narrow = min(
            chits, key=lambda h: (h.line_end - h.line_start, h.line_start, h.tool, h.rule_id)
        )
        flagged = gitleaks_lines.get(cluster.file_path, set())
        text = flagged_text(
            source_root, cluster.file_path, narrow.line_start, narrow.line_end, flagged
        )
        if text is None:
            basis_kind, material = "location", f"L{narrow.line_start}-{narrow.line_end}"
        else:
            basis_kind, material = "content", text
        fingerprint = hashlib.sha256(
            "\x1f".join([FINGERPRINT_TAG, issue_class, cluster.file_path, material]).encode()
        ).hexdigest()
        cwes = sorted({c for h in chits for c in h.cwe_ids}, key=_class_key)
        confidence = max(
            (h.confidence for h in chits), key=lambda c: c.rank, default=Confidence.UNKNOWN
        )
        aliases = tuple(sorted({a for h in chits for a in h.aliases}))
        fixes = tuple(sorted({f for h in chits for f in h.fix_versions}))
        drafts.append(
            dict(
                fingerprint=fingerprint,
                fingerprint_basis=basis_kind,
                title=_title(best, chits),
                issue_class=issue_class,
                file_path=cluster.file_path,
                line_start=cluster.start,
                line_end=cluster.end,
                hits=tuple(
                    sorted(chits, key=lambda h: (h.tool, h.rule_id, h.raw_ref.pointer_sort))
                ),
                cwe_ids=tuple(cwes),
                owasp_2025=owasp_category(
                    tuple(cwes), primary=issue_class if issue_class.startswith("CWE-") else None
                ),
                severity=severity,
                severity_basis=basis,
                confidence=confidence,
                snippet=make_snippet(
                    source_root, cluster.file_path, cluster.start, cluster.end, flagged
                ),
                is_test_path=is_test_path(cluster.file_path),
                aliases=aliases,
                fix_versions=fixes,
            )
        )
    # ids: fingerprint + ordinal among equal fingerprints (ordered by position) -> idempotent
    by_fp: dict[str, list[dict]] = defaultdict(list)
    for d in drafts:
        by_fp[d["fingerprint"]].append(d)
    findings: list[SecurityFinding] = []
    for fp, group in by_fp.items():
        for ordinal, d in enumerate(sorted(group, key=lambda x: (x["line_start"], x["line_end"]))):
            fid = "F-" + hashlib.sha256(f"{fp}|{ordinal}".encode()).hexdigest()[:12]
            findings.append(SecurityFinding(id=fid, **d))
    findings.sort(key=lambda f: (f.file_path, f.line_start, f.issue_class, f.id))
    return findings, warnings, collapsed
