"""Generic SARIF reader plus the per-tool quirks recorded in Phase 0/1 (see DISCOVERY.md).

Rules of this module:
  * never crash on unexpected input; every raw result becomes a ToolHit or a SkippedResult;
  * NEVER read `region.snippet`, `contextRegion` or any other code text: hits carry location and
    metadata only (raw SARIF is secret-bearing, derived data must not be);
  * paths that escape the source root are dropped, counted and reported as a warning.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secaudit.core.models import Confidence, RawRef, SkippedResult, ToolHit
from secaudit.core.normalize.cwe import extract_cwes, gitleaks_cwe
from secaudit.core.normalize.masking import mask_message, sanitize
from secaudit.core.normalize.paths import normalize_source_path
from secaudit.core.normalize.severity_map import map_confidence

MAX_RESULTS_PER_ARTIFACT = 200_000


@dataclass
class ParseResult:
    hits: list[ToolHit] = field(default_factory=list)
    skipped: list[SkippedResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_count: int = 0


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _text(value: object, limit: int) -> str | None:
    return sanitize(value, limit) if isinstance(value, str) and value else None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def parse_sarif(
    tool: str, doc: object, *, artifact: str, sha256: str, tool_version: str | None
) -> ParseResult:
    out = ParseResult()
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        out.warnings.append(f"{tool}: artifact is not a SARIF document with a runs list")
        return out
    escapes = 0
    unreviewed_gitleaks: set[str] = set()
    for run_index, run in enumerate(doc["runs"]):
        driver = _dict(_dict(_dict(run).get("tool")).get("driver"))
        rules = [r for r in _list(driver.get("rules")) if isinstance(r, dict)]
        by_id = {r["id"]: r for r in rules if isinstance(r.get("id"), str)}
        version = tool_version
        if (
            version is None and tool != "gitleaks"
        ):  # Gitleaks writes a bogus driver version (v8.0.0)
            version = _text(driver.get("semanticVersion") or driver.get("version"), 50)
        results = _list(_dict(run).get("results"))
        if len(results) > MAX_RESULTS_PER_ARTIFACT:
            out.warnings.append(
                f"{tool}: {len(results)} results; only the first {MAX_RESULTS_PER_ARTIFACT} read"
            )
            results = results[:MAX_RESULTS_PER_ARTIFACT]
        for index, result in enumerate(results):
            pointer = f"/runs/{run_index}/results/{index}"
            out.raw_count += 1
            try:
                hit, reason, extra_warning = _parse_result(
                    tool,
                    result,
                    rules,
                    by_id,
                    version,
                    RawRef(artifact=artifact, artifact_sha256=sha256, pointer=pointer),
                    unreviewed_gitleaks,
                )
            except Exception as exc:  # noqa: BLE001 - hostile input must never crash normalization
                hit, reason, extra_warning = None, f"malformed_result:{type(exc).__name__}", None
            if extra_warning:
                out.warnings.append(extra_warning)
            if hit is not None:
                out.hits.append(hit)
            else:
                if reason in {
                    "path_escapes_source_root",
                    "absolute_path_outside_source_root",
                    "absolute_path",
                }:
                    escapes += 1
                out.skipped.append(SkippedResult(tool=tool, pointer=pointer, reason=str(reason)))
    if escapes:
        out.warnings.append(
            f"{tool}: dropped {escapes} result(s) whose path lies outside the source root"
        )
    out.warnings.extend(
        f"gitleaks rule {r!r} is not in the reviewed rule table (mapped to the default CWE)"
        for r in sorted(unreviewed_gitleaks)
    )
    return out


def _parse_result(tool, result, rules, by_id, version, ref, unreviewed_gitleaks):
    result = _dict(result)
    rule_id = _text(result.get("ruleId"), 300)
    rule: dict = by_id.get(rule_id, {}) if rule_id else {}
    index = result.get("ruleIndex")
    if not rule and isinstance(index, int) and 0 <= index < len(rules):
        rule = rules[index]
        rule_id = rule_id or _text(rule.get("id"), 300)
    if not rule_id:
        return None, "missing_rule_id", None

    locations = [loc for loc in _list(result.get("locations")) if isinstance(loc, dict)]
    if not locations:
        return None, "no_location", None
    physical = _dict(locations[0].get("physicalLocation"))
    path, why = normalize_source_path(_dict(physical.get("artifactLocation")).get("uri"))
    if path is None:
        return None, why, None
    region = _dict(physical.get("region"))
    start = _int(region.get("startLine"))
    if start is None:
        return None, "no_line", None
    end = _int(region.get("endLine")) or start
    end = max(end, start)

    rule_props = _dict(rule.get("properties"))
    result_props = _dict(result.get("properties"))
    tags = tuple(
        t
        for t in _list(rule_props.get("tags")) + _list(result_props.get("tags"))
        if isinstance(t, str)
    )
    cwe_ids = extract_cwes(tags)
    extra_warning = None
    raw_severity: str | None = None
    if tool == "bandit":
        raw_severity = _text(result_props.get("issue_severity"), 20)
    elif tool == "semgrep":
        raw_severity = _text(_dict(rule.get("defaultConfiguration")).get("level"), 20) or _text(
            result.get("level"), 20
        )
    elif tool == "gitleaks":
        cwe, reviewed = gitleaks_cwe(rule_id)
        cwe_ids = (cwe,)
        if not reviewed:
            unreviewed_gitleaks.add(rule_id)
    else:
        raw_severity = _text(result.get("level"), 20)

    confidence = map_confidence(
        tool,
        raw=_text(result_props.get("issue_confidence"), 20),
        tags=tuple(t for t in tags if isinstance(t, str)),
        precision=_text(rule_props.get("precision"), 20),
    )
    message = _dict(result.get("message")).get("text")
    if not isinstance(message, str):
        message = _dict(rule.get("shortDescription")).get("text") or ""
    name = _dict(rule.get("shortDescription")).get("text") or rule.get("name")
    hit = ToolHit(
        tool=tool,
        tool_version=version,
        rule_id=rule_id,
        rule_name=mask_message(name, 200) if isinstance(name, str) and name else None,
        raw_severity=raw_severity,
        confidence=confidence if isinstance(confidence, Confidence) else Confidence.UNKNOWN,
        message=mask_message(message),
        file_path=path,
        line_start=start,
        line_end=end,
        cwe_ids=cwe_ids,
        raw_ref=ref,
    )
    return hit, None, extra_warning
