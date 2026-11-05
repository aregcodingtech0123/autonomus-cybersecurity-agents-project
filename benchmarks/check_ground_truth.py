"""Validate the benchmark ground truth against the real benchmark target files.

`check` validates benchmarks/expected_findings.yaml. Per case: the file exists inside the target,
the 1-indexed line range lies within the file, and the `anchor` substring occurs inside that range.
Also checks schema, id uniqueness and that the full planned case set is present.

`check_expansion` validates benchmarks/expected_findings_expansion.yaml (Phase 2C-A): the same
per-case checks plus the pre-registration fields, the quotas, the README banners and the sha256
manifest of the existing target. Target code is parsed, never imported or executed.

Usage: python benchmarks/check_ground_truth.py   (exit code 1 on any problem)
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

BENCH_DIR = Path(__file__).resolve().parent
DEFAULT_GROUND_TRUTH = BENCH_DIR / "expected_findings.yaml"
DEFAULT_EXPANSION = BENCH_DIR / "expected_findings_expansion.yaml"
DEFAULT_MANIFEST = BENCH_DIR / "vuln_python_app.sha256.json"
TARGETS_ROOT = BENCH_DIR / "targets"
REPO_ROOT = BENCH_DIR.parent

KINDS = {"positive", "negative", "injection_bait", "related_informational"}
KIND_PREFIX = {
    "positive": "P",
    "negative": "N",
    "injection_bait": "I",
    "related_informational": "R",
}
TOOLS = {"semgrep", "bandit", "gitleaks", "pip-audit"}
REQUIRED = ("id", "title", "kind", "file", "line_start", "line_end", "anchor", "notes")
CWE_RE = re.compile(r"^CWE-\d+$")
EXPECTED_IDS = (
    {f"P{i:02d}" for i in range(1, 11)}
    | {"P08b", "P11"}
    | {f"N{i:02d}" for i in range(1, 8)}
    | {f"I{i:02d}" for i in range(1, 3)}
    | {"R01", "R02"}
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

    generated_problems = _ensure_generated(doc["cases"], target)
    seen: set[str] = set()
    for index, case in enumerate(doc["cases"]):
        cid = case.get("id", f"<case #{index}>")
        problems.extend(f"{cid}: {msg}" for msg in _check_case(case, target))
        if cid in seen:
            problems.append(f"{cid}: duplicate id")
        seen.add(cid)

    problems.extend(generated_problems)
    problems.extend(_check_related(doc["cases"]))
    missing = EXPECTED_IDS - seen
    if missing:
        problems.append(f"missing planned cases: {sorted(missing)}")
    unexpected = seen - EXPECTED_IDS
    if unexpected:
        problems.append(f"unplanned case ids: {sorted(unexpected)}")
    return problems


def _ensure_generated(cases: list, target: Path) -> list[str]:
    """Create deterministic generated benchmark files (P11) and verify their pinned content hash."""
    problems: list[str] = []
    for case in cases:
        spec = case.get("generated") if isinstance(case, dict) else None
        if not spec:
            continue
        cid = case.get("id", "?")
        generator = (REPO_ROOT / str(spec.get("generator", ""))).resolve()
        if not generator.is_file() or not generator.is_relative_to(REPO_ROOT):
            problems.append(f"{cid}: generator not found: {spec.get('generator')!r}")
            continue
        loader = importlib.util.spec_from_file_location(f"gt_generator_{cid}", generator)
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
        module.ensure(target)
        if module.expected_sha256() != spec.get("sha256"):
            problems.append(
                f"{cid}: generator output sha256 differs from the pinned {spec.get('sha256')!r}"
            )
        if len(module.content()) < int(spec.get("min_bytes", 0)):
            problems.append(f"{cid}: generated file is smaller than min_bytes")
        if module.RELATIVE_PATH != spec.get("path") or module.RELATIVE_PATH != case.get("file"):
            problems.append(f"{cid}: generated path does not match the case file")
        if module.vulnerable_line() != case.get("line_start"):
            actual, stated = module.vulnerable_line(), case.get("line_start")
            problems.append(f"{cid}: vulnerable line is {actual}, case says {stated}")
    return problems


def _check_related(cases: list) -> list[str]:
    """`related_to` of a related_informational item must name an existing positive or negative."""
    kinds = {c.get("id"): c.get("kind") for c in cases if isinstance(c, dict)}
    problems: list[str] = []
    for case in cases:
        if not isinstance(case, dict) or case.get("kind") != "related_informational":
            continue
        target = case.get("related_to")
        if kinds.get(target) not in ("positive", "negative"):
            problems.append(
                f"{case.get('id')}: related_to {target!r} must name an existing positive/negative"
            )
    return problems


def _check_match(case: dict, target: Path) -> list[str]:
    """Optional `match:` entries (Phase 2A): ranges and accepted classes for `secaudit eval`."""
    problems: list[str] = []
    entries = case.get("match")
    if entries is None:
        if case["kind"] in ("positive", "related_informational") and case.get("cwe") is None:
            problems.append(f"{case['kind']} case without cwe needs a match entry with classes")
        return problems
    if not isinstance(entries, list) or not entries:
        return ["match must be a non-empty list"]
    for index, entry in enumerate(entries):
        where = f"match[{index}]"
        if not isinstance(entry, dict) or not {"file", "line_start", "line_end"} <= set(entry):
            problems.append(f"{where}: needs file, line_start, line_end")
            continue
        path = (target / str(entry["file"])).resolve()
        if not path.is_relative_to(target) or not path.is_file():
            problems.append(f"{where}: file does not exist inside the target: {entry['file']!r}")
            continue
        total = len(path.read_text(encoding="utf-8").splitlines())
        a, b = entry["line_start"], entry["line_end"]
        if not (isinstance(a, int) and isinstance(b, int) and 1 <= a <= b <= total):
            problems.append(
                f"{where}: line range {a}-{b} invalid for {entry['file']} ({total} lines)"
            )
        cwes = entry.get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        if any(not CWE_RE.match(str(c)) for c in cwes):
            problems.append(f"{where}: malformed cwe in {cwes!r}")
        if case["kind"] in ("positive", "related_informational") and not (
            cwes or entry.get("classes")
        ):
            problems.append(f"{where}: positive match needs cwe or classes")
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
    for key in ("expected_detecting_tools", "observed_false_alarms", "observed_by_tools"):
        unknown = set(case.get(key) or []) - TOOLS
        if unknown:
            problems.append(f"unknown tools in {key}: {sorted(unknown)}")
    if kind != "positive" and case.get("expected_detecting_tools"):
        problems.append("only positive cases may list expected_detecting_tools")
    if kind != "negative" and case.get("observed_false_alarms"):
        problems.append("only negative cases may list observed_false_alarms")
    if kind != "related_informational" and case.get("observed_by_tools"):
        problems.append("only related_informational cases may list observed_by_tools")
    if kind == "related_informational" and case.get("expected_detecting_tools"):
        problems.append(
            "related_informational items are not detections: no expected_detecting_tools"
        )

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
    problems.extend(_check_match(case, target))
    return problems


# ---------------------------------------------------------------- Phase 2C-A expansion

# Named explicitly: nothing here ever lists benchmarks/targets, so an unknown target cannot slip in.
EXISTING_TARGET = "vuln_python_app"
EXPANSION_TARGETS = ("admin_portal", "ops_toolbox", "shop_api")
BANNER = "INTENTIONALLY VULNERABLE - FOR SCANNER BENCHMARKING ONLY - NEVER DEPLOY"
MIN_TARGET_FILES, MAX_TARGET_FILES = 8, 15
GENERATED_FILE = "webshop/generated_big_module.py"  # git-ignored; P11 pins its generator's sha256

EXPANSION_FIRST_ID = {"positive": 12, "negative": 8, "injection_bait": 3, "masking_probe": 1}
EXPANSION_PREFIX = {"positive": "P", "negative": "N", "injection_bait": "I", "masking_probe": "M"}
EXPANSION_QUOTA = {"positive": 14, "negative": 11, "injection_bait": 8, "masking_probe": 6}
TOTAL_QUOTA = {"positive": 24, "negative": 17}
MIN_TOOL_BLIND = 5
MIN_PINNED_DEPENDENCY_CASES = 2
REQUIRED_BAIT_GOALS = {
    "mark_false_positive",
    "lower_severity",
    "ignore_file",
    "reveal_system_prompt",
    "run_command",
    "exfiltrate_secrets",
}
EXPANSION_REQUIRED = (
    "id",
    "target",
    "kind",
    "title",
    "file",
    "line_start",
    "line_end",
    "anchor",
    "rationale",
    "context",
    "confidence_in_label",
)
PRIOR_CLASSES = {"sast", "secrets", "sca"}
PRIOR_VALUES = {"yes", "maybe", "no"}
EXPOSURES = {"public", "authenticated", "internal", "unreachable"}
CONFIDENCE = {"high", "medium", "low"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def target_files(target: Path) -> list[Path]:
    """Every file below one explicitly named target, in a stable order on every OS."""
    files = (p for p in target.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    return sorted(files, key=lambda p: p.relative_to(target).as_posix())


def existing_target_hashes(target: Path) -> dict[str, str]:
    """{relative posix path: sha256} of the existing target, without the generated module."""
    hashes = {}
    for path in target_files(target):
        relative = path.relative_to(target).as_posix()
        if relative != GENERATED_FILE:
            hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _check_existing_target(target: Path, manifest_path: Path) -> list[str]:
    if not manifest_path.is_file():
        return [f"manifest not found: {manifest_path.name}"]
    if not target.is_dir():
        return [f"existing target not found: {target.name}"]
    pinned = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = existing_target_hashes(target)
    problems = [f"existing target file added: {p}" for p in sorted(set(actual) - set(pinned))]
    problems += [f"existing target file removed: {p}" for p in sorted(set(pinned) - set(actual))]
    problems += [
        f"existing target file modified: {p}"
        for p in sorted(set(actual) & set(pinned))
        if actual[p] != pinned[p]
    ]
    return problems


def _check_target_dir(name: str, target: Path) -> list[str]:
    if not target.is_dir():
        return [f"{name}: target directory does not exist"]
    problems = []
    readme = target / "README.md"
    if not readme.is_file() or BANNER not in readme.read_text(encoding="utf-8"):
        problems.append(f"{name}: README.md does not carry the banner")
    files = target_files(target)
    if not MIN_TARGET_FILES <= len(files) <= MAX_TARGET_FILES:
        problems.append(
            f"{name}: has {len(files)} files, allowed {MIN_TARGET_FILES}-{MAX_TARGET_FILES}"
        )
    for path in files:
        if path.suffix != ".py":
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            problems.append(f"{name}: {path.name} does not parse: {exc.msg}")
    return problems


def _check_prior(case: dict) -> list[str]:
    prior = case.get("prior_detectability")
    if case["kind"] not in ("positive", "negative") and prior is None:
        return []
    if not isinstance(prior, dict):
        return ["missing prior_detectability"]
    if set(prior) != PRIOR_CLASSES:
        return [f"prior_detectability needs exactly {sorted(PRIOR_CLASSES)}"]
    problems = [
        f"prior_detectability.{k}: {v!r} is not one of {sorted(PRIOR_VALUES)}"
        for k, v in sorted(prior.items())
        if v not in PRIOR_VALUES
    ]
    if prior["secrets"] == "yes":
        problems.append('prior_detectability.secrets must not be "yes": Gitleaks was not run')
    return problems


def _check_context(case: dict) -> list[str]:
    context = case["context"]
    if not isinstance(context, dict):
        return ["context must be a mapping"]
    problems = []
    if context.get("exposure") not in EXPOSURES:
        problems.append(f"invalid context.exposure {context.get('exposure')!r}")
    if context.get("attacker_input") not in ("yes", "no"):
        problems.append(f"invalid context.attacker_input {context.get('attacker_input')!r}")
    if not str(context.get("notes") or "").strip():
        problems.append("missing context.notes")
    return problems


def _check_advisories(case: dict) -> list[str]:
    problems = []
    for index, advisory in enumerate(case.get("advisories") or []):
        missing = {"id", "package", "affected", "source", "checked"} - set(advisory)
        if missing:
            problems.append(f"advisories[{index}]: missing {sorted(missing)}")
        elif not DATE_RE.match(str(advisory["checked"])):
            problems.append(f"advisories[{index}]: checked must be a quoted YYYY-MM-DD")
    needs_them = any("vuln:*" in (e.get("classes") or []) for e in case.get("match") or [])
    if needs_them and not case.get("advisories"):
        problems.append("dependency positive without advisories")
    return problems


def _check_kind_fields(case: dict) -> list[str]:
    kind = case["kind"]
    problems = []
    if kind == "positive" and not case.get("match"):
        problems.append("positive without match entries")
    if kind != "positive" and (case.get("tool_blind") or case.get("advisories")):
        problems.append("tool_blind and advisories are for positives only")
    if kind == "injection_bait" and not (case.get("carrier") and case.get("goal")):
        problems.append("injection_bait needs carrier and goal")
    if kind == "masking_probe" and not case.get("canary"):
        problems.append("masking_probe without canary")
    if kind != "masking_probe" and case.get("canary"):
        problems.append("only masking_probe may have a canary")
    return problems


def _check_canary(case: dict, window: str) -> list[str]:
    canary = case.get("canary")
    if case["kind"] != "masking_probe" or not canary:
        return []
    fragments = case.get("canary_fragments")
    if fragments is None:
        return [] if canary in window else ["canary not found in the stated lines"]
    if "".join(fragments) != canary:
        return ["canary_fragments do not join to canary"]
    return [f"canary fragment {f!r} not in the stated lines" for f in fragments if f not in window]


def _check_expansion_case(case: dict, targets_root: Path) -> list[str]:
    problems = [f"missing field '{f}'" for f in EXPANSION_REQUIRED if not case.get(f)]
    if problems:
        return problems
    kind = case["kind"]
    if kind not in EXPANSION_PREFIX:
        return [f"invalid kind {kind!r}"]
    if case["target"] not in EXPANSION_TARGETS:
        return [f"unknown target {case['target']!r}"]
    if case.get("cwe") is not None and not CWE_RE.match(str(case["cwe"])):
        problems.append(f"malformed cwe {case['cwe']!r}")
    if not str(case["rationale"]).strip():
        problems.append("missing rationale")
    if case["confidence_in_label"] not in CONFIDENCE:
        problems.append(f"invalid confidence_in_label {case['confidence_in_label']!r}")
    elif case["confidence_in_label"] != "high" and not case.get("label_doubt"):
        problems.append("confidence below high needs label_doubt")
    problems += _check_prior(case) + _check_context(case)
    problems += _check_kind_fields(case) + _check_advisories(case)

    target = (targets_root / case["target"]).resolve()
    file_path = (target / str(case["file"])).resolve()
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
    problems += _check_canary(case, window)
    if case.get("match") is not None:
        problems += _check_match(case, target)
    return problems


def _footprint(case: dict) -> list[tuple[str, str, int, int]]:
    """Every (target, file, start, end) a case claims, match ranges included."""
    target = case.get("target")
    spans = [(target, case.get("file"), case.get("line_start"), case.get("line_end"))]
    for entry in case.get("match") or []:
        if isinstance(entry, dict):
            spans.append(
                (target, entry.get("file"), entry.get("line_start"), entry.get("line_end"))
            )
    return [s for s in spans if isinstance(s[2], int) and isinstance(s[3], int)]


def _check_overlaps(cases: list[dict]) -> list[str]:
    """`secaudit eval` flags a negative or bait on any overlapping finding, so ranges stay apart."""
    problems = []
    for index, left in enumerate(cases):
        for right in cases[index + 1 :]:
            for a in _footprint(left):
                if any(a[:2] == b[:2] and a[2] <= b[3] and b[2] <= a[3] for b in _footprint(right)):
                    problems.append(f"{left.get('id')} and {right.get('id')} overlap in {a[1]}")
                    break
    return problems


def _id_number(case_id: object) -> int | None:
    match = re.fullmatch(r"[A-Z](\d+)", str(case_id))
    return int(match.group(1)) if match else None


def _check_ids(cases: list[dict], existing_ids: set[str]) -> list[str]:
    problems = []
    seen: set[str] = set()
    for case in cases:
        cid = str(case.get("id"))
        if cid in seen:
            problems.append(f"{cid}: duplicate id")
        if cid in existing_ids:
            problems.append(f"{cid}: id already used in {DEFAULT_GROUND_TRUTH.name}")
        seen.add(cid)
    for kind, prefix in EXPANSION_PREFIX.items():
        numbers = sorted(
            {
                _id_number(c.get("id"))
                for c in cases
                if c.get("kind") == kind and str(c.get("id")).startswith(prefix)
            }
            - {None}
        )
        wrong_prefix = [
            c.get("id")
            for c in cases
            if c.get("kind") == kind and not str(c.get("id")).startswith(prefix)
        ]
        if wrong_prefix:
            problems.append(f"{kind}: id prefix must be {prefix}: {wrong_prefix}")
        first = EXPANSION_FIRST_ID[kind]
        if numbers and numbers != list(range(first, first + len(numbers))):
            problems.append(f"{kind}: ids must run from {prefix}{first:02d} without gaps")
    return problems


def _check_quotas(cases: list[dict], existing_cases: list[dict]) -> list[str]:
    problems = []

    def count(items: list[dict], kind: str) -> int:
        return sum(1 for c in items if c.get("kind") == kind)

    for kind, minimum in EXPANSION_QUOTA.items():
        if count(cases, kind) < minimum:
            problems.append(f"quota not met: {count(cases, kind)} new {kind}, need {minimum}")
    for kind, minimum in TOTAL_QUOTA.items():
        total = count(cases, kind) + count(existing_cases, kind)
        if total < minimum:
            problems.append(f"quota not met: {total} total {kind}, need {minimum}")
    blind = sum(1 for c in cases if c.get("kind") == "positive" and c.get("tool_blind"))
    if blind < MIN_TOOL_BLIND:
        problems.append(f"quota not met: {blind} tool_blind positives, need {MIN_TOOL_BLIND}")
    dependency = [c for c in cases if c.get("advisories")]
    pinned = [c for c in dependency if not c.get("unpinned")]
    if len(pinned) < MIN_PINNED_DEPENDENCY_CASES or len({c.get("file") for c in pinned}) < 2:
        problems.append("quota not met: pinned vulnerable packages need two different manifests")
    if not any(c.get("unpinned") for c in dependency):
        problems.append("quota not met: no unpinned requirement case")
    goals = {c.get("goal") for c in cases if c.get("kind") == "injection_bait"}
    if not REQUIRED_BAIT_GOALS <= goals:
        problems.append(f"quota not met: bait goals missing {sorted(REQUIRED_BAIT_GOALS - goals)}")
    return problems


def _check_near_cases(cases: list[dict]) -> list[str]:
    ids = {c.get("id") for c in cases}
    return [
        f"{c.get('id')}: near_case {c['near_case']!r} does not exist"
        for c in cases
        if c.get("near_case") and c["near_case"] not in ids
    ]


def check_expansion(
    path: Path = DEFAULT_EXPANSION,
    targets_root: Path = TARGETS_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST,
    existing_path: Path = DEFAULT_GROUND_TRUTH,
) -> list[str]:
    """Return a list of human-readable problems; empty means the expansion is valid."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list):
        return [f"{path.name}: top level must be a mapping with a 'cases' list"]
    if not all(isinstance(c, dict) for c in doc["cases"]):
        return [f"{path.name}: every case must be a mapping"]
    cases = doc["cases"]
    existing_cases = yaml.safe_load(existing_path.read_text(encoding="utf-8"))["cases"]

    problems = _check_ids(cases, {str(c["id"]) for c in existing_cases})
    for case in cases:
        problems += [f"{case.get('id')}: {m}" for m in _check_expansion_case(case, targets_root)]
    problems += _check_overlaps(cases)
    problems += _check_near_cases(cases)
    problems += _check_quotas(cases, existing_cases)
    for name in EXPANSION_TARGETS:
        problems += _check_target_dir(name, targets_root / name)
    problems += _check_existing_target(targets_root / EXISTING_TARGET, manifest_path)
    return problems


def main() -> int:
    results = {
        DEFAULT_GROUND_TRUTH.name: check(),
        DEFAULT_EXPANSION.name: check_expansion(),
    }
    failed = False
    for name, problems in results.items():
        for problem in problems:
            print(f"FAIL {name}: {problem}", file=sys.stderr)
        if problems:
            failed = True
        else:
            print(f"ground truth OK: {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
