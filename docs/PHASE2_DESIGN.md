# Phase 2A design: normalization core and tool-only metrics

Scope: turn raw scanner output into versioned, de-duplicated, secret-free findings and measure tool-only detection
against `benchmarks/expected_findings.yaml`. Out of scope: LLMs, agents, storage, reports, API (see ROADMAP).
Rule of thumb used throughout: **raw files are secret-bearing and untouched; every derived field is secret-free.**

## 1. Data model (`core/models.py`, `SCHEMA_VERSION = "1"`)
- `Severity` CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN, `Confidence` HIGH/MEDIUM/LOW/UNKNOWN.
- `ToolHit`: tool, tool_version, rule_id, raw_severity (as emitted or null), message (**masked**), file_path (POSIX, relative to the
  source root), line_start/end, cwe_ids, `raw_ref` (artifact path relative to the audit dir + artifact sha256 + JSON pointer).
  A hit never contains SARIF `snippet`/`contextRegion` text.
- `SecurityFinding`: id, fingerprint, `fingerprint_basis` (`content` | `location`), title, issue_class, location, `hits` (**min length 1**:
  a finding without tool evidence cannot be constructed), cwe_ids, owasp_2025 (category id or null), severity + `severity_basis`,
  confidence, snippet (masked, bounded), is_test_path, status `open`, and EMPTY reserved `triage`, `risk`, `remediation`.
- `ToolCoverage` (analyzed/skipped files or an explicit `unknown`, plus declared limitations), `ToolRun`, `Audit` (mirrors `manifest.json`
  including `neutralized_files`, `source`, `warnings`, `skipped_results`). Fields originating in scanned (untrusted) content are named in docstrings.

## 2. Issue class and merge rules
`issue_class` = primary CWE passed through a reviewed equivalence table (CWE-328 -> 327, CWE-259 -> 798, CWE-95/96 stay separate);
without a CWE: `rule:<tool>:<rule_id>`; pip-audit: `vuln:<package>@<version>`.
1. Identical hits of the same tool (same rule, location) collapse.
2. Cross-tool merge ONLY if same file AND overlapping line ranges AND same issue_class. Different classes on one line are never merged.
3. pip-audit: one finding per (package, version); aliases (PYSEC/GHSA/CVE) unioned, fix versions kept, duplicate entries collapsed.
4. A merged finding keeps ALL hits. Severity = highest mapped severity among hits; `severity_basis` names tool and rule; raw severities stay on hits.

## 3. Fingerprint and ids
`fingerprint = sha256(schema tag | issue_class | file_path | normalised text of the flagged lines)`; the text is whitespace-normalised and
**masked first**, so rotating a secret does not change it and no secret-derived hash exists. Inserting lines above the flagged code does not
change it; editing the flagged line does. If source is unavailable the basis falls back to the location (`fingerprint_basis=location`, documented
as unstable). `id = sha256(fingerprint | ordinal among equal fingerprints ordered by line)` so re-normalising the same audit is byte-identical.

## 4. Severity policy (single file `normalize/severity_map.py`)
Bandit: HIGH/MEDIUM/LOW as emitted (MEDIUM has no SARIF `level`; read `issue_severity`). Semgrep: rule `defaultConfiguration.level`
error/warning/note -> HIGH/MEDIUM/LOW (a stated policy, not tool truth). Gitleaks emits no severity: an explicit reviewed policy table marks
secret rules HIGH and records `basis=policy`. pip-audit emits none: UNKNOWN (CVSS enrichment is Phase 4). Unknown level/rule -> UNKNOWN + warning.

## 5. Snippets and masking (`normalize/masking.py`, `snippets.py`)
Snippets are +/-3 lines taken from the **retained source**, never from SARIF. Masking order: (1) every line range flagged by Gitleaks;
(2) shape regexes (AWS access keys, Stripe, GitHub/Slack tokens, JWTs, private-key blocks); (3) `key = value` / quoted literals for sensitive
names (password, secret, token, api_key, ...). The same masker is applied to tool **messages**: Bandit's B105 message embeds the literal
(`Possible hardcoded password: '<value>'`, verified in the committed output). Length is capped; control characters and ANSI escapes are stripped.
Findings in test paths are tagged `is_test_path` and never excluded.

## 6. Source retention
The sanitized workspace is kept as `<audit>/source/` (read-only where the OS allows) unless `--no-keep-source`. Temp dirs and containers are
still always cleaned and cleanup still fails loudly; the retained directory lies outside the temp root. It may contain secrets (SECURITY_POLICY).
`.semgrepignore` injected by the orchestrator is listed under `source.injected_files` and ignored by normalization.

## 7. Evaluation matching (`expected_findings.yaml`, backward compatible)
Cases may carry `match:` entries `{file, line_start, line_end, cwe: [...], classes: [...]}`; without them the case's own file/lines/cwe are used.
Positive: detected iff some finding overlaps in file+lines and its issue_class/CWE is accepted; `detected_by` = tools among the finding's hits.
Negative: flagged iff ANY finding overlaps its range (a tool alert on a safe look-alike is a false alarm whatever its class). Findings matching no
case are **unlabeled**: listed for manual labeling, never counted as false positives. `--exclude ID` drops cases (used to reproduce the Phase 1 numbers).
