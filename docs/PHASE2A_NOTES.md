# Phase 2A notes: normalization core and tool-only baseline

Design rationale lives in `PHASE2_DESIGN.md`; this file records what was built, what was measured, and
what is still weak. Nothing here involves an LLM.

## What exists now

| Command | Purpose |
|---|---|
| `secaudit scan ...` | As before; now retains the sanitized source at `<audit>/source/` (owner-only, read-only) unless `--no-keep-source`. Prints one line saying where and that it may contain secrets. |
| `secaudit audit delete <audit_id> [--out DIR]` | Removes an audit directory including the read-only source copy. The id is validated and resolved inside the out root. |
| `secaudit normalize <audit_dir> [--out findings.json]` | Raw outputs + manifest + retained source -> versioned, secret-free `findings.json`. |
| `secaudit eval --from-raw RAW --source SRC [--exclude P11] [--out-dir D]` | Tool-only metrics against `benchmarks/expected_findings.yaml`. Needs no Docker. Writes `metrics_tool_only.{json,md}`. |

Pipeline: parse (`normalize/sarif.py`, `pip_audit.py`) -> severity policy (`severity_map.py`, the only place
severities are decided) -> CWE/OWASP (`cwe.py`, `owasp.py`) -> mask + snippets (`masking.py`, `snippets.py`)
-> dedup + fingerprints (`dedup.py`) -> coverage (`coverage.py`) -> `Audit` (`pipeline.py`, `models.py`).

## Invariants that are tested

- Raw files are never modified; every `ToolHit.raw_ref` carries artifact path, sha256 and JSON pointer, and the
  hash is re-checked in tests.
- A `SecurityFinding` without hits cannot be constructed. Every raw result becomes a `ToolHit` or a counted
  `skipped_results` entry with a reason. Malformed documents never raise.
- `ToolHit` never contains snippet or context text. Messages are masked too, because Bandit's SARIF message
  embeds the secret literal (B105: `Possible hardcoded password: '<literal>'`).
- Planted fake secrets (Phase 1 N07 keys, P02/P03 values, Bandit messages) are grepped for in every derived
  output (`findings.json`, metrics JSON/MD, SARIF-derived text); none may appear.
- Normalizing twice gives byte-identical output; finding ids are stable; fingerprints survive line shifts above
  the flagged code and change when the flagged line changes.
- `metrics_tool_only.{json,md}` are deterministic (no timestamps) and a test pins the committed files to a fresh
  `eval` of the committed raw outputs.

## The baseline (replaces the Phase 1 figures)

`benchmarks/baseline/` was regenerated with a fresh container scan (audit `20261103T081804Z-06b4cbe7`, same
rules snapshot as Phase 1) because the Phase 1 manifest predates `neutralized_files`/`limitations` and because
P11 plus `semgrep.json` needed a new run.

| | Phase 1 | Phase 2A | Why it differs |
|---|---|---|---|
| Positives detected | 9/11 | **9/12** | Only the denominator: P11 was added and every tool misses it. |
| Negatives flagged | 4/7 | **4/7** | Identical (N02, N04, N05, N06). |
| Missed | P08, P10 | P08, P10, P11 | P11 is new. |

Raw `bandit.sarif` is unchanged except the end timestamp and Bandit's file metrics (it analyses the generated
module); `pip-audit.json` has the same advisories per package; Semgrep/Gitleaks SARIF are byte-identical. The
Phase 1 numbers are reproduced from the frozen Phase 1 raw files (`tests/fixtures/phase1_baseline/`) via
`eval --exclude P11`, which a test asserts.

Raw results -> findings: Bandit 16 -> 16, Semgrep 11 -> 8, Gitleaks 3 -> 3, pip-audit 16 -> 8 unique -> 3
findings; 46 raw -> 25 findings in total.

## Known weaknesses and judgement calls

- **Gitleaks severity is policy, not tool output.** Gitleaks reports none; every secret rule is HIGH with
  `severity_basis = policy:gitleaks-secret`. Semgrep's `error/warning/note` -> HIGH/MEDIUM/LOW is likewise a
  stated mapping. pip-audit is UNKNOWN until Phase 4 (CVSS).
- **Three unlabeled findings** are listed, not counted as false positives: `webshop/db.py:21` (Semgrep tags its
  taint-SQL rule CWE-704; it overlaps P01 but that class is not accepted), `webshop/serialization.py:3` (B403,
  import of pickle) and `webshop/system.py:3` (B404, import of subprocess). They need human labeling.
- **OWASP mapping gaps.** CWE-704 has no Top 10:2025 category. The three pip-audit findings carry no CWE at all
  (pip-audit does not emit one), so they are unmapped until an advisory enrichment step exists. Unmapped is
  `null` and is counted, never guessed. The CWE lists were copied from the official category pages; only ids are
  stored because page titles proved unreliable.
- **Cross-tool merging is deliberately conservative.** Hits on the same line with different classes stay separate
  (`dev_server.py:14` CWE-489 vs CWE-94; `yaml.load` CWE-502 vs CWE-20). That keeps evidence honest but inflates
  the finding count; the `match` entries in the ground truth accept the right class sets.
- **Coverage.** Semgrep: known, derived from `paths.scanned` and the retained source (this is what exposes the
  skipped P11 module). pip-audit: known, from the manifest. Bandit and Gitleaks: `unknown`, stated as such
  (Bandit lists analysed files only in `-f json`; no second run was added).
- **I01 bait text** appears verbatim in snippets. Snippets are untrusted data; Phase 3 must treat them that way
  (I01/I02 are the tests for it).
- **Test-path findings** (5 in the baseline) are tagged `is_test_path`, never excluded.
- **Windows ACL on `source/`.** Access is restricted to the current user by SID on the directory (verified via
  `icacls /save` SDDL). Administrators and SYSTEM can still read it as in any Windows ACL model; this is a
  confidentiality-at-rest nicety, not a security boundary. See `SECURITY_POLICY.md`.
- **The committed baseline manifest says `source.retained: true`** although no source directory is committed;
  the source is regenerated from `benchmarks/targets/`.
- **Deviations:** packaged data lives in `src/secaudit/data/` rather than a repo-level `data/` so it ships in the
  wheel; `pydantic` and `pyyaml` are now runtime dependencies; Phase 1 code was touched only for source retention
  (`scan.py`, `retention.py`, `exe.py` System32 pinning) and the optional `semgrep.json` extra output
  (`scanners/base.py`, `semgrep.py`).

## P11

A deterministic generator (`benchmarks/p11_generator.py`, sha256 pinned in the ground truth) writes a ~1.08 MB
module with a path-traversal handler on its last lines. The file is git-ignored and regenerated by
`check_ground_truth.py` and `secaudit eval` when missing. Semgrep (1,000,000-byte limit) drops it without any
notice in the SARIF; Bandit analyses it but has no rule for `open(request.args...)`. The same pattern is found
by Semgrep in a small file, so the miss is attributable to the size limit, which the coverage record now shows.

## What Phase 2B and Phase 3 need

- Phase 2B: persistence (SQLite) for `Audit`/`SecurityFinding` keyed by fingerprint, report export from
  `findings.json`, `schema_version` migration policy, a manual labeling pass for the 3 unlabeled findings, and
  an advisory-enrichment source for pip-audit CWE/CVSS.
- Phase 3 triage agent: consume only `findings.json` (never raw files), treat message/snippet as untrusted,
  mask again before any LLM call, never delete a finding (the triage/risk/remediation fields are reserved and
  empty), and evaluate against `metrics_tool_only.json` as the number to beat.

## Foreseen risks

- Masking is pattern-based; a secret shape it does not know and a key name it does not treat as sensitive
  would pass through into snippets. Keep adding cases to the adversarial tests.
- Fingerprints fall back to location basis when source is not retained (`--no-keep-source`); such ids are not
  stable across edits.
- The baseline depends on the Semgrep rules snapshot; refreshing rules changes the numbers and must regenerate
  the baseline in one commit.
