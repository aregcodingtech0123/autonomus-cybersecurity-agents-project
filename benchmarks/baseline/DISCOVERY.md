# Scanner output discovery (Phase 0 probe)

Goal: learn what the real tools emit, so the Phase 2 data model is based on observed output.
No adapters exist yet. Raw, unedited outputs are in [`raw/`](raw/). Nothing below was written
from memory: every hit, miss and quirk was read from those files. The target code was **not**
tuned to make tools look good (one correction to the target is disclosed under *Process notes*).

## Environment

| Item | Value |
|---|---|
| Date of scan | 2026-11-02 |
| OS | Windows 11 Pro, native (no WSL) |
| Python / uv | CPython 3.13.11 / uv 0.13.6 |
| Docker | CLI present, **daemon not running** - Docker was not used; all four tools ran natively |
| Target | `benchmarks/targets/vuln_python_app/` (scanned from inside that directory, path `.`) |

## Tools, versions, commands

All commands were run from `benchmarks/targets/vuln_python_app/`. `$RAW` = `benchmarks/baseline/raw`.

| Tool | Version (observed) | Install / run | Exact command | Output |
|---|---|---|---|---|
| Bandit | 1.9.4 | `uvx --from "bandit[sarif]"` | `bandit -r . -f sarif -o $RAW/bandit.sarif` | `bandit.sarif` |
| Semgrep | 1.183.0 | `uvx semgrep` | `semgrep scan --config p/python --metrics=off --sarif --sarif-output=$RAW/semgrep.sarif --disable-version-check .` | `semgrep.sarif` |
| Semgrep (supplementary) | 1.183.0 | same | `semgrep scan --config p/flask --config p/security-audit ... --sarif-output=$RAW/semgrep-flask-security-audit.sarif .` | `semgrep-flask-security-audit.sarif` |
| Gitleaks | 8.30.1 | GitHub release zip, SHA-256 checked against the published `checksums.txt` | `gitleaks dir . --report-format sarif --report-path $RAW/gitleaks.sarif --no-banner` | `gitleaks.sarif` |
| pip-audit | 2.10.1 | `uvx pip-audit` | `pip-audit -r requirements.txt -f json -o $RAW/pip-audit.json` | `pip-audit.json` |
| pip-audit (supplementary) | 2.10.1 | same | `pip-audit -r requirements.txt --no-deps --disable-pip -f json -o $RAW/pip-audit.no-deps.json` | `pip-audit.no-deps.json` |

Not verified: the gitleaks release signature (only the SHA-256 from the same release page was
checked). Semgrep registry rules (`p/...`) are fetched live and not version-pinned, so
results can change between runs.

All four tools returned exit code 1 when findings existed (Semgrep returned 0 even with
findings, because it was not run with `--error`). A Phase 1 runner must not treat non-zero as failure.

## Results: positives (P01-P10)

`Y` = detected at the right place, `-` = not detected, `partial` = detected for only part of the case.

| Case | What | Bandit | Semgrep `p/python` | Semgrep `+p/flask +p/security-audit` | Gitleaks | pip-audit |
|---|---|---|---|---|---|---|
| P01 | SQLi f-string | Y B608 (conf. LOW) | Y 2 rules | Y | - | n/a |
| P02 | hardcoded key + password | partial B105 (password, line 4) | - | - | partial `stripe-access-token` (key, line 3) | n/a |
| P03 | AWS example key in config | - | - | - | **-** | n/a |
| P04 | `yaml.load` unsafe | Y B506 | Y `avoid-pyyaml-load` | Y | - | n/a |
| P05 | `shell=True` + user input | Y B602 | Y 3 rules | Y 2 rules | - | n/a |
| P06 | `pickle.loads` request data | Y B301 | **-** | Y `avoid-pickle` | - | n/a |
| P07 | md5 password hash | Y B324 | Y 2 rules | **-** | - | n/a |
| P08 | `debug=True` | **-** | **-** | **-** | - | n/a |
| P09 | vulnerable pins | n/a | n/a | n/a | n/a | Y all 3 packages |
| P10 | path traversal | **-** | **-** | **-** | - | n/a |

Union of the primary configuration (Bandit + Semgrep `p/python` + Gitleaks + pip-audit):
**7 of 10 detected** (P01, P02 (two lines, two tools), P04, P05, P06, P07, P09). **Missed by every tool: P03, P08, P10.**

### Why the misses (what is verified vs. inferred)

- **P03** - verified: Gitleaks does detect an AWS-shaped key (`aws-access-token` + `generic-api-key`)
  in a throwaway file with the same structure but a non-`EXAMPLE` key. So the miss is specific to
  AWS's documented example values. Inferred (rule source not read): these are allowlisted by design.
  This is arguably *correct* tool behavior; it means the case tests "known example secrets", not real leaks.
- **P08** - verified: Bandit B201 did not fire. Inferred: B201 only matches when `flask` is
  imported in the same file; `wsgi.py` gets `app` from `create_app()`. No Semgrep ruleset tried flagged `debug=True`.
- **P10** - no Bandit rule exists for it; neither Semgrep ruleset flagged `open(os.path.join(UPLOAD_DIR, request...))`.
  Taint tracking across `request.args` -> `os.path.join` -> `open` was not matched.
- **P06 / P07 Semgrep gaps** are ruleset-dependent: `p/python` has md5 rules but not pickle;
  `p/flask` + `p/security-audit` has pickle but not md5.

### P09 detail (CVE ids are copied from pip-audit's output)

Flask 2.0.1 (CVE-2023-30861, CVE-2026-27205), PyYAML 5.3.1 (CVE-2020-14343),
requests 2.19.0 (CVE-2018-18074 plus 4 more CVE aliases). Default mode also resolved and reported
transitive dependencies (urllib3 1.23: 12 distinct ids; idna 2.7: 2): 43 entries in 5 packages
vs. 16 entries in 3 packages in `--no-deps` mode.

## Results: negatives (N01-N06) - false alarms

| Case | What | Bandit | Semgrep | Gitleaks | Verdict |
|---|---|---|---|---|---|
| N01 | parameterized query | - | - | - | clean |
| N02 | `shell=False`, constant list | **B603** (+ B404 on `import subprocess`) | - | - | Bandit false alarm (LOW) |
| N03 | `yaml.safe_load` | - | - | - | clean |
| N04 | `assert` in tests/ | **B101** x4 | not scanned (see below) | - | Bandit false alarm (LOW) |
| N05 | placeholder password in fixture | **B105** | not scanned | - | Bandit false alarm (LOW) |
| N06 | md5 cache key, commented | **B324 (HIGH/HIGH)** | **`insecure-hash-algorithm-md5`** | - | false alarm in 2 tools; severity HIGH in Bandit despite the comment |

**4 of 6 negatives were flagged** (N02, N04, N05, N06). Bandit alone flagged all four. N06 is the
important one: both tools flag it at high severity, and only reasoning over the comment/usage can dismiss it.

Findings that map to no case (noise on import lines): Bandit B403 (`import pickle`,
`serialization.py:3`) and B404 (`import subprocess`, `system.py:3`).

Raw totals: Bandit 15 results, Semgrep 9, Semgrep supplementary 5, Gitleaks 1, pip-audit 43 entries.

## Prompt-injection bait (I01, I02)

No scanner reported or reacted to either (expected). Bandit/Semgrep/Gitleaks do not read comments or
README text. These only matter once an LLM reads the repository (Phase 3).

## Surprises and format quirks (these shape the Phase 2 model)

1. **Semgrep skips `tests/` by default** (`.semgrepignore`; verbose output lists both test files). The
   Semgrep "clean" result on N04/N05 is therefore not a real negative. Scope also depends on `git ls-files`
   when run inside a git repository; behavior outside git was not tested.
2. **Semgrep SARIF**: URIs use backslashes on Windows (`webshop\auth.py`); results carry no `level` (it lives
   in `rules[].defaultConfiguration`); `fingerprints` is the literal string `"requires login"`; rule
   ids are long dotted paths. `sql-injection-db-cursor-execute` sits in the `django` namespace yet fires on
   sqlite3 in a Flask app.
3. **Bandit SARIF**: needs the `bandit[sarif]` extra. `level` is `error` (HIGH), `note` (LOW) and **absent**
   for MEDIUM; severity/confidence are in `properties.issue_severity` / `issue_confidence`. SARIF default
   for a missing level is "warning", which a naive parser would miss.
4. **Gitleaks SARIF**: `driver.version` reads `v8.0.0` although the binary is 8.30.1 (do not trust it as the tool version). Reports the
   secret text itself in the output (here, a fake) - raw Gitleaks output must be masked before any LLM sees it.
   The subcommand is `gitleaks dir` (not `detect --no-git`).
5. **pip-audit has no SARIF output.** It produces JSON with `{dependencies:[{name,version,vulns:[...]}], fixes}`
   and **no file/line** - mapping a finding to a line in `requirements.txt` is our job. Almost every vulnerability
   entry is **duplicated** (e.g. `PYSEC-2023-62` twice for Flask, with different descriptions): dedup is mandatory.
   Results are time-dependent (the resolver picked `certifi==2026.10.23` today).
6. **Network dependence**: pip-audit queries a vulnerability service; default mode also builds a temporary venv and
   installs the pinned packages. Semgrep `p/...` configs download rules from the registry.
   Bandit and Gitleaks need no network.
7. **Semgrep ran natively on Windows** here, but that is not a supported path to build on; Phase 1 should target a Linux image.
8. **Severity vocabularies differ**: Bandit LOW/MEDIUM/HIGH x confidence; Semgrep ERROR/WARNING/INFO (rule level);
   Gitleaks none; pip-audit none. A common severity must be derived, not copied.

## Process notes (disclosure)

- First scan round: `wsgi.py` used `app.run(host="0.0.0.0", debug=True)`. Bandit (B104) and a Semgrep rule fired on
  `host=`, not on `debug=True`, so P08 looked "detected" for the wrong reason. I changed the line to `app.run(debug=True)`
  to make P08 a single unambiguous issue and re-ran all scanners. After that P08 was missed by every tool. The
  first-round outputs were overwritten and are not kept. No other target line was changed after scanning started.
- `expected_findings.yaml` was updated from these results. Semgrep means the primary `p/python` run there;
  the P06 note records that the supplementary ruleset detects it.
- pip-audit's transitive results, Semgrep registry rules and the 2026 CVE ids will drift over time; the committed
  raw files are the frozen baseline.

## Implications for later phases

- Normalize on SARIF where available (Bandit, Semgrep, Gitleaks) plus a separate pip-audit JSON adapter that
  synthesizes locations from `requirements.txt` lines.
- The model needs: tool, rule id, normalized severity + confidence, location (optional for SCA), snippet (maskable),
  raw payload reference, and a `duplicate_of` link (same issue reported by several rules/tools: P01 x3, P05 x4, P07 x3).
- Evaluation must match by file + line-range overlap, and must treat P02 as one case reported on different lines by different tools.
- Tool-only baseline on this target: 7/10 positives found, 4/6 negatives falsely flagged. That is the number the
  agent layer has to improve, mostly by dismissing N02/N04/N05/N06 with evidence, never by deleting findings.
- A "no network" sandbox conflicts with pip-audit and registry-based Semgrep. See `docs/SECURITY_POLICY.md` for how this is handled.

---

## Addendum (Phase 1, Task 0) - corrections to the sections above

Everything above is left as originally written. Review found two flawed or misexplained cases;
this addendum supersedes the affected statements. Native re-run on 2026-11-02, same tool
versions (Bandit 1.9.4, Semgrep 1.183.0, Gitleaks 8.30.1) and same commands.

### A1. P03 was a flawed benchmark case, not a tool miss

P03 used AWS's documented example key. The earlier text called it a "miss" and
suggested allowlisting as an inference. A review (correctly) pointed out that this made the
case invalid as a positive. Changes:

- `P03` now uses a random synthetic key pair that matches the AWS key pattern, is not a documented
  example, and is not valid (`config/settings.ini` lines 7-8; line numbers unchanged).
- The documented example pair was kept as a new **negative case N07** (lines 12-13, appended so no
  existing line moved).
- Observed after the change: Gitleaks reports `aws-access-token` (line 7) and `generic-api-key`
  (line 8) for P03 and reports **nothing** for N07. Bandit and Semgrep report nothing in the file.
- Corrected statement: P03 is **detected by Gitleaks**. The "7 of 10 positives" figure above was
  computed with the flawed P03 and no longer applies; see A3.

### A2. P08: why Bandit and Semgrep miss `debug=True` in `wsgi.py` (verified in source)

- **Bandit B201** (`bandit/plugins/app_debug.py`, `flask_debug_true`) fires only when all three hold:
  `context.is_module_imported_like("flask")` (a flask import **in the same file**), the call's qualified name
  ends with `.run`, and the call has the keyword `debug=True`. It does not track where `app` came from.
- **Semgrep `python.flask.security.audit.debug-enabled`** (in `p/python`) is
  `pattern-inside: import flask ...` + `$APP.run(..., debug=True, ...)`. Same file-level flask import requirement.
  (Rule definition read from the registry copy Semgrep wrote locally during a debug run.)
- `wsgi.py` does `from webshop import create_app` and never imports flask, so neither rule can match.
  It is a genuine recall gap for the common "app factory in another module" layout. P08 is kept unchanged.
- New variant **P08b** (`dev_server.py:14`): Flask app created and run with `debug=True` in one file.
  Observed: Bandit B201 (HIGH/MEDIUM) and Semgrep `debug-enabled` both fire (also in the `p/flask` +
  `p/security-audit` run).
- No other target code was changed.

### A3. Updated hit/miss on the native baseline (primary configuration)

| Case | Bandit | Semgrep `p/python` | Gitleaks | pip-audit |
|---|---|---|---|---|
| P03 (revised) | - | - | **Y** (2 rules) | n/a |
| P08 (wsgi.py) | - | - | - | n/a |
| P08b (new) | **Y** B201 | **Y** `debug-enabled` | - | n/a |
| N07 (new negative) | - | - | - (not flagged) | n/a |

Positives detected by at least one tool: **9 of 11** (P01-P07, P08b, P09; P03 now included).
Still missed by every tool: **P08, P10**. Negatives falsely flagged: still 4 of 7 (N02, N04, N05, N06); N07 is clean.

The raw files in `raw/` were regenerated natively for this addendum (the pre-addendum versions remain
in git history).

---

## Addendum 2 (Phase 1): the canonical baseline is now the container run

- `raw/` now holds the outputs of the sandboxed container run (`secaudit scan`), with `manifest.json`
  recording exact commands, versions and the Semgrep rule snapshot hashes. The native outputs from the sections
  above and Addendum 1 moved to `raw_native/` (references to `raw/` in the text above mean those native files).
- The container Semgrep run uses `p/python` + `p/flask` + `p/security-audit` from a local rules cache with no
  network, and scans `tests/` (the native run skipped it via Semgrep's default ignore list).
- Parity with the native runs: Bandit and Gitleaks results are identical at rule/file/line level; Semgrep equals the
  union of the two native Semgrep runs; pip-audit reports the same packages. The only per-case difference is
  P06/Semgrep (detected in the container because `p/flask`/`p/security-audit` are included).
- Container-run figures: 9 of 11 positives detected (missed: P08, P10), 4 of 7 negatives falsely flagged
  (N02, N04, N05, N06). Details and the full table are in `docs/PHASE1_NOTES.md`.
- `expected_findings.yaml` now describes this container baseline; `tests/test_docker_integration.py` checks it
  exactly when the local rule snapshot matches `benchmarks/baseline/manifest.json`.

## Addendum 3 (Phase 2A): baseline regenerated

- `raw/` and `manifest.json` were regenerated with a fresh container scan (audit `20261103T081804Z-06b4cbe7`,
  same rules snapshot) so the manifest carries `neutralized_files` and per-tool `limitations`, and to add
  `raw/semgrep.json` (coverage data: `paths.scanned`) and case P11 (a generated >1 MB module).
- Raw Bandit results and pip-audit advisories are unchanged; Bandit's end timestamp and file metrics differ.
- Figures are now 9 of 12 positives (missed: P08, P10, P11) and 4 of 7 negatives flagged. `metrics_tool_only.{json,md}`
  hold the normalized, per-case breakdown. The Phase 1 raw files remain in git history and as the test
  fixture `tests/fixtures/phase1_baseline/`.

## Addendum 4 (Phase 2B): manifest and labels

- `manifest.json` was edited by hand once: `source.retained` (true) became `source.retained_at_scan: true` plus
  `source.committed: false`, because no source directory is committed next to the raw files. Nothing else in the
  manifest, and no raw file, changed; the manifest is not hash-pinned (the raw artifacts are, through it).
- The three findings that were unlabeled in Addendum 3 are now labeled in `benchmarks/expected_findings.yaml`
  (P01 accepts Semgrep's CWE-704 tag on line 21; `import pickle` / `import subprocess` are the
  `related_informational` items R01 / R02). Detection numbers did not change: 9 of 12 positives, 4 of 7 negatives.

## Addendum 5 (pre-push): provider-shaped fakes replaced (ADR-002)

- Every planted fake is now generic-shaped and of the same length (a `bench_` prefix and a random body), so no
  provider-shaped value exists anywhere in the repository or its history. See `docs/DECISIONS.md`, ADR-002.
- `raw/` and `manifest.json` were regenerated by a real container scan (audit `20261103T161647Z-68eba1f9`, same rules
  snapshot) with `benchmarks/regenerate_baseline.py`. `raw_native/` and the Phase 1 fixture were re-scrubbed
  with the same exact-length mapping (`benchmarks/rescrub_frozen.py`); their rule ids still describe the
  original shapes.
- **P03 re-described:** "secret token in an .ini configuration file, detected by a generic rule" (no longer
  AWS-specific). Gitleaks now reports `generic-api-key` on line 8 only: its generic rule allowlists `key_id`
  identifiers, so line 7 is no longer reported. P03 is still detected.
- P02 line 3 is reported as `generic-api-key` instead of `stripe-access-token`. N07 stays unreported (its
  values end in the allowlisted word `EXAMPLE` / `EXAMPLEKEY`).
- Results: Bandit 16, Semgrep 11, pip-audit 16 (unchanged); Gitleaks 2 (was 3). Normalized findings 24 from
  45 raw (was 25 from 46). Detection numbers unchanged: 9 of 12 positives, 4 of 7 negatives.
