# Phase 2B notes: labels, masking, storage, report, CLI, CI

What was built, what was decided and why, what is still weak, and what could not be verified here.
Design background is in `PHASE2_DESIGN.md` and `PHASE2A_NOTES.md`. No LLM, API or UI exists yet.

## 1. Labeling the three unlabeled findings

The Phase 2A baseline listed three findings that no ground-truth case covered. I read the code at each
location (benchmark target files unchanged; no detection logic changed) and decided:

| Finding | What the code is | Decision | Result |
|---|---|---|---|
| `webshop/db.py:21`, Semgrep `python.flask.security.injection.tainted-sql-string`, tagged CWE-704 | `query = f"SELECT ... WHERE username = '{username}'"`: this is the P01 SQL injection line itself. The rule reports the right place; only its own CWE tag (704, not 89) differs. | (i) another location of an existing positive: P01 gets a second, narrow `match` entry (line 21 only, CWE-704) | P01 was already detected by Bandit B608 and Semgrep `sql-injection-db-cursor-execute`; its `detected_by` stays `bandit, semgrep`. No denominator change. |
| `webshop/serialization.py:3`, Bandit B403 | `import pickle`. Not a vulnerability; it exists because of `pickle.loads` on line 25 (P06). | (iii) new kind `related_informational`, **R01**, `related_to: P06` | Reported separately; not a detection, not a false positive. |
| `webshop/system.py:3`, Bandit B404 | `import subprocess`, needed by the `shell=True` call on line 13 (P05) and by N02. N02's range is lines 19-21, so line 3 never touched it. | (iii) **R02**, `related_to: P05` | Same. |

No new positive (P12...) was added: none of the three is a distinct vulnerability. The CWE-704 acceptance is the
only judgement call that widens what counts as "matching"; it is scoped to one line of one case and could not
move any number, which is what makes it safe to keep. Without it the finding would have stayed unlabeled, which
is the honest alternative if you disagree.

`related_informational` is implemented in the checker (`benchmarks/check_ground_truth.py`: id prefix `R`, a
valid `related_to`, no `expected_detecting_tools`), in `core/evaluation.py` (labeled but excluded from both
counts, own section in `metrics_tool_only.{json,md}`), and in the parity test. Detection numbers are unchanged
and the unlabeled list is now empty.

### Final tool-only baseline (audit `20261103T081804Z-06b4cbe7`, regenerated metrics)

| Case | Result | Tools |
|---|---|---|
| P01, P04, P05, P06, P07, P08b | detected | bandit, semgrep |
| P02 | detected | bandit, gitleaks |
| P03 | detected | gitleaks |
| P09 | detected | pip-audit |
| P08, P10, P11 | **missed by every tool** | - |
| N02, N04, N05 | flagged | bandit |
| N06 | flagged | bandit, semgrep |
| N01, N03, N07, I01, I02 | clean | - |
| R01, R02 (related informational) | reported, not counted | bandit (B403, B404) |

**9 of 12 positives, 4 of 7 negatives flagged, 46 raw results -> 25 findings, 0 unlabeled.**

## 2. Manifest `source` semantics

The manifest said `source.retained: true` for the committed baseline although no source directory is committed,
and the Audit model reused the name for a different fact ("the source was readable when normalizing"). Now:

- `retained_at_scan` (manifest, written by `scan`): the scan copied the sanitized source into the audit directory;
- `committed` (manifest, default false): the source directory is part of a shared/committed artifact;
- `available` (Audit only, computed from the source tree actually passed in, never read from the manifest).

The legacy key `retained` is still read. `SCHEMA_VERSION` went to `"2"`. The fingerprint tag was tied to the
schema version, so a bump would have silently changed every finding id; it is now the constant `secaudit-fp-v1`
(a test pins it). The committed baseline manifest was edited by hand once (documented in `DISCOVERY.md`);
`tests/fixtures/phase1_baseline/` is untouched.

## 3. Masking, fail closed

Added: `sk-` keys (OpenAI/Anthropic style), `scheme://user:password@host` and `scheme://token@host`,
`Authorization:` header values of any scheme, bare `Bearer`/`Basic` values, a high-entropy fallback (any token of
32+ characters of base64/hex-ish alphabet with letters and digits and Shannon entropy >= 4.2), typed assignments
(`secret: str = "x"`, `password: Optional[str] = "x"` used to leak the value), nested keys in messages
(`secret: secret_key = "x"`), a stricter exemption for dotted names, stripping of zero-width / bidi / C1
characters before matching (an invisible character inside a token must not defeat a shape), and PEM handling
**across lines**: a snippet window in the middle of a key body contains neither header nor footer, so the
private-key spans are now computed from the whole retained file and those lines are replaced outright.

Tests build every canary at runtime (`tests/canaries.py`: fragments concatenated when the function runs), so no
token-shaped literal is in the repository; two older test literals (a JWT and a Slack token) were converted too.
Every canary is checked in messages, snippets, fingerprint input and the exported JSON; masking is idempotent;
output never exceeds the cap (also tiny caps); megabyte-long adversarial runs finish in linear time; an unknown
shape inside a Gitleaks-flagged range is masked because the whole range is.

Real baseline: ids and metrics did not change with the new masker.

**Residual risks (not claimed solved):**
- Masking is pattern-based. A secret that looks like ordinary text, has no sensitive key nearby and is shorter than
  32 characters passes (a short password in a variable not named like a secret).
- Hex secrets are not caught by the entropy fallback (hex tops out at 4.0 bits); they are caught only by shape or
  by a sensitive key name.
- The entropy fallback over-redacts some long identifiers and base64 blobs. That is the intended direction.
- A secret split across two lines (string concatenation) is not reassembled.
- Findings whose flagged lines are fully redacted share a fingerprint (the two Gitleaks lines in
  `config/settings.ini` do); their ids differ only by order. Stable, but not content-addressed.

## 4. Storage

`src/secaudit/store/`: `orm.py` (the only module importing SQLModel), `convert.py` (pydantic <-> rows),
`repo.py` (repository, expression API only, no SQL strings), `db.py` (engine, WAL, permissions, migrations),
`ingest.py` (verification), `migrations/` (Alembic). `core/models.py` has no ORM import.

Tables: `schema_version`, `audit`, `tool_run`, `raw_artifact` (path, sha256, kind; the bytes are not stored),
`finding`, `finding_hit` (1:1 with `ToolHit`, so every pip-audit advisory is its own row with its aliases,
affected version, fix versions and raw pointer; the benchmark's 3 pip-audit findings hold 8 advisory rows).
Foreign keys cascade, so deleting an audit removes everything under it.

**Deviation from the brief: fingerprint uniqueness.** "Unique per audit" cannot be a plain constraint: dedup gives
findings with equal fingerprints distinct ids by ordinal, and the real baseline contains such a pair. The
constraints are `unique(audit_id, id)` and `unique(audit_id, fingerprint, ordinal)`, with an index on
`fingerprint`.

**Ingest** (`secaudit ingest <audit_dir>`): needs `findings.json` and `manifest.json` (otherwise it says to run
`normalize`, exit 2); validates `findings.json` against the models; checks the audit ids agree; hashes every raw
artifact the manifest lists (primary and extra) and compares with the manifest **and** with each hit's `raw_ref`;
any mismatch, missing file or unacceptable path -> exit 3 and nothing is written. Same audit and same content ->
no-op. Same audit id with different content -> refused unless `--replace` (an explicit overwrite; I added the flag
so a re-normalize after a masking upgrade is possible without deleting the audit).

**Migration policy.** Revisions are append-only and hand-written; a released revision is never edited. Any change
to `orm.py` ships a new revision in the same commit; the drift test in `tests/test_store.py`
(`test_migrated_schema_has_no_drift_from_the_orm_tables`, via Alembic `compare_metadata`) fails otherwise. The
test also covers upgrade from empty, re-running upgrade as a no-op, and a downgrade/upgrade round trip.
`downgrade` exists for development and tests, not for production data. A new `findings.json` schema version
needs a revision that updates `schema_version.models_schema` and an ingest path for the old version (or a
documented re-normalize). Type comparison is off in the drift test (SQLModel's string type differs by name from
`VARCHAR` without differing in storage); structure, nullability and constraints are compared.

**Concurrency and permissions.** WAL, a 30 s busy timeout, foreign keys on, and every write transaction starts
with `BEGIN IMMEDIATE`. Tested with real OS processes (2 on one audit, 2 on different audits, 4 on two audits).
**Two bugs the tests caught while building this:** (1) `PRAGMA journal_mode=WAL` on every connection raced
between processes ("database is locked", the mode switch ignores the busy handler); it is now switched once with
retries. (2) On Windows the Phase 2A grant `(OI)(CI)F` leaves a *file* with an empty ACL, so the freshly secured
database could not be reopened; `restrict_to_owner` now uses a plain grant for files (regression test added).
POSIX: file created 0600; Windows: file and (default location) directory restricted by SID. Administrators and
SYSTEM can still take ownership; a directory that already has explicit ACEs (e.g. one made by Python's
`mkdtemp`) keeps them, because `/inheritance:r` only removes inherited ones.

## 5. Report and schema

`secaudit report <audit_id> --format html|json [--out PATH]` reads the database. HTML: Jinja2 with autoescape
on and `StrictUndefined`; no JavaScript, no external resource, no inline style attributes; a CSP `<meta>` with
`default-src 'none'` and `style-src` pinned to the sha256 of the one stylesheet (the only thing passed as markup,
a module constant). Every interpolated value also loses control/ANSI characters before escaping, so printing the
page to a terminal is safe. Sections: summary (severity / tool / OWASP), scan coverage and limitations (declared
limitations, files a tool skipped), findings, per-finding evidence (tool, rule, raw severity, masked snippet,
raw pointer), related informational, warnings and skipped results, and one INFO line per neutralized scanner
configuration file ("scanner configuration found in repository and neutralized").

The **related informational** section needs the benchmark ground truth (`--ground-truth`), because that kind
exists only there; without it the section says no labeling was supplied. A real audit therefore has no such
section. That is the honest consequence of the data-flow rule, not an oversight.

`docs/schema/audit.schema.json` is generated from the models (`python -m secaudit.core.schema_export`) and a
test fails when it drifts.

## 6. CLI

`scan` keeps its flags and exit codes and now also normalizes, writes `findings.json`, ingests (through the same
hash-verifying path), writes `report.html` and prints a summary; `--raw-only` skips all of that. A
post-processing failure keeps the raw audit, prints how to retry (`normalize`, `ingest`) and exits 1. New:
`findings list|show`, `report`, `ingest`, `audit list`; `audit delete` also removes the database rows (and still
works if the directory is already gone). Finding ids repeat across audits (they hash content), so `findings show`
takes `--audit` and otherwise uses the latest audit that contains the id. The default database is
`<out>/secaudit.db`; `--db` overrides it (for `report`, whose `--out` is the output file, `--db` is the only way
to point at another root).

Exit codes: 2 usage / unknown id / missing prerequisite, 3 input rejected (tampered raw artifact, malformed
`findings.json`, conflicting re-ingest), 6 cleanup, 1 internal. No traceback on stdout; `--debug` prints it.

## 7. CI

`.github/workflows/ci.yml`: ruff, ground-truth checker and `pytest -m "not docker"` on ubuntu and windows; a
separate Linux job builds the images, fetches the Semgrep rules fresh with `secaudit rules update`, runs
`pytest -m docker` and deletes the rules. Least-privilege token, no secrets, no cache, no artifact upload
(ADR-001). **It has not been run.** GitHub Actions cannot run locally and `actionlint` was not installed; it
was parsed as YAML and checked structurally (`tests/test_ci_workflow.py`). Action versions are major tags
(`@v4`, `@v5`), not commit SHAs, and the pinned `uv` version is the one used locally; I could not verify either
against GitHub from here.

## 8. What was not verified

- The CI workflow itself, and therefore the first **real Linux run** of the POSIX-specific tests (mode bits,
  symlinks, FIFOs, hard links, `--user <host uid>`, multi-user cleanup). Locally only Windows + a Linux
  container simulation ran. `README.md` ("Verifying on Linux") has the exact commands.
- Windows behavior of the POSIX-only database test (skipped here) and POSIX behavior of the Windows ACL test.
- The `report` HTML in real browsers (CSP enforcement); only its structure and escaping were tested.
- SQLite over network file systems (WAL is not supported there).

## 9. Recommended before Phase 2C / 3

1. Read the first CI run, especially the Linux job, before expanding the benchmark.
2. Phase 2C (30-40 cases) must exist before the triage agent: with 12 positives and 7 negatives one case moves
   a rate by 8-14 points.
3. Decide how Phase 3 reads data: only through the repository / `findings.json`, never raw files; treat
   `message`, `snippet` and `title` as untrusted input (the I01 bait text is present verbatim in snippets).
4. Add the planned LLM egress guard as a second line behind normalization-time masking; masking is pattern-based.
5. Custom Semgrep rules for P08, P10, P11 (also the exit from the Semgrep Rules License boundary, ADR-001).
6. pip-audit findings have no CWE (OWASP-unmapped); the per-advisory rows are ready for OSV/CVSS enrichment.
7. Bandit and Gitleaks coverage is still `unknown`; decide whether a second Bandit JSON run is worth it.
8. Consider restricting `audits/` (not only the database) at creation on Windows if explicit ACEs are a concern.
