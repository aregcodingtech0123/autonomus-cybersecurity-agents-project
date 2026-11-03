# secaudit

A multi-agent security audit platform for Python source code.

**Core principle:** real security tools (Semgrep, Bandit, Gitleaks, pip-audit) do the
scanning. LLM agents only triage, assess risk and propose fixes based on tool evidence.
The LLM is never the scanning engine.

## Status

**Phases 0, 1, 2A and 2B complete.** No LLM, agents, API or UI yet.

- Phase 0: repo skeleton, a deliberately vulnerable benchmark target, a verified ground-truth file.
- Phase 1: safe intake (directory / ZIP / https Git URL), sandboxed scanner execution in pinned Docker
  images, raw result collection into an audit directory with `manifest.json`.
- Phase 2A: normalization of raw output into versioned, secret-free findings (dedup, fingerprints, CWE/OWASP
  Top 10:2025, coverage) and a tool-only baseline (`benchmarks/baseline/metrics_tool_only.md`).
- Phase 2B: SQLite storage with migrations, hash-verified ingest, a self-contained HTML report, the full
  CLI, hardened masking, and a CI workflow (first run found 3 failures; the fixes have not run on GitHub yet).

See [docs/SCOPE.md](docs/SCOPE.md), [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md), [docs/DECISIONS.md](docs/DECISIONS.md),
[docs/PHASE1_NOTES.md](docs/PHASE1_NOTES.md), [docs/PHASE2A_NOTES.md](docs/PHASE2A_NOTES.md),
[docs/PHASE2B_NOTES.md](docs/PHASE2B_NOTES.md) and
[benchmarks/baseline/DISCOVERY.md](benchmarks/baseline/DISCOVERY.md).

## Development

```sh
uv sync
uv run pytest                 # unit tests + docker-marked tests (Docker must be running)
uv run ruff check . && uv run ruff format --check .

# one-time setup for scanning (needs Docker and network)
uv run secaudit build-images
uv run secaudit rules update

uv run secaudit scan benchmarks/targets/vuln_python_app --out audits
# -> audits/<audit_id>/raw/{bandit.sarif,semgrep.sarif,semgrep.json,gitleaks.sarif,pip-audit.json}
#    + manifest.json + findings.json + report.html
#    + source/ (sanitized copy, owner-only, may contain secrets; --no-keep-source skips it)
#    and the findings are stored in audits/secaudit.db (--raw-only stops after the scanners)
```

Working with stored audits:

```sh
uv run secaudit audit list --out audits
uv run secaudit findings list --out audits [--audit ID] [--severity HIGH] [--tool bandit]
uv run secaudit findings show F-0123456789ab --out audits [--audit ID]
uv run secaudit report <audit_id> --format html --out report.html      # or --format json; --db audits/secaudit.db
uv run secaudit normalize audits/<audit_id>        # raw -> findings.json (scan does this for you)
uv run secaudit ingest audits/<audit_id>           # findings.json -> SQLite; verifies raw sha256 first
uv run secaudit audit delete <audit_id> --out audits   # removes raw output, retained source and DB rows
uv run secaudit eval --from-raw benchmarks/baseline/raw --source benchmarks/targets/vuln_python_app
# -> metrics_tool_only.{json,md}; needs no Docker
```

Exit codes: `0` scan completed (findings do not change it), `2` usage / refused native run / unknown id,
`3` input rejected (including a raw artifact that no longer matches its manifest hash),
`4` a tool failed or timed out, `5` environment problem (Docker down, images or rules missing),
`6` temporary files could not be removed (leftovers are listed), `1` unexpected internal error
(a traceback is printed only with `--debug`).

`--runner native` runs the tools on the host with **no isolation** and requires `--i-trust-this-code`.

`benchmarks/targets/` contains intentionally vulnerable code. It is excluded from lint,
format and test collection, and must never be deployed.

## Verifying on Linux

Phase 1 was developed on Windows 11 with Docker Desktop, and the POSIX behavior (symlinks, FIFOs, hard
links, file modes, container users) was only simulated in a Linux container. The CI workflow
(`.github/workflows/ci.yml`) is meant to give the first real Linux run, but it has **not been run yet**.
To check by hand on a Linux host with Docker, git and [uv](https://docs.astral.sh/uv/):

```sh
git clone <this repository> secaudit && cd secaudit
uv sync --locked
uv run ruff check . && uv run ruff format --check .
uv run python benchmarks/check_ground_truth.py

# 1. everything that does not need Docker, natively on Linux (POSIX modes 0600/0700, symlinks, FIFOs, ...)
uv run pytest -m "not docker" -q -rs

# 2. the Docker-marked tests, including the Linux container probes
uv run secaudit build-images
uv run secaudit rules update          # fetches the Semgrep rules fresh; never commit or upload them
uv run pytest -m docker -q -rs

# 3. an end-to-end scan; then inspect the result
uv run secaudit scan benchmarks/targets/vuln_python_app --out /tmp/audits
uv run secaudit findings list --out /tmp/audits
stat -c '%a %n' /tmp/audits /tmp/audits/secaudit.db /tmp/audits/*/raw/*   # expect 700, 600, 600
```

Workflow lint (downloads the pinned actionlint release once and verifies its SHA-256):
`uv run python tools/actionlint.py`. The per-claim status of the POSIX tests is in
`docs/PHASE1_NOTES.md` ("POSIX / Linux verification status"); fill in its Run column from the first CI run.

What to look for: `test_parity_exact_match_with_recorded_baseline` is **skipped with a stated reason** when the
Semgrep rules you just fetched differ from the recorded snapshot; that is expected and not a failure. Any
other failure in step 1 or 2 is a real Linux finding to report, not to skip (`--user <host uid>` handling and
multi-user cleanup were never exercised on a real Linux host before).
