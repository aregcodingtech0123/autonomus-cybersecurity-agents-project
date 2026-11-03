# Roadmap

Check an item only when it is done and verified. Work found tempting out of phase goes here, not into code.

## Phase 0 - Foundation & benchmark
- [x] Monorepo skeleton (uv, Python >=3.11, ruff, pytest), stub CLI `secaudit --version`
- [x] Benchmark target with 11 positives, 7 negatives, 2 injection baits (P03 revised, N07 and P08b added in Phase 1 Task 0)
- [x] Ground truth `expected_findings.yaml` + line-verifying checker run in pytest
- [x] Scanner output discovery for Bandit, Semgrep, Gitleaks, pip-audit (`benchmarks/baseline/`)
- [x] SCOPE, SECURITY_POLICY, ROADMAP

## Phase 1 - Scanner engine
- [x] Scanner adapter interface and the four adapters (Semgrep, Bandit, Gitleaks, pip-audit)
- [x] Docker isolation per `SECURITY_POLICY.md` (non-root, read-only, no network, limits)
- [x] Offline rules/advisory update step (`secaudit rules update`; pip-audit is the one declared egress-only exception)
- [x] Pinned Semgrep rulesets (`p/python` + `p/flask` + `p/security-audit`, hash-pinned snapshot; tests/ scanned)
- [x] Safe repository and ZIP intake (traversal, symlink and zip-bomb protections)
- [x] Do not treat non-zero scanner exit codes as failure
- [x] Container-produced canonical baseline + native parity check (`docs/PHASE1_NOTES.md`)
- [ ] Verify on a Linux host (Phase 1 was run on Windows 11 / Docker Desktop only)
- [ ] Image signature/attestation verification, SBOMs, scan our own images
- [ ] Resolve the Semgrep Rules License question before any hosted/distributed use (see `PHASE1_NOTES.md`)

## Phase 2 - Normalization (complete: 2A and 2B)
Phase 2A (normalization core, see `PHASE2A_NOTES.md`):
- [x] `SecurityFinding` / `ToolHit` / `Audit` Pydantic models with `schema_version`
- [x] Deduplication across rules and tools (pip-audit emits duplicates), stable fingerprints
- [x] CWE / OWASP Top 10:2025 mapping from the official pages (unmapped CWEs counted, e.g. CWE-704)
- [x] Tool-only baseline metrics: 9/12 positives detected, 4/7 negatives flagged (`benchmarks/baseline/metrics_tool_only.md`)
- [x] Mask secrets in all derived data (raw outputs stay secret-bearing and byte-identical)
- [x] Model scanner coverage (Semgrep >1 MB skip is visible via benchmark case P11)
- [x] Map pip-audit findings to requirement lines via `manifest.json` `pinned_requirements`
- [x] Retained source snapshot (`<audit>/source/`, owner-only) and `secaudit audit delete`

Phase 2B (see `PHASE2B_NOTES.md`):
- [x] The 3 unlabeled baseline findings labeled (P01 match for the CWE-704 tag; new kind `related_informational`: R01, R02)
- [x] Manifest `source` flags split into `retained_at_scan` / `committed` (+ computed `available`); schema version 2
- [x] Masking hardened to fail closed (url credentials, Bearer/Basic, `sk-` keys, entropy fallback, PEM blocks across lines)
- [x] SQLite storage (SQLModel + Alembic migrations, per-advisory pip-audit hits, WAL, private file) and hash-verified `secaudit ingest`
- [x] JSON Schema export (`docs/schema/`) and a self-contained HTML report (autoescape, CSP, no JS)
- [x] Full CLI: `scan` normalizes/stores/reports, `findings list|show`, `report`, `ingest`, `audit list|delete`; terminal-injection-safe output
- [x] CI workflow written (`.github/workflows/ci.yml`) - **not yet run on GitHub**
- [x] Planted fakes made generic-shaped before the first push; baseline regenerated (ADR-003: Gitleaks 3 -> 2 results, P03 re-described, metrics unchanged at 9/12 and 4/7)
- [ ] Bandit and Gitleaks coverage are still `unknown`

## Phase 3 - Triage agent
- [ ] CrewAI Flow with evidence-required structured output
- [ ] Secret masking before every LLM call
- [ ] Prompt-injection tests (I01, I02)
- [ ] LLM may lower severity with justification, can never delete a finding

## Phase 4 - Risk
- [ ] Threat Modeler agent
- [ ] CVSS v4.0 computed by a library from LLM-chosen metrics
- [ ] EPSS / KEV enrichment
- [ ] Business priority

## Phase 5 - Remediation + QA
- [ ] Unified-diff patch proposals
- [ ] Apply on a copy, syntax check, rescan
- [ ] Human approval gate; never auto-apply

## Phase 6 - Reporting
- [ ] Executive and technical reports (Jinja2 -> HTML -> PDF)
- [ ] Cost and time metrics

## Phase 7 - API, dashboard, MCP
- [ ] FastAPI service
- [ ] Next.js + TypeScript + Tailwind dashboard (`web/`)
- [ ] First MCP server

## Phase 8 - Integrations
- [ ] GitHub Action
- [ ] SARIF export
- [ ] Docker Compose
- [ ] README with metrics, demo
- [ ] Egress allow-list proxy and private/link-local blocking for Linux deployment (closes the declared residual risk in SECURITY_POLICY section 6)

## Phase 9 - Live audit (passive only)
- [ ] Passive live-system checks, explicit authorization required

## Phase 10 - Hybrid audit (stretch)
- [ ] Combined code + live audit

## Future work packages (not started, not scheduled)
- [ ] **Custom Semgrep rules to close recall gaps** (path traversal via `open(os.path.join(..., request...))`,
      Flask `debug=True` when the app comes from another module, cross-module pickle/yaml sinks, ...).
      Motivated by benchmark cases P08 and P10, which every tool misses. Our own rules would also avoid the
      registry license limits.
- [ ] Larger/second benchmark target so detection metrics are not measured on one tiny app.
- [ ] **Phase 2C: benchmark expansion to 30-40 cases, BEFORE Phase 3.** One 12-positive / 7-negative app is too small
      to tell a triage agent's effect from noise; more cases, more shapes of each vulnerability, more negatives.
- [ ] **Custom Semgrep rules for P08, P10 and P11** (the cases no registry rule detects), owned by the project;
      this is also the path out of the Semgrep Rules License boundary (`DECISIONS.md`, ADR-001).
- [ ] **Review the first Linux CI results.** Phase 1 only simulated Linux in a container; the CI run is the first
      real one. Do not treat any POSIX claim as verified until that run has been read.
- [ ] **Egress allow-list proxy** (Phase 8, with private/link-local blocking) to close the pip-audit egress residual risk.
- [ ] **CWE/CVSS enrichment for pip-audit advisories via OSV** (Phase 4). pip-audit emits no CWE, so its findings are
      OWASP-unmapped today; every advisory is already its own stored hit, which is what per-advisory scoring needs.
- [ ] **LLM egress guard** (Phase 3): a last-mile secret filter on everything that leaves for a model, independent
      of the masking done during normalization.
