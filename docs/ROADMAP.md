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

## Phase 2 - Normalization
- [ ] `SecurityFinding` Pydantic model
- [ ] Deduplication across rules and tools (pip-audit emits duplicates)
- [ ] CWE / OWASP Top 10 2025 mapping
- [ ] SQLite persistence (SQLModel/SQLAlchemy)
- [ ] JSON and HTML report
- [ ] Tool-only baseline metrics (compare against 9/11 positives detected, 4/7 negatives falsely flagged)
- [ ] Model scanner coverage (files actually analyzed/skipped; Semgrep ignores files over 1 MB silently)
- [ ] Map pip-audit findings to requirement lines via `manifest.json` `pinned_requirements`

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
