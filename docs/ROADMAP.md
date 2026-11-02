# Roadmap

Check an item only when it is done and verified. Work found tempting out of phase goes here, not into code.

## Phase 0 - Foundation & benchmark
- [x] Monorepo skeleton (uv, Python >=3.11, ruff, pytest), stub CLI `secaudit --version`
- [x] Benchmark target with 10 positives, 6 negatives, 2 injection baits
- [x] Ground truth `expected_findings.yaml` + line-verifying checker run in pytest
- [x] Scanner output discovery for Bandit, Semgrep, Gitleaks, pip-audit (`benchmarks/baseline/`)
- [x] SCOPE, SECURITY_POLICY, ROADMAP

## Phase 1 - Scanner engine
- [ ] Scanner adapter interface and the four adapters (Semgrep, Bandit, Gitleaks, pip-audit)
- [ ] Docker isolation per `SECURITY_POLICY.md` (non-root, read-only, no network, limits)
- [ ] Offline rules/advisory update step (pip-audit and Semgrep registry need network)
- [ ] Pinned Semgrep rulesets (decide on `p/python` + `p/flask` + `p/security-audit`; tests/ scope)
- [ ] Safe repository and ZIP intake (traversal, symlink and zip-bomb protections)
- [ ] Do not treat non-zero scanner exit codes as failure

## Phase 2 - Normalization
- [ ] `SecurityFinding` Pydantic model
- [ ] Deduplication across rules and tools (pip-audit emits duplicates)
- [ ] CWE / OWASP Top 10 2025 mapping
- [ ] SQLite persistence (SQLModel/SQLAlchemy)
- [ ] JSON and HTML report
- [ ] Tool-only baseline metrics (compare against 7/10 detected, 4/6 false alarms)

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
