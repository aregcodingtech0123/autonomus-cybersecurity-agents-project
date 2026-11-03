# Scope

## Principle

Real security tools find issues. LLM agents only triage, assess risk and propose fixes
**from tool evidence**. The LLM is never the scanning engine.

## MVP scope

- **Language:** Python only. Adapter-based scanner layer so JS/TS and Java can follow later.
- **Mode:** Code Audit only (source code or ZIP supplied by an authorized user).
- **Scanners:** Semgrep, Bandit, Gitleaks, pip-audit.
- **Storage:** SQLite first (SQLModel/SQLAlchemy); PostgreSQL later. No Redis.
- **Data model:** one normalized Pydantic `SecurityFinding`; SARIF as the scanner input format
  where the tool supports it (pip-audit does not; it needs a JSON adapter).
- **Interfaces:** one Python core exposed through a CLI, a FastAPI service (for the Next.js
  dashboard) and an MCP server. Only the CLI `--version` stub exists in Phase 0.
- **Patches:** proposed as unified diffs, validated on a copy, **never auto-applied**. A human approves.
- **LLM powers:** may lower severity with a written justification; may never delete a finding.

## Non-goals

- Live-system scanning, port scanning, active exploitation or fuzzing of running systems (until Phase 9, passive only).
- Auto-applying fixes to the user's repository.
- Replacing SAST/SCA tools with LLM judgment, or "AI-only" vulnerability discovery.
- Languages other than Python in the MVP; IaC, container-image and cloud-config scanning.
- Multi-tenant SaaS, authentication/billing, Redis/queue infrastructure.
- Scanning code the user is not authorized to audit.

## Success metrics

Measured against `benchmarks/expected_findings.yaml` and compared with the tool-only baseline
(Phase 2A tool-only baseline: 9 of 12 positives detected, 4 of 7 negatives falsely flagged, see
`benchmarks/baseline/metrics_tool_only.md` and `docs/PHASE2A_NOTES.md`; the Phase 1 figures were 9 of 11 and
4 of 7, the difference being the added case P11). The Phase 0 figure of 7 of 10 was
computed with a flawed P03 case and is superseded.

| Metric | Definition |
|---|---|
| **Detection Accuracy** | Share of planted positives (P-cases) reported, matched by file and line-range overlap. |
| **False Positive Rate** | Share of reported findings that land on a negative (N-case) or are otherwise judged not real, after triage. |
| **Evidence Coverage** | Share of final findings that cite concrete tool evidence (tool, rule id, location, snippet). Target: 100%. |
| **Patch Validation Rate** | Share of proposed patches that apply cleanly, pass a syntax check, and make the original finding disappear on rescan without adding new ones. |
| **Agent Reliability** | Share of runs that produce schema-valid output and resist the injection baits (I01, I02): no suppressed findings, no prompt or credential leakage. |
| **Cost per audit** | LLM tokens and wall-clock time per audit, reported in currency and seconds. |
