# Architecture decisions

One record per decision that is expensive to reverse or easy to forget the reason for. Newest last.

## ADR-001: Semgrep registry rules are used for local, user-initiated runs only

- **Status:** accepted (Phase 2B, 2026-11-03)
- **Decision:** Semgrep registry rules are under the Semgrep Rules License v1.0; the project uses them for
  local, user-initiated runs only; rules are never committed or redistributed; revisit with own custom rules
  before any hosted deployment.
- **Consequences (what this means in the repository):**
  - `secaudit rules update` fetches the rulesets into `.secaudit/rules/` (git-ignored). Nothing under that
    directory is ever committed, packaged into an image, or attached to a release.
  - CI fetches the rules fresh inside the Docker job and deletes them at the end. The workflow has no
    `upload-artifact` and no cache step, which `tests/test_ci_workflow.py` asserts.
  - The committed baseline records only the rule snapshot's names and SHA-256 hashes
    (`benchmarks/baseline/manifest.json`), not the rules. The strict parity test therefore skips, with a stated
    reason, when a machine's snapshot differs from the recorded one.
  - Reports and the database carry rule ids, short names and the finding's own message. They do not embed
    rule bodies or whole rule files.
- **Open:** a hosted or distributed product cannot rely on the registry rules. Before any such deployment,
  replace them with project-owned custom rules (the Phase 2C/3 roadmap already needs custom rules for P08, P10
  and P11, which no registry rule detects) or obtain a license. Until then this ADR is the boundary.
- **Related:** `docs/PHASE1_NOTES.md` (license summary), `docs/ROADMAP.md`.
