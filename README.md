# secaudit

A multi-agent security audit platform for Python source code.

**Core principle:** real security tools (Semgrep, Bandit, Gitleaks, pip-audit) do the
scanning. LLM agents only triage, assess risk and propose fixes based on tool evidence.
The LLM is never the scanning engine.

## Status

**Phase 0 and Phase 1 complete.**

- Phase 0: repo skeleton, a deliberately vulnerable benchmark target, a verified ground-truth file.
- Phase 1: safe intake (directory / ZIP / https Git URL), sandboxed scanner execution in pinned Docker
  images, raw result collection into an audit directory with `manifest.json`.

Not yet: finding normalization, agents, API, MCP server, UI.

See [docs/SCOPE.md](docs/SCOPE.md), [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md), [docs/PHASE1_NOTES.md](docs/PHASE1_NOTES.md) and
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
# -> audits/<audit_id>/raw/{bandit.sarif,semgrep.sarif,gitleaks.sarif,pip-audit.json} + manifest.json
```

Exit codes: `0` scan completed (findings do not change it), `2` usage / refused native run,
`3` input rejected, `4` a tool failed or timed out, `5` environment problem (Docker down, images or rules missing).

`--runner native` runs the tools on the host with **no isolation** and requires `--i-trust-this-code`.

`benchmarks/targets/` contains intentionally vulnerable code. It is excluded from lint,
format and test collection, and must never be deployed.
