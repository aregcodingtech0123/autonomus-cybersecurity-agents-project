# secaudit

A multi-agent security audit platform for Python source code.

**Core principle:** real security tools (Semgrep, Bandit, Gitleaks, pip-audit) do the
scanning. LLM agents only triage, assess risk and propose fixes based on tool evidence.
The LLM is never the scanning engine.

## Status

**Phase 0 complete** - foundation and benchmark infrastructure only:
repo skeleton, a deliberately vulnerable benchmark target, a verified ground-truth file,
and a raw-output discovery of the four scanners. No adapters, agents, API, MCP server or UI yet.

See [docs/SCOPE.md](docs/SCOPE.md), [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md) and
[benchmarks/baseline/DISCOVERY.md](benchmarks/baseline/DISCOVERY.md).

## Development

```sh
uv sync
uv run pytest
uv run ruff check .
uv run secaudit --version
```

`benchmarks/targets/` contains intentionally vulnerable code. It is excluded from lint,
format and test collection, and must never be deployed.
