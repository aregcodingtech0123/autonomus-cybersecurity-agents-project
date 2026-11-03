# secaudit

A multi-agent security audit platform for Python source code.

**Core principle:** real security tools (Semgrep, Bandit, Gitleaks, pip-audit) do the
scanning. LLM agents only triage, assess risk and propose fixes based on tool evidence.
The LLM is never the scanning engine.

## Status

**Phase 0, Phase 1 and Phase 2A complete.**

- Phase 0: repo skeleton, a deliberately vulnerable benchmark target, a verified ground-truth file.
- Phase 1: safe intake (directory / ZIP / https Git URL), sandboxed scanner execution in pinned Docker
  images, raw result collection into an audit directory with `manifest.json`.

- Phase 2A: normalization of raw output into versioned, secret-free findings (dedup, fingerprints, CWE/OWASP
  Top 10:2025, coverage) and a tool-only baseline (`benchmarks/baseline/metrics_tool_only.md`).

Not yet: persistence, reports, agents, API, MCP server, UI.

See [docs/SCOPE.md](docs/SCOPE.md), [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md), [docs/PHASE1_NOTES.md](docs/PHASE1_NOTES.md),
[docs/PHASE2A_NOTES.md](docs/PHASE2A_NOTES.md) and
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
#    + manifest.json + source/ (sanitized copy, owner-only, may contain secrets; --no-keep-source skips it)

uv run secaudit normalize audits/<audit_id>            # -> findings.json (secret-free)
uv run secaudit audit delete <audit_id> --out audits   # removes raw output and retained source
uv run secaudit eval --from-raw benchmarks/baseline/raw --source benchmarks/targets/vuln_python_app
# -> metrics_tool_only.{json,md}; needs no Docker
```

Exit codes: `0` scan completed (findings do not change it), `2` usage / refused native run,
`3` input rejected, `4` a tool failed or timed out, `5` environment problem (Docker down, images or rules missing),
`6` temporary files could not be removed (leftovers are listed), `1` unexpected internal error.

`--runner native` runs the tools on the host with **no isolation** and requires `--i-trust-this-code`.

`benchmarks/targets/` contains intentionally vulnerable code. It is excluded from lint,
format and test collection, and must never be deployed.
