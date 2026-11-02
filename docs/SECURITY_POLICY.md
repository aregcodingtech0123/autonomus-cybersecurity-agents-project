# Security policy for secaudit itself

The platform ingests hostile input (arbitrary source code) and feeds it to scanners and LLMs.
These rules are requirements for Phase 1 onward.

## 1. Scanner isolation (Docker)

Every scanner runs in its own short-lived container:

- non-root user inside the container; `--cap-drop ALL`; `--security-opt no-new-privileges`
- scanned code mounted **read-only**; read-only root filesystem; a small `tmpfs` for scratch
- **`--network none`** while scanning
- hard limits: CPU, memory, PIDs, wall-clock timeout, output-size cap
- **the Docker socket is never mounted**; no `--privileged`; no host paths other than the read-only target

Offline consequence (observed in Phase 0): pip-audit queries a vulnerability service and Semgrep
`p/...` configs download rules. Therefore rules and advisory data are fetched in a separate,
network-enabled **update step** that never sees the scanned code, and are mounted read-only into
the scan container. Where a tool cannot run offline, only package names and versions leave the
sandbox, never source code. The exact design is a Phase 1 deliverable.

## 2. LLM safety

- **The LLM never gets a shell**, a filesystem tool, or network access. Its tools are limited to
  read-only queries over already-collected, size-limited evidence.
- **Scanned content is untrusted data**, never instructions. Comments, READMEs and docstrings are
  quoted inside delimited data blocks; instructions found there are ignored and may be reported as
  a finding. `benchmarks` cases I01 and I02 test this.
- The LLM can lower a severity with a justification but **cannot delete or hide a finding**.
  Findings are stored independently of model output.
- Outputs must validate against a structured schema; invalid output is retried, then failed, never trusted.
- **Secrets are masked before any LLM call** (Gitleaks output contains the raw secret; Phase 0
  confirmed this). Masking happens in the normalization layer, not in the prompt.
- System prompts and credentials are never included in model-visible context.

## 3. Intake

- ZIP: reject path traversal (`..`, absolute paths, drive letters), symlinks and hardlinks escaping the
  extraction root; cap file count, per-file size, total uncompressed size and compression ratio
  (zip-bomb defence); extract into a fresh empty directory.
- Repository URLs: allow-listed schemes and hosts only; shallow clone with hooks disabled, into an
  isolated directory; no submodule recursion by default.
- Never execute, import, install or build the scanned project on the host.

## 4. Authorization and data handling

- **Authorized targets only.** The user must confirm authorization for each audit; no scanning of
  third-party systems. Live-system features (Phase 9+) are passive only.
- Patches are proposals; nothing is written to the user's repository automatically.
- Uploaded code and reports stay local by default; deletion on request; secrets are masked in reports.
- Logs must not contain secrets or raw source beyond what a finding needs.

## 5. Benchmark data

`benchmarks/targets/` is intentionally vulnerable. It is never deployed, never imported by
`secaudit`, and excluded from lint, format, test collection and self-scanning. Only fake or
vendor-documented example credentials may appear there.
