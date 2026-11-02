# Security policy for secaudit itself

The platform ingests hostile input (arbitrary source code) and feeds it to scanners and, later, LLMs.
These rules are requirements. Sections 1-3 are implemented and tested as of Phase 1
(see `docs/PHASE1_NOTES.md` for the threat -> mitigation -> test table); section 4 applies from Phase 3.

## 1. Scanner isolation (Docker)

Each tool runs in its own short-lived container, built by `core/sandbox.py` as an argument list
(never a shell string). These flags are always present:

| Control | Flag / value |
|---|---|
| Cleanup, no implicit pulls | `--rm`, `--pull never` (images are built locally and pinned) |
| Network | `--network none`; only pip-audit gets `--network bridge` (outbound only, nothing published) |
| Filesystem | `--read-only` root, `--tmpfs /tmp:rw,noexec,nosuid,size=256m`, `--workdir /src` or `/tmp` |
| Privileges | non-root `--user 10001:10001`, `--cap-drop ALL`, `--security-opt no-new-privileges` (default seccomp/AppArmor left on, never `unconfined`) |
| Resources | `--pids-limit 256`, `--memory 1g`, `--memory-swap 1g`, `--cpus 2` |
| Mounts | source read-only at `/src`; Semgrep rules read-only at `/rules`; a **separate** per-tool writable `/out`. Nothing else |
| Environment | explicit allow-list of names (`HOME`, `TMPDIR`, `LANG`, `XDG_CACHE_HOME`, `PYTHONDONTWRITEBYTECODE`, `SEMGREP_SEND_METRICS`, `SEMGREP_ENABLE_VERSION_CHECK`) with explicit values; no host passthrough |
| Time / output | 600 s wall clock per tool, then `docker kill` + `docker rm -f` **by container name**; 64 KiB captured per stream; container killed if a stream exceeds 8 MiB; result file at most 100 MiB |

Never produced: `--privileged`, host network/PID/IPC/UTS namespaces, `--device`, `--cap-add`, `-v`/`--volume`,
`--env-file`, any mount of the Docker socket. Mount sources must be absolute real directories and may not contain
`,` `'` `"` or newlines (mount-option injection), and the output mount may not overlap an input mount.

**Network exceptions are declared per adapter, not ad hoc:**
- *pip-audit* ("egress-only, no-source"): the container receives only a staged `requirements.audit.txt` of exact
  pins, never the source tree; it never resolves or installs dependencies (`--no-deps --disable-pip`). Only package
  names and versions leave the machine.
- *Semgrep rules update* (`secaudit rules update`): runs the fetcher in the Semgrep image with network and **no
  scanned code mounted**; rules are hash-verified, smoke-scanned offline, then mounted read-only for scans.

**Scan policy is ours.** Scanned content cannot configure or silence the scan: a neutral `.semgrepignore` is written
into the workspace copy, Gitleaks uses a baked config and empty ignore path, and `--ignore-nosec`, `--disable-nosem`
and `--ignore-gitleaks-allow` are always on. Gitleaks runs with `--redact`.

**Images:** base images pinned by digest; Python tools installed with `--require-hashes` lockfiles; the Gitleaks
tarball is verified against a hard-coded SHA-256 and the published checksums (build fails on mismatch). Release
signatures/attestations are not verified.

Disclosed gaps: no per-container disk quota on `/out`; default (not hardened) seccomp profile; shared host kernel.

## 2. Intake (implemented in `core/intake.py`)

Every rejection raises `IntakeError` with a stable reason code. Defaults (all configurable via `IntakeLimits`):

| Limit | Default |
|---|---|
| Files per input | 10,000 |
| Total uncompressed bytes | 256 MiB |
| Single file | 64 MiB |
| Compression ratio (entries/archives >= 1 MiB) | 100 : 1 |
| Path length | 240 characters |
| Git clone wall clock / size | 120 s / 256 MiB |
| Git hosts (https only) | github.com, gitlab.com, bitbucket.org, codeberg.org |

- **Directories:** copied entry by entry without following links. Symlinks that escape the root reject the input;
  internal symlinks are skipped (never recreated); devices, sockets and FIFOs reject the input; `.git` is excluded
  unless `--include-git`. Files are opened with `O_NOFOLLOW` and re-checked after opening.
- **ZIP:** manual per-entry extraction (never `extractall`). Rejects absolute paths, `..`, backslashes, drive
  letters, NTFS streams, reserved device names, control characters, symlink/special entries, encrypted entries,
  nested archives (by extension and magic bytes), duplicate or case/Unicode-colliding names, lying size headers,
  and anything exceeding the limits above (checked on declared and on actually written bytes).
- **Git URL:** `https://` only, host allow-list, no credentials, no IP literals, default port only, no query/fragment.
  `git clone --depth 1 --single-branch --no-tags --no-recurse-submodules` with hooks directed to an empty directory,
  `protocol.file.allow=never`, `core.symlinks=false`, `http.followRedirects=false`, `GIT_TERMINAL_PROMPT=0`, no
  system/global config, a scrubbed environment, a time limit and size polling. `.git` is deleted afterwards and the
  tree is re-validated by the directory intake.
- Never execute, import, install or build the scanned project on the host.

## 3. Authorization and data handling

- **Authorized targets only.** The user must confirm authorization for each audit; no scanning of third-party
  systems. Live-system features (Phase 9+) are passive only.
- Patches are proposals; nothing is written to the user's repository automatically.
- Audit output is local (`./audits/<audit_id>/`). **Raw scanner outputs are SECRET-BEARING.** Only Gitleaks redacts
  (`--redact`); Bandit embeds the offending source line verbatim (and Semgrep may), so `raw/bandit.sarif` contains
  hardcoded passwords and keys found in the scanned code (verified: `tests/test_docker_integration.py::
  test_secret_literals_appear_only_in_documented_raw_files`). Treat the whole audit directory as sensitive.
  On POSIX the audit directory and `raw/` are created `0700` and raw files and `manifest.json` `0600`
  (permissions only; raw bytes stay byte-identical so the manifest SHA-256 remains valid). On Windows no
  permission hardening is applied (no portable stdlib equivalent; **unverified/not done**).
  Only `manifest.json` and CLI summaries are guaranteed secret-free (no host paths, no secret values).
  Masking of any *derived* data (findings, evidence snippets, anything shown to an LLM) happens in Phase 2.
- The temporary workspace is deleted after every run, including failures and timeouts.
- `--runner native` has no isolation: it refuses to run without `--i-trust-this-code` and prints a warning.
- Fetched Semgrep rules are never committed to the repository (license; see `docs/PHASE1_NOTES.md`).

## 4. LLM safety (applies from Phase 3)

- **The LLM never gets a shell**, a filesystem tool, or network access. Its tools are limited to read-only queries
  over already-collected, size-limited evidence.
- **Scanned content is untrusted data**, never instructions. Comments, READMEs and docstrings are quoted inside
  delimited data blocks; instructions found there are ignored and may be reported as a finding. Benchmark cases
  I01 and I02 test this.
- The LLM can lower a severity with a justification but **cannot delete or hide a finding**. Findings are stored
  independently of model output.
- Outputs must validate against a structured schema; invalid output is retried, then failed, never trusted.
- **Secrets are masked before any LLM call.** Gitleaks output is already redacted on disk; masking of other
  evidence happens in the normalization layer, not in the prompt.
- System prompts and credentials are never included in model-visible context.

## 5. Benchmark data

`benchmarks/targets/` is intentionally vulnerable. It is never deployed, never imported by `secaudit`, and excluded
from lint, format, test collection and self-scanning. Only fake or vendor-documented example credentials may appear
there. (It *is* scanned on purpose by the benchmark, inside the sandbox.)
