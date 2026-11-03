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
| Privileges | non-root `--user`: the host `uid:gid` on POSIX (root falls back to `10001:10001`), fixed `10001:10001` on Windows; `--cap-drop ALL`, `--security-opt no-new-privileges` (default seccomp/AppArmor left on, never `unconfined`) |
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
| Files **and directories** per input | 10,000 |
| ZIP file size (checked before opening or hashing) | 128 MiB |
| Total uncompressed bytes | 256 MiB |
| Single file | 64 MiB |
| Compression ratio (entries/archives >= 1 MiB) | 100 : 1 |
| Entry name length / component / joined path | 240 chars / 255 bytes / 259 on Windows, 4095 on POSIX |
| Git clone wall clock / size | 120 s / 256 MiB |
| Git hosts (https only) | github.com, gitlab.com, bitbucket.org, codeberg.org |

- **Directories:** copied entry by entry without following links. Symlinks that escape the root reject the input;
  internal symlinks are skipped (never recreated); devices, sockets and FIFOs reject the input; files with more than
  one hard link reject the input (`hardlink`); `.git` is excluded unless `--include-git`. Files are opened with
  `O_NOFOLLOW` and re-checked after opening (type, hard-link count, and `st_dev`/`st_ino` against an earlier `lstat`).
  Every filesystem error becomes a typed `IntakeError` (`io_error`) without host paths.
- **ZIP:** manual per-entry extraction (never `extractall`). Rejects absolute paths, `..`, backslashes, drive
  letters, NTFS streams, reserved device names (NFKC-folded, incl. `CONIN$`/`CONOUT$`/`COM0-9`/`LPT0-9`), characters
  invalid on Windows (`<>"|?*`), control characters, symlink/special entries, encrypted entries,
  nested archives (by extension and magic bytes), duplicate or case/Unicode-colliding names, lying size headers,
  and anything exceeding the limits above (checked on declared and on actually written bytes). The archive size, the
  entry count and the central-directory size are checked from the end-of-central-directory record BEFORE the archive
  is hashed or parsed.
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
  (permissions only; raw bytes stay byte-identical so the manifest SHA-256 remains valid). On Windows the
  audit directory is restricted to the current user with `icacls` (user SID, inheritance removed; verified by
  reading back the SDDL in `tests/test_source_retention.py`). Administrators and SYSTEM can still take
  ownership. `manifest.json` records `source.restricted_to_owner`; if it is false (restriction failed) the
  CLI says so.
- **Retained source (Phase 2A).** `secaudit scan` keeps the sanitized workspace as `<audit>/source/`
  (read-only; `--no-keep-source` disables it) because triage and patch validation need the code. It is the
  neutralized copy the scanners saw (policy files removed, `.semgrepignore` injected), **not** the user's
  original. It can contain secrets (that is what is being audited), so every scan prints one notice with its
  location and how to remove it: `secaudit audit delete <audit_id>` (validates the id, refuses directories
  without `manifest.json`, removes read-only trees on every OS). Temp directories are still always cleaned
  and cleanup still fails loudly; the retained directory is outside the temp root by design. It is
  *copied* (not moved) into place: a rename would keep the files' old, broader Windows ACLs.
- **Derived data is secret-free (Phase 2A).** `findings.json`, snippets and metrics are masked: Gitleaks-flagged
  lines are replaced, secret shapes and sensitive assignments are redacted, and tool **messages** are masked
  too (Bandit's B105 message embeds the literal). Snippets come from the retained source, never from SARIF.
  Tests grep every derived output for the planted fake secrets; raw files are exempt.
  Only `manifest.json` and CLI summaries are guaranteed secret-free (no host paths, no secret values).
- **Database, report and CLI are derived data too (Phase 2B).** `findings.json`, the SQLite database
  (`<out>/secaudit.db`, WAL included), `report.html` and everything the CLI prints are built only from
  `findings.json` / `manifest.json`; raw scanner files are opened for one purpose, verifying their SHA-256
  (`secaudit ingest` refuses, exit 3, when a raw artifact no longer matches the manifest or a finding's `raw_ref`).
  Masking fails closed (URL credentials, Authorization/Bearer/Basic values, `sk-`/GitHub/Slack/Google/AWS/JWT
  shapes, a high-entropy token fallback, typed assignments, and whole private-key blocks found from the full
  retained file). A test greps all of these outputs for the benchmark's planted fakes and for runtime-built
  canaries of every shape; raw files are exempt.
- **The database file is owner-only where the OS allows it:** POSIX 0600 (created that way before SQLite
  touches it, so the -wal/-shm files inherit it); Windows icacls by SID on the file and, for the default
  location, its directory. Administrators and SYSTEM can still take ownership. On Windows a grant with
  `(OI)(CI)` on a file leaves an empty ACL; `restrict_to_owner` uses the plain grant for files.
- **POSIX claims are not yet verified on a real Linux host.** The `0700`/`0600` modes, the `--user <host uid>`
  mapping, symlink/FIFO/hard-link rejection and multi-user cleanup above were exercised on a Windows host with
  Linux containers only. `docs/PHASE1_NOTES.md` ("POSIX / Linux verification status") lists each claim with its
  status and the CI run id once one exists; until a row says VERIFIED with a run id, read it as simulated.
- **Terminal output is escaped.** Every scanned value the CLI prints (paths, titles, rule text, input names)
  passes `cliout.safe`, which removes ANSI/OSC sequences, control, bidi and zero-width characters. The HTML
  report additionally strips them before HTML-escaping, has no script, no external resource and a CSP pinned to
  its one stylesheet.
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

## 6. Known residual risks (declared, not fixed)

- **Egress network reaches the Docker host side (review #9).** The only container with network access (pip-audit, and the
  Semgrep rules fetch) uses Docker's default bridge. Measured on Docker Desktop 2026-11-03: it can reach `host.docker.internal`
  (192.168.65.254), the bridge gateway (172.17.0.1) and the link-local address 169.254.169.254 (TCP connect answers
  `refused`, i.e. the address is routed); 192.168.65.1 timed out. Mitigations were TRIED and none closes it:

  | Variant | Internal *names* | Internal *IPs* | Internet |
  |---|---|---|---|
  | default bridge (current) | resolve | reachable | open |
  | `--add-host host.docker.internal:127.0.0.1` ... | point to loopback | **still reachable** | open |
  | `--dns 1.1.1.1` | do not resolve | **still reachable** | open |
  | user-defined bridge network | resolve | **still reachable** | open |

  Only name resolution changes, which a malicious tool does not need; `--dns` also adds a third-party DNS dependency.
  No flag was added because none gives a boundary. Exposure is limited because the pip-audit container receives only
  package names and versions, never source, and runs with all other restrictions. A real boundary needs an egress
  allow-list proxy and blocking of private/link-local ranges on the host (ROADMAP, Phase 8, Linux deployment).
  Pinned by `tests/test_limitations_and_egress.py::test_KNOWN_RESIDUAL_RISK_egress_network_can_reach_the_docker_host_side`.
- **Gitleaks default path allowlist (review #10).** The baked config uses `useDefault = true`, which keeps Gitleaks' built-in
  path allowlist: a secret under `node_modules/`, in lock files (`go.sum`, `package-lock.json`, `poetry.lock`), or in `.svg` /
  `.pdf` files is NOT reported; binary files are not scanned either (verified). Declared in the manifest as
  `limitations` for every tool so Phase 2's coverage model can surface it. The config was deliberately not rewritten in Phase 1.
- **Scanner coverage is partly invisible.** Bandit silently omits files it cannot parse and Semgrep silently skips files over
  1,000,000 bytes (both verified); see each tool's `limitations` in `manifest.json`.
- **Check-to-open race on intake (review #12).** `lstat` identity is compared with the opened descriptor, but Windows has no
  `O_NOFOLLOW` and still follows parent junctions; a concurrent local attacker is out of scope.

## 7. Secrets policy

- **Real secrets** (API keys, tokens, passwords) reach the program only through environment variables or an untracked
  `.env` file. `.env` and `.env.*` are git-ignored; the only tracked exception is `.env.example`, which lists variable
  names with empty values. Never commit a real value, and never paste one into an issue, a log, a test or a document.
- **Test canaries** are built at runtime, in one place: `tests/canaries.py` assembles every provider-shaped test value from
  harmless fragments when a test calls it, so no realistic token literal sits in the repository or its history. Tests
  must pass on a fresh clone and in CI with no environment file, so fixtures never come from `.env`.
  `tests/test_no_secret_literals.py` scans every tracked file and fails on a provider-shaped literal.
- **No provider-shaped value anywhere** (ADR-003): no file in the repository or its history holds a value
  shaped like a provider credential (Stripe, AWS, GitHub, Slack, Google, GitLab, SendGrid, Shopify, npm, PyPI,
  Hugging Face, DigitalOcean, PEM private keys, JWTs, URLs with credentials), not even a fake one, not even
  in benchmark data, raw scanner outputs or frozen fixtures. `tests/test_no_secret_literals.py` enforces this
  over every tracked file with no allowlist.
- **Benchmark secrets are generic-shaped, intentionally hardcoded, and fake**: they are the vulnerability the
  scanners are measured against, so they stay literal in `benchmarks/targets/`, in the raw outputs that
  quote them, and in `benchmarks/expected_findings.yaml`. Their shape (a `bench_` prefix and a random body)
  matches no provider format, and Gitleaks still detects the positive cases with its generic rule.
- **If a real secret is ever committed**, treat it as compromised: revoke and rotate it first, then remove it from
  history. Removing it from history does not make it safe again.
