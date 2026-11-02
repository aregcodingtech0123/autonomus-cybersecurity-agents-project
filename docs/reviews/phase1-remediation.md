# Phase 1 remediation log

Every row: reproduce with a failing regression test, fix, show it passing. "Before" = output of the new test on the
unfixed code; "After" = same test on the fix. Statuses: fixed / mitigated / documented / deferred / unverified.

## Summary table

| # | Finding | Status | Regression test (examples) | Evidence |
|---|---|---|---|---|
| 1 | cwd executable hijack (Windows) | **fixed** | `test_exe.py::test_planted_docker_and_git_in_cwd_are_never_executed`, resolver tests, AST guard | before: planted `docker.exe` ran -> `(False, 'docker info failed')`; after: real Docker answers, planted git/bandit refused |
| 2 | `.bandit` disables Bandit | **fixed** | `test_scanner_neutralization.py[bandit-root/-nested/-dir-named]` | 1 and 13 results -> 16 |
| 3 | nested `.semgrepignore` hides Semgrep findings | **fixed** | `[semgrepignore-nested/-root-dir/-in-tests]`, policy test x5 | 1 result -> 11; dir-named no longer aborts the scan |
| 3+ | **new:** `.gitleaksignore` hides all Gitleaks findings | **fixed** | `[gitleaksignore-root/-nested]` | 0 -> 3 results |
| 4 | "no raw secrets on disk" false | **fixed (docs + permissions)** | `test_secret_literals_appear_only_in_documented_raw_files`, `test_posix_audit_directory_and_raw_files_are_private` | Bandit output proven secret-bearing; POSIX `0700/0600`; Windows ACLs **not done** |
| 5 | cleanup chmods through symlink / leaves files | **fixed** | `test_cleanup_and_user.py` (4 Linux-container tests) | victim `0o700` -> `0o600` kept; leftovers -> `CleanupError`; **new:** read-only trees were never removed before |
| 6 | hardlinks | **fixed** | `test_hardlink_*` (Windows `os.link` + Linux) | accepted -> `hardlink` |
| 7 | untyped errors, tracebacks, host paths | **fixed** | `test_intake_hardening.py`, `test_cli_errors.py` | 6 crashes + long path + dir `.semgrepignore` -> typed; CLI prints one line, `--debug` opt-in |
| 8 | exhaustion before limits | **fixed** | `test_intake_limits.py` | 9.79 s / 168 MB -> 0.011 s / 0.1 MB; 5,000 dirs rejected |
| 9 | egress reaches Docker host side | **documented** (no mitigation demonstrable) | `test_KNOWN_RESIDUAL_RISK_...` | 4 network variants measured; none closes it |
| 10 | Gitleaks default path allowlist | **documented** | `test_manifest_declares_per_tool_limitations` | `limitations` in every tool's manifest entry |
| 11 | reserved device names | **fixed** | `test_reserved_windows_device_names_are_rejected` (14) | 6 variants accepted -> rejected |
| 12 | TOCTOU | **mitigated** (identity check) | `test_file_swapped_between_check_and_open_is_detected` | Windows residual (no `O_NOFOLLOW`, parent junctions) documented, not eliminated |
| 13 | no deadline inside container | **fixed** | `test_container_deadline.py` | orphan alive 25 s after parent kill -> reaped / self-terminates |
| T | tests that overclaimed | **fixed** | `test_intake_real_links.py`, SIZE_MISMATCH simulation (mutation-checked), policy x5, filler removed | see section below |

Deviations: CLI exit code for internal bugs is 1 (typed input rejections stay 3); exit code 6 added for cleanup failure;
`SIZE_MISMATCH` is tested by simulation; Windows file-permission hardening not implemented; #9 not mitigated.

## Review probes: before / after

| Probe (from the review) | Before | After |
|---|---|---|
| junction escaping the input | rejected | rejected (`symlink_escape`) |
| hardlink to outside file | ACCEPTED, content copied | `hardlink` |
| ZIP names with `? < > \| " *` | untyped `OSError` x6 | `unsafe_name` x6 |
| 237-char entry (MAX_PATH) | untyped `FileNotFoundError` | `unsafe_name` |
| `CONIN$`, `CONOUT$`, COM-superscript, `LPT`-superscript, `CON .txt`, `AUX .py` | ACCEPTED x6 | `unsafe_name` x6 |
| `.semgrepignore/` directory | `PermissionError`, whole audit aborted | neutralized, scan continues |
| 300,000-entry ZIP | 9.79 s, 168 MB | 0.011 s, ~0 MB |
| `.bandit` (root / nested) | 1 / 13 of 16 results | 16 / 16 |
| nested `.semgrepignore` | 1 of 11 | 11 |
| `.gitleaksignore` (new) | 0 of 3 | 3 |
| planted `docker.exe` in cwd | planted binary ran | real Docker used |
| orphan after killed parent | still running after 25 s | reaped / self-terminates |
| Gitleaks path-allowlist (node_modules, go.sum, svg) | 3 (key not found) | 3 (**unchanged, declared limitation**) |

Benchmark unchanged: a fresh container scan matches `benchmarks/baseline/raw/` at rule/file/line level (Bandit 16, Semgrep 11,
Gitleaks 3) and reports the same vulnerable pins for pip-audit (Flask 2.0.1, PyYAML 5.3.1, requests 2.19.0).
Observed side effect, not attributed: per-container durations were noisier/higher in the final run (3-4 s vs ~1 s); the same
plain `docker run` varied between 1.4 s and 6.3 s in a direct measurement, so the `timeout` wrapper is not shown to be the cause.

## Evidence

### #1 Current-directory executable hijack (Windows) - FIXED
- Test: `tests/test_exe.py` (resolver unit tests, `test_no_subprocess_calls_outside_exe_module`,
  `test_planted_docker_and_git_in_cwd_are_never_executed`).
- Before (unfixed code): `ImportError: cannot import name 'exe'` for all resolver tests; the AST guard reported
  `cli.py:139 subprocess.run` plus 11 more direct `subprocess`/`shutil.which` sites; with a planted `docker.exe`
  (hostname.exe) in the cwd and the env var removed, `docker_available()` returned
  `(False, 'docker info failed')` (the planted binary ran).
- Fix: `core/exe.py` walks PATH itself (skips cwd, relative/empty entries, scanned input/workspace, `.bat/.cmd`),
  `taskkill` from `%SystemRoot%\System32`, wrappers `exe.run/exe.popen` are the only spawners; the CLI also sets
  `NoDefaultCurrentDirectoryInExePath=1`.
- After: planting test passes (git prints `git version ...`, real Docker answers, planted `bandit.exe` refused).
- Unverified: behaviour on non-Windows hosts (the cwd-search problem is Windows-specific).

### #2, #3 Scanned code changing scanner behaviour - FIXED (plus a new finding)
- Tests: `tests/test_scanner_neutralization.py` (28 cases, docker), `tests/test_neutralize.py` (unit + manifest wiring).
- Before (unfixed code, `pytest tests/test_scanner_neutralization.py`): `23 failed, 5 passed`. Causes seen:
  `AssertionError: bandit-root changed the bandit result count / assert 1 == 16`,
  `gitleaksignore-root ... assert 0 == 3`, `PermissionError ... .semgrepignore` for the directory-named case,
  `KeyError: 'neutralized_files'` for the rest.
- New finding from the matrix: `.gitleaksignore` hides all Gitleaks findings (3 -> 0) despite `--gitleaks-ignore-path`.
- Fix: `core/neutralize.py` removes `.bandit`, `.semgrepignore`, `.gitleaksignore`, `.gitleaks.toml` at any depth (files or
  directories, case-insensitive), replaces the root `.semgrepignore`, raises a typed `IntakeError(IO_ERROR)` on failure;
  manifest gains `neutralized_files`.
- After: `28 passed` (every result count equals the baseline); unit suite `211 passed, 2 skipped`.

### #4 "No raw secrets on disk" claim - FIXED (docs + permissions)
- Tests: `test_secret_literals_appear_only_in_documented_raw_files` and `test_raw_files_are_byte_identical_to_what_the_manifest_hashes`
  (docker, replace the Gitleaks-only test; also checks `manifest.json` and the CLI stdout/stderr), and
  `tests/test_raw_output_secrecy.py::test_posix_audit_directory_and_raw_files_are_private` (runs the orchestrator in a Linux container).
- Before: permissions test failed with `'0o755' == '0o700'`. The content test passed on unfixed code because the
  claim was wrong in the docs, not in the code; it now pins the truth (Bandit output contains the literal secret,
  Gitleaks/pip-audit/manifest/CLI do not).
- Fix: SECURITY_POLICY corrected; audit dir/`raw/` 0700, raw files and manifest 0600 on POSIX; bytes untouched.
- After: both pass. Unverified: any permission hardening on Windows (not implemented).

### #5 Cleanup follows symlinks and leaves files behind - FIXED (option (a): host uid:gid on POSIX)
- Tests: `tests/test_cleanup_and_user.py` (container-user unit tests; four `docker` tests in a Linux container with users 10001 and 1000).
- Before: `AttributeError: ... no attribute 'container_user'` (x5), `AssertionError: victim file permissions were changed / '0o700' == '0o600'`,
  `assert None == 'CleanupError'` (leftover `d` silently ignored), and `{'gone': False} != {'gone': True}` (read-only directory tree not removed:
  second, unreported bug in the old cleanup).
- Fix: `sandbox.container_user()` / `output_dir_mode()`; symlink-safe `remove_tree` + `CleanupError`; `_discard` for failure paths; orchestrator
  raises loudly after the manifest; CLI exit 6. Output dirs are 0700 (0777 only for the root-host fallback).
- After: `26 passed` (cleanup + docker integration). Justification for (a) is in docs/PHASE1_NOTES.md.
- Unverified: real Linux/macOS hosts (no `--user <host uid>` run there); Windows semantics unchanged (fixed uid 10001).

### #6 Hardlinks, #7 untyped errors/hostile names, #11 reserved names, #12 TOCTOU - FIXED
- Tests: `tests/test_intake_hardening.py` (hardlinks incl. a Linux-container case, six Windows-invalid characters, 300-byte component,
  237-char MAX_PATH entry, total path-length rule, ANY OSError during zip/dir copy -> typed), `tests/test_intake_names_toctou.py`
  (all six review variants plus eight more reserved names, look-alikes that must still be accepted, a deterministic lstat->open race).
- Before (unfixed code): `27 failed, 12 passed` (AttributeError for `Reason.HARDLINK`/`CHANGED_DURING_INTAKE`/`IO_ERROR`; the six
  invalid characters, the long path and every OSError case were not typed; reserved variants like `CONIN$`, `COM1`+superscript were accepted).
- Fix: `Reason.HARDLINK` (reject, never skip: two hardlinked repo files would otherwise be silently hidden), `IO_ERROR`, `CHANGED_DURING_INTAKE`;
  `_io_guard` converts any OSError (errno only, no paths); `<>"|?*` and >255-byte components rejected; total path length checked before
  anything is written (Windows 259, POSIX 4095); NFKC-normalised reserved-name check incl. `CONIN$`/`CONOUT$`/`COM0-9`/`LPT0-9`;
  `os.lstat` identity (`st_dev`, `st_ino`) compared with `fstat` of the opened descriptor.
- After: `39 passed`. TOCTOU residual (documented, unverified to be exploitable): Windows has no `O_NOFOLLOW` and still follows parent
  junctions; the identity check narrows but cannot close that window. A concurrent local attacker is out of scope for the container sandbox.
- Directory-named `.semgrepignore` aborting every tool (#7) was fixed in T2 (`neutralize_workspace`) and is covered there.

### #7 CLI tracebacks and host paths - FIXED
- Tests: `tests/test_cli_errors.py` (10 cases).
- Before: `5 failed, 5 passed` (an unexpected exception escaped `main()` as a raw traceback).
- Fix: catch-all prints ONE line with the exception type only, writes the traceback to `.secaudit/logs/secaudit-*.log`
  (`SECAUDIT_LOG_DIR` overrides), `--debug` (before or after the subcommand) prints it. Input-caused failures stay typed (exit 3);
  an internal bug exits 1. Deviation: the task text asked for exit code 3 for everything; reporting a bug as "input rejected" would mislead.
- After: `10 passed`; full non-docker suite `266 passed, 2 skipped`.

### #8 Resource exhaustion before limits apply - FIXED
- Tests: `tests/test_intake_limits.py` (7 cases): archive size limit enforced before hashing/parsing (tripwires on `_hash_file` and
  `zipfile.ZipFile`), EOCD entry count and central-directory size checked before the ZipFile is built, directories count toward the limit,
  real 300,000-entry ZIP (also exercises ZIP64) under a 3 s / 64 MB budget, 5,000 empty directories with `max_files=100`.
- Before (unfixed code): `5 failed, 2 passed`; `rejection took 10.47s (was 9.79s)`; tripwires hit (hashed/parsed first); the directory flood was accepted.
- Fix: `IntakeLimits.max_archive_bytes` (128 MiB, `Reason.ARCHIVE_TOO_LARGE`), `_read_eocd` reads only the last 66 KiB (incl. ZIP64 locator),
  entries > `max_files` or central directory > `max_files * 1024` bytes are rejected before any parsing; `_Budget` counts files AND directories
  (`file_count` in the result still reports files only).
- After: `7 passed`. Measured: 300,000-entry ZIP rejected in 0.011 s with 0.1 MB peak Python heap (before: 9.79 s / 168 MB).

### #13 No deadline inside the container / orphans after a killed parent - FIXED
- Tests: `tests/test_container_deadline.py` (builder wrapper + labels, `pid_alive`, and four real-container tests; `docker` marker) and the
  updated layout assertion in `tests/test_sandbox_command.py`.
- Before (behavioural, unfixed code): a child process started a container with `timeout_s=3`, was hard-killed, and 25 s later
  `orphan still running ... : True`. New tests failed at collection (`cannot import name 'pid_alive'`).
- Fix: the container command is wrapped in coreutils `timeout -k 5 <timeout_s+10>` (present in all four images, verified); containers carry
  `org.secaudit.owner-pid` / `org.secaudit.started` labels; `reap_stale_containers()` (run by `preflight` and `rules update`) removes labelled
  containers whose owner pid is dead (posix `kill(pid,0)`, Windows `OpenProcess`) or older than 24 h (guards pid reuse).
- After: `27 passed` for the two files; full suite `329 passed, 2 skipped`, 0 labelled containers left. Killed-parent evidence: the orphan
  survives `Popen.kill()` of its parent (precondition asserted), is removed by the reaper, and a separate orphan exits on its own within 60 s.
- Not covered: the 24 h age cap and the Windows `OpenProcess` access-denied branch are reasoned, not exercised.

### #9 Egress network reaches the Docker host side - DOCUMENTED (no mitigation could be demonstrated)
- Experiment (container probing TCP reachability, `scratchpad/review/egress_probe.py`): default bridge, `--add-host` overrides, `--dns 1.1.1.1`
  and a user-defined bridge all left `192.168.65.254:2375` and `169.254.169.254:80` answering `refused(host answered)`; only name resolution varied.
  No flag was added. Table and reasoning in SECURITY_POLICY section 6; ROADMAP Phase 8 item added.
- Tests: `test_internet_is_reachable_only_for_adapters_that_declare_egress` (the renamed overclaiming test; it proves only internet reachability) and
  `test_KNOWN_RESIDUAL_RISK_egress_network_can_reach_the_docker_host_side` (Docker Desktop only; pins the residual exposure so a change is noticed).
- Unverified: Linux hosts (Docker's bridge gateway there is the host itself; not measured) and any cloud metadata behaviour beyond the TCP answer seen here.

### #10 Gitleaks default path allowlist - DOCUMENTED + surfaced in the manifest
- Test: `tests/test_limitations_and_egress.py::test_manifest_declares_per_tool_limitations` (+ skipped-tool variant).
  Before: `2 failed` (`KeyError: 'limitations'`). After: `4 passed` in the file.
- Verified while at it (`coverage_probe.py`): Bandit omits an unparsable file with no notice; Semgrep skips a >1 MB file with no notice but reports
  parse errors as notifications; Gitleaks skips binary files. All four adapters now declare `limitations`, copied into every tool's manifest entry.

### Tests that did not prove what their names claim - FIXED (T9)
| Review item | Change | Evidence |
|---|---|---|
| Stubbed symlink tests; real-symlink test skipped here | New `tests/test_intake_real_links.py`: real NTFS junctions (escaping -> `symlink_escape`, internal -> skipped) on Windows; real symlinks (absolute, relative, directory, dangling, loop), FIFO, char device and unix socket in a Linux container | `11 passed`. First time the symlink/special-file logic runs against real links; the stub tests remain as fast unit tests. The old real-symlink test is kept for hosts that may create symlinks. |
| `test_lying_header...` accepted any error | Parametrised stored/deflated, asserts exactly `INVALID_ARCHIVE` with a CRC message | observed reason first (`Bad CRC-32`), then pinned |
| `SIZE_MISMATCH` never exercised | Two simulation tests (stream grows past / shrinks below the declared size); real archives cannot reach the branch because zipfile bounds output by the declared size | mutation check: with both branches disabled `2 failed`, restored `2 passed` |
| Policy test checked only the root file | Five variants: root file, nested file, deeply nested file, root directory, nested directory; asserts the container is handed exactly one neutral `.semgrepignore` | plus the 28-case docker matrix from T2 |
| `assert intake` / `assert DockerExecutor` filler | Dispatcher test asserts extracted contents; ZIP round trip asserts archive SHA-256, file count 15 and that Bandit analysed `webshop/db.py` | - |
| Cleanup test Windows-only | Linux-container two-user scenarios (T4) + orchestration tests proving a `CleanupError` is raised after the audit is written and never masks the real error (`__notes__`) | `test_a_cleanup_failure_*` |
| Egress test overclaimed | Renamed, residual risk pinned separately (T8) | - |
- Full suite after T9: `352 passed, 2 skipped` (symlink-on-Windows and opt-in network), 0 labelled containers left.
