# Phase 1 remediation log

Every row: reproduce with a failing regression test, fix, show it passing. "Before" = output of the new test on the
unfixed code; "After" = same test on the fix. Statuses: fixed / mitigated / documented / deferred / unverified.

## Summary table
(filled in as each task lands; final table at the end)

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
