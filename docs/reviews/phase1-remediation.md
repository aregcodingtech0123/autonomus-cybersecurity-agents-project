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
