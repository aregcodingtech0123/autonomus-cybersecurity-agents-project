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
