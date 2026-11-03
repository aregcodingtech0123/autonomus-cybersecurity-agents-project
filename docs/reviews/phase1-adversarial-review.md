# Phase 1 adversarial review (verbatim record)

Independent adversarial review of the Phase 1 scanner engine, performed against commit `4bba2a4`.
Environment: Windows 11 build 26200, Docker 29.9.2. Findings marked CONFIRMED were reproduced; the two
Linux-specific findings were reproduced inside a Linux container simulating separate host and container
users. The review changed no code. Remediation status lives in `phase1-remediation.md`.

**Bottom line:** the sandbox itself held under every probe, but three things broke the platform's promise:
on Windows, scanning from inside an untrusted folder runs the attacker's program on the host before any
sandbox starts; a planted `.bandit` file or a nested `.semgrepignore` silently erases findings while the
manifest still says `completed`; and the "no raw secrets on disk" claim is false because Bandit's SARIF
contains the secrets verbatim.

## Findings, most severe first

### 1. HIGH (CONFIRMED): planted executables in the current folder run on the host (Windows)
- **Where:** every subprocess call used a bare program name: `sandbox.py:241,297,355` (`docker`),
  `intake.py:524,585,647` (`git`), `intake.py:568` (`taskkill`), `executors.py:122` (`shutil.which`, native runner).
- **Exploit:** a malicious repo ships `docker.exe` or `git.exe`; the user runs `cd repo && secaudit scan .`.
  Windows searches the current folder before PATH, so the attacker's binary runs as the user before any container exists.
- **Evidence:** `whoami.exe` renamed `docker.exe` in a scratch folder, `NoDefaultCurrentDirectoryInExePath`
  removed: `subprocess.run(['docker'])` printed `'desktop-vo5fj4o\\user'`; `docker_available()` returned
  `(False, 'docker info failed')` (the planted binary ran); `shutil.which('git')` -> `.\git.EXE`,
  `shutil.which('bandit')` -> `.\bandit.EXE`. With the variable set (as in the review shells) the real binaries ran,
  which is why the test suite never noticed.
- **Fix:** set the variable at CLI start; resolve every external program once to an absolute path, rejecting results
  in the cwd/input; call `taskkill` from `%SystemRoot%\System32`.

### 2. HIGH (CONFIRMED): a `.bandit` file in the scanned code turns off Bandit
- **Where:** `scanners/bandit.py:12`. Bandit reads `.bandit` from the target directory.
- **Evidence:** real adapter through the sandbox: `[bd-baseline] 16 results` -> `[bd-dot-bandit] 0 results`, status `completed`.
  Not effective: `[tool.bandit]` in `pyproject.toml`, Bandit default exclude names (`.tox`, `*.egg`, `.eggs`,
  `__pycache__`, `.hg`, `CVS`), `.pyw` extension.
- **Fix:** delete/neutralize `.bandit` in the workspace copy, pass a secaudit-owned config, add a test.

### 3. HIGH (CONFIRMED): a nested `.semgrepignore` hides findings from Semgrep
- **Where:** `scan.py:163-166` wrote the neutral policy file only at the workspace root.
- **Evidence:** `[sg-baseline] 11 results` -> `[sg-nested-semgrepignore] 1 results in ['dev_server.py']` with `webshop/.semgrepignore`
  containing `*.py`. Nested and root `.gitignore` had no effect.
- **Why tests missed it:** `test_scan_scope_policy_cannot_be_overridden_by_scanned_code` only checked the root file.
- **Fix:** remove every `.semgrepignore` below the root, record removals in the manifest, add a nested test.

### 4. MEDIUM (CONFIRMED): raw secrets are written to disk by Bandit
- **Claim:** SECURITY_POLICY section 3 said audit output has "no raw secrets (Gitleaks is redacted)".
- **Evidence:** `grep -F` over `benchmarks/baseline/raw/` found `not-a-real-password-benchmark-fake`,
  `placeholder-not-a-real-password` and a fake `sk_test_`-prefixed key in `bandit.sarif`.
- **Why the test missed it:** `test_gitleaks_output_contains_no_raw_secret` only checked Gitleaks' file.
- **Fix:** treat every raw output as secret-bearing (restrictive permissions, masking in Phase 2), correct the policy text,
  extend the test.

### 5. MEDIUM (CONFIRMED under Linux semantics): cleanup chmods through a symlink and leaves files behind
- **Where:** `intake.py:133-135` (`_onerror` calls `os.chmod`, which follows symlinks).
- **Exploit:** a compromised scanner (container user 10001) creates `/out/d/link` -> host file and `chmod 555 d`;
  the host user's `remove_tree` cannot delete the link, so it chmods the link target.
- **Evidence:** Linux container with users 10001 and 1000: victim mode `0o600` -> `0o700`; `leftover after cleanup: True ['d']`.
- **Fix:** never chmod symlinks; run containers as the host uid or clean `/out` as the container user; fail loudly on leftovers.

### 6. MEDIUM (CONFIRMED): hardlinks pull files from outside the input into the workspace
- **Where:** `_copy_tree` / `_copy_regular` check symlinks, not hardlinks.
- **Evidence:** `mklink /H` (no admin needed): `st_nlink = 2`, `[B-hardlink-outside] ACCEPTED -> copied content: 'aws_secret_access_key = bench_BvXX7C2JUs'`.
- **Fix:** reject `fstat().st_nlink > 1` (`HARDLINK` reason).

### 7. MEDIUM (CONFIRMED): malformed names crash the scan with untyped errors
- **Evidence:** ZIP entry with `? < > | " *` -> `UNTYPED OSError: [Errno 22]`; a 237-character entry -> `FileNotFoundError`
  (over MAX_PATH once joined to the temp path); a `.semgrepignore/` directory input -> `PermissionError` aborting all tools;
  through the CLI both end in a traceback, exit 1, printing host temp paths. Cleanup did happen.
- **Fix:** reject `<>:"|?*`, check joined path length, convert any `OSError` into `IntakeError`, handle a directory-named
  policy file, add a CLI catch-all without traceback.

### 8. LOW-MEDIUM (CONFIRMED): resource exhaustion before limits apply
- 300,000 empty entries (26 MB) took 9.79 s and 168 MB before `too_many_files`; no archive size limit; the archive is hashed
  and fully parsed first. Directories are not counted: `max_files=1` accepted 5,000 empty directories.
- **Fix:** `max_archive_bytes`, read the entry count from the end-of-central-directory record first, count directories.

### 9. LOW-MEDIUM (CONFIRMED reachability): "egress-only" network reaches the Docker host and metadata address
- `host.docker.internal -> 192.168.65.254`, `gateway.docker.internal -> 192.168.65.1`, `169.254.169.254` addressable;
  TCP connect to `host.docker.internal:2375` returned `ConnectionRefusedError` (the host answered). Low exploitability:
  pip-audit only receives sanitized pins.
- **Fix:** egress allowlist/proxy and private-range blocking; rename the overclaiming test.

### 10. LOW (CONFIRMED): Gitleaks' default path allowlist hides secrets in some locations
- Synthetic AWS key found in `src/`, `vendor/`, `*.min.js`, `.git_backup/`; NOT found in `node_modules/`, `go.sum`,
  `package-lock.json`, `poetry.lock`, `*.svg`, `*.pdf`. Cause: `useDefault = true` keeps the built-in path allowlist.

### 11. LOW (SUSPECTED): reserved Windows device names slip through
- `_WINDOWS_RESERVED` check compares `part.split(".")[0]`; `CONIN$`, `CONOUT$`, `COM¹`, `LPT²`, `"CON .txt"`, `"AUX .py"` were
  accepted (ordinary files on build 26200; older Windows may open devices).

### 12. LOW (SUSPECTED, not reproduced): check-to-copy race (TOCTOU)
- `O_NOFOLLOW` does not exist on Windows (silently 0) and only protects the last path component; a concurrent local attacker
  could swap a file for a link after the check.

### 13. LOW (SUSPECTED, reasoned): no deadline inside the container
- If the secaudit process is SIGKILLed, the host timeout and `docker kill` never run and the container lives until the tool ends.

## Tests that don't prove what their names claim
- `test_escaping_symlink_rejected` and the internal-symlink test stub `_is_link`/`_within`; the real-symlink test skips on this account.
- `test_lying_header_is_rejected_not_trusted` accepts any error (zipfile's CRC check fires); no test exercises `SIZE_MISMATCH`.
- `test_scan_scope_policy_...` and `test_gitleaks_output_contains_no_raw_secret` each check only part of their claim.
- Filler assertions: `test_dispatcher_routes_zip` ends with `assert intake`; `test_zip_input_round_trips_through_the_sandbox` ends with `assert DockerExecutor`.
- `test_workspace_and_containers_are_cleaned_up` runs on Windows only, so it cannot catch #5.
- `test_egress_policy_really_allows_outbound_only_when_declared` never tests what else is reachable.

## What held up (tried and failed to break)
ZIP path traversal variants (second-layer defense held when the explicit `..` check was removed); real junction escape;
command construction (no `shell=True`, mount-path injection rejected, Git URL after `--`); Git config isolation;
sandbox properties (no network/DNS, read-only fs, uid 10001, no caps, NoNewPrivs, no Docker socket, timeouts/floods killed);
Gitleaks redaction in its own file; symlinks in `/out`.

## Probe scripts (scratchpad)
- `C:\Users\User\AppData\Local\Temp\claude\d--Kendi-Projelerim-autonomus-cybersecurity-agents-project\26e93906-6abb-4e27-b8d8-8d62874bddd4\scratchpad\review\attacks_intake.py`
- `C:\Users\User\AppData\Local\Temp\claude\d--Kendi-Projelerim-autonomus-cybersecurity-agents-project\26e93906-6abb-4e27-b8d8-8d62874bddd4\scratchpad\review\attacks_scanners.py`
