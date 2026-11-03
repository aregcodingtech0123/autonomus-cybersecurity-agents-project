# Phase 1 notes: scanner engine

Scope delivered: safe intake, sandboxed scanner execution, raw result collection, audit directory
with a manifest. Nothing here parses or normalizes findings (Phase 2). Everything below was run
on Windows 11 with Docker 29.9.2 (Linux engine, x86_64); a Linux or macOS host was **not** tested.

## Design decisions

- **One door per concern.** `core/intake.py` (untrusted input -> sanitized workspace),
  `core/sandbox.py` (exactly one hardened container), `core/scanners/*` (build a command and judge
  completion; never parse), `core/scan.py` (orchestrate and write `manifest.json`), `cli.py` (thin).
- **Exit codes are data.** Every tool returns 1 when it finds something, so each adapter declares
  `completed_exit_codes = {0, 1}`. A run is `completed` only if the exit code is accepted **and** a regular
  result file exists **and** it is well-formed JSON/SARIF. Anything else is `failed`/`timeout`/`skipped`
  in the manifest and never aborts the other tools.
- **Scan policy comes from us, not from the scanned code.** An attacker-controlled repository could hide
  findings with `.semgrepignore`, `.gitleaks.toml`, `.gitleaksignore`, `# nosec`, `# nosemgrep` or
  `gitleaks:allow`. We neutralize all of them: a neutral `.semgrepignore` is written into the *workspace copy*
  (this also removes Semgrep's default exclusion of `tests/`; Semgrep 1.183.0 has no flag for that), Gitleaks
  uses a baked config and an empty ignore path, and the three inline-suppression switches are on.
- **Separate output mount per tool.** Each container gets its own writable `/out`; only the one expected
  file is copied into `raw/`, and only if it is a regular file (not a symlink) within the size cap.
- **pip-audit is "egress-only, no-source".** We parse requirements ourselves, keep exact pins only and
  stage a single `requirements.audit.txt`; the container never sees the source tree and never resolves or
  installs anything (`--no-deps --disable-pip`). Unpinned/URL/editable/include lines go to `unresolved` in
  the manifest. Only package names and versions leave the machine.
- **Offline Semgrep.** `secaudit rules update` runs a fetcher inside the Semgrep image with network and
  **no** code mounted, verifies hashes, smoke-scans offline (`--validate` itself needs the network), then
  atomically switches a `CURRENT` pointer. Scans mount the snapshot read-only with `--network none`.
  The cache is hash-verified on every load.
- **Images are pinned and hash-verified.** Base images by digest; Python tools from `--require-hashes`
  lockfiles; the Gitleaks tarball against a hard-coded SHA-256 *and* the release checksums file (the build
  fails on mismatch: negative-tested by hand with a wrong hash, no image produced). Signature/attestation
  verification is **not** done.
- **Native runner** exists for development only: refuses without `--i-trust-this-code`, prints a warning,
  and reports `could not start tool` if a tool is not on PATH.

CLI exit codes: `0` scan completed (findings never change it), `2` usage or refused native run, `3` input
rejected, `4` a tool failed/timed out, `5` environment (Docker down, images or rules missing), `1` unexpected.

## Threat table

| Threat | Mitigation | Test |
|---|---|---|
| ZIP path traversal (`../`, absolute, `\`, drive letter, NTFS stream, reserved name) | per-entry name validation on the raw name, plus a second `realpath` containment check | `test_intake_zip.py::test_unsafe_names_rejected` |
| ZIP symlink / device / FIFO / socket entries | rejected from the entry's Unix mode bits | `test_symlink_entry_rejected`, `test_special_entries_rejected` |
| Directory symlink escaping the root; special files | escaping link rejects the input; internal links skipped, never recreated; special files rejected; `O_NOFOLLOW` copy | `test_escaping_symlink_rejected`, `test_special_files_rejected`, `test_internal_symlink_is_skipped_not_copied`, `test_real_symlink_escape_rejected` (skipped here: Windows account may not create symlinks) |
| Decompression bomb | declared and actual byte counts, per-entry and archive ratio, file count, total and per-file size | `test_compression_bomb_high_ratio_rejected`, `test_total_size_limit_rejected`, `test_single_file_size_limit_rejected`, `test_too_many_files_rejected`, `test_lying_header_is_rejected_not_trusted` |
| Nested archives (incl. disguised) | extension list and magic bytes | `test_nested_archive_by_extension_rejected`, `test_nested_archive_by_magic_bytes_rejected`, `test_gzip_magic_rejected` |
| Duplicate / case / Unicode-colliding names; file-vs-dir clash | NFC + casefold keys | `test_duplicate_or_colliding_names_rejected` |
| Encrypted entries | rejected (cannot be scanned) | `test_encrypted_entry_rejected` |
| Malicious Git URL (file, ssh, git, http, scp-style, local path, option injection, credentials, IP / non-allow-listed host, port, query) | https-only + host allow-list; URL placed after `--` | `test_git_url_rejections`, `test_dispatcher_sends_urlish_inputs_to_git_validation` |
| Git hooks, submodules, config injection, prompts, symlinks, redirects | `core.hooksPath`=empty dir, `--no-recurse-submodules`, `protocol.file.allow=never`, `core.symlinks=false`, `http.followRedirects=false`, scrubbed environment, no system/global config | `test_clone_command_is_hardened`, `test_git_environment_is_scrubbed`; real clone: `test_real_clone_of_small_public_repo` (opt-in, passed) |
| Clone DoS (slow or huge) | time limit and size polling that kills the process tree | `test_clone_time_limit_kills_the_process`, `test_clone_size_limit_kills_the_process` |
| `.git` history exposure | removed after recording the commit hash | `test_git_intake_removes_dot_git_and_scratch` |
| Container privilege / escape surface | fixed flag set: non-root, `--cap-drop ALL`, `no-new-privileges`, read-only rootfs, `noexec` tmpfs, pids/memory/CPU limits, `--pull never`, no `--privileged`/host namespaces/devices | `test_every_mandatory_flag_is_present`, `test_forbidden_options_are_never_produced`, `test_docker_inspect_matches_expected_hostconfig`, `test_sandbox_properties_in_a_real_container` (docker) |
| Docker socket / extra mounts / mount-option injection via crafted path | only `/src`, `/rules` read-only and `/out`; sources validated (no `,` `'` `"`, no `docker.sock`, real dir, no overlap) | `test_mount_source_validation`, `test_output_mount_must_not_overlap_inputs` |
| Host environment / secrets leaking into the container | explicit `KEY=VALUE` allow-list only | `test_env_allowlist_enforced`, `test_sandbox_properties_in_a_real_container` |
| Scanner exfiltration over the network | `--network none` for bandit, semgrep, gitleaks; only pip-audit gets `bridge` | `test_egress_policy_really_allows_outbound_only_when_declared` (docker), `test_adapter_declarations` |
| pip-audit seeing source, or executing sdist build code | staging dir with one file; `--no-deps --disable-pip`; unpinned never resolved | `test_pip_audit_prepare_stages_only_requirements_never_source`, `test_pip_audit_container_never_sees_source` (docker), `test_pip_audit_command_never_resolves_dependencies` |
| Hung tool | wall-clock timeout; container killed **by name** | `test_timeout_really_kills_the_container` (docker), `test_timeout_kills_the_container_by_name` |
| Output flood | stream cap kills the container; capture is bounded | `test_output_flood_kills_the_container` (docker), `test_subprocess_runner_kills_output_flood` |
| Tool hides or forges results via shared dirs, symlinks, malformed files | per-tool `/out`; regular-file + size + JSON/SARIF check; copy of one named file | `test_each_tool_gets_its_own_output_directory`, `test_artifact_must_be_a_regular_file`, `test_malformed_sarif_fails` |
| Scanned code suppresses its own findings | neutral `.semgrepignore`, baked Gitleaks config/ignore, `--ignore-nosec`, `--disable-nosem`, `--ignore-gitleaks-allow` | `test_scan_scope_policy_cannot_be_overridden_by_scanned_code`, `test_bandit_command`, `test_semgrep_command_is_offline_and_scans_tests`, `test_gitleaks_command_redacts_and_ignores_repo_config` |
| Raw secrets written to disk | Gitleaks `--redact` | `test_gitleaks_output_contains_no_raw_secret` (docker) |
| Rules cache poisoning / tampering | hash re-verified on load; file names whitelisted; fetch verified before `CURRENT` moves | `test_rules_cache_detects_tampering`, `test_rules_manifest_with_unsafe_file_names_rejected`, `test_rules_current_pointer_must_be_well_formed` |
| One tool failing aborts the audit | per-tool isolation, status in manifest | `test_a_failing_tool_does_not_abort_the_others`, `test_unexpected_exception_in_one_tool_is_contained`, `test_timeout_is_recorded_per_tool` |
| Leftover workspaces / containers | cleanup in `finally` plus a name-prefix container sweep | `test_workspace_is_always_cleaned_up`, `test_workspace_and_containers_are_cleaned_up` (docker) |
| Unsafe native execution | refuses without `--i-trust-this-code` | `test_native_runner_refuses_without_trust_flag` |
| Local paths leaking into the manifest | host paths replaced by placeholders; POSIX-relative artifact paths | `test_manifest_and_raw_outputs` |
| **Remediation rows (adversarial review)** | | |
| Planted `docker.exe`/`git.exe`/tool in the cwd or the scanned input runs on the host (#1) | `core/exe.py` resolves every program to a trusted absolute path (no cwd, relative/empty PATH entries or untrusted roots; `.exe/.com` only; `taskkill` from System32); only `exe.run/popen` may spawn; CLI sets `NoDefaultCurrentDirectoryInExePath` | `tests/test_exe.py::test_planted_docker_and_git_in_cwd_are_never_executed`, `test_no_subprocess_calls_outside_exe_module`, resolver unit tests |
| `.bandit` / nested or directory-named `.semgrepignore` / `.gitleaksignore` / `.gitleaks.toml` hide findings or abort the scan (#2, #3) | `core/neutralize.py` deletes them at any depth (files or directories), replaces the root `.semgrepignore`; `manifest.neutralized_files` | `tests/test_scanner_neutralization.py` (28 docker cases), `tests/test_neutralize.py`, `test_scan_scope_policy_cannot_be_overridden_by_scanned_code` |
| `git` mode tricks (`.git`, `.gitignore`) | no `git` binary in any image | `test_images_contain_no_git_so_git_mode_cannot_activate` |
| Raw outputs treated as secret-free (#4) | documented as secret-bearing; POSIX `0700/0600`; manifest/CLI secret-free; hashes unchanged | `test_secret_literals_appear_only_in_documented_raw_files`, `test_posix_audit_directory_and_raw_files_are_private`, `test_raw_files_are_byte_identical_to_what_the_manifest_hashes` |
| Cleanup chmods through a symlink, leaves read-only trees, hides failures (#5) | symlink-safe `remove_tree`, directories made deletable, `CleanupError` after the manifest, never masks the real error; containers run as host uid on POSIX; exit code 6 | `tests/test_cleanup_and_user.py::TestCleanupInLinux`, `test_a_cleanup_failure_is_raised_loudly_after_the_audit_is_written`, `test_a_cleanup_failure_never_masks_the_real_error` |
| Hardlink pulls an outside file into the workspace, or hides a repo file (#6) | `fstat().st_nlink > 1` -> `HARDLINK` (reject, never skip) | `test_hardlink_to_a_file_outside_the_input_is_rejected`, `test_two_hardlinked_files_inside_the_input_are_rejected_not_silently_hidden`, `test_hardlink_rejected_on_linux_too` |
| Untyped crashes from Windows-invalid names, MAX_PATH, I/O errors; tracebacks and host paths on the terminal (#7) | `<>"\|?*` and >255-byte components rejected; joined path length checked first; `_io_guard` types every OSError; CLI catch-all logs to a file, `--debug` opts in | `test_windows_invalid_characters_are_a_typed_rejection`, `test_entry_that_exceeds_windows_max_path_once_joined_is_rejected`, `test_any_oserror_during_*`, `tests/test_cli_errors.py` |
| Resource exhaustion before limits apply (#8) | `max_archive_bytes` by `stat`; entry count + central-directory size from the EOCD (incl. ZIP64) before parsing; directories count | `tests/test_intake_limits.py` (300,000 entries: 9.79 s / 168 MB -> 0.011 s / 0.1 MB) |
| Reserved device names slip through (#11) | NFKC fold, strip trailing spaces/dots, `CONIN$/CONOUT$/COM0-9/LPT0-9` | `test_reserved_windows_device_names_are_rejected` (14 variants) |
| Check-to-open race (#12) | `lstat` vs `fstat` identity (`st_dev`, `st_ino`); residual documented | `test_file_swapped_between_check_and_open_is_detected` |
| Orphan container after a killed secaudit (#13) | in-container `timeout -k 5 <timeout_s+10>`; owner-pid/start labels; `reap_stale_containers()` | `tests/test_container_deadline.py` (4 docker tests incl. hard-killed parent) |
| Egress network reaches the Docker host side (#9) | NOT mitigated (no flag demonstrated to help); declared residual risk | `test_KNOWN_RESIDUAL_RISK_egress_network_can_reach_the_docker_host_side` |
| Undeclared coverage gaps (#10) | per-tool `limitations` in the manifest (Gitleaks path allowlist, Bandit unparsable files, Semgrep >1 MB, pip-audit pins) | `test_manifest_declares_per_tool_limitations` |

## Scanner neutralization matrix (remediation of review #2/#3)

Every mechanism below was planted in a copy of the benchmark target and scanned through the real orchestrator and
sandbox (`tests/test_scanner_neutralization.py`, marker `docker`). "Before" = unfixed Phase 1 code (root policy
file only); "after" = with `core/neutralize.py`. Baseline counts: Bandit 16, Semgrep 11, Gitleaks 3.

| Tool | Mechanism planted in the scanned tree | Before | Neutralization |
|---|---|---|---|
| Bandit | `.bandit` at root | **1 result: effective** | removed |
| Bandit | `.bandit` nested (`webshop/`) | **13: effective** | removed at any depth |
| Bandit | `.bandit` as a directory | 16, not effective | removed anyway |
| Bandit | `setup.cfg` / `tox.ini` `[bandit]`, `pyproject [tool.bandit]`, `bandit.yaml` | 16, not effective | left alone (verified inert) |
| Bandit | `#nosec` comment | 16, not effective (`--ignore-nosec`) | flag |
| Semgrep | `.semgrepignore` nested | **1 result: effective** | removed at any depth |
| Semgrep | `.semgrepignore` at root / as a directory | root file replaced; directory **crashed the scan** (`PermissionError`) | replaced or removed |
| Semgrep | `tests/.semgrepignore`, `.semgrep/settings.yml`, `.gitignore`, hostile `.git/` dir, `# nosemgrep` | 11, not effective | left alone |
| Gitleaks | `.gitleaksignore` root or nested | **0 results: effective** (new finding, not in the review; `--gitleaks-ignore-path /opt/no-ignore` does not stop it) | removed at any depth |
| Gitleaks | `.gitleaks.toml` root / nested / directory | 3, not effective in the sandbox (`--config` is passed) but effective for the native runner | removed |
| Gitleaks | `gitleaks:allow` comment, `.gitignore` listing secrets | 3, not effective (`--ignore-gitleaks-allow`) | flag |
| pip-audit | hostile requirements options (`--index-url`, `--extra-index-url`, `-r`, `-e`, URLs, unpinned) | not effective by construction: only exact `name==version` pins are staged, the rest becomes `unresolved` | n/a |

Why `.git` and `.gitignore` are inert: none of the four images contains a `git` binary (asserted by
`test_images_contain_no_git_so_git_mode_cannot_activate`), so Semgrep's git-tracked-files mode cannot activate.
That test exists because the situation would change silently if someone added git to an image (and, on a Linux
host with `--user <host uid>`, directory ownership would no longer stop git from trusting the workspace).
Every removed or replaced path is listed in `manifest.json` under `neutralized_files`. Explicit tool config was
not used: deletion is uniform across tools and the native runner and is verified empirically.

## Container vs native parity

Both runs scan the same target. Native = Phase 0/Task 0 outputs (now `benchmarks/baseline/raw_native/`),
container = canonical baseline (`benchmarks/baseline/raw/`, `manifest.json`). Cell: `native/container`, `Y` = hit
on the case's file and lines, `-` = none.

| Case | Bandit | Semgrep | Gitleaks | pip-audit |
|---|---|---|---|---|
| P01 | Y/Y | Y/Y | -/- | -/- |
| P02 | Y/Y | -/- | Y/Y | -/- |
| P03 (revised) | -/- | -/- | Y/Y | -/- |
| P04 | Y/Y | Y/Y | -/- | -/- |
| P05 | Y/Y | Y/Y | -/- | -/- |
| P06 | Y/Y | **-/Y** | -/- | -/- |
| P07 | Y/Y | Y/Y | -/- | -/- |
| P08 | -/- | -/- | -/- | -/- |
| P08b (new) | Y/Y | Y/Y | -/- | -/- |
| P09 | -/- | -/- | -/- | Y/Y |
| P10 | -/- | -/- | -/- | -/- |
| N01 | -/- | -/- | -/- | -/- |
| N02 | Y/Y | -/- | -/- | -/- |
| N03 | -/- | -/- | -/- | -/- |
| N04 | Y/Y | -/- | -/- | -/- |
| N05 | Y/Y | -/- | -/- | -/- |
| N06 | Y/Y | Y/Y | -/- | -/- |
| N07 (new) | -/- | -/- | -/- | -/- |

**One difference, explained and verified:** P06/Semgrep. The "native" Semgrep column is the `p/python`-only run;
the container uses `p/python` + `p/flask` + `p/security-audit`, and only the latter two contain `avoid-pickle`.
At rule level the container's 11 Semgrep results equal the **union** of the two native Semgrep runs (10 + 6
results, 5 shared), with no extras on either side. Bandit (16 results) and Gitleaks (3) are identical at
rule/file/line level. pip-audit reports the same vulnerable packages. So the container is faithful to the
native tools; the sandbox flags (`noexec` tmpfs, read-only rootfs, no network, non-root, no caps) did not
break any tool.

Bandit also reports two import-line results that map to no case (`B403` `serialization.py:3`, `B404`
`system.py:3`).

### Updated hit/miss (container baseline)

| Case | Detected by |
|---|---|
| P01 SQLi | bandit, semgrep |
| P02 key + password | bandit (line 4), gitleaks (line 3); no tool covers both lines |
| P03 synthetic AWS key | gitleaks |
| P04 yaml.load | bandit, semgrep |
| P05 shell=True | bandit, semgrep |
| P06 pickle | bandit, semgrep (ruleset-dependent) |
| P07 md5 password | bandit, semgrep |
| **P08 debug=True (wsgi.py)** | **missed by all** |
| P08b debug=True, same file | bandit, semgrep |
| P09 vulnerable pins | pip-audit |
| **P10 path traversal** | **missed by all** |
| N02, N04, N05 | false alarm: bandit |
| N06 | false alarm: bandit, semgrep |
| N01, N03, N07 | clean |

9 of 11 positives detected; 4 of 7 negatives falsely flagged. Semgrep scanned `tests/` this time and still
reported nothing for N04/N05, so those are now genuine negatives for Semgrep.

## Semgrep rules: license summary

Source: the license text at `semgrep.dev/legal/rules-license` (Semgrep Rules License v. 1.0, "last updated
December 13th, 2024"), read on 2026-11-02. All 394 cached rules (p/python 151, p/flask 18, p/security-audit 225)
carry `license: Semgrep Rules License v1.0` in their metadata. This is a summary, not legal advice.

- **Allowed:** a non-exclusive, royalty-free, worldwide, non-sublicensable, non-transferable license to *use*
  the rules, plus a patent license for using them.
- **Limitations:** use only for your **own internal business purposes**. You may not **distribute** the rules or
  **make them available to others as a service**. You may not alter or remove licensor notices; copies must keep
  them; modified copies must carry a prominent modification notice.
- **Termination:** use in violation terminates the licenses; a written patent claim against the rules or Semgrep
  ends the patent license.
- **No warranty or liability.**

Consequences for this project: (1) the fetched rules live only in the git-ignored `.secaudit/rules/` cache
and are **never committed** (enforced by `.gitignore`); (2) running them on code you audit yourself is the
intended case; (3) **offering secaudit as a hosted service to third parties, or shipping the rules in a
published Docker image or repo, may conflict with the "no service / no distribution" terms**. Resolve this
(own rules, a commercial agreement, or restricting to internal use) before Phase 7/8. Only the Semgrep engine
and the rules in this registry were reviewed; other licenses (engine, Bandit, Gitleaks, pip-audit) were not.

## Cleanup and container user (remediation of review #5)

Decision: **option (a)**, run the container as the host `uid:gid` on POSIX. Why: the root cause was two different
uids (host user, container user 10001) sharing bind mounts, which forced world-writable output directories and a
host-side `chmod` fallback during cleanup. With (a) the output belongs to the host user, needs `0700` instead of
`0777`, and cleanup needs no privileges. Option (b) (delete `/out` from inside another container) costs an extra
container per tool and would still leave the host-side symlink-chmod bug. A root host user falls back to `10001`
(the container is never root); Windows keeps `10001` because Docker Desktop bind mounts ignore uid.
`remove_tree` never chmods a symlink, makes directories (not files) deletable, and raises `CleanupError` listing
leftovers; the orchestrator raises it after writing the manifest and never masks an in-flight error. CLI exit code 6.
A second bug was found on the way: the old cleanup chmod-ed the failing *file* instead of its read-only *parent
directory*, so read-only trees were silently left behind (reproduced and fixed). Verified only in a Linux
container simulating two users; behaviour on real Linux/macOS hosts is unverified.

## Known limitations

- **Semgrep silently ignores files over 1,000,000 bytes** (`--max-target-bytes` default; confirmed in `--help`).
  An attacker can pad a file to dodge it. Bandit and Gitleaks have their own unreported skips (unparsable files,
  binaries). No tool reports coverage in our raw outputs, so "scanned vs skipped" is unknown.
- **No git history scanning** (Gitleaks runs on the working tree; `.git` is removed by design).
- **pip-audit audits exact pins only.** Unpinned, URL, editable and `-r` lines are listed as `unresolved` and
  not audited; transitive dependencies are not resolved (Phase 0 showed default mode finds more, e.g. urllib3).
  Environment markers and extras are dropped. Findings depend on the vulnerability service on the scan date.
- **Rules are not versioned by the registry.** A snapshot is pinned by content hash, not by an upstream version.
  Re-running `rules update` can change results; the strict parity test then skips and says so.
- **No disk quota on `/out`**: bind mounts cannot be size-limited; only time, output-stream and artifact-size
  caps apply, so a pathological input could still fill the host disk until the timeout.
- **Defaults otherwise:** Docker's default seccomp/AppArmor profiles apply (not weakened, not strengthened);
  no gVisor/rootless; containers share the host kernel. Base images may contain unpatched OS packages.
- **Windows host only.** POSIX behaviour (symlinks, FIFOs, devices, hard links, file modes, multi-user cleanup) is tested
  in a Linux container via `tests/linux_probe.py`, not on a real Linux/macOS host. `--user <host uid>` and
  `NoDefaultCurrentDirectoryInExePath` outside Windows are unverified. No permission hardening exists on Windows.
  Status per claim, and what a real runner would add, is in **"POSIX / Linux verification status"** below.

## POSIX / Linux verification status

Source of truth for which POSIX claims are **VERIFIED on a real Linux runner** and which are still only
**simulated**. Nothing in the "Run" column is filled in until a GitHub Actions run of `.github/workflows/ci.yml`
has actually executed and its result has been read; a claim is never marked VERIFIED from a local run.
(State at the time of writing: the workflow had never run; the repository on GitHub was empty.)

What "simulated" means here: `tests/linux_probe.py` starts a throwaway Linux container (as root, with a tmpfs and a
few capabilities) on a Windows host with Docker Desktop. That exercises Linux syscalls but not a Linux *host*: the
daemon, the bind-mount ownership, the invoking uid and the filesystem under the audit directory were still
Windows/Docker Desktop's. On the runner the `docker` job runs the same probes (so they test the same thing on a
real engine), and the `lint-test` job additionally runs the host-native POSIX branches as the non-root `runner`
user, which has never happened before.

| # | Claim | Existing evidence (all on a Windows host) | Exercised on the runner by | Status | Run |
|---|---|---|---|---|---|
| 1 | Symlinks: one leaving the input rejects the input; internal ones are skipped and never recreated | `TestRealLinuxLinks` (probe); native test skipped on this host (account may not create symlinks) | `docker` job (probe) and `lint-test`/ubuntu (native `test_real_symlink_escape_rejected`, `test_internal_symlink_is_skipped_not_copied`) | simulated | - |
| 2 | FIFOs, devices and sockets reject the input | `test_special_files_reject_the_input` (probe) | `docker` job | simulated | - |
| 3 | Hard links (to outside files, or two inside) reject the input | `test_hardlink_rejected_on_linux_too` (probe); native tests ran on NTFS | `docker` job (probe) and `lint-test`/ubuntu (native `test_hardlink_*`) | simulated | - |
| 4 | Audit dir `0700`, raw files and manifest `0600` with a permissive umask | `test_posix_audit_directory_and_raw_files_are_private` (probe) | `docker` job | simulated | - |
| 5 | Owner-only retained source and database (`restrict_to_owner`, `make_tree_readonly`, DB `0600` incl. -wal/-shm) | POSIX branches never ran natively; the Windows ACL branches did | `lint-test`/ubuntu (`test_store.py::test_posix_database_files_are_owner_only`, `test_source_retention.py`) | **untested on POSIX natively** | - |
| 6 | Containers run as the host `uid:gid` on POSIX; output belongs to the host user | `test_container_user_selection` (pure function, all OS values mocked) | `docker` job: real scans as the runner uid with bind mounts | simulated | - |
| 7 | Cleanup of read-only trees, never chmods through a symlink, fails loudly | `TestCleanupInLinux` (probe, root plus simulated second user) | `docker` job (probe); `lint-test`/ubuntu (native `remove_tree` tests) | simulated | - |
| 8 | Multi-user cleanup | probe with users created inside the container | `docker` job (same probe) | simulated; a real second host user is **not** exercised even on the runner | - |
| 9 | `NoDefaultCurrentDirectoryInExePath` and the `core/exe.py` resolver off Windows | Windows only; POSIX branch noted "unverified" | `lint-test`/ubuntu (`test_exe.py` POSIX branches) | **unverified** | - |
| 10 | Sandbox flag set holds on a native Linux Docker engine (`docker inspect` HostConfig, read-only rootfs, no network, non-root) | `test_docker_inspect_matches_expected_hostconfig`, `test_sandbox_properties_in_a_real_container` on Docker Desktop | `docker` job | simulated (Docker Desktop VM only) | - |

When a run exists: for each row record the run id or URL, then change the status to **VERIFIED (run &lt;id&gt;)**,
or to **FAILED (run &lt;id&gt;): &lt;what&gt;** with the finding and its fix. A failing row is a real finding, never
something to skip or xfail. Rows 5 and 9 have never executed their POSIX branches on any POSIX host, so a first
failure there is expected evidence, not a surprise.
- **Git intake needs a `git` executable on the host** and an allow-listed host (default: github.com,
  gitlab.com, bitbucket.org, codeberg.org; extend with `--allow-git-host`).
- **Not done:** image signature/attestation verification, SBOMs, vulnerability scanning of our own images.

> Phase 2A has since implemented most of this list; see `PHASE2A_NOTES.md`. The Phase 1 baseline figures
> (9/11, 4/7) were superseded by 9/12 and 4/7 when case P11 was added.

## What Phase 2 needs from these outputs

- `manifest.json` is the index: per-tool status, exact command, pinned vs reported version, ruleset
  snapshot (names + SHA-256), exit code, duration, artifact path + SHA-256, and for pip-audit the
  `pinned_requirements` (with file + line) and `unresolved` lists that raw pip-audit JSON lacks.
- Paths: in container runs SARIF URIs are already relative (`webshop/auth.py`) because the working directory is
  the workspace; Semgrep rule ids are unprefixed (`--no-rewrite-rule-ids`). Native Windows runs use backslashes.
- Severity vocabularies still differ (Bandit LOW/MEDIUM/HIGH + confidence, MEDIUM has no SARIF `level`;
  Semgrep rule-level; Gitleaks none; pip-audit none): derive, do not copy.
- Dedup is mandatory: one issue is reported by up to 4 rules (P05) and pip-audit duplicates entries.
- Gitleaks results are already redacted (`REDACTED` snippet): keep it that way through the model layer.
- Add **coverage** to the model (which files a tool actually analyzed); today it is invisible.
- Matching against `expected_findings.yaml` is by file + line-range overlap; P02 spans two lines reported by
  different tools, and pip-audit needs the requirement-line mapping (see `tests/hits.py` for a minimal lookup).
