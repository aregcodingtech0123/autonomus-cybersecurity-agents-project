"""Neutralize files inside the scanned tree that could change what the scanners report.

Reviews #2/#3: scanned content is hostile, so it must not be able to configure or silence the
tools that scan it. Which names matter was established EMPIRICALLY through the real sandbox
(see docs/PHASE1_NOTES.md, "Scanner neutralization matrix"):

  * `.bandit` (any depth)         effective: hides Bandit findings
  * `.semgrepignore` (any depth)  effective: nested files hide Semgrep findings
  * `.gitleaksignore` (any depth) effective: hides Gitleaks findings even with
                                  --gitleaks-ignore-path
  * `.gitleaks.toml` (any depth)  not effective in the sandbox (we pass --config) but effective
                                  for the native runner, so it is removed as well

Matching entries are deleted whether they are files or directories, at any depth,
case-insensitively.
The root `.semgrepignore` is then replaced with a neutral file: that is how Semgrep's built-in
exclusion of `tests/` is switched off (it has no flag for it). Everything is done on the workspace
COPY, never on the user's original input.
"""

from __future__ import annotations

import os
from pathlib import Path

from secaudit.core.intake import IntakeError, Reason, remove_tree
from secaudit.core.scanners.semgrep import SEMGREPIGNORE_BODY, SEMGREPIGNORE_NAME

NEUTRALIZED_NAMES = frozenset({".bandit", ".gitleaksignore", ".gitleaks.toml", SEMGREPIGNORE_NAME})


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        remove_tree(path)
    else:
        path.unlink()
    if path.exists() or path.is_symlink():
        raise OSError(f"could not remove {path.name}")


def neutralize_workspace(workspace: Path) -> list[str]:
    """Remove policy-like files/directories and install the neutral root `.semgrepignore`.

    Returns the POSIX-relative paths that were removed or replaced (the manifest records them).
    Raises IntakeError(IO_ERROR) if anything cannot be neutralized.
    """
    removed: list[str] = []
    try:
        for root, dirs, files in os.walk(workspace, topdown=True, followlinks=False):
            for name in sorted([*dirs, *files]):
                if name.casefold() not in NEUTRALIZED_NAMES:
                    continue
                path = Path(root) / name
                _remove(path)
                removed.append(path.relative_to(workspace).as_posix())
                if name in dirs:
                    dirs.remove(name)  # do not descend into a directory we just deleted
        policy = workspace / SEMGREPIGNORE_NAME
        policy.write_text(SEMGREPIGNORE_BODY, encoding="utf-8", newline="\n")
        if os.name == "posix":
            os.chmod(policy, 0o644)
    except OSError as exc:
        raise IntakeError(
            Reason.IO_ERROR, f"could not neutralize scanner-policy files (errno {exc.errno})"
        ) from None
    return sorted(removed)
