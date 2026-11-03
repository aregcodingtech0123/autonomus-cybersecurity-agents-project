"""Retained source snapshot: read-only copy, owner-only access, and safe deletion.

The sanitized workspace is kept as <audit>/source/ so later phases (triage, patch validation) can
read the code. It may contain secrets. Hardening applied here:
  * files are made read-only (POSIX: mode bits; Windows: read-only attribute);
  * the audit directory is restricted to the current user (POSIX: 0700; Windows: icacls with the
    user's SID, inheritance removed). Administrators and SYSTEM can still take ownership on Windows;
  * `delete_audit` removes the whole tree, including read-only files, and refuses anything that
    is not an audit directory.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from secaudit.core import exe
from secaudit.core.intake import remove_tree

AUDIT_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")


class AuditNotFoundError(ValueError):
    """The id is not an audit id, or no audit directory with that id exists."""


def make_tree_readonly(root: Path) -> None:
    """Make every file under root read-only (POSIX: directories too); links are skipped."""
    for dirpath, _dirs, filenames in os.walk(root, topdown=False, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                continue
            os.chmod(path, stat.S_IREAD if os.name == "nt" else stat.S_IMODE(mode) & ~0o222)
        if os.name == "posix":
            os.chmod(dirpath, stat.S_IMODE(os.lstat(dirpath).st_mode) & ~0o222)


def _current_sid() -> str | None:
    """The current user's SID via whoami (CSV: locale independent)."""
    done = exe.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=False
    )
    parts = done.stdout.strip().split(",")
    sid = parts[1].strip().strip('"') if done.returncode == 0 and len(parts) >= 2 else ""
    return sid if re.fullmatch(r"S-\d+(-\d+)+", sid) else None


def restrict_to_owner(path: Path, *, reset_children: bool = False) -> bool:
    """Owner-only access to `path`; True if applied, False if not (never raises).

    Windows: the grant is set on the directory only. Do NOT add /T to the GRANT: applying an
    (OI)(CI) grant to files with /T leaves them with an EMPTY ACL (verified: even the owner could
    not read them). NTFS propagates the inheritable ACE to existing and future children.

    `/inheritance:r` removes only INHERITED entries. An object created where its parent has no
    inheritable ACE gets the creating process's default DACL as explicit entries (SYSTEM,
    Administrators, ...), as on the GitHub Windows runner's elevated account, and those would
    survive. So the path is first `/reset` to a clean ACL (explicit entries dropped), then locked.
    With `reset_children=True` (a directory that already holds files) every existing child is also
    reset, so it falls back to inheriting exactly the owner's entry; `/reset` is not a grant, so it
    does not cause the empty-ACL problem above.
    """
    path = Path(path)
    if not path.exists():
        return False
    try:
        if os.name == "posix":
            # A directory needs the search bit, a file must not get an execute bit it never had.
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
            return True
        sid = _current_sid()
        if sid is None:
            return False
        # (OI)(CI) only makes sense on a directory: on a FILE it yields an ACE that applies to no
        # object, i.e. an empty ACL and a file nobody can open (found when the SQLite file got it).
        grant = f"*{sid}:(OI)(CI)F" if path.is_dir() else f"*{sid}:F"
        reset = exe.run(["icacls", str(path), "/reset"], capture_output=True, check=False)
        if reset.returncode != 0:
            return False
        done = exe.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
            capture_output=True,
            check=False,
        )
        if done.returncode != 0:
            return False
        if reset_children and path.is_dir() and any(path.iterdir()):
            # path/* with /T: every existing child (recursively) back to "inherit from parent".
            children = exe.run(
                ["icacls", str(path / "*"), "/reset", "/T", "/C"],
                capture_output=True,
                check=False,
            )
            return children.returncode == 0
        return True
    except OSError:
        return False


def delete_audit(out_root: Path, audit_id: str) -> Path:
    """Delete <out_root>/<audit_id>; raises AuditNotFoundError or CleanupError."""
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
        raise AuditNotFoundError("not a valid audit id (expected YYYYMMDDTHHMMSSZ-xxxxxxxx)")
    root = Path(out_root).resolve()
    target = root / audit_id
    if target.is_symlink() or not target.is_dir() or target.resolve().parent != root:
        raise AuditNotFoundError("no such audit directory")
    if not (target / "manifest.json").is_file():
        raise AuditNotFoundError("refusing to delete a directory without manifest.json")
    remove_tree(target)
    return target
