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


def restrict_to_owner(path: Path) -> bool:
    """Owner-only access to `path`; True if applied, False if not (never raises).

    Windows: the grant is set on the directory only. Do NOT add /T: applying an (OI)(CI) grant to
    files with /T leaves them with an EMPTY ACL (verified: even the owner could not read them).
    NTFS propagates the inheritable ACE to existing and future children.
    """
    path = Path(path)
    if not path.exists():
        return False
    try:
        if os.name == "posix":
            os.chmod(path, 0o700)
            return True
        sid = _current_sid()
        if sid is None:
            return False
        done = exe.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
            capture_output=True,
            check=False,
        )
        return done.returncode == 0
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
