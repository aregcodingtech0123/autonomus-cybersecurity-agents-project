"""Windows ACL helpers for tests: read a DACL back through `icacls /save` (SDDL), locale independent.

SDDL writes well-known principals as aliases, so comparing against a raw SID string is wrong for some
accounts. The GitHub Windows runner's `runneradmin` is the built-in Administrator (RID 500), which
SDDL prints as `LA`; `current_principal()` returns the form that appears in SDDL.
"""

from __future__ import annotations

import re
from pathlib import Path

from secaudit.core import exe

_RID_500 = re.compile(r"S-1-5-21-\d+-\d+-\d+-500")


def current_sid() -> str:
    done = exe.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
    )
    return done.stdout.strip().split(",")[1].strip().strip('"')


def current_principal() -> str:
    """The current user as SDDL spells it (the RID-500 Administrator account becomes `LA`)."""
    sid = current_sid()
    return "LA" if _RID_500.fullmatch(sid) else sid


def sddl_dacl(path: Path, scratch: Path) -> tuple[str, list[str]]:
    """(DACL flags, ACE strings) of `path`."""
    target = Path(scratch) / "acl.txt"
    exe.run(["icacls", str(path), "/save", str(target)], capture_output=True, check=True)
    sddl = target.read_bytes().decode("utf-16")
    match = re.search(r"D:([A-Z]*)((?:\([^)]*\))*)", sddl)
    assert match, sddl
    return match.group(1), re.findall(r"\(([^)]*)\)", match.group(2))


def principals(path: Path, scratch: Path) -> set[str]:
    """Every principal that has an ACE on `path`, explicit or inherited."""
    return {ace.split(";")[-1] for ace in sddl_dacl(path, scratch)[1]}


def without_inheritable_aces(directory: Path) -> None:
    """Give `directory` an ACL with no inheritable ACE.

    New children then get the creating process's default DACL as EXPLICIT ACEs (SYSTEM,
    Administrators, ...). That is what an elevated admin account such as `runneradmin` gets in
    practice; on an ordinary developer profile everything is inherited and the problem stays hidden.
    """
    exe.run(
        ["icacls", str(directory), "/inheritance:r", "/grant:r", f"*{current_sid()}:F"],
        capture_output=True,
        check=True,
    )
