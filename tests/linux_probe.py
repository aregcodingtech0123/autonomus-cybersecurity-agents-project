"""Run a Python script inside a throwaway Linux container to test POSIX semantics (symlinks,
FIFOs, file modes, multiple users, hardlinks) from a Windows host. TEST SUPPORT ONLY.

This is NOT the scanner sandbox: it runs as root with a tmpfs at /h so scripts can create several
users and files. It mounts the repository's src/ and tests/ read-only, has no network, and uses an
image that is already built (any secaudit image contains Python 3.13).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from secaudit.core import exe

REPO = Path(__file__).resolve().parent.parent
IMAGE = "secaudit/bandit:1.9.4"


@dataclass(frozen=True)
class LinuxResult:
    returncode: int
    stdout: str
    stderr: str

    def json(self):
        """Parse the last stdout line as JSON (scripts print one JSON document at the end)."""
        return json.loads(self.stdout.strip().splitlines()[-1])


def run_linux(script: str, *, timeout: float = 120.0) -> LinuxResult:
    argv = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--user", "0", "--cap-drop", "ALL",
        "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "MKNOD",
        "--tmpfs", "/h:rw,exec,mode=1777,size=128m",
        "--mount", f"type=bind,source={REPO / 'src'},target=/app/src,readonly",
        "--mount", f"type=bind,source={REPO / 'tests'},target=/app/tests,readonly",
        "--env", "PYTHONPATH=/app/src:/app/tests", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "HOME=/h", "--workdir", "/h",
        IMAGE, "python", "-c", script,
    ]  # fmt: skip
    done = exe.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL
    )
    return LinuxResult(done.returncode, done.stdout, done.stderr)
