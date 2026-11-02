"""Review #4: raw scanner outputs are SECRET-BEARING; the manifest and summaries must not be."""

from __future__ import annotations

import textwrap

import pytest

from linux_probe import run_linux

pytestmark = [pytest.mark.docker, pytest.mark.usefixtures("docker_images")]

SCRIPT = textwrap.dedent(
    """
    import json, os, stat, tempfile
    from pathlib import Path
    from fakes import FakeExecutor, fake_rules
    from secaudit.core.scan import ScanOptions, run_scan

    os.umask(0o022)  # a typical default: would give 0755/0644 without explicit hardening
    tmp = Path("/h/t"); tmp.mkdir()
    project = tmp / "proj"; project.mkdir()
    (project / "app.py").write_text("x = 1\\n")
    outcome = run_scan(str(project), ScanOptions(out_root=tmp / "audits", tools=("bandit", "gitleaks")),
                       executor=FakeExecutor(), rules=fake_rules(tmp))
    audit = outcome.audit_dir
    mode = lambda p: oct(stat.S_IMODE(os.lstat(p).st_mode))
    print(json.dumps({
        "audit_dir": mode(audit), "raw_dir": mode(audit / "raw"), "manifest": mode(audit / "manifest.json"),
        "raw_files": {p.name: mode(p) for p in (audit / "raw").iterdir()},
    }))
    """
)


def test_posix_audit_directory_and_raw_files_are_private():
    result = run_linux(SCRIPT)
    assert result.returncode == 0, result.stderr
    modes = result.json()
    assert modes["audit_dir"] == "0o700" and modes["raw_dir"] == "0o700"
    assert modes["manifest"] == "0o600"
    assert modes["raw_files"] and set(modes["raw_files"].values()) == {"0o600"}
