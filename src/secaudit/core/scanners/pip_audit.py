"""pip-audit adapter: JSON output, pinned requirements only, egress-only / no-source policy.

pip-audit's normal `-r` mode resolves dependencies by installing into a temporary venv, which
can run arbitrary build code from untrusted sdists. We never do that: we parse requirements
files ourselves, keep only exact pins (`name==version`), write them into a staging directory
that is the ONLY thing the container sees, and run `--no-deps --disable-pip`. Anything that is
not an exact pin is recorded as `unresolved` in the manifest and is never resolved.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from secaudit.core.sandbox import NetworkPolicy
from secaudit.core.scanners.base import Prepared, ScannerAdapter, ToolPaths

STAGED_NAME = "requirements.audit.txt"
MAX_REQUIREMENT_FILES = 20
MAX_REQUIREMENT_BYTES = 1024 * 1024
_SKIP_DIRS = {".venv", "venv", "node_modules", "site-packages", "__pycache__", ".tox", ".git"}
_FILE_RE = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.][\w.-]*)?\.txt$", re.IGNORECASE)
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\]]*\])?\s*===?\s*(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)$"
)
_HASH_RE = re.compile(r"\s--hash[= ]\S+")
_INCLUDE_PREFIXES = ("-r", "--requirement", "-c", "--constraint")
_EDITABLE_PREFIXES = ("-e", "--editable")


def find_requirements_files(workspace: Path) -> list[Path]:
    found: list[Path] = []
    for root, dirs, files in os.walk(workspace, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            path = Path(root) / name
            if _FILE_RE.match(name) and path.is_file() and not path.is_symlink():
                found.append(path)
    return found[:MAX_REQUIREMENT_FILES]


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; return (first_line_number, text) pairs."""
    out: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        out.append((start, buffer + line))
        buffer = ""
    if buffer:
        out.append((start, buffer))
    return out


def parse_requirements(files: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Return (pinned, unresolved) from {relative_posix_path: text}. No installation, no I/O."""
    pinned: list[dict] = []
    unresolved: list[dict] = []
    for rel, text in files.items():
        for number, line in _logical_lines(text):
            line = re.sub(r"(^|\s)#.*$", "", line).strip()
            if not line:
                continue
            entry = {"file": rel, "line": number, "requirement": line[:200]}
            if line.startswith(_INCLUDE_PREFIXES):
                unresolved.append({**entry, "reason": "include_not_followed"})
                continue
            if line.startswith(_EDITABLE_PREFIXES):
                unresolved.append({**entry, "reason": "editable"})
                continue
            if line.startswith("-"):
                continue  # index/find-links/trusted-host options: not requirements
            candidate = _HASH_RE.sub("", line).split(";")[0].strip()
            if "://" in candidate or " @ " in candidate or candidate.startswith((".", "/")):
                unresolved.append({**entry, "reason": "url_or_path"})
                continue
            match = _PIN_RE.match(candidate)
            if match:
                pinned.append(
                    {
                        "name": match["name"],
                        "version": match["version"],
                        "file": rel,
                        "line": number,
                    }
                )
            else:
                unresolved.append({**entry, "reason": "unpinned"})
    return pinned, unresolved


class PipAuditAdapter(ScannerAdapter):
    name = "pip-audit"
    version = "2.10.1"
    output_filename = "pip-audit.json"
    artifact_kind = "json"
    network_policy = NetworkPolicy.EGRESS_ONLY  # reaches the vulnerability service
    workdir = "/tmp"

    def prepare(self, workspace: Path, staging: Path) -> Prepared:
        texts: dict[str, str] = {}
        for path in find_requirements_files(workspace):
            if path.stat().st_size > MAX_REQUIREMENT_BYTES:
                continue
            rel = path.relative_to(workspace).as_posix()
            texts[rel] = path.read_text(encoding="utf-8", errors="replace")
        pinned, unresolved = parse_requirements(texts)
        extra = {
            "requirements_files": sorted(texts),
            "pinned_requirements": pinned,
            "unresolved": unresolved,
        }
        if not pinned:
            return Prepared(skip_reason="no exact-pinned requirements to audit", extra=extra)
        seen: set[tuple[str, str]] = set()
        lines = []
        for p in pinned:
            key = (p["name"].lower(), p["version"])
            if key not in seen:
                seen.add(key)
                lines.append(f"{p['name']}=={p['version']}")
        (staging / STAGED_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(staging, 0o755)
            os.chmod(staging / STAGED_NAME, 0o644)
        return Prepared(src_dir=staging, extra=extra)  # only requirements, never source code

    def build_command(self, paths: ToolPaths) -> list[str]:
        return [
            "pip-audit", "-r", f"{paths.src}{paths.sep}{STAGED_NAME}",
            "--no-deps", "--disable-pip",
            "-f", "json", "-o", paths.out_file(self.output_filename),
            "--progress-spinner", "off",
        ]  # fmt: skip
