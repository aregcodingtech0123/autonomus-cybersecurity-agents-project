"""Semgrep rules cache: fetched once with network and NO scanned code, then mounted read-only.

Layout (git-ignored):  <cache>/semgrep/<fetch_id>/{p-python.yaml, ..., rules-manifest.json}
                       <cache>/semgrep/CURRENT            (text file holding the active fetch_id)

The registry does not version rulesets, so "pinning" means: a fetched snapshot is immutable,
its SHA-256 hashes are recorded in the manifest and re-verified on every load, and every scan
manifest cites the snapshot it used. Rules are never committed to this repository (see
docs/PHASE1_NOTES.md for the license summary).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from secaudit.core.sandbox import (
    RULES_TARGET,
    CommandRunner,
    ContainerSpec,
    Mount,
    NetworkPolicy,
    ResourceLimits,
    output_dir_mode,
    run_container,
    subprocess_runner,
)

DEFAULT_RULESETS = ("p/python", "p/flask", "p/security-audit")
RULES_ENV = "SECAUDIT_RULES_DIR"
MANIFEST_NAME = "rules-manifest.json"
_FETCH_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")
_RULESET_RE = re.compile(r"^p/[a-z0-9][a-z0-9_-]*$")
_FILE_RE = re.compile(r"^p-[a-z0-9_-]+\.yaml$")


class RulesError(RuntimeError):
    """The rules cache is missing, corrupt, or could not be updated."""


@dataclass(frozen=True)
class RulesCache:
    path: Path  # directory holding the YAML files and the manifest
    fetch_id: str
    fetched_at: str
    rulesets: tuple[dict, ...]  # {ruleset, url, file, sha256, bytes}

    @property
    def files(self) -> tuple[str, ...]:
        return tuple(r["file"] for r in self.rulesets)

    def describe(self) -> dict:
        return {
            "fetch_id": self.fetch_id,
            "fetched_at": self.fetched_at,
            "rulesets": [
                {
                    "name": r["ruleset"],
                    "file": r["file"],
                    "sha256": r["sha256"],
                    "bytes": r["bytes"],
                }
                for r in self.rulesets
            ],
        }


def default_cache_dir() -> Path:
    return Path(os.environ.get(RULES_ENV) or Path.cwd() / ".secaudit" / "rules")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rules_cache(cache_dir: Path | None = None) -> RulesCache:
    """Load the CURRENT snapshot and re-verify every file hash. Raises RulesError."""
    base = (cache_dir or default_cache_dir()) / "semgrep"
    current = base / "CURRENT"
    if not current.is_file():
        raise RulesError(f"no Semgrep rules cache at {base}; run `secaudit rules update`")
    fetch_id = current.read_text(encoding="utf-8").strip()
    if not _FETCH_ID_RE.match(fetch_id):
        raise RulesError("rules cache CURRENT file is malformed")
    snapshot = base / fetch_id
    try:
        manifest = json.loads((snapshot / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RulesError(f"unreadable rules manifest in {snapshot}: {exc}") from exc
    rulesets = tuple(manifest.get("rulesets", ()))
    if not rulesets:
        raise RulesError("rules manifest lists no rulesets")
    for entry in rulesets:
        if not _FILE_RE.match(str(entry.get("file", ""))):
            raise RulesError(f"unsafe rule file name in manifest: {entry.get('file')!r}")
        file = snapshot / entry["file"]
        if file.is_symlink() or not file.is_file() or _sha256(file) != entry["sha256"]:
            raise RulesError(f"rules file {entry['file']} failed integrity verification")
    return RulesCache(snapshot, fetch_id, manifest["fetched_at"], rulesets)


def update_rules(
    *,
    image: str,
    cache_dir: Path | None = None,
    rulesets: tuple[str, ...] = DEFAULT_RULESETS,
    runner: CommandRunner = subprocess_runner,
    semgrep_version: str = "unknown",
) -> RulesCache:
    """Fetch rulesets in the Semgrep image WITH network and WITHOUT any scanned code,
    then verify them with an offline smoke scan before switching CURRENT."""
    for name in rulesets:
        if not _RULESET_RE.match(name):
            raise RulesError(f"invalid ruleset name {name!r}")
    base = (cache_dir or default_cache_dir()).resolve() / "semgrep"
    now = datetime.now(UTC)
    fetch_id = now.strftime("%Y%m%dT%H%M%SZ")
    snapshot = base / fetch_id
    snapshot.mkdir(parents=True, exist_ok=False)
    if os.name == "posix":
        os.chmod(snapshot, output_dir_mode())  # the container user is not the host user
    try:
        env = {"HOME": "/tmp"}
        fetch = run_container(
            ContainerSpec(
                image=image,
                command=("python", "/opt/fetch_rules.py", *rulesets),
                output_dir=snapshot,
                inputs=(),  # no scanned code is present while the network is enabled
                network=NetworkPolicy.EGRESS_ONLY,
                env=env,
                limits=ResourceLimits(timeout_s=300),
            ).with_name("rules-fetch"),
            runner=runner,
        )
        if fetch.exit_code != 0 or fetch.timed_out:
            raise RulesError(f"rules fetch failed (exit {fetch.exit_code}): {fetch.stderr[-300:]}")
        entries = _verify_fetched(snapshot, fetch.stdout, rulesets)
        smoke = run_container(
            ContainerSpec(
                image=image,
                command=(
                    "semgrep",
                    "scan",
                    *[arg for e in entries for arg in ("--config", f"{RULES_TARGET}/{e['file']}")],
                    "--metrics=off",
                    "--disable-version-check",
                    "--quiet",
                    f"{RULES_TARGET}/{entries[0]['file']}",
                ),
                output_dir=_scratch_out(base),
                inputs=(Mount(snapshot, RULES_TARGET),),
                network=NetworkPolicy.NONE,
                env={"HOME": "/tmp", "SEMGREP_SEND_METRICS": "off"},
                limits=ResourceLimits(timeout_s=300),
            ).with_name("rules-check"),
            runner=runner,
        )
        shutil.rmtree(smoke.output_dir, ignore_errors=True)
        if smoke.exit_code != 0:
            raise RulesError(f"offline rules smoke scan failed (exit {smoke.exit_code})")
        manifest = {
            "fetch_id": fetch_id,
            "fetched_at": now.isoformat(timespec="seconds"),
            "semgrep_image": image,
            "semgrep_version": semgrep_version,
            "rulesets": entries,
        }
        (snapshot / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        current_tmp = base / "CURRENT.tmp"
        current_tmp.write_text(fetch_id + "\n", encoding="utf-8")
        os.replace(current_tmp, base / "CURRENT")
    except BaseException:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise
    return load_rules_cache(cache_dir)


def _scratch_out(base: Path) -> Path:
    scratch = base / ".scratch"
    scratch.mkdir(exist_ok=True)
    if os.name == "posix":
        os.chmod(scratch, output_dir_mode())
    return scratch


def _verify_fetched(snapshot: Path, stdout: str, rulesets: tuple[str, ...]) -> list[dict]:
    """Trust only files we can account for: expected names, regular files, matching hashes."""
    entries: list[dict] = []
    for line in stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("ruleset") in rulesets and _FILE_RE.match(str(entry.get("file", ""))):
            entries.append(entry)
    if [e["ruleset"] for e in entries] != list(rulesets):
        raise RulesError("fetch output does not list every requested ruleset")
    on_disk = sorted(p.name for p in snapshot.iterdir())
    if on_disk != sorted(e["file"] for e in entries):
        raise RulesError(f"unexpected files in rules snapshot: {on_disk}")
    for entry in entries:
        file = snapshot / entry["file"]
        if file.is_symlink() or not file.is_file():
            raise RulesError(f"{entry['file']} is not a regular file")
        if _sha256(file) != entry["sha256"] or file.stat().st_size != entry["bytes"]:
            raise RulesError(f"{entry['file']} does not match the hash reported by the fetcher")
    return entries
