"""Re-scrub the FROZEN records with an exact-length value mapping; recompute their hashes (ADR-002).

    uv run python benchmarks/rescrub_frozen.py --mapping PATH [--phase1-commit SHA]

Frozen records are outputs the current pipeline cannot reproduce, so they are not regenerated:

* tests/fixtures/phase1_baseline/raw/** (the Phase 1 container run, with its manifest), and
* benchmarks/baseline/raw_native/** (the Phase 0/1 native discovery runs; no manifest).

PATH is a JSON file OUTSIDE the repository, `{"<case>": {"old": "...", "new": "..."}}`. It holds
the old values, so it is never committed. Every replacement must keep the length, so line structure,
SARIF columns and byte counts are unchanged. Then the fixture manifest is updated:

* tools.<tool>.artifact_sha256 is recomputed from the re-scrubbed bytes;
* input.sha256 is recomputed with the intake's tree-hash formula (sha256 over sorted
  "relpath\\0sha256(file)\\n" lines) over the target as it was at --phase1-commit, with the same
  mapping applied. The script first proves the formula by reproducing the recorded hash from the
  unmapped tree (or the already-mapped tree, when re-run after the history rewrite).

Re-running with the same mapping is a no-op.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "phase1_baseline"
RAW_NATIVE = REPO / "benchmarks" / "baseline" / "raw_native"
TARGET_PREFIX = "benchmarks/targets/vuln_python_app/"


def load_mapping(path: Path) -> list[tuple[bytes, bytes]]:
    pairs = []
    for case, entry in json.loads(path.read_text("utf-8")).items():
        old, new = entry["old"].encode(), entry["new"].encode()
        if len(old) != len(new):
            raise SystemExit(f"{case}: replacement must keep the length")
        pairs.append((old, new))
    return pairs


def apply(data: bytes, pairs: list[tuple[bytes, bytes]]) -> bytes:
    for old, new in pairs:
        data = data.replace(old, new)
    return data


def git(*args: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],  # noqa: S607 - git from PATH, like the other benchmark tooling
        cwd=REPO,
        capture_output=True,
        check=True,
    ).stdout


def tree_hash(commit: str, pairs: list[tuple[bytes, bytes]] | None) -> str:
    entries = []
    for row in git("ls-tree", "-r", commit, TARGET_PREFIX).decode().splitlines():
        meta, path = row.split("\t", 1)
        data = git("cat-file", "blob", meta.split()[2])
        if pairs:
            data = apply(data, pairs)
        entries.append((path[len(TARGET_PREFIX) :], hashlib.sha256(data).hexdigest()))
    digest = hashlib.sha256()
    for rel, file_hash in sorted(entries):
        digest.update(f"{rel}\0{file_hash}\n".encode())
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--phase1-commit", help="commit the Phase 1 fixture was scanned at")
    args = parser.parse_args(argv)
    if args.mapping.resolve().is_relative_to(REPO):
        raise SystemExit("the mapping holds the old values: keep it outside the repository")
    pairs = load_mapping(args.mapping)

    changed = []
    for folder in (FIXTURE / "raw", RAW_NATIVE):
        for path in sorted(folder.iterdir()):
            data = path.read_bytes()
            new = apply(data, pairs)
            if new != data:
                assert len(new) == len(data)  # noqa: S101 - guaranteed by load_mapping
                path.write_bytes(new)
                changed.append(path.relative_to(REPO).as_posix())

    manifest_path = FIXTURE / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    for tool in manifest["tools"].values():
        if tool.get("artifact"):
            tool["artifact_sha256"] = hashlib.sha256(
                (FIXTURE / tool["artifact"]).read_bytes()
            ).hexdigest()
    if args.phase1_commit:
        recorded = manifest["input"]["sha256"]
        mapped = tree_hash(args.phase1_commit, pairs)
        if recorded not in (tree_hash(args.phase1_commit, None), mapped):
            raise SystemExit("cannot reproduce the recorded input hash at --phase1-commit")
        manifest["input"]["sha256"] = mapped
    text = json.dumps(manifest, indent=2) + "\n"
    if text != manifest_path.read_text("utf-8"):
        manifest_path.write_text(text, encoding="utf-8", newline="\n")
        changed.append(manifest_path.relative_to(REPO).as_posix())
    print("re-scrubbed:", ", ".join(changed) if changed else "nothing (already done)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
