"""Deterministic generator for benchmark case P11: a vulnerable pattern inside a >1 MB Python file.

Semgrep silently skips files larger than 1,000,000 bytes (`--max-target-bytes` default), so a
vulnerability inside one is invisible to it. The file is generated, not committed (it is ~1.1 MB and
git-ignored); `EXPECTED_SHA256` pins its exact content so the benchmark stays reproducible.

  python benchmarks/p11_generator.py            # (re)generate into the default target
  from p11_generator import ensure   # used by `secaudit eval` and the ground-truth checker
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

RELATIVE_PATH = "webshop/generated_big_module.py"
FILLER_FUNCTIONS = 21_000
HEADER = '''"""Generated benchmark module (P11). INTENTIONALLY VULNERABLE - benchmark use only.

Thousands of harmless helpers pad this file beyond Semgrep's 1,000,000-byte limit; the vulnerable
handler is at the very end.
"""

from flask import Flask, request

app = Flask(__name__)

'''
VULNERABLE_TAIL = """

@app.route("/archive/read")
def read_archive():
    with open(request.args.get("f"), "rb") as fh:
        return fh.read()
"""
ANCHOR = 'open(request.args.get("f"), "rb")'


def render() -> str:
    parts = [HEADER]
    for i in range(FILLER_FUNCTIONS):
        parts.append(f"def helper_{i:05d}(value):\n    return value + {i}\n\n\n")
    parts.append(VULNERABLE_TAIL.lstrip("\n"))
    return "".join(parts)


def content() -> bytes:
    return render().encode("utf-8")


def expected_sha256() -> str:
    return hashlib.sha256(content()).hexdigest()


def vulnerable_line() -> int:
    """1-based line number of the vulnerable `open(...)` call."""
    for number, line in enumerate(render().splitlines(), start=1):
        if ANCHOR in line:
            return number
    raise RuntimeError("anchor not found")  # pragma: no cover


def ensure(target_root: Path) -> bool:
    """Create or repair the generated file under `target_root`; True if (re)written."""
    path = Path(target_root) / RELATIVE_PATH
    wanted = content()
    if path.is_file() and path.read_bytes() == wanted:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wanted)
    return True


if __name__ == "__main__":
    default = Path(__file__).parent / "targets" / "vuln_python_app"
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    written = ensure(root)
    data = content()
    state = "wrote" if written else "unchanged"
    print(f"{state} {RELATIVE_PATH}: {len(data)} bytes, sha256 {expected_sha256()}")
    print(f"vulnerable line {vulnerable_line()}")
