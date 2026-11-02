"""Download Semgrep registry rulesets into /out (runs inside the semgrep image, with network).

usage: fetch_rules.py RULESET [RULESET ...]      e.g. p/python p/flask

Only fetches https://semgrep.dev/c/<ruleset>; no scanned code is mounted when this runs.
Writes one YAML file per ruleset (slash replaced by dash) and prints a JSON line per file.
"""

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

BASE_URL = "https://semgrep.dev/c/"
OUT_DIR = Path("/out")
MAX_BYTES = 20 * 1024 * 1024
RULESET_RE = re.compile(r"^p/[a-z0-9][a-z0-9_-]*$")


def fetch(ruleset: str) -> dict:
    if not RULESET_RE.match(ruleset):
        raise SystemExit(f"refusing ruleset name {ruleset!r}")
    url = BASE_URL + ruleset
    # BASE_URL is a fixed https:// constant and RULESET_RE restricts the suffix: no file: scheme.
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "secaudit-rules-update"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise SystemExit(f"{ruleset}: response larger than {MAX_BYTES} bytes")
    if not body.lstrip().startswith(b"rules:"):
        raise SystemExit(f"{ruleset}: response does not look like a Semgrep rules file")
    filename = ruleset.replace("/", "-") + ".yaml"
    (OUT_DIR / filename).write_bytes(body)
    return {
        "ruleset": ruleset,
        "url": url,
        "file": filename,
        "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body),
    }


def main(argv: list[str]) -> int:
    if not argv:
        raise SystemExit(__doc__)
    for ruleset in argv:
        print(json.dumps(fetch(ruleset)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
