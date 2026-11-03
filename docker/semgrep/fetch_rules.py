"""Download Semgrep registry rulesets into /out (runs inside the semgrep image, with network).

usage: fetch_rules.py RULESET [RULESET ...]      e.g. p/python p/flask

Only fetches https://semgrep.dev/c/<ruleset>; no scanned code is mounted when this runs.
Writes one YAML file per ruleset (slash replaced by dash) and prints a JSON line per file.
"""

import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "https://semgrep.dev/c/"
OUT_DIR = Path("/out")
MAX_BYTES = 20 * 1024 * 1024
RULESET_RE = re.compile(r"^p/[a-z0-9][a-z0-9_-]*$")
ATTEMPTS = (
    3  # the registry once answered with something that was not a rules file; the re-run passed
)
BACKOFF_S = (2, 5)  # pause before attempt 2 and 3


def describe(status: object, content_type: object, body: bytes) -> str:
    """What the server returned, safe to print: printable ASCII only, first 80 bytes."""
    sample = "".join(chr(b) if 32 <= b < 127 else "." for b in body[:80])
    return (
        f"HTTP {status}, content-type {content_type!r}, {len(body)} bytes, starts with {sample!r}"
    )


def fetch(ruleset: str) -> dict:
    if not RULESET_RE.match(ruleset):
        raise SystemExit(f"refusing ruleset name {ruleset!r}")
    url = BASE_URL + ruleset
    # BASE_URL is a fixed https:// constant and RULESET_RE restricts the suffix: no file: scheme.
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "secaudit-rules-update"}
    )
    problem = "no response"
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                status, content_type = response.status, response.headers.get("content-type")
                body = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            problem = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code != 429:  # a client error will not fix itself
                raise SystemExit(f"{ruleset}: {problem}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            problem = f"network error ({type(exc).__name__})"
        else:
            if len(body) > MAX_BYTES:
                raise SystemExit(f"{ruleset}: response larger than {MAX_BYTES} bytes")
            if body.lstrip().startswith(b"rules:"):
                break
            problem = "response does not look like a Semgrep rules file: " + describe(
                status, content_type, body
            )
        if attempt < ATTEMPTS:
            print(f"{ruleset}: attempt {attempt} failed ({problem}); retrying", file=sys.stderr)
            time.sleep(BACKOFF_S[attempt - 1])
    else:
        raise SystemExit(f"{ruleset}: {problem} (after {ATTEMPTS} attempts)")
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
