"""Download (once), verify and run the official actionlint binary.

    uv run python tools/actionlint.py [actionlint args]   # default: lint .github/workflows/*.yml

Why not the `actionlint-py` wrapper on PyPI: its 1.7.x releases are source-only and fetch the
binary from GitHub while building, with no checksum. Here the release archive's SHA-256 is pinned
in this file and the download is refused if it does not match. The hashes were taken from the
release's own `actionlint_1.7.12_checksums.txt` (trust on first use: they prove the binary did not
change since this file was reviewed, not that the first download was honest). Bump VERSION and the
table together.

The binary is cached in `.tools/` (git-ignored). Exit code is actionlint's own, or 2 if the
download cannot be verified.
"""

from __future__ import annotations

import hashlib
import io
import platform
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.7.12"
BASE_URL = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}"
ARCHIVES = {  # (system, machine) -> (archive name, sha256)
    ("linux", "amd64"): (
        f"actionlint_{VERSION}_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    ),
    ("linux", "arm64"): (
        f"actionlint_{VERSION}_linux_arm64.tar.gz",
        "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
    ),
    ("windows", "amd64"): (
        f"actionlint_{VERSION}_windows_amd64.zip",
        "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9",
    ),
    ("darwin", "amd64"): (
        f"actionlint_{VERSION}_darwin_amd64.tar.gz",
        "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644",
    ),
    ("darwin", "arm64"): (
        f"actionlint_{VERSION}_darwin_arm64.tar.gz",
        "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f",
    ),
}
ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".tools" / "actionlint" / VERSION
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024


class ActionlintError(RuntimeError):
    pass


def platform_key() -> tuple[str, str]:
    machine = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    return platform.system().lower(), machine


def binary_path() -> Path:
    return CACHE / ("actionlint.exe" if platform.system() == "Windows" else "actionlint")


def fetch(url: str) -> bytes:
    if not url.startswith("https://github.com/rhysd/actionlint/releases/download/"):
        raise ActionlintError("refusing to download from an unexpected URL")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - https URL checked above
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ActionlintError("archive is larger than expected")
    return data


def extract(archive_name: str, data: bytes, destination: Path) -> None:
    """Extract only the actionlint executable (never trust member paths from an archive)."""
    wanted = "actionlint.exe" if archive_name.endswith(".zip") else "actionlint"
    destination.mkdir(parents=True, exist_ok=True)
    if archive_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            payload = zf.read(wanted)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            member = tf.extractfile(wanted)
            if member is None:
                raise ActionlintError(f"{wanted} not found in the archive")
            payload = member.read()
    target = destination / wanted
    target.write_bytes(payload)
    target.chmod(0o755)


def ensure_binary() -> Path:
    path = binary_path()
    if path.is_file():
        return path
    key = platform_key()
    if key not in ARCHIVES:
        raise ActionlintError(f"no pinned actionlint build for {key[0]}/{key[1]}")
    name, expected = ARCHIVES[key]
    data = fetch(f"{BASE_URL}/{name}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ActionlintError(
            f"{name}: sha256 {actual} does not match the pinned {expected}; not installing"
        )
    extract(name, data, CACHE)
    return path


def main(argv: list[str]) -> int:
    try:
        binary = ensure_binary()
    except (ActionlintError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args = argv or [str(p) for p in sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))]
    return subprocess.run([str(binary), *args], check=False).returncode  # noqa: S603


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
