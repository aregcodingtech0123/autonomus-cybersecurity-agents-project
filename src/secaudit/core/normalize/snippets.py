"""Bounded, masked source snippets. Text comes from the RETAINED SOURCE, never from SARIF fields.

The source tree is attacker-controlled data: paths are re-validated against the source root,
symlinks are refused, and reading is bounded (per line and in total) so a 1 MB single-line file
cannot blow up.
"""

from __future__ import annotations

import functools
import os
import re
from pathlib import Path

from secaudit.core.models import MAX_SNIPPET_CHARS
from secaudit.core.normalize.masking import mask_lines

CONTEXT_LINES = 3
MAX_LINE_BYTES = 2000
MAX_SNIPPET_LINES = 12
_TEST_DIRS = {"test", "tests", "testing", "__tests__"}
MAX_PEM_SCAN_BYTES = 8_000_000
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")


def is_test_path(path: str) -> bool:
    """Tag (never filter) findings that live in test code."""
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        any(p in _TEST_DIRS for p in parts[:-1])
        or name.startswith("test_")
        or re.search(r"(_test|\.test|\.spec)\.[a-z]+$", name) is not None
        or name == "conftest.py"
    )


def resolve_inside(source_root: Path, rel_path: str) -> Path | None:
    """The file path if it is a regular, non-symlink file inside the source root, else None."""
    try:
        root = os.path.realpath(source_root)
        candidate = os.path.join(root, *rel_path.split("/"))
        if (
            os.path.islink(candidate)
            or os.path.commonpath([root, os.path.realpath(candidate)]) != root
        ):
            return None
        return Path(candidate) if os.path.isfile(candidate) else None
    except (OSError, ValueError):
        return None


def read_lines(
    source_root: Path | None, rel_path: str, first: int, last: int
) -> list[tuple[int, str]] | None:
    """Numbered lines first..last (1-based, inclusive) or None if the file is unreadable."""
    if source_root is None:
        return None
    path = resolve_inside(source_root, rel_path)
    if path is None or first < 1 or last < first:
        return None
    lines: list[tuple[int, str]] = []
    try:
        with path.open("rb") as handle:
            number = 0
            while number < last:
                chunk = handle.readline(MAX_LINE_BYTES + 1)
                if not chunk:
                    break
                number += 1
                if len(chunk) > MAX_LINE_BYTES and not chunk.endswith(b"\n"):
                    while True:  # drain the rest of an over-long line without keeping it
                        rest = handle.readline(65536)
                        if not rest or rest.endswith(b"\n"):
                            break
                if number >= first:
                    text = chunk[:MAX_LINE_BYTES].decode("utf-8", "replace").rstrip("\r\n")
                    lines.append((number, text))
    except OSError:
        return None
    return lines or None


@functools.lru_cache(maxsize=128)
def _scan_pem_lines(path: str, size: int, mtime_ns: int) -> frozenset[int]:
    """1-based numbers of every line inside a private-key block (header to footer, inclusive).

    A snippet window can sit in the middle of a long key body, where neither the header nor the
    footer is visible and no per-line pattern matches base64. An unterminated block runs to the end
    of the scanned part. `size` and `mtime_ns` only key the cache. Reading is bounded.
    """
    lines: set[int] = set()
    inside = False
    number = 1
    read = 0
    try:
        with open(path, "rb") as handle:
            while read < MAX_PEM_SCAN_BYTES:
                chunk = handle.readline(65537)
                if not chunk:
                    break
                read += len(chunk)
                text = chunk.decode("utf-8", "replace")
                if _PEM_BEGIN.search(text):
                    inside = True
                if inside:
                    lines.add(number)
                    if _PEM_END.search(text):
                        inside = False
                if chunk.endswith(b"\n"):
                    number += 1
    except OSError:
        return frozenset()
    return frozenset(lines)


def pem_lines(source_root: Path | None, rel_path: str) -> frozenset[int]:
    """Lines of `rel_path` that belong to a private-key block (empty without readable source)."""
    path = resolve_inside(source_root, rel_path) if source_root is not None else None
    if path is None:
        return frozenset()
    try:
        info = path.stat()
    except OSError:
        return frozenset()
    return _scan_pem_lines(str(path), info.st_size, info.st_mtime_ns)


def make_snippet(
    source_root: Path | None,
    rel_path: str,
    line_start: int,
    line_end: int,
    flagged: set[int],
) -> str | None:
    """+/-3 lines around the finding, masked, numbered, bounded; None without source."""
    first = max(1, line_start - CONTEXT_LINES)
    last = min(line_end + CONTEXT_LINES, first + MAX_SNIPPET_LINES - 1)
    lines = read_lines(source_root, rel_path, first, last)
    if not lines:
        return None
    masked = mask_lines(lines[:MAX_SNIPPET_LINES], flagged, pem=pem_lines(source_root, rel_path))
    out: list[str] = []
    total = 0
    for number, text in masked:
        row = f"{number:>5} | {text}"
        if total + len(row) + 1 > MAX_SNIPPET_CHARS:
            break
        out.append(row)
        total += len(row) + 1
    return "\n".join(out) or None


def flagged_text(
    source_root: Path | None, rel_path: str, line_start: int, line_end: int, flagged: set[int]
) -> str | None:
    """Whitespace-normalised, MASKED text of exactly the flagged lines (fingerprint input)."""
    lines = read_lines(source_root, rel_path, line_start, min(line_end, line_start + 50))
    if not lines:
        return None
    masked = mask_lines(lines, flagged, 400, pem=pem_lines(source_root, rel_path))
    return "\n".join(" ".join(text.split()) for _n, text in masked)
