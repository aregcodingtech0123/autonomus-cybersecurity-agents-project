"""Turn the path strings tools emit into POSIX paths relative to the source root, or refuse.

Tool output is hostile text: SARIF URIs may be percent-encoded, `file:///` URLs, container paths
(`/src/...`), Windows backslash paths, or outright attacks (`../..`, drive letters, absolute paths).
Anything that cannot be proven to lie inside the source root is dropped and COUNTED by the caller.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import unquote

MAX_PATH_CHARS = 1024
CONTAINER_PREFIX = "/src/"
_DRIVE = re.compile(r"^[A-Za-z]:")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def normalize_source_path(raw: object) -> tuple[str | None, str | None]:
    """Return (path, None) on success or (None, reason) when the path must be dropped."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "empty_path"
    if len(raw) > MAX_PATH_CHARS * 3:  # before decoding: percent-encoding can triple the length
        return None, "path_too_long"
    text = raw.strip()
    if text.lower().startswith("file:"):
        text = re.sub(r"^file:(//)?", "", text, flags=re.IGNORECASE)
        if text.startswith("/") and _DRIVE.match(text[1:]):
            text = text[1:]  # file:///C:/x -> C:/x (then rejected below as a drive path)
    text = unquote(text)
    if _CONTROL.search(text):
        return None, "control_character"
    text = text.replace("\\", "/")
    if text.startswith(CONTAINER_PREFIX):
        text = text[len(CONTAINER_PREFIX) :]
    elif text == CONTAINER_PREFIX.rstrip("/"):
        return None, "is_source_root"
    if _DRIVE.match(text) or text.startswith("//"):
        return None, "absolute_path"
    if text.startswith("/"):
        return None, "absolute_path_outside_source_root"
    normalized = posixpath.normpath(text)
    if normalized in (".", ""):
        return None, "is_source_root"
    if normalized == ".." or normalized.startswith("../") or "/../" in f"/{normalized}/":
        return None, "path_escapes_source_root"
    if len(normalized) > MAX_PATH_CHARS:
        return None, "path_too_long"
    return normalized, None
