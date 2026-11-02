"""Safe intake: turn an untrusted directory, ZIP archive or Git URL into a sanitized workspace.

Every input is treated as hostile. The result is a fresh directory that contains only regular
files and directories (no symlinks, devices, sockets or FIFOs), is bounded by configurable
limits, and carries metadata (kind, sha256, file count, total bytes). Every rejection raises
`IntakeError` with a stable `Reason` code.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from secaudit.core import exe

if TYPE_CHECKING:
    from subprocess import Popen

CHUNK = 64 * 1024
MIB = 1024 * 1024


class Reason(enum.StrEnum):
    """Stable reason codes; never rename, only add."""

    INPUT_NOT_FOUND = "input_not_found"
    UNSUPPORTED_INPUT = "unsupported_input"
    INVALID_ARCHIVE = "invalid_archive"
    ENCRYPTED_ENTRY = "encrypted_entry"
    ABSOLUTE_PATH = "absolute_path"
    PARENT_TRAVERSAL = "parent_traversal"
    BACKSLASH_IN_PATH = "backslash_in_path"
    DRIVE_LETTER = "drive_letter"
    UNSAFE_NAME = "unsafe_name"
    SYMLINK_ENTRY = "symlink_entry"
    SYMLINK_ESCAPE = "symlink_escape"
    SPECIAL_FILE = "special_file"
    NESTED_ARCHIVE = "nested_archive"
    DUPLICATE_ENTRY = "duplicate_entry"
    TOO_MANY_FILES = "too_many_files"
    TOTAL_SIZE_EXCEEDED = "total_size_exceeded"
    FILE_SIZE_EXCEEDED = "file_size_exceeded"
    COMPRESSION_RATIO_EXCEEDED = "compression_ratio_exceeded"
    SIZE_MISMATCH = "size_mismatch"
    IO_ERROR = "io_error"
    GIT_URL_SCHEME = "git_url_scheme"
    GIT_URL_INVALID = "git_url_invalid"
    GIT_HOST_NOT_ALLOWED = "git_host_not_allowed"
    GIT_CREDENTIALS_IN_URL = "git_credentials_in_url"
    GIT_UNAVAILABLE = "git_unavailable"
    GIT_CLONE_FAILED = "git_clone_failed"
    GIT_CLONE_TIMEOUT = "git_clone_timeout"
    GIT_CLONE_TOO_LARGE = "git_clone_too_large"


class IntakeError(Exception):
    """Raised for every rejected input. `reason` is a stable machine-readable code."""

    def __init__(self, reason: Reason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class IntakeLimits:
    """Configurable safety limits. Defaults are documented in docs/SECURITY_POLICY.md."""

    max_files: int = 10_000
    max_total_bytes: int = 256 * MIB
    max_file_bytes: int = 64 * MIB
    max_compression_ratio: float = 100.0
    # Ratio checks only apply to entries/archives whose uncompressed size is at least this big.
    ratio_min_bytes: int = 1 * MIB
    max_path_length: int = 240
    git_clone_timeout_s: float = 120.0
    git_clone_max_bytes: int = 256 * MIB
    git_allowed_hosts: frozenset[str] = frozenset(
        {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}
    )


DEFAULT_LIMITS = IntakeLimits()


@dataclass(frozen=True)
class IntakeResult:
    workspace: Path
    kind: str  # "directory" | "zip" | "git"
    input_sha256: str
    file_count: int
    total_bytes: int
    skipped: tuple[str, ...] = field(default=())
    commit: str | None = None


# --------------------------------------------------------------------------- helpers

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}  # fmt: skip
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ARCHIVE_EXTENSIONS = (
    ".zip", ".jar", ".war", ".ear", ".whl", ".egg", ".apk", ".tar", ".tgz", ".gz",
    ".bz2", ".xz", ".7z", ".rar", ".zst", ".lz4",
)  # fmt: skip


def _looks_like_archive(head: bytes) -> bool:
    return (
        head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"))
        or head.startswith(b"\x1f\x8b\x08")
        or head.startswith(b"\xfd7zXZ\x00")
        or (head.startswith(b"BZh") and head[4:10] == b"1AY&SY")
        or head[257:262] == b"ustar"
    )


class CleanupError(RuntimeError):
    """Something could not be deleted; the leftover paths are listed (cleanup must fail loudly)."""


def _chmod_for_delete(path: str) -> None:
    """Make a directory (POSIX) or file (Windows read-only attribute) deletable. NEVER follows a
    symlink: the review showed chmod-through-symlink changing a host file's permissions."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        return
    try:
        if stat.S_ISDIR(st.st_mode) and os.name == "posix":
            os.chmod(path, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
        elif stat.S_ISREG(st.st_mode) and os.name == "nt":
            os.chmod(path, stat.S_IMODE(st.st_mode) | stat.S_IWRITE)
    except OSError:
        pass  # not ours to change: the leftover check below reports it


def remove_tree(path: Path) -> None:
    """Delete a directory tree, tolerating read-only entries; raise CleanupError on leftovers.

    Symlinks are removed, never followed or chmod-ed. A missing path is not an error.
    """
    path = Path(path)
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
        return
    for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
        _chmod_for_delete(root)
        for name in [*dirs, *files]:
            _chmod_for_delete(os.path.join(root, name))

    def record_and_retry(func, p, _exc):  # noqa: ANN001
        _chmod_for_delete(os.path.dirname(p))
        _chmod_for_delete(p)
        try:
            func(p)
        except OSError:
            pass  # still there: reported below

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=record_and_retry)
    else:  # pragma: no cover - the project supports 3.11
        shutil.rmtree(path, onerror=record_and_retry)
    if os.path.lexists(path):
        left = []
        for root, dirs, files in os.walk(path, followlinks=False):
            left += [os.path.relpath(os.path.join(root, n), path) for n in [*dirs, *files]]
        shown = ", ".join(sorted(left)[:10]) or "(top directory)"
        raise CleanupError(f"could not remove {len(left) or 1} item(s) under {path}: {shown}")


def _discard(path: Path, original: BaseException) -> None:
    """Remove a half-built workspace on a failure path without hiding the original error."""
    try:
        remove_tree(path)
    except CleanupError as cleanup:
        raise cleanup from original


def _is_link(path: str | os.PathLike[str]) -> bool:
    """True for symlinks and, on Windows, junctions / other reparse points."""
    if os.path.islink(path):
        return True
    try:
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _within(root: str, candidate: str) -> bool:
    root = os.path.normcase(os.path.realpath(root))
    candidate = os.path.normcase(os.path.realpath(candidate))
    return os.path.commonpath([root, candidate]) == root


def _chmod_public(path: Path, is_dir: bool) -> None:
    """Make the workspace readable by an unprivileged container user (POSIX only)."""
    if os.name == "posix":
        os.chmod(path, 0o755 if is_dir else 0o644)


class _Budget:
    """Tracks file count and bytes against the limits as data is actually written."""

    def __init__(self, limits: IntakeLimits) -> None:
        self.limits = limits
        self.files = 0
        self.total = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise IntakeError(Reason.TOO_MANY_FILES, f"more than {self.limits.max_files} files")

    def add_bytes(self, n: int, file_total: int) -> None:
        self.total += n
        if file_total > self.limits.max_file_bytes:
            raise IntakeError(
                Reason.FILE_SIZE_EXCEEDED, f"file larger than {self.limits.max_file_bytes} bytes"
            )
        if self.total > self.limits.max_total_bytes:
            raise IntakeError(
                Reason.TOTAL_SIZE_EXCEEDED, f"more than {self.limits.max_total_bytes} bytes total"
            )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _make_workspace(parent: Path | None) -> Path:
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="secaudit-ws-", dir=parent))
    _chmod_public(workspace, is_dir=True)
    return workspace


# --------------------------------------------------------------------------- directory


def _iter_tree(root: str, include_git: bool) -> Iterator[tuple[str, os.DirEntry[str] | None]]:
    """Yield (relative_posix_path, DirEntry) depth-first, without following links."""
    stack = [("", root)]
    while stack:
        rel_dir, abs_dir = stack.pop()
        with os.scandir(abs_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if entry.name == ".git" and not include_git:
                continue
            yield rel, entry
            if entry.is_dir(follow_symlinks=False) and not _is_link(entry.path):
                stack.append((rel, entry.path))


def _copy_tree(
    src_root: Path, dest: Path, limits: IntakeLimits, include_git: bool
) -> tuple[int, int, str, list[str]]:
    """Copy a directory tree with validation. Returns (files, bytes, tree_sha256, skipped)."""
    root = os.path.realpath(src_root)
    budget = _Budget(limits)
    hashes: list[tuple[str, str]] = []
    skipped: list[str] = []
    for rel, entry in _iter_tree(root, include_git):
        assert entry is not None  # noqa: S101 - iterator contract
        target = dest.joinpath(*rel.split("/"))
        if len(rel) > limits.max_path_length:
            raise IntakeError(Reason.UNSAFE_NAME, f"path too long: {rel[:80]}...")
        if _is_link(entry.path):
            if not _within(root, entry.path):
                raise IntakeError(Reason.SYMLINK_ESCAPE, f"{rel} points outside the input root")
            skipped.append(f"symlink:{rel}")  # internal links are never recreated
            continue
        mode = entry.stat(follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            target.mkdir(parents=True, exist_ok=True)
            _chmod_public(target, is_dir=True)
        elif stat.S_ISREG(mode):
            budget.add_file()
            hashes.append((rel, _copy_regular(Path(entry.path), target, budget)))
        else:
            raise IntakeError(Reason.SPECIAL_FILE, f"{rel} is not a regular file or directory")
    tree = hashlib.sha256()
    for rel, digest in sorted(hashes):
        tree.update(f"{rel}\0{digest}\n".encode())
    return budget.files, budget.total, tree.hexdigest(), skipped


def _copy_regular(src: Path, dest: Path, budget: _Budget) -> str:
    """Copy one file via an O_NOFOLLOW descriptor, re-checking the type after opening."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(src, flags)
    except OSError as exc:
        raise IntakeError(Reason.SPECIAL_FILE, f"cannot open {src.name} safely: {exc}") from exc
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise IntakeError(Reason.SPECIAL_FILE, f"{src.name} changed type during copy")
        dest.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with dest.open("xb") as out:
            while chunk := handle.read(CHUNK):
                written += len(chunk)
                budget.add_bytes(len(chunk), written)
                digest.update(chunk)
                out.write(chunk)
    _chmod_public(dest, is_dir=False)
    return digest.hexdigest()


def intake_directory(
    path: str | os.PathLike[str],
    *,
    limits: IntakeLimits = DEFAULT_LIMITS,
    workspace_parent: Path | None = None,
    include_git: bool = False,
) -> IntakeResult:
    src = Path(path)
    if not src.is_dir():
        raise IntakeError(Reason.INPUT_NOT_FOUND, f"not a directory: {src.name}")
    workspace = _make_workspace(workspace_parent)
    try:
        files, total, digest, skipped = _copy_tree(src, workspace, limits, include_git)
    except BaseException as exc:
        _discard(workspace, exc)
        raise
    return IntakeResult(workspace, "directory", digest, files, total, tuple(skipped))


# --------------------------------------------------------------------------- zip


def _check_member_name(raw: str, limits: IntakeLimits) -> tuple[list[str], bool]:
    """Validate a raw archive member name. Returns (components, is_dir)."""
    if not raw or "\x00" in raw or any(ord(c) < 32 for c in raw):
        raise IntakeError(Reason.UNSAFE_NAME, "empty name or control character in entry name")
    if _DRIVE_RE.match(raw):
        raise IntakeError(Reason.DRIVE_LETTER, f"drive letter in entry name: {raw[:60]!r}")
    if "\\" in raw:
        raise IntakeError(Reason.BACKSLASH_IN_PATH, f"backslash in entry name: {raw[:60]!r}")
    if raw.startswith("/"):
        raise IntakeError(Reason.ABSOLUTE_PATH, f"absolute entry name: {raw[:60]!r}")
    if len(raw) > limits.max_path_length:
        raise IntakeError(Reason.UNSAFE_NAME, "entry name too long")
    is_dir = raw.endswith("/")
    parts = raw.rstrip("/").split("/")
    for part in parts:
        if part == "..":
            raise IntakeError(Reason.PARENT_TRAVERSAL, f"'..' in entry name: {raw[:60]!r}")
        if part in ("", "."):
            raise IntakeError(Reason.UNSAFE_NAME, f"empty or '.' component: {raw[:60]!r}")
        if ":" in part or part.endswith((" ", ".")):
            raise IntakeError(Reason.UNSAFE_NAME, f"unsafe component {part[:40]!r}")
        if part.split(".")[0].upper() in _WINDOWS_RESERVED:
            raise IntakeError(Reason.UNSAFE_NAME, f"reserved device name {part[:40]!r}")
    return parts, is_dir


def _check_member_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise IntakeError(Reason.ENCRYPTED_ENTRY, f"encrypted entry {info.orig_filename[:60]!r}")
    unix_mode = info.external_attr >> 16
    if stat.S_ISLNK(unix_mode):
        raise IntakeError(Reason.SYMLINK_ENTRY, f"symlink entry {info.orig_filename[:60]!r}")
    if stat.S_IFMT(unix_mode) in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
        raise IntakeError(Reason.SPECIAL_FILE, f"special entry {info.orig_filename[:60]!r}")


def _check_ratio(file_size: int, compressed: int, limits: IntakeLimits, what: str) -> None:
    if file_size >= limits.ratio_min_bytes and file_size / max(compressed, 1) > (
        limits.max_compression_ratio
    ):
        raise IntakeError(
            Reason.COMPRESSION_RATIO_EXCEEDED,
            f"{what}: ratio above {limits.max_compression_ratio:g}:1",
        )


def intake_zip(
    path: str | os.PathLike[str],
    *,
    limits: IntakeLimits = DEFAULT_LIMITS,
    workspace_parent: Path | None = None,
) -> IntakeResult:
    archive = Path(path)
    if not archive.is_file():
        raise IntakeError(Reason.INPUT_NOT_FOUND, f"not a file: {archive.name}")
    input_sha = _hash_file(archive)
    workspace = _make_workspace(workspace_parent)
    try:
        files, total = _extract_zip(archive, workspace, limits)
    except BaseException as exc:
        _discard(workspace, exc)
        raise
    return IntakeResult(workspace, "zip", input_sha, files, total)


def _extract_zip(archive: Path, workspace: Path, limits: IntakeLimits) -> tuple[int, int]:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError, NotImplementedError) as exc:
        raise IntakeError(Reason.INVALID_ARCHIVE, f"not a readable ZIP: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise IntakeError(Reason.TOO_MANY_FILES, f"{len(infos)} entries in archive")
        declared_total = sum(i.file_size for i in infos)
        if declared_total > limits.max_total_bytes:
            raise IntakeError(Reason.TOTAL_SIZE_EXCEEDED, f"declared {declared_total} bytes")
        _check_ratio(declared_total, archive.stat().st_size, limits, "archive")

        # Pass 1: validate every entry before writing anything.
        plan: list[tuple[zipfile.ZipInfo, list[str], bool]] = []
        file_keys: set[str] = set()
        dir_keys: set[str] = set()
        for info in infos:
            parts, is_dir = _check_member_name(info.orig_filename, limits)
            _check_member_type(info)
            if info.file_size > limits.max_file_bytes:
                raise IntakeError(Reason.FILE_SIZE_EXCEEDED, f"{info.orig_filename[:60]!r}")
            _check_ratio(info.file_size, info.compress_size, limits, info.orig_filename[:60])
            if not is_dir and info.filename.lower().endswith(_ARCHIVE_EXTENSIONS):
                raise IntakeError(Reason.NESTED_ARCHIVE, f"nested archive {info.filename[:60]!r}")
            keys = ["/".join(parts[: i + 1]) for i in range(len(parts))]
            keys = [unicodedata.normalize("NFC", k).casefold() for k in keys]
            if is_dir:
                if keys[-1] in file_keys:
                    raise IntakeError(Reason.DUPLICATE_ENTRY, f"{info.filename[:60]!r}")
                dir_keys.update(keys)
            else:
                if keys[-1] in file_keys or keys[-1] in dir_keys:
                    raise IntakeError(Reason.DUPLICATE_ENTRY, f"{info.filename[:60]!r}")
                if any(k in file_keys for k in keys[:-1]):
                    raise IntakeError(Reason.DUPLICATE_ENTRY, f"{info.filename[:60]!r}")
                file_keys.add(keys[-1])
                dir_keys.update(keys[:-1])
            plan.append((info, parts, is_dir))

        # Pass 2: extract entry by entry, counting the bytes that are actually produced.
        budget = _Budget(limits)
        for info, parts, is_dir in plan:
            target = workspace.joinpath(*parts)
            if not _within(str(workspace), str(target.parent)):
                raise IntakeError(Reason.PARENT_TRAVERSAL, f"{info.filename[:60]!r}")
            if is_dir:
                target.mkdir(parents=True, exist_ok=True)
                _chmod_public(target, is_dir=True)
                continue
            budget.add_file()
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_member(zf, info, target, budget)
        return budget.files, budget.total


def _write_member(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, budget: _Budget
) -> None:
    written = 0
    try:
        with zf.open(info) as src, target.open("xb") as out:
            first = True
            while chunk := src.read(CHUNK):
                if first:
                    first = False
                    if _looks_like_archive(chunk[:512]):
                        raise IntakeError(Reason.NESTED_ARCHIVE, f"{info.filename[:60]!r}")
                written += len(chunk)
                if written > info.file_size:
                    raise IntakeError(Reason.SIZE_MISMATCH, f"{info.filename[:60]!r} grows")
                budget.add_bytes(len(chunk), written)
                out.write(chunk)
    except IntakeError:
        raise
    except FileExistsError as exc:
        raise IntakeError(Reason.DUPLICATE_ENTRY, f"{info.filename[:60]!r}") from exc
    except (zipfile.BadZipFile, zlib_error, NotImplementedError, RuntimeError, EOFError) as exc:
        raise IntakeError(Reason.INVALID_ARCHIVE, f"{info.filename[:60]!r}: {exc}") from exc
    if written != info.file_size:
        raise IntakeError(Reason.SIZE_MISMATCH, f"{info.filename[:60]!r} size differs from header")
    _chmod_public(target, is_dir=False)


try:  # zlib.error is what a corrupt deflate stream raises
    from zlib import error as zlib_error
except ImportError:  # pragma: no cover
    zlib_error = ValueError  # type: ignore[assignment, misc]


# --------------------------------------------------------------------------- git


def validate_git_url(url: str, limits: IntakeLimits = DEFAULT_LIMITS) -> str:
    """Return the canonical https URL or raise IntakeError. Never touches the network."""
    if not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise IntakeError(Reason.GIT_URL_INVALID, "empty URL or whitespace/control characters")
    if not url.lower().startswith("https://"):
        raise IntakeError(Reason.GIT_URL_SCHEME, "only https:// URLs are accepted")
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise IntakeError(Reason.GIT_CREDENTIALS_IN_URL, "credentials in URL are not accepted")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise IntakeError(Reason.GIT_URL_INVALID, "missing host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise IntakeError(Reason.GIT_HOST_NOT_ALLOWED, "IP-literal hosts are not accepted")
    if host not in limits.git_allowed_hosts:
        raise IntakeError(Reason.GIT_HOST_NOT_ALLOWED, f"host {host!r} is not allow-listed")
    try:
        port = parts.port
    except ValueError as exc:
        raise IntakeError(Reason.GIT_URL_INVALID, "invalid port") from exc
    if port not in (None, 443):
        raise IntakeError(Reason.GIT_URL_INVALID, "only the default https port is accepted")
    if parts.query or parts.fragment:
        raise IntakeError(Reason.GIT_URL_INVALID, "query strings and fragments are not accepted")
    if not parts.path.strip("/") or ".." in parts.path.split("/"):
        raise IntakeError(Reason.GIT_URL_INVALID, "missing or unsafe repository path")
    return f"https://{host}{parts.path}"


_GIT_PASSTHROUGH_ENV = ("PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG")


def _git_env(home: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in _GIT_PASSTHROUGH_ENV if k in os.environ}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_ASKPASS": "echo",
            "SSH_ASKPASS": "echo",
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home),
        }
    )
    return env


def build_clone_command(url: str, dest: Path, hooks_dir: Path) -> list[str]:
    """The hardened `git clone` argument list (never shell-built)."""
    return [
        "git",
        "-c", f"core.hooksPath={hooks_dir}",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.file.allow=never",
        "-c", "core.symlinks=false",
        "-c", "core.protectNTFS=true",
        "-c", "core.protectHFS=true",
        "-c", "core.fsmonitor=false",
        "-c", "http.followRedirects=false",
        "-c", "credential.helper=",
        "-c", "transfer.fsckObjects=true",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
        "--",
        url,
        str(dest),
    ]  # fmt: skip


def _dir_size(path: Path, stop_above: int) -> int:
    total = 0
    stack = [str(path)]
    while stack:
        with os.scandir(stack.pop()) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                    if total > stop_above:
                        return total
    return total


def _kill_tree(proc: Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        exe.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.kill()


def _run_clone(argv: list[str], env: dict[str, str], dest: Path, limits: IntakeLimits) -> None:
    creation = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    with tempfile.TemporaryFile() as err:
        proc = exe.popen(
            argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
            **creation,
        )  # fmt: skip
        started = time.monotonic()
        try:
            while proc.poll() is None:
                if time.monotonic() - started > limits.git_clone_timeout_s:
                    _kill_tree(proc)
                    raise IntakeError(Reason.GIT_CLONE_TIMEOUT, "clone exceeded the time limit")
                if dest.exists() and _dir_size(dest, limits.git_clone_max_bytes) > (
                    limits.git_clone_max_bytes
                ):
                    _kill_tree(proc)
                    raise IntakeError(Reason.GIT_CLONE_TOO_LARGE, "clone exceeded the size limit")
                time.sleep(0.2)
        except BaseException:
            _kill_tree(proc)
            raise
        if proc.returncode != 0:
            err.seek(0)
            tail = err.read()[-400:].decode("utf-8", "replace")
            tail = "".join(c if c.isprintable() or c == "\n" else "?" for c in tail)
            raise IntakeError(Reason.GIT_CLONE_FAILED, f"git exited {proc.returncode}: {tail}")


def intake_git(
    url: str,
    *,
    limits: IntakeLimits = DEFAULT_LIMITS,
    workspace_parent: Path | None = None,
) -> IntakeResult:
    canonical = validate_git_url(url, limits)
    try:
        exe.resolve("git")
    except exe.ExecutableNotFound as exc:
        raise IntakeError(Reason.GIT_UNAVAILABLE, "no trusted git executable found") from exc
    scratch = Path(tempfile.mkdtemp(prefix="secaudit-clone-"))
    workspace: Path | None = None
    try:
        hooks = scratch / "no-hooks"
        home = scratch / "home"
        hooks.mkdir()
        home.mkdir()
        clone_dir = scratch / "repo"
        _run_clone(
            build_clone_command(canonical, clone_dir, hooks), _git_env(home), clone_dir, limits
        )
        commit = _git_head(clone_dir, _git_env(home))
        remove_tree(clone_dir / ".git")  # history is never scanned or exposed
        workspace = _make_workspace(workspace_parent)
        files, total, _tree, skipped = _copy_tree(clone_dir, workspace, limits, include_git=False)
    except BaseException as exc:
        if workspace is not None:
            _discard(workspace, exc)
        raise
    finally:
        remove_tree(scratch)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return IntakeResult(workspace, "git", digest, files, total, tuple(skipped), commit)


def _git_head(repo: Path, env: dict[str, str]) -> str | None:
    result = exe.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    value = result.stdout.strip()
    return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else None


# --------------------------------------------------------------------------- dispatcher

_SCP_LIKE = re.compile(r"^[\w.-]+@[\w.-]+:")


def intake(
    source: str | os.PathLike[str],
    *,
    limits: IntakeLimits = DEFAULT_LIMITS,
    workspace_parent: Path | None = None,
    include_git: bool = False,
) -> IntakeResult:
    """Dispatch on input kind: URL -> git, existing directory -> directory, file -> ZIP."""
    text = os.fspath(source)
    if "://" in text or _SCP_LIKE.match(text):
        return intake_git(text, limits=limits, workspace_parent=workspace_parent)
    path = Path(text)
    if path.is_dir():
        return intake_directory(
            path, limits=limits, workspace_parent=workspace_parent, include_git=include_git
        )
    if path.is_file():
        if zipfile.is_zipfile(path) or path.suffix.lower() == ".zip":
            return intake_zip(path, limits=limits, workspace_parent=workspace_parent)
        raise IntakeError(Reason.UNSUPPORTED_INPUT, f"{path.name} is not a ZIP archive")
    raise IntakeError(Reason.INPUT_NOT_FOUND, f"no such file or directory: {path.name}")
