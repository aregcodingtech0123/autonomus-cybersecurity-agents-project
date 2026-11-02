"""Review #8: limits must be enforced BEFORE the expensive work (hashing, parsing, copying)."""

from __future__ import annotations

import struct
import time
import tracemalloc
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from secaudit.core import intake as intake_mod
from secaudit.core.intake import DEFAULT_LIMITS, IntakeError, Reason, intake_directory, intake_zip


def reject(path, ws_parent, reason, limits=DEFAULT_LIMITS):
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, limits=limits, workspace_parent=ws_parent)
    assert exc.value.reason is reason, exc.value
    assert list(ws_parent.iterdir()) == []


def small_zip(path: Path, n: int = 3) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(n):
            zf.writestr(f"f{i}.txt", b"x")
    return path


def patch_eocd(path: Path, *, entries: int | None = None, cd_size: int | None = None) -> None:
    raw = bytearray(path.read_bytes())
    at = raw.rindex(b"PK\x05\x06")
    if entries is not None:
        raw[at + 8 : at + 10] = struct.pack("<H", entries)
        raw[at + 10 : at + 12] = struct.pack("<H", entries)
    if cd_size is not None:
        raw[at + 12 : at + 16] = struct.pack("<I", cd_size)
    path.write_bytes(bytes(raw))


class Boom(AssertionError):
    """Raised by tripwires: the expensive step must not have been reached."""


def tripwire(monkeypatch):
    def no_zipfile(*a, **k):
        raise Boom("zipfile.ZipFile was constructed before the cheap limits were checked")

    def no_hash(*a, **k):
        raise Boom("the archive was hashed before the cheap limits were checked")

    monkeypatch.setattr(intake_mod.zipfile, "ZipFile", no_zipfile)
    monkeypatch.setattr(intake_mod, "_hash_file", no_hash)


def test_archive_larger_than_the_limit_is_rejected_before_hashing_or_parsing(
    tmp_path, ws_parent, monkeypatch
):
    path = small_zip(tmp_path / "a.zip", n=50)
    tripwire(monkeypatch)
    limits = replace(DEFAULT_LIMITS, max_archive_bytes=500)
    assert path.stat().st_size > 500
    reject(path, ws_parent, Reason.ARCHIVE_TOO_LARGE, limits)


def test_eocd_entry_count_is_checked_before_building_the_zipfile(tmp_path, ws_parent, monkeypatch):
    path = small_zip(tmp_path / "a.zip")
    patch_eocd(path, entries=100)
    tripwire(monkeypatch)
    reject(path, ws_parent, Reason.TOO_MANY_FILES, replace(DEFAULT_LIMITS, max_files=5))


def test_a_central_directory_far_bigger_than_the_entry_count_allows_is_rejected(
    tmp_path, ws_parent, monkeypatch
):
    """The EOCD entry count can lie low; the central directory size cannot hide a flood."""
    path = small_zip(tmp_path / "a.zip")
    patch_eocd(path, entries=3, cd_size=50 * 1024 * 1024)
    tripwire(monkeypatch)
    reject(path, ws_parent, Reason.TOO_MANY_FILES)


def test_directory_entries_count_toward_the_entry_limit(tmp_path, ws_parent):
    path = tmp_path / "dirs.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(6):
            zf.writestr(f"d{i}/", b"")
    reject(path, ws_parent, Reason.TOO_MANY_FILES, replace(DEFAULT_LIMITS, max_files=5))


def test_300000_entry_zip_is_rejected_quickly_and_cheaply(tmp_path, ws_parent):
    """Review measured 9.79 s and 168 MB of Python heap before rejection (this also exercises ZIP64)."""
    big = tmp_path / "many.zip"
    with zipfile.ZipFile(big, "w") as zf:
        for i in range(300_000):
            zf.writestr(str(i), b"")
    assert big.stat().st_size > 20_000_000
    tracemalloc.start()
    started = time.perf_counter()
    try:
        reject(big, ws_parent, Reason.TOO_MANY_FILES)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert elapsed < 3.0, f"rejection took {elapsed:.2f}s (was 9.79s)"
    assert peak < 64 * 1024 * 1024, f"peak Python heap {peak / 1e6:.0f} MB (was 168 MB)"


def test_empty_directory_flood_is_rejected_with_a_small_limit(tmp_path, ws_parent):
    src = tmp_path / "src"
    for i in range(5000):
        (src / f"d{i}").mkdir(parents=True)
    (src / "a.py").write_bytes(b"x")
    started = time.perf_counter()
    with pytest.raises(IntakeError) as exc:
        intake_directory(
            src, limits=replace(DEFAULT_LIMITS, max_files=100), workspace_parent=ws_parent
        )
    assert exc.value.reason is Reason.TOO_MANY_FILES
    assert time.perf_counter() - started < 5
    assert list(ws_parent.iterdir()) == []


def test_files_alone_still_report_file_count_not_directories(tmp_path, ws_parent):
    src = tmp_path / "src"
    (src / "a" / "b").mkdir(parents=True)
    (src / "a" / "b" / "f.py").write_bytes(b"x")
    result = intake_directory(src, workspace_parent=ws_parent)
    assert result.file_count == 1, "metadata keeps counting files only"
