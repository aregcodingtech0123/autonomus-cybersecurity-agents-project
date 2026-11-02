import stat
import zipfile
from dataclasses import replace

import pytest

from secaudit.core.intake import DEFAULT_LIMITS, IntakeError, Reason, intake, intake_zip

OK = {"name": "pkg/app.py", "data": b"print('hi')\n"}
MIB = 1024 * 1024


def reject(zip_path, ws_parent, reason, limits=DEFAULT_LIMITS):
    with pytest.raises(IntakeError) as exc:
        intake_zip(zip_path, limits=limits, workspace_parent=ws_parent)
    assert exc.value.reason is reason, exc.value
    assert list(ws_parent.iterdir()) == [], "rejected input must not leave a workspace behind"


def test_valid_zip_extracts_with_metadata(zip_factory, ws_parent):
    path = zip_factory([OK, {"name": "pkg/", "data": b""}, {"name": "README.md", "data": b"# x"}])
    result = intake_zip(path, workspace_parent=ws_parent)
    assert result.kind == "zip"
    assert (result.workspace / "pkg" / "app.py").read_bytes() == OK["data"]
    assert result.file_count == 2
    assert result.total_bytes == len(OK["data"]) + 3
    assert len(result.input_sha256) == 64


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("../evil.py", Reason.PARENT_TRAVERSAL),
        ("a/../../evil.py", Reason.PARENT_TRAVERSAL),
        ("/etc/passwd", Reason.ABSOLUTE_PATH),
        ("..\\evil.py", Reason.BACKSLASH_IN_PATH),
        ("pkg\\evil.py", Reason.BACKSLASH_IN_PATH),
        ("C:/Windows/evil.py", Reason.DRIVE_LETTER),
        ("C:\\evil.py", Reason.DRIVE_LETTER),
        ("c:evil.py", Reason.DRIVE_LETTER),
        ("a/b:stream.py", Reason.UNSAFE_NAME),
        ("a\x00b.py", Reason.UNSAFE_NAME),
        ("a/./b.py", Reason.UNSAFE_NAME),
        ("a//b.py", Reason.UNSAFE_NAME),
        ("CON.txt", Reason.UNSAFE_NAME),
        ("trailing-dot.", Reason.UNSAFE_NAME),
    ],
)
def test_unsafe_names_rejected(zip_factory, ws_parent, name, reason):
    reject(zip_factory([OK, {"name": name, "data": b"x"}]), ws_parent, reason)


def test_symlink_entry_rejected(zip_factory, ws_parent):
    link = {"name": "link", "data": b"/etc/passwd", "mode": stat.S_IFLNK | 0o777}
    reject(zip_factory([OK, link]), ws_parent, Reason.SYMLINK_ENTRY)


@pytest.mark.parametrize("fmt", [stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK])
def test_special_entries_rejected(zip_factory, ws_parent, fmt):
    reject(zip_factory([{"name": "dev", "mode": fmt | 0o644}]), ws_parent, Reason.SPECIAL_FILE)


def test_compression_bomb_high_ratio_rejected(zip_factory, ws_parent):
    limits = replace(DEFAULT_LIMITS, max_compression_ratio=20, ratio_min_bytes=1 * MIB)
    bomb = zip_factory([{"name": "zeros.bin", "data": b"\0" * (4 * MIB)}])
    reject(bomb, ws_parent, Reason.COMPRESSION_RATIO_EXCEEDED, limits)


def test_total_size_limit_rejected(zip_factory, ws_parent):
    limits = replace(DEFAULT_LIMITS, max_total_bytes=1 * MIB, max_compression_ratio=1e9)
    big = zip_factory([{"name": f"f{i}.txt", "data": b"a" * (600 * 1024)} for i in range(2)])
    reject(big, ws_parent, Reason.TOTAL_SIZE_EXCEEDED, limits)


def test_single_file_size_limit_rejected(zip_factory, ws_parent):
    limits = replace(DEFAULT_LIMITS, max_file_bytes=1000, max_compression_ratio=1e9)
    reject(
        zip_factory([{"name": "big.txt", "data": b"a" * 5000}]),
        ws_parent,
        Reason.FILE_SIZE_EXCEEDED,
        limits,
    )


def test_too_many_files_rejected(zip_factory, ws_parent):
    limits = replace(DEFAULT_LIMITS, max_files=5)
    many = zip_factory([{"name": f"f{i}.txt", "data": b"x"} for i in range(6)])
    reject(many, ws_parent, Reason.TOO_MANY_FILES, limits)


@pytest.mark.parametrize(
    "names",
    [
        ["README.md", "readme.MD"],  # case collision
        ["a/b.py", "a/b.py"],  # exact duplicate
        ["pkg/mod.py", "PKG/MOD.py"],  # case collision in directories
        ["a", "a/b.py"],  # file vs directory
        ["caf\u00e9.py", "cafe\u0301.py"],  # NFC / NFD collision
    ],
)
@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_duplicate_or_colliding_names_rejected(zip_factory, ws_parent, names):
    entries = [{"name": n, "data": b"x"} for n in names]
    reject(zip_factory(entries), ws_parent, Reason.DUPLICATE_ENTRY)


@pytest.mark.parametrize(
    "name", ["inner.zip", "libs/dep.whl", "data.tar.gz", "x.7z", "ARCHIVE.JAR"]
)
def test_nested_archive_by_extension_rejected(zip_factory, ws_parent, name):
    reject(zip_factory([OK, {"name": name, "data": b"x"}]), ws_parent, Reason.NESTED_ARCHIVE)


def test_nested_archive_by_magic_bytes_rejected(zip_factory, ws_parent, tmp_path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("a.txt", "x")
    disguised = {"name": "notes.txt", "data": inner.read_bytes()}
    reject(zip_factory([disguised]), ws_parent, Reason.NESTED_ARCHIVE)


def test_gzip_magic_rejected(zip_factory, ws_parent):
    reject(
        zip_factory([{"name": "x.dat", "data": b"\x1f\x8b\x08" + b"0" * 40}]),
        ws_parent,
        Reason.NESTED_ARCHIVE,
    )


def test_encrypted_entry_rejected(zip_factory, ws_parent):
    path = zip_factory([OK])
    raw = bytearray(path.read_bytes())
    # set the "encrypted" general-purpose flag bit in both the local and central headers
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        raw[raw.index(sig) + off] |= 0x01
    path.write_bytes(bytes(raw))
    reject(path, ws_parent, Reason.ENCRYPTED_ENTRY)


def test_not_a_zip_rejected(tmp_path, ws_parent):
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"this is not a zip" * 10)
    reject(junk, ws_parent, Reason.INVALID_ARCHIVE)


@pytest.mark.parametrize("compress", [False, True], ids=["stored", "deflated"])
def test_lying_header_is_rejected_as_a_corrupt_archive(zip_factory, ws_parent, compress):
    """A header that understates the real size can never yield an oversized extraction: zipfile
    bounds the output by the declared size and its CRC check then fails, which we map to
    INVALID_ARCHIVE. (The SIZE_MISMATCH tests below simulate a library that does not.)"""
    path = zip_factory([{"name": "a.txt", "data": b"A" * 5000}], compress=compress)
    raw = bytearray(path.read_bytes())
    local, central = raw.index(b"PK\x03\x04"), raw.index(b"PK\x01\x02")
    raw[local + 22 : local + 26] = (10).to_bytes(4, "little")  # local header: uncompressed size
    raw[central + 24 : central + 28] = (10).to_bytes(4, "little")  # central directory: same
    path.write_bytes(bytes(raw))
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.INVALID_ARCHIVE and "CRC" in exc.value.detail
    assert list(ws_parent.iterdir()) == []


class _FakeMember:
    """Stands in for zipfile's member stream: delivers `payload` whatever size the header declared."""

    def __init__(self, payload: bytes):
        self._chunks = [payload, b""]

    def read(self, n=-1):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize(
    ("delivered", "case"), [(b"x" * 20, "grows past"), (b"xx", "shrinks below")]
)
def test_size_mismatch_branch_is_exercised_by_simulating_a_misbehaving_library(
    zip_factory, ws_parent, monkeypatch, delivered, case
):
    """Real archives cannot reach SIZE_MISMATCH (zipfile bounds output by the declared size and
    raises on short data), so this defence-in-depth branch is driven by simulation: a 10-byte
    entry whose stream delivers `delivered` instead."""
    path = zip_factory([{"name": "a.txt", "data": b"0123456789"}])
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda self, info, *a, **k: _FakeMember(delivered))
    with pytest.raises(IntakeError) as exc:
        intake_zip(path, workspace_parent=ws_parent)
    monkeypatch.undo()
    assert exc.value.reason is Reason.SIZE_MISMATCH, case
    assert list(ws_parent.iterdir()) == []


def test_dispatcher_routes_zip_and_extracts_the_real_contents(zip_factory, ws_parent):
    result = intake(
        zip_factory([OK, {"name": "docs/n.md", "data": b"# n"}]), workspace_parent=ws_parent
    )
    assert result.kind == "zip" and result.file_count == 2
    assert (result.workspace / "pkg" / "app.py").read_bytes() == OK["data"]
    assert (result.workspace / "docs" / "n.md").read_bytes() == b"# n"


def test_dispatcher_rejects_non_zip_file(tmp_path, ws_parent):
    plain = tmp_path / "notes.txt"
    plain.write_text("hello")
    with pytest.raises(IntakeError) as exc:
        intake(plain, workspace_parent=ws_parent)
    assert exc.value.reason is Reason.UNSUPPORTED_INPUT
