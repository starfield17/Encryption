from __future__ import annotations

import os
import stat
import zipfile
from io import BytesIO

import pytest

import core.archiver as archiver_module
from core.archiver import RAW_DUMP_MESSAGE, RAW_DUMP_SIZE, SUCCESS_MESSAGE, DeniableArchiver, UnsafeZipError


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(archiver_module, "SCRYPT_N", 2**12)


def test_roundtrip_keeps_container_shape_and_hides_plaintext(tmp_path):
    archiver = DeniableArchiver()
    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (source / "hello.txt").write_text("hello world", encoding="utf-8")
    (nested / "data.bin").write_bytes(b"\x00\x01\x02")

    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    before = vault.read_bytes()

    archiver.write_payload(vault, source, "correct horse battery staple", 1, slot_count=4)
    after = vault.read_bytes()

    assert len(after) == len(before) == 1024 * 1024
    slot_size = len(after) // 4
    assert after[:slot_size] == before[:slot_size]
    assert after[slot_size : slot_size * 2] != before[slot_size : slot_size * 2]
    assert after[slot_size * 2 :] == before[slot_size * 2 :]
    assert b"hello.txt" not in after
    assert b"PAYL" not in after

    output = tmp_path / "output"
    result = archiver.extract_payload(vault, "correct horse battery staple", output, slot_count=4)

    assert result.message == SUCCESS_MESSAGE
    assert result.raw_dumped is False
    assert (output / "hello.txt").read_text(encoding="utf-8") == "hello world"
    assert (output / "nested" / "data.bin").read_bytes() == b"\x00\x01\x02"


def test_wrong_password_produces_generic_raw_dump(tmp_path):
    archiver = DeniableArchiver()
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("secret", encoding="utf-8")

    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "right password", 0, slot_count=4)

    output = tmp_path / "wrong-output"
    result = archiver.extract_payload(vault, "wrong password", output, slot_count=4)

    assert result.message == RAW_DUMP_MESSAGE
    assert result.raw_dumped is True
    assert (output / "decrypted_raw.bin").exists()
    assert (output / "decrypted_raw.bin").stat().st_size == 1024 * 1024


def test_raw_dump_is_one_mib_even_for_small_valid_random_container(tmp_path):
    archiver = DeniableArchiver()
    vault = tmp_path / "small-random.darc"
    vault.write_bytes(os.urandom(256))

    output = tmp_path / "output"
    result = archiver.extract_payload(vault, "password", output, slot_count=2)

    assert result.message == RAW_DUMP_MESSAGE
    assert result.raw_dumped is True
    assert (output / "decrypted_raw.bin").stat().st_size == RAW_DUMP_SIZE


def test_payload_too_large_for_selected_slot(tmp_path):
    archiver = DeniableArchiver()
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.dat").write_bytes(os.urandom(300_000))

    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)

    with pytest.raises(ValueError, match="Payload too large for selected slot"):
        archiver.write_payload(vault, source, "password", 2, slot_count=4)


def test_container_validation(tmp_path):
    archiver = DeniableArchiver()
    with pytest.raises(ValueError):
        archiver.initialize_container(tmp_path / "bad.darc", size_mb=0, slot_count=4)
    with pytest.raises(ValueError):
        archiver.initialize_container(tmp_path / "bad.darc", size_mb=1, slot_count=1)


def _zip_with_entry(name: str, data: bytes = b"x", external_attr: int | None = None) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(name)
        if external_attr is not None:
            info.external_attr = external_attr
        archive.writestr(info, data)
    return buffer.getvalue()


def _zip_with_entries(names: list[str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"x")
    return buffer.getvalue()


@pytest.mark.parametrize(
    "entry_name",
    [
        "../../secret.txt",
        "../outside.txt",
        "/absolute/path.txt",
        "C:\\Users\\name\\file.txt",
        "folder/../../../escape.txt",
        "",
    ],
)
def test_safe_extract_rejects_unsafe_paths(tmp_path, entry_name):
    archiver = DeniableArchiver()
    with pytest.raises((UnsafeZipError, IndexError)):
        archiver._safe_extract_zip(_zip_with_entry(entry_name), tmp_path / "out", 1024)
    assert not (tmp_path / "secret.txt").exists()


@pytest.mark.parametrize(
    "entry_name",
    [
        "CON",
        "NUL.txt",
        "folder/COM1.dat",
        "folder/LPT9.log",
        "bad./file.txt",
        "bad /file.txt",
    ],
)
def test_safe_extract_rejects_unsafe_filenames(tmp_path, entry_name):
    archiver = DeniableArchiver()

    with pytest.raises(UnsafeZipError):
        archiver._safe_extract_zip(_zip_with_entry(entry_name), tmp_path / "out", 1024)


def test_safe_extract_rejects_duplicate_output_targets(tmp_path):
    archiver = DeniableArchiver()
    zip_bytes = _zip_with_entries(["folder\\file.txt", "folder/file.txt"])

    with pytest.raises(UnsafeZipError, match="Duplicate zip output path"):
        archiver._safe_extract_zip(zip_bytes, tmp_path / "out", 1024)


def test_safe_extract_rejects_symlink_and_device_entries(tmp_path):
    archiver = DeniableArchiver()
    symlink_attr = (stat.S_IFLNK | 0o777) << 16
    device_attr = (stat.S_IFCHR | 0o600) << 16

    with pytest.raises(UnsafeZipError):
        archiver._safe_extract_zip(_zip_with_entry("link", external_attr=symlink_attr), tmp_path / "out", 1024)
    with pytest.raises(UnsafeZipError):
        archiver._safe_extract_zip(_zip_with_entry("device", external_attr=device_attr), tmp_path / "out", 1024)


def test_safe_extract_limits_total_uncompressed_size(tmp_path):
    archiver = DeniableArchiver()
    zip_bytes = _zip_with_entry("large.txt", b"a" * 20)

    with pytest.raises(UnsafeZipError):
        archiver._safe_extract_zip(zip_bytes, tmp_path / "out", 10)


def test_safe_extract_writes_regular_nested_files(tmp_path):
    archiver = DeniableArchiver()
    zip_bytes = _zip_with_entry("folder/file.txt", b"ok")
    output = tmp_path / "out"

    archiver._safe_extract_zip(zip_bytes, output, 1024)

    assert (output / "folder" / "file.txt").read_bytes() == b"ok"
