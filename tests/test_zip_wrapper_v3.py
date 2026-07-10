from __future__ import annotations

import io
import os
import zipfile

import pytest
import pyzipper

import core.zip_wrapper as zip_wrapper_module
from core.zip_wrapper import (
    DEFAULT_WRAPPER_ENTRY_NAME,
    ZIP_ENTRY_MODE_ARCHIVE,
    ZIP_ENTRY_MODE_FILES,
    ZipWrapperOptions,
    build_prefixed_zip_suffix,
    detect_slot_region_size,
    detect_zip_prefix_offset,
    validate_wrapper_options,
)


def test_prefixed_wrapper_roundtrip_uses_aes256_direct_entries(tmp_path):
    visible = tmp_path / "visible"
    encrypted = tmp_path / "encrypted"
    (encrypted / "nested").mkdir(parents=True)
    visible.mkdir()
    (visible / "readme.txt").write_text("visible", encoding="utf-8")
    (encrypted / "secret.txt").write_text("secret", encoding="utf-8")
    (encrypted / "nested" / "data.bin").write_bytes(b"data")

    prefix = os.urandom(4096)
    suffix = build_prefixed_zip_suffix(
        ZipWrapperOptions(
            enabled=True,
            visible_source_dir=visible,
            encrypted_entry_source_dir=encrypted,
            encrypted_entry_password="entry password",
            encrypted_entry_mode=ZIP_ENTRY_MODE_FILES,
        ),
        len(prefix),
    )
    container = tmp_path / "container.zip"
    container.write_bytes(prefix + suffix)

    assert detect_zip_prefix_offset(container) == len(prefix)
    assert detect_slot_region_size(container) == len(prefix)
    with zipfile.ZipFile(container) as archive:
        assert archive.namelist() == ["readme.txt", "nested/data.bin", "secret.txt"]
        assert archive.read("readme.txt") == b"visible"
        assert archive.getinfo("secret.txt").flag_bits & 0x1

    with pyzipper.AESZipFile(container) as archive:
        assert archive.getinfo("secret.txt").wz_aes_strength == 3
        archive.setpassword(b"entry password")
        assert archive.read("secret.txt") == b"secret"
        assert archive.read("nested/data.bin") == b"data"


def test_archive_mode_keeps_default_encrypted_entry_semantics(tmp_path):
    encrypted = tmp_path / "encrypted"
    encrypted.mkdir()
    (encrypted / "document.txt").write_text("document", encoding="utf-8")

    suffix = build_prefixed_zip_suffix(
        ZipWrapperOptions(
            enabled=True,
            encrypted_entry_source_dir=encrypted,
            encrypted_entry_password="entry password",
            encrypted_entry_mode=ZIP_ENTRY_MODE_ARCHIVE,
        ),
        0,
    )

    with pyzipper.AESZipFile(io.BytesIO(suffix)) as archive:
        assert archive.namelist() == [DEFAULT_WRAPPER_ENTRY_NAME]
        assert archive.getinfo(DEFAULT_WRAPPER_ENTRY_NAME).wz_aes_strength == 3
        archive.setpassword(b"entry password")
        inner_bytes = archive.read(DEFAULT_WRAPPER_ENTRY_NAME)
    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
        assert inner.read("document.txt") == b"document"


def test_enabled_wrapper_rejects_missing_sources():
    with pytest.raises(ValueError, match="at least one source entry"):
        validate_wrapper_options(ZipWrapperOptions(enabled=True))


def test_enabled_wrapper_rejects_empty_sources(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(ValueError, match="at least one source entry"):
        validate_wrapper_options(ZipWrapperOptions(enabled=True, visible_source_dir=empty))
    with pytest.raises(ValueError, match="contains no file entries"):
        validate_wrapper_options(
            ZipWrapperOptions(
                enabled=True,
                encrypted_entry_source_dir=empty,
                encrypted_entry_password="password",
            )
        )


def test_wrapper_rejects_unsupported_mode_and_missing_password(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported ZIP entry mode"):
        validate_wrapper_options(
            ZipWrapperOptions(enabled=True, visible_source_dir=source, encrypted_entry_mode="other")
        )
    with pytest.raises(ValueError, match="password is required"):
        validate_wrapper_options(ZipWrapperOptions(enabled=True, encrypted_entry_source_dir=source))


@pytest.mark.parametrize("entry_name", ["/absolute.zip", "../escape.zip", "C:\\drive.zip", "bad?.zip"])
def test_wrapper_rejects_unsafe_encrypted_entry_names(tmp_path, entry_name):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe ZIP entry"):
        validate_wrapper_options(
            ZipWrapperOptions(
                enabled=True,
                encrypted_entry_source_dir=source,
                encrypted_entry_password="password",
                encrypted_entry_name=entry_name,
            )
        )


def test_wrapper_rejects_symlinks_special_files_and_unsafe_source_names(tmp_path):
    symlink_source = tmp_path / "symlink-source"
    symlink_source.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    try:
        (symlink_source / "link.txt").symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this platform")
    with pytest.raises(ValueError, match="unsupported symlink"):
        validate_wrapper_options(ZipWrapperOptions(enabled=True, visible_source_dir=symlink_source))

    if os.name != "nt":
        unsafe_source = tmp_path / "unsafe-source"
        unsafe_source.mkdir()
        (unsafe_source / "CON.txt").write_text("unsafe", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsafe ZIP entry name"):
            validate_wrapper_options(ZipWrapperOptions(enabled=True, visible_source_dir=unsafe_source))

    if hasattr(os, "mkfifo"):
        special_source = tmp_path / "special-source"
        special_source.mkdir()
        os.mkfifo(special_source / "pipe")
        with pytest.raises(ValueError, match="unsupported file type"):
            validate_wrapper_options(ZipWrapperOptions(enabled=True, visible_source_dir=special_source))


def test_wrapper_rejects_same_size_source_rewrite_after_scan(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    changed = source / "file.txt"
    changed.write_text("original", encoding="utf-8")
    prepare_wrapper = zip_wrapper_module._prepare_wrapper

    def prepare_then_change(options, prefix_len):
        prepared = prepare_wrapper(options, prefix_len)
        original_stat = changed.stat()
        changed.write_text("modified", encoding="utf-8")
        os.utime(
            changed,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
        )
        return prepared

    monkeypatch.setattr(zip_wrapper_module, "_prepare_wrapper", prepare_then_change)

    with pytest.raises(ValueError, match="changed during wrapper creation"):
        build_prefixed_zip_suffix(ZipWrapperOptions(enabled=True, visible_source_dir=source), 0)


def test_direct_entries_reject_case_insensitive_visible_duplicate(tmp_path):
    visible = tmp_path / "visible"
    encrypted = tmp_path / "encrypted"
    visible.mkdir()
    encrypted.mkdir()
    (visible / "same.txt").write_text("visible", encoding="utf-8")
    (encrypted / "SAME.txt").write_text("encrypted", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicates a visible file"):
        validate_wrapper_options(
            ZipWrapperOptions(
                enabled=True,
                visible_source_dir=visible,
                encrypted_entry_source_dir=encrypted,
                encrypted_entry_password="password",
                encrypted_entry_mode=ZIP_ENTRY_MODE_FILES,
            )
        )


def test_prefix_limit_is_rejected_before_source_traversal(tmp_path):
    missing_source = tmp_path / "missing"
    options = ZipWrapperOptions(enabled=True, visible_source_dir=missing_source)

    with pytest.raises(ValueError, match="non-ZIP64 offsets"):
        validate_wrapper_options(options, prefix_len=0xFFFFFFFF)
    with pytest.raises(ValueError, match="non-ZIP64 offsets"):
        build_prefixed_zip_suffix(options, prefix_len=0xFFFFFFFF)


def test_detects_unadjusted_zip_suffix_and_plain_container(tmp_path):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("file.txt", b"data")
    prefix = b"prefix bytes"
    unadjusted = tmp_path / "unadjusted.zip"
    unadjusted.write_bytes(prefix + zip_buffer.getvalue())

    plain = tmp_path / "plain.darc"
    plain.write_bytes(b"not a zip container")

    assert detect_zip_prefix_offset(unadjusted) == len(prefix)
    assert detect_slot_region_size(unadjusted) == len(prefix)
    assert detect_zip_prefix_offset(plain) is None
    assert detect_slot_region_size(plain) == plain.stat().st_size


def test_disabled_wrapper_builds_no_suffix():
    options = ZipWrapperOptions(enabled=False)

    validate_wrapper_options(options, prefix_len=0xFFFFFFFF)
    assert build_prefixed_zip_suffix(options, prefix_len=0xFFFFFFFF) == b""
