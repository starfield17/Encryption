from __future__ import annotations

import io
import os
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

import core.archiver as archiver_module
import core.format_v3 as format_v3
from core.archive_stream import scan_source_directory, write_tar_zstd
from core.archiver import (
    MAX_CONTAINER_SIZE_MB,
    ConflictPolicy,
    ContainerSpec,
    DeniableArchiver,
    ExtractionStatus,
    FormatCapacityError,
    OperationCancelled,
    PayloadSpec,
    ZipWrapperOptions,
)
from core.format_v3 import (
    CONTROL_CIPHERTEXT_LEN,
    DATA_CHUNK_PLAINTEXT_LEN,
    NONCE_PREFIX_LEN,
    SALT_LEN,
    SLOT_PREFIX_LEN,
    TAG_LEN,
    make_layout_commitment,
    record_plaintext_lengths,
)
from core.layout import MIB, MIN_SLOT_BYTES, equal_layout, normalize_layout, slot_offset


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(format_v3, "SCRYPT_N", 2**12)


def _source(tmp_path: Path, name: str = "source") -> Path:
    source = tmp_path / name
    (source / "nested").mkdir(parents=True)
    (source / "hello.txt").write_text("hello world", encoding="utf-8")
    (source / "nested" / "data.bin").write_bytes(b"\x00\x01\x02")
    return source


def test_v3_roundtrip_hides_plaintext_and_only_changes_selected_slot(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    before = vault.read_bytes()

    archiver.write_payload(vault, source, "correct horse battery staple", 1, slot_count=4)
    after = vault.read_bytes()

    slot_size = len(after) // 4
    assert after[:slot_size] == before[:slot_size]
    assert after[slot_size : slot_size * 2] != before[slot_size : slot_size * 2]
    assert after[slot_size * 2 :] == before[slot_size * 2 :]
    assert b"hello.txt" not in after
    assert b"hello world" not in after
    assert b"DARC3PAY" not in after

    output = tmp_path / "output"
    result = archiver.extract_payload(vault, "correct horse battery staple", output, slot_count=4)
    assert result.status is ExtractionStatus.EXTRACTED
    assert (output / "hello.txt").read_text(encoding="utf-8") == "hello world"
    assert (output / "nested" / "data.bin").read_bytes() == b"\x00\x01\x02"


def test_highly_compressible_payload_roundtrips_when_uncompressed_size_exceeds_slot(tmp_path):
    archiver = DeniableArchiver()
    source = tmp_path / "source"
    source.mkdir()
    logical_size = 2 * MIB
    (source / "zeros.bin").write_bytes(b"0" * logical_size)
    vault = tmp_path / "compressed.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)

    estimate = archiver.estimate_payload(source)
    assert estimate.compressed_size < 256 * 1024
    assert estimate.uncompressed_size == logical_size
    archiver.write_payload(vault, source, "long unique passphrase", 0, slot_count=4)

    output = tmp_path / "output"
    result = archiver.extract_payload(vault, "long unique passphrase", output, slot_count=4)
    assert result.status is ExtractionStatus.EXTRACTED
    assert (output / "zeros.bin").stat().st_size == logical_size


def test_wrong_password_returns_no_match_without_creating_output(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "right password", 0, slot_count=4)

    output = tmp_path / "output"
    result = archiver.extract_payload(vault, "wrong password", output, slot_count=4)

    assert result.status is ExtractionStatus.NO_MATCH
    assert result.output_dir is None
    assert not output.exists()
    assert not (output / "decrypted_raw.bin").exists()


@pytest.mark.parametrize("operation", ["write", "extract"])
def test_empty_password_is_rejected_by_core(tmp_path, operation):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)

    with pytest.raises(ValueError, match="must not be empty"):
        if operation == "write":
            archiver.write_payload(vault, source, "", 0, slot_count=4)
        else:
            archiver.extract_payload(vault, "", tmp_path / "out", slot_count=4)


def test_payload_larger_than_compressed_slot_capacity_preserves_original_container(tmp_path):
    archiver = DeniableArchiver()
    source = tmp_path / "source"
    source.mkdir()
    (source / "random.bin").write_bytes(os.urandom(512 * 1024))
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    before = vault.read_bytes()

    with pytest.raises(FormatCapacityError, match="Payload too large"):
        archiver.write_payload(vault, source, "strong password", 0, slot_count=4)

    assert vault.read_bytes() == before


@pytest.mark.parametrize("relative_offset", [0, SALT_LEN, SALT_LEN + NONCE_PREFIX_LEN, SLOT_PREFIX_LEN + 17])
def test_tampering_any_authenticated_slot_region_returns_no_match(tmp_path, relative_offset):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    layout = equal_layout(MIB, 4)
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 2, slot_count=4)

    target = slot_offset(layout, 2) + relative_offset
    with vault.open("r+b") as handle:
        handle.seek(target)
        original = handle.read(1)
        handle.seek(target)
        handle.write(bytes([original[0] ^ 0x80]))

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", slot_count=4)
    assert result.status is ExtractionStatus.NO_MATCH
    assert not (tmp_path / "out").exists()


def test_tampering_padding_record_is_detected_before_output_is_published(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    layout = equal_layout(4 * MIB, 4)
    archiver.initialize_container(vault, size_mb=4, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=4)

    with vault.open("r+b") as handle:
        handle.seek(layout[0] - 1)
        byte = handle.read(1)
        handle.seek(layout[0] - 1)
        handle.write(bytes([byte[0] ^ 1]))

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", slot_count=4)
    assert result.status is ExtractionStatus.NO_MATCH
    assert not (tmp_path / "out").exists()


def test_slot_relocation_is_rejected_by_aad(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    layout = equal_layout(MIB, 4)
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=4)

    with vault.open("r+b") as handle:
        handle.seek(0)
        encrypted_slot = handle.read(layout[0])
        handle.seek(0)
        handle.write(os.urandom(layout[0]))
        handle.seek(slot_offset(layout, 1))
        handle.write(encrypted_slot)

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", slot_count=4)
    assert result.status is ExtractionStatus.NO_MATCH


def test_reordered_equal_length_records_are_rejected(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    layout = equal_layout(8 * MIB, 2)
    archiver.initialize_container(vault, size_mb=8, slot_count=2)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=2)
    lengths = record_plaintext_lengths(layout[0])
    assert lengths[0] == lengths[1] == DATA_CHUNK_PLAINTEXT_LEN
    cipher_len = DATA_CHUNK_PLAINTEXT_LEN + TAG_LEN

    with vault.open("r+b") as handle:
        handle.seek(SLOT_PREFIX_LEN)
        first = handle.read(cipher_len)
        second = handle.read(cipher_len)
        handle.seek(SLOT_PREFIX_LEN)
        handle.write(second)
        handle.write(first)

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", slot_count=2)
    assert result.status is ExtractionStatus.NO_MATCH


def test_truncating_whole_trailing_slots_is_rejected_by_layout_commitment(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=4, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=4)

    with vault.open("r+b") as handle:
        handle.truncate(2 * MIB)

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", slot_count=2)
    assert result.status is ExtractionStatus.NO_MATCH
    assert not (tmp_path / "out").exists()


def test_enabled_wrapper_requires_real_content_and_visible_layer_survives_slot_update(tmp_path):
    archiver = DeniableArchiver()
    with pytest.raises(ValueError, match="at least one source"):
        archiver.initialize_container(
            tmp_path / "empty.zip",
            size_mb=1,
            slot_count=4,
            zip_wrapper=ZipWrapperOptions(enabled=True),
        )

    visible = tmp_path / "visible"
    visible.mkdir()
    (visible / "readme.txt").write_text("cover", encoding="utf-8")
    payload = _source(tmp_path, "payload")
    vault = tmp_path / "vault.zip"
    archiver.initialize_container(
        vault,
        size_mb=1,
        slot_count=4,
        zip_wrapper=ZipWrapperOptions(enabled=True, visible_source_dir=visible),
    )
    archiver.write_payload(vault, payload, "payload password", 3, slot_count=4)

    assert archiver.slot_region_size(vault) == MIB
    with zipfile.ZipFile(vault) as archive:
        assert archive.namelist() == ["readme.txt"]
        assert archive.read("readme.txt") == b"cover"
    result = archiver.extract_payload(vault, "payload password", tmp_path / "out", slot_count=4)
    assert result.status is ExtractionStatus.EXTRACTED


def test_container_and_public_secret_source_overlaps_are_rejected_before_creation(tmp_path):
    archiver = DeniableArchiver()
    root = tmp_path / "source"
    secret = root / "secret"
    secret.mkdir(parents=True)
    (root / "cover.txt").write_text("cover", encoding="utf-8")
    (secret / "private.txt").write_text("private", encoding="utf-8")
    layout = equal_layout(MIB, 4)

    with pytest.raises(ValueError, match="must not be inside"):
        archiver.initialize_container(
            root / "vault.zip",
            size_mb=1,
            slot_count=4,
            zip_wrapper=ZipWrapperOptions(enabled=True, visible_source_dir=root),
        )

    destination = tmp_path / "vault.zip"
    with pytest.raises(ValueError, match="must not overlap"):
        archiver.create_container(
            destination,
            ContainerSpec(layout, ZipWrapperOptions(enabled=True, visible_source_dir=root)),
            [PayloadSpec(0, secret, "secret password")],
        )
    assert not destination.exists()


def test_initialize_requires_explicit_regular_file_replacement(tmp_path):
    archiver = DeniableArchiver()
    vault = tmp_path / "vault.darc"
    vault.write_bytes(b"existing")

    with pytest.raises(FileExistsError, match="already exists"):
        archiver.initialize_container(vault, size_mb=1, slot_count=4)
    assert vault.read_bytes() == b"existing"

    archiver.initialize_container(vault, size_mb=1, slot_count=4, replace_existing=True)
    assert vault.stat().st_size == MIB


def test_initialize_rechecks_destination_after_acquiring_lock(tmp_path, monkeypatch):
    archiver = DeniableArchiver()
    vault = tmp_path / "vault.darc"

    @contextmanager
    def competing_creator(_path):
        vault.write_bytes(b"created while waiting for lock")
        yield

    monkeypatch.setattr(archiver_module, "container_lock", competing_creator)

    with pytest.raises(FileExistsError, match="already exists"):
        archiver.initialize_container(vault, size_mb=1, slot_count=4)
    assert vault.read_bytes() == b"created while waiting for lock"


def test_no_replace_commit_preserves_destination_created_during_build(tmp_path, monkeypatch):
    archiver = DeniableArchiver()
    vault = tmp_path / "vault.darc"
    initialize_file = archiver._initialize_file

    def initialize_then_compete(path, region_size, wrapper, progress, cancelled):
        initialize_file(path, region_size, wrapper, progress, cancelled)
        vault.write_bytes(b"created during container build")

    monkeypatch.setattr(archiver, "_initialize_file", initialize_then_compete)

    with pytest.raises(FileExistsError):
        archiver.initialize_container(vault, size_mb=1, slot_count=4)
    assert vault.read_bytes() == b"created during container build"
    assert not list(tmp_path.glob(f".{vault.name}.*.tmp"))


def test_initialize_never_follows_existing_destination_symlink(tmp_path):
    archiver = DeniableArchiver()
    target = tmp_path / "target.darc"
    target.write_bytes(b"preserve")
    link = tmp_path / "link.darc"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this platform")

    with pytest.raises(ValueError, match="symbolic link"):
        archiver.initialize_container(link, size_mb=1, slot_count=4, replace_existing=True)
    assert target.read_bytes() == b"preserve"


def test_batch_create_rejects_duplicate_slots_passwords_and_overlapping_sources(tmp_path):
    archiver = DeniableArchiver()
    first = _source(tmp_path, "first")
    second = _source(tmp_path, "second")
    layout = equal_layout(MIB, 4)

    with pytest.raises(ValueError, match="slots must be unique"):
        archiver.create_container(
            tmp_path / "slots.darc",
            ContainerSpec(layout),
            [PayloadSpec(0, first, "first password"), PayloadSpec(0, second, "second password")],
        )
    with pytest.raises(ValueError, match="passwords must be unique"):
        archiver.create_container(
            tmp_path / "passwords.darc",
            ContainerSpec(layout),
            [PayloadSpec(0, first, "same password"), PayloadSpec(1, second, "same password")],
        )
    with pytest.raises(ValueError, match="must not overlap"):
        archiver.create_container(
            tmp_path / "sources.darc",
            ContainerSpec(layout),
            [PayloadSpec(0, first, "first password"), PayloadSpec(1, first / "nested", "second password")],
        )


def test_archive_stream_rejects_same_size_source_rewrite_after_scan(tmp_path):
    source = _source(tmp_path)
    entries = scan_source_directory(source)
    changed = source / "hello.txt"
    original_stat = changed.stat()
    changed.write_text("HELLO WORLD", encoding="utf-8")
    os.utime(
        changed,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
    )

    with pytest.raises(ValueError, match="changed while archiving"):
        write_tar_zstd(entries, io.BytesIO())


def test_extract_requires_empty_output_unless_replace_is_explicit(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=4)
    output = tmp_path / "output"
    output.mkdir()
    (output / "existing.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="not empty"):
        archiver.extract_payload(vault, "strong password", output, slot_count=4)
    assert (output / "existing.txt").read_text(encoding="utf-8") == "keep"

    result = archiver.extract_payload(
        vault,
        "strong password",
        output,
        slot_count=4,
        conflict_policy=ConflictPolicy.REPLACE,
    )
    assert result.status is ExtractionStatus.EXTRACTED
    assert not (output / "existing.txt").exists()
    assert (output / "hello.txt").exists()


def test_output_directory_cannot_contain_input_container(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    container_dir = tmp_path / "containers"
    container_dir.mkdir()
    vault = container_dir / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "strong password", 0, slot_count=4)

    with pytest.raises(ValueError, match="input container"):
        archiver.extract_payload(vault, "strong password", container_dir, slot_count=4)


def test_cancelled_update_preserves_original_container(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    before = vault.read_bytes()

    with pytest.raises(OperationCancelled):
        archiver.write_payload(
            vault,
            source,
            "strong password",
            0,
            slot_count=4,
            cancelled=lambda: True,
        )
    assert vault.read_bytes() == before


def test_oversized_external_region_is_rejected_before_update_copy_or_extract(tmp_path, monkeypatch):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "oversized.darc"
    vault.write_bytes(b"small placeholder")
    oversized = MAX_CONTAINER_SIZE_MB * MIB + 1
    monkeypatch.setattr(archiver_module, "detect_slot_region_size", lambda _path: oversized)

    @contextmanager
    def unexpected_copy(_path):
        pytest.fail("oversized container must be rejected before it is copied")
        yield

    monkeypatch.setattr(archiver_module, "atomic_copy_for_update", unexpected_copy)

    with pytest.raises(ValueError, match="must not exceed"):
        archiver.write_payload(vault, source, "strong password", 0, slot_count=4)
    with pytest.raises(ValueError, match="must not exceed"):
        archiver.extract_payload(vault, "strong password", tmp_path / "output", slot_count=4)
    assert not (tmp_path / "output").exists()


def test_oversized_total_file_is_rejected_before_zip_detection(tmp_path, monkeypatch):
    archiver = DeniableArchiver()
    vault = tmp_path / "oversized-wrapper.zip"
    vault.write_bytes(b"placeholder")

    class OversizedPath:
        @staticmethod
        def stat():
            class Stat:
                st_size = MAX_CONTAINER_SIZE_MB * MIB + 1

            return Stat()

    monkeypatch.setattr(archiver_module, "Path", lambda _path: OversizedPath())
    monkeypatch.setattr(
        archiver_module,
        "detect_slot_region_size",
        lambda _path: pytest.fail("oversized file must be rejected before ZIP detection"),
    )

    with pytest.raises(ValueError, match="Container file must not exceed"):
        archiver.slot_region_size(vault)


def test_update_rechecks_region_limit_after_acquiring_lock(tmp_path, monkeypatch):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    vault = tmp_path / "changed.darc"
    vault.write_bytes(b"small placeholder")
    sizes = iter((MIB, MAX_CONTAINER_SIZE_MB * MIB + 1))
    monkeypatch.setattr(archiver_module, "detect_slot_region_size", lambda _path: next(sizes))

    @contextmanager
    def unexpected_copy(_path):
        pytest.fail("container changed while waiting for the lock must not be copied")
        yield

    monkeypatch.setattr(archiver_module, "atomic_copy_for_update", unexpected_copy)

    with pytest.raises(ValueError, match="must not exceed"):
        archiver.write_payload(vault, source, "strong password", 0, slot_count=4)


def test_custom_layout_roundtrip(tmp_path):
    archiver = DeniableArchiver()
    source = _source(tmp_path)
    layout = (MIB // 4, 3 * MIB // 4)
    vault = tmp_path / "custom.darc"
    archiver.initialize_container(vault, size_mb=1, layout=layout)
    archiver.write_payload(vault, source, "strong password", 1, layout=layout)

    result = archiver.extract_payload(vault, "strong password", tmp_path / "out", layout=layout)
    assert result.status is ExtractionStatus.EXTRACTED


def test_control_record_size_constant_covers_ciphertext_tag():
    assert CONTROL_CIPHERTEXT_LEN > 128


def test_minimum_representable_slot_size_matches_format_capacity():
    assert normalize_layout((MIN_SLOT_BYTES, MIN_SLOT_BYTES)) == (MIN_SLOT_BYTES, MIN_SLOT_BYTES)
    assert record_plaintext_lengths(MIN_SLOT_BYTES) == (1,)


def test_layout_commitment_binds_slot_count_sizes_and_order():
    base = make_layout_commitment((MIB, 2 * MIB, MIB))

    assert len(base) == 32
    assert base != make_layout_commitment((MIB, 2 * MIB))
    assert base != make_layout_commitment((MIB, MIB, 2 * MIB))
