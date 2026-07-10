from __future__ import annotations

import io
import os
import stat
import struct
import time
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

import pyzipper

ZIP_ENTRY_MODE_ARCHIVE = "archive"
ZIP_ENTRY_MODE_FILES = "files"
DEFAULT_WRAPPER_ENTRY_NAME = "Documents.zip"

ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
ZIP_LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
ZIP_EOCD_LEN = 22
ZIP_CENTRAL_DIRECTORY_HEADER_LEN = 46
ZIP_LOCAL_FILE_HEADER_LEN = 30
ZIP_MAX_COMMENT_LEN = 65_535
ZIP32_MAX = 0xFFFFFFFF
ZIP32_MAX_FILES = 0xFFFF
ZIP_COPY_CHUNK = 1024 * 1024

_AES_EXTRA_LEN = 11
_AES_PAYLOAD_OVERHEAD = 28
_WINDOWS_INVALID_FILENAME_CHARS = frozenset('<>:"|?*')


@dataclass(frozen=True)
class ZipWrapperOptions:
    enabled: bool = False
    visible_source_dir: Path | None = None
    encrypted_entry_source_dir: Path | None = None
    encrypted_entry_name: str = DEFAULT_WRAPPER_ENTRY_NAME
    encrypted_entry_password: str | None = None
    encrypted_entry_mode: str = ZIP_ENTRY_MODE_ARCHIVE


@dataclass(frozen=True)
class _SourceEntry:
    path: Path
    archive_name: str
    size: int
    mode: int
    mtime: int
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int


@dataclass(frozen=True)
class _PreparedWrapper:
    visible_entries: tuple[_SourceEntry, ...]
    encrypted_entries: tuple[_SourceEntry, ...]
    encrypted_entry_name: str | None


@dataclass(frozen=True)
class _PlannedEntry:
    archive_name: str
    data_size_upper_bound: int
    encrypted: bool


class _EntryRegistry:
    def __init__(self) -> None:
        self._files: dict[tuple[str, ...], tuple[str, str]] = {}
        self._parents: set[tuple[str, ...]] = set()

    def add(self, archive_name: str, owner: str) -> None:
        key = tuple(unicodedata.normalize("NFC", part).casefold() for part in archive_name.split("/"))
        conflict = self._files.get(key)
        if conflict is not None:
            self._raise_conflict(owner, conflict[1])
        if key in self._parents:
            raise ValueError("ZIP entry path conflicts with another file entry")
        for index in range(1, len(key)):
            conflict = self._files.get(key[:index])
            if conflict is not None:
                raise ValueError("ZIP entry path conflicts with another file entry")

        self._files[key] = (archive_name, owner)
        self._parents.update(key[:index] for index in range(1, len(key)))

    @staticmethod
    def _raise_conflict(owner: str, existing_owner: str) -> None:
        if {owner, existing_owner} == {"visible", "encrypted"}:
            raise ValueError("ZIP entry name duplicates a visible file")
        raise ValueError("ZIP entry name duplicates another entry")


def validate_wrapper_options(options: ZipWrapperOptions, prefix_len: int = 0) -> None:
    """Validate wrapper sources and ZIP32 limits without reading file contents."""

    _prepare_wrapper(options, prefix_len)


def build_prefixed_zip_suffix(options: ZipWrapperOptions, prefix_len: int) -> bytes:
    """Build a ZIP suffix whose stored offsets account for a preceding byte region."""

    prepared = _prepare_wrapper(options, prefix_len)
    if not options.enabled:
        return b""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        _write_entries(archive, prepared.visible_entries)

    if prepared.encrypted_entries:
        password = options.encrypted_entry_password
        if password is None:
            raise AssertionError("Validated encrypted ZIP password is missing")
        if options.encrypted_entry_mode == ZIP_ENTRY_MODE_ARCHIVE:
            inner_zip = _build_inner_zip(prepared.encrypted_entries)
            entry_name = prepared.encrypted_entry_name
            if entry_name is None:
                raise AssertionError("Validated encrypted ZIP entry name is missing")
            _append_encrypted_data(buffer, entry_name, inner_zip, password)
        else:
            _append_encrypted_entries(buffer, prepared.encrypted_entries, password)

    return _adjust_zip_offsets(buffer.getvalue(), prefix_len)


def detect_zip_prefix_offset(container_path: str | Path) -> int | None:
    """Return the byte offset where a trailing ZIP begins, or ``None`` if absent."""

    container = Path(container_path)
    file_size = container.stat().st_size
    tail_len = min(file_size, ZIP_EOCD_LEN + ZIP_MAX_COMMENT_LEN)
    with container.open("rb") as handle:
        handle.seek(file_size - tail_len)
        tail = handle.read(tail_len)

    search_end = len(tail)
    while True:
        index = tail.rfind(ZIP_EOCD_SIGNATURE, 0, search_end)
        if index < 0:
            return None
        offset = _parse_zip_prefix_offset(container, file_size, tail, index)
        if offset is not None:
            return offset
        search_end = index


def detect_slot_region_size(container_path: str | Path) -> int:
    """Return the bytes before a ZIP suffix, or the whole file when no suffix exists."""

    container = Path(container_path)
    prefix_offset = detect_zip_prefix_offset(container)
    return container.stat().st_size if prefix_offset is None else prefix_offset


def _prepare_wrapper(options: ZipWrapperOptions, prefix_len: int) -> _PreparedWrapper:
    if not isinstance(options, ZipWrapperOptions):
        raise TypeError("options must be a ZipWrapperOptions instance")
    if not options.enabled:
        return _PreparedWrapper((), (), None)

    _validate_prefix_len(prefix_len)
    if options.encrypted_entry_mode not in {ZIP_ENTRY_MODE_ARCHIVE, ZIP_ENTRY_MODE_FILES}:
        raise ValueError("Unsupported ZIP entry mode")
    if options.visible_source_dir is None and options.encrypted_entry_source_dir is None:
        raise ValueError("Enabled ZIP wrapper requires at least one source entry")
    if options.encrypted_entry_source_dir is not None and not options.encrypted_entry_password:
        raise ValueError("ZIP entry password is required")
    if options.encrypted_entry_source_dir is not None and not isinstance(options.encrypted_entry_password, str):
        raise TypeError("ZIP entry password must be a string")

    encrypted_entry_name = None
    if options.encrypted_entry_source_dir is not None and options.encrypted_entry_mode == ZIP_ENTRY_MODE_ARCHIVE:
        encrypted_entry_name = _normalize_zip_entry_name(options.encrypted_entry_name)

    visible_entries = (
        _scan_source_entries(options.visible_source_dir, "visible") if options.visible_source_dir is not None else ()
    )
    encrypted_entries = (
        _scan_source_entries(options.encrypted_entry_source_dir, "encrypted")
        if options.encrypted_entry_source_dir is not None
        else ()
    )
    if options.encrypted_entry_source_dir is not None and not encrypted_entries:
        raise ValueError("Encrypted ZIP source contains no file entries")
    if not visible_entries and not encrypted_entries:
        raise ValueError("Enabled ZIP wrapper requires at least one source entry")

    outer_names = _EntryRegistry()
    for entry in visible_entries:
        outer_names.add(entry.archive_name, "visible")
    if encrypted_entries:
        if options.encrypted_entry_mode == ZIP_ENTRY_MODE_ARCHIVE:
            if encrypted_entry_name is None:
                raise AssertionError("Validated encrypted ZIP entry name is missing")
            outer_names.add(encrypted_entry_name, "encrypted")
        else:
            for entry in encrypted_entries:
                outer_names.add(entry.archive_name, "encrypted")

    prepared = _PreparedWrapper(visible_entries, encrypted_entries, encrypted_entry_name)
    _preflight_zip32_limits(options, prepared, prefix_len)
    return prepared


def _validate_prefix_len(prefix_len: int) -> None:
    if isinstance(prefix_len, bool) or not isinstance(prefix_len, int):
        raise TypeError("prefix_len must be an integer")
    if prefix_len < 0:
        raise ValueError("prefix_len must not be negative")
    if prefix_len > ZIP32_MAX - ZIP_LOCAL_FILE_HEADER_LEN:
        raise ValueError("ZIP wrapper prefix is too large for non-ZIP64 offsets")


def _scan_source_entries(source_dir: str | Path, owner: str) -> tuple[_SourceEntry, ...]:
    source_path = Path(source_dir)
    if source_path.is_symlink():
        raise ValueError(f"ZIP source directory must not be a symlink: {source_path}")
    if not source_path.exists() or not source_path.is_dir():
        raise FileNotFoundError(f"Source directory does not exist: {source_path}")

    source_root = source_path.resolve(strict=True)
    entries: list[_SourceEntry] = []
    names = _EntryRegistry()
    for item in sorted(source_root.rglob("*")):
        item_stat = item.lstat()
        if stat.S_ISLNK(item_stat.st_mode):
            raise ValueError(f"Source directory contains an unsupported symlink: {item}")
        if stat.S_ISDIR(item_stat.st_mode):
            continue
        if not stat.S_ISREG(item_stat.st_mode):
            raise ValueError(f"Source directory contains an unsupported file type: {item}")

        archive_name = _normalize_zip_entry_name(item.relative_to(source_root).as_posix())
        names.add(archive_name, owner)
        if item_stat.st_size > zipfile.ZIP64_LIMIT:
            raise ValueError(f"Source file is too large for a non-ZIP64 wrapper: {item}")
        entries.append(
            _SourceEntry(
                path=item,
                archive_name=archive_name,
                size=item_stat.st_size,
                mode=stat.S_IMODE(item_stat.st_mode),
                mtime=int(item_stat.st_mtime),
                mtime_ns=item_stat.st_mtime_ns,
                ctime_ns=item_stat.st_ctime_ns,
                device=item_stat.st_dev,
                inode=item_stat.st_ino,
            )
        )
        if len(entries) > ZIP32_MAX_FILES:
            raise ValueError("ZIP wrapper has too many entries for non-ZIP64 format")
    return tuple(entries)


def _normalize_zip_entry_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("ZIP entry name must be a string")
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or "\x00" in normalized
        or any(ord(char) < 32 for char in normalized)
    ):
        raise ValueError("Unsafe ZIP entry name")
    if PureWindowsPath(normalized).drive or PureWindowsPath(normalized).is_absolute():
        raise ValueError("Unsafe ZIP entry path")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Unsafe ZIP entry path")
    path = PurePosixPath(*parts)
    if path.is_absolute():
        raise ValueError("Unsafe ZIP entry path")
    for part in path.parts:
        _validate_filename_part(part)
    if len(path.as_posix().encode("utf-8")) > 0xFFFF:
        raise ValueError("ZIP entry name is too long")
    return path.as_posix()


def _validate_filename_part(part: str) -> None:
    if part.rstrip(" .") != part or any(char in _WINDOWS_INVALID_FILENAME_CHARS for char in part):
        raise ValueError("Unsafe ZIP entry name")
    stem = part.split(".", 1)[0].upper()
    reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
    if stem in reserved_names:
        raise ValueError("Unsafe ZIP entry name")


def _preflight_zip32_limits(options: ZipWrapperOptions, prepared: _PreparedWrapper, prefix_len: int) -> None:
    planned_outer = [
        _PlannedEntry(entry.archive_name, entry.size, encrypted=False) for entry in prepared.visible_entries
    ]

    if prepared.encrypted_entries and options.encrypted_entry_mode == ZIP_ENTRY_MODE_ARCHIVE:
        inner_central_offset, inner_central_size, inner_total_size = _zip_size_upper_bounds(
            [_PlannedEntry(entry.archive_name, entry.size, encrypted=False) for entry in prepared.encrypted_entries]
        )
        _check_unprefixed_zip_bounds(inner_central_offset, inner_central_size)
        if prepared.encrypted_entry_name is None:
            raise AssertionError("Validated encrypted ZIP entry name is missing")
        planned_outer.append(_PlannedEntry(prepared.encrypted_entry_name, inner_total_size, encrypted=True))
    elif prepared.encrypted_entries:
        planned_outer.extend(
            _PlannedEntry(entry.archive_name, entry.size, encrypted=True) for entry in prepared.encrypted_entries
        )

    if len(planned_outer) > ZIP32_MAX_FILES:
        raise ValueError("ZIP wrapper has too many entries for non-ZIP64 format")
    central_offset, central_size, _total_size = _zip_size_upper_bounds(planned_outer)
    _check_unprefixed_zip_bounds(central_offset, central_size)
    if prefix_len + central_offset > ZIP32_MAX:
        raise ValueError("ZIP wrapper prefix is too large for non-ZIP64 offsets")


def _zip_size_upper_bounds(entries: list[_PlannedEntry]) -> tuple[int, int, int]:
    central_offset = 0
    central_size = 0
    for entry in entries:
        name_len = len(entry.archive_name.encode("utf-8"))
        aes_extra_len = _AES_EXTRA_LEN if entry.encrypted else 0
        aes_payload_overhead = _AES_PAYLOAD_OVERHEAD if entry.encrypted else 0
        central_offset += (
            ZIP_LOCAL_FILE_HEADER_LEN
            + name_len
            + aes_extra_len
            + _deflate_size_upper_bound(entry.data_size_upper_bound)
            + aes_payload_overhead
        )
        central_size += ZIP_CENTRAL_DIRECTORY_HEADER_LEN + name_len + aes_extra_len
    total_size = central_offset + central_size + ZIP_EOCD_LEN
    return central_offset, central_size, total_size


def _deflate_size_upper_bound(size: int) -> int:
    # This deliberately exceeds zlib's compressBound formula and avoids reading source data.
    return size + size // 8 + 1024


def _check_unprefixed_zip_bounds(central_offset: int, central_size: int) -> None:
    if central_offset > zipfile.ZIP64_LIMIT or central_size > zipfile.ZIP64_LIMIT:
        raise ValueError("ZIP wrapper is too large for non-ZIP64 format")


def _write_entries(archive: zipfile.ZipFile, entries: tuple[_SourceEntry, ...]) -> None:
    for entry in entries:
        with _open_verified_source(entry) as source:
            info = _zip_info(archive, entry)
            with archive.open(info, "w", force_zip64=False) as destination:
                written = 0
                while written < entry.size:
                    chunk = source.read(min(ZIP_COPY_CHUNK, entry.size - written))
                    if not chunk:
                        raise ValueError(f"ZIP source entry ended early: {entry.path}")
                    destination.write(chunk)
                    written += len(chunk)
                if source.read(1):
                    raise ValueError(f"ZIP source entry exceeds its scanned size: {entry.path}")
            _verify_open_source(entry, source.fileno())


def _build_inner_zip(entries: tuple[_SourceEntry, ...]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        _write_entries(archive, entries)
    return buffer.getvalue()


def _append_encrypted_entries(buffer: io.BytesIO, entries: tuple[_SourceEntry, ...], password: str) -> None:
    buffer.seek(0, io.SEEK_END)
    with pyzipper.AESZipFile(
        buffer,
        "a",
        compression=zipfile.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
        allowZip64=False,
    ) as archive:
        archive.setpassword(password.encode("utf-8"))
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        _write_entries(archive, entries)


def _append_encrypted_data(buffer: io.BytesIO, name: str, data: bytes, password: str) -> None:
    buffer.seek(0, io.SEEK_END)
    with pyzipper.AESZipFile(
        buffer,
        "a",
        compression=zipfile.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
        allowZip64=False,
    ) as archive:
        archive.setpassword(password.encode("utf-8"))
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(name, data)


def _zip_info(archive: zipfile.ZipFile, entry: _SourceEntry):
    date_time = time.localtime(entry.mtime)[:6]
    if not 1980 <= date_time[0] <= 2107:
        raise ValueError(f"ZIP source timestamp is outside the supported range: {entry.path}")
    info_type = getattr(archive, "zipinfo_cls", zipfile.ZipInfo)
    info = info_type(entry.archive_name, date_time=date_time)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | entry.mode) << 16
    info.file_size = entry.size
    return info


def _open_verified_source(entry: _SourceEntry):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(entry.path, flags)
    try:
        _verify_open_source(entry, descriptor)
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _verify_open_source(entry: _SourceEntry, descriptor: int) -> None:
    current = os.fstat(descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != entry.device
        or current.st_ino != entry.inode
        or current.st_size != entry.size
        or current.st_mtime_ns != entry.mtime_ns
        or current.st_ctime_ns != entry.ctime_ns
    ):
        raise ValueError(f"ZIP source entry changed during wrapper creation: {entry.path}")


def _adjust_zip_offsets(zip_bytes: bytes, prefix_len: int) -> bytes:
    if prefix_len == 0:
        return zip_bytes
    data = bytearray(zip_bytes)
    eocd_offset = data.rfind(ZIP_EOCD_SIGNATURE)
    if eocd_offset < 0 or eocd_offset + ZIP_EOCD_LEN != len(data):
        raise ValueError("ZIP wrapper is missing a valid end record")

    (
        _signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_len,
    ) = struct.unpack("<4s4H2LH", data[eocd_offset : eocd_offset + ZIP_EOCD_LEN])
    if (
        disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or comment_len != 0
        or central_offset == ZIP32_MAX
        or central_size == ZIP32_MAX
        or central_offset + central_size != eocd_offset
    ):
        raise ValueError("ZIP wrapper central directory is invalid")

    cursor = central_offset
    for _index in range(total_entries):
        if (
            cursor + ZIP_CENTRAL_DIRECTORY_HEADER_LEN > eocd_offset
            or bytes(data[cursor : cursor + 4]) != ZIP_CENTRAL_DIRECTORY_SIGNATURE
        ):
            raise ValueError("ZIP wrapper central directory is invalid")
        name_len, extra_len, entry_comment_len = struct.unpack("<HHH", data[cursor + 28 : cursor + 34])
        local_offset = struct.unpack("<L", data[cursor + 42 : cursor + 46])[0]
        if local_offset == ZIP32_MAX:
            raise ValueError("ZIP64 wrapper offsets are not supported")
        _write_u32(data, cursor + 42, local_offset + prefix_len)
        cursor += ZIP_CENTRAL_DIRECTORY_HEADER_LEN + name_len + extra_len + entry_comment_len
    if cursor != central_offset + central_size:
        raise ValueError("ZIP wrapper central directory is invalid")

    _write_u32(data, eocd_offset + 16, central_offset + prefix_len)
    return bytes(data)


def _write_u32(data: bytearray, offset: int, value: int) -> None:
    if not 0 <= value <= ZIP32_MAX:
        raise ValueError("ZIP wrapper is too large for non-ZIP64 offsets")
    data[offset : offset + 4] = struct.pack("<L", value)


def _parse_zip_prefix_offset(container: Path, file_size: int, tail: bytes, eocd_tail_index: int) -> int | None:
    if eocd_tail_index + ZIP_EOCD_LEN > len(tail):
        return None
    eocd_abs = file_size - len(tail) + eocd_tail_index
    (
        _signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_len,
    ) = struct.unpack("<4s4H2LH", tail[eocd_tail_index : eocd_tail_index + ZIP_EOCD_LEN])
    if comment_len != file_size - eocd_abs - ZIP_EOCD_LEN:
        return None
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        return None
    if central_size == ZIP32_MAX or central_offset == ZIP32_MAX:
        return None

    central_start = eocd_abs - central_size
    if central_start < 0:
        return None
    if total_entries == 0:
        prefix_offset = central_start - central_offset
        if prefix_offset < 0:
            return None
    else:
        local_offsets = _read_central_directory_offsets(container, central_start, central_size, total_entries)
        if not local_offsets:
            return None
        relative_prefix = central_start - central_offset
        if (
            relative_prefix >= 0
            and (relative_prefix > 0 or min(local_offsets) == 0)
            and _all_local_headers_at(container, local_offsets, relative_prefix)
        ):
            prefix_offset = relative_prefix
        elif _all_local_headers_at(container, local_offsets, 0):
            prefix_offset = min(local_offsets)
        else:
            return None

    try:
        with zipfile.ZipFile(container) as archive:
            if len(archive.infolist()) != total_entries:
                return None
    except (OSError, zipfile.BadZipFile):
        return None
    return prefix_offset


def _read_central_directory_offsets(
    container: Path, central_start: int, central_size: int, total_entries: int
) -> list[int]:
    offsets: list[int] = []
    try:
        with container.open("rb") as handle:
            handle.seek(central_start)
            consumed = 0
            while consumed < central_size and len(offsets) < total_entries:
                fixed = handle.read(ZIP_CENTRAL_DIRECTORY_HEADER_LEN)
                if len(fixed) != ZIP_CENTRAL_DIRECTORY_HEADER_LEN or fixed[:4] != ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                    return []
                name_len, extra_len, comment_len = struct.unpack("<HHH", fixed[28:34])
                local_offset = struct.unpack("<L", fixed[42:46])[0]
                if local_offset == ZIP32_MAX:
                    return []
                skip_len = name_len + extra_len + comment_len
                handle.seek(skip_len, io.SEEK_CUR)
                consumed += ZIP_CENTRAL_DIRECTORY_HEADER_LEN + skip_len
                offsets.append(local_offset)
    except OSError:
        return []
    if consumed != central_size or len(offsets) != total_entries:
        return []
    return offsets


def _all_local_headers_at(container: Path, local_offsets: list[int], adjustment: int) -> bool:
    if adjustment < 0:
        return False
    try:
        with container.open("rb") as handle:
            for offset in local_offsets:
                handle.seek(adjustment + offset)
                if handle.read(4) != ZIP_LOCAL_FILE_SIGNATURE:
                    return False
    except OSError:
        return False
    return True


__all__ = [
    "DEFAULT_WRAPPER_ENTRY_NAME",
    "ZIP_ENTRY_MODE_ARCHIVE",
    "ZIP_ENTRY_MODE_FILES",
    "ZipWrapperOptions",
    "build_prefixed_zip_suffix",
    "detect_slot_region_size",
    "detect_zip_prefix_offset",
    "validate_wrapper_options",
]
