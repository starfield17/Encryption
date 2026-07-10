from __future__ import annotations

import os
import stat
import tarfile
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO

import zstandard

ARCHIVE_COMPRESSION_LEVEL = 6
ARCHIVE_COPY_CHUNK = 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
_WINDOWS_INVALID_FILENAME_CHARS = frozenset('<>:"|?*')


class UnsafeArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class SourceEntry:
    path: Path
    archive_name: str
    is_dir: bool
    size: int
    mode: int
    mtime: int
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int


@dataclass(frozen=True)
class ArchiveStats:
    compressed_size: int
    uncompressed_size: int
    entry_count: int


def scan_source_directory(source_dir: str | Path) -> tuple[SourceEntry, ...]:
    source_path = Path(source_dir)
    if source_path.is_symlink():
        raise ValueError(f"Source directory must not be a symlink: {source_path}")
    root = source_path.resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Source directory does not exist: {root}")
    entries: list[SourceEntry] = []
    seen_names: set[tuple[str, ...]] = set()
    for item in sorted(root.rglob("*")):
        try:
            item_stat = item.lstat()
        except OSError as exc:
            raise ValueError(f"Could not inspect source item: {item}") from exc
        if stat.S_ISLNK(item_stat.st_mode):
            raise ValueError(f"Source directory contains an unsupported symlink: {item}")
        if stat.S_ISDIR(item_stat.st_mode):
            is_dir = True
            size = 0
        elif stat.S_ISREG(item_stat.st_mode):
            is_dir = False
            size = item_stat.st_size
        else:
            raise ValueError(f"Source directory contains an unsupported file type: {item}")
        archive_name = normalize_archive_name(item.relative_to(root).as_posix())
        collision_key = archive_name_collision_key(archive_name)
        if collision_key in seen_names:
            raise ValueError("Source directory contains cross-platform duplicate paths")
        seen_names.add(collision_key)
        entries.append(
            SourceEntry(
                path=item,
                archive_name=archive_name,
                is_dir=is_dir,
                size=size,
                mode=stat.S_IMODE(item_stat.st_mode),
                mtime=int(item_stat.st_mtime),
                mtime_ns=item_stat.st_mtime_ns,
                ctime_ns=item_stat.st_ctime_ns,
                device=item_stat.st_dev,
                inode=item_stat.st_ino,
            )
        )
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("Source directory contains too many entries")
    return tuple(entries)


def source_stats(entries: Iterable[SourceEntry]) -> tuple[int, int]:
    materialized = tuple(entries)
    return sum(entry.size for entry in materialized if not entry.is_dir), len(materialized)


def write_tar_zstd(
    entries: Iterable[SourceEntry],
    sink: BinaryIO,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> ArchiveStats:
    materialized = tuple(entries)
    total_size, entry_count = source_stats(materialized)
    compressor = zstandard.ZstdCompressor(level=ARCHIVE_COMPRESSION_LEVEL)
    with (
        compressor.stream_writer(sink, closefd=False) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive,
    ):
        for entry in materialized:
            _check_cancelled(cancelled)
            info = _tar_info(entry)
            if entry.is_dir:
                _verify_source_entry(entry)
                archive.addfile(info)
                continue
            with _open_verified_source(entry) as source:
                archive.addfile(info, source)
                _verify_open_source(entry, source.fileno())
    return ArchiveStats(
        compressed_size=int(sink.tell()),
        uncompressed_size=total_size,
        entry_count=entry_count,
    )


class _CountingSink:
    def __init__(self) -> None:
        self.length = 0

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.length

    def write(self, data: bytes | bytearray | memoryview) -> int:
        length = len(data)
        self.length += length
        return length

    def flush(self) -> None:
        return None


def estimate_tar_zstd_size(
    source_dir: str | Path,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> ArchiveStats:
    entries = scan_source_directory(source_dir)
    sink = _CountingSink()
    return write_tar_zstd(entries, sink, cancelled=cancelled)  # type: ignore[arg-type]


def safe_extract_tar_zstd(
    source: BinaryIO,
    output_dir: Path,
    *,
    expected_size: int,
    expected_entries: int,
    cancelled: Callable[[], bool] | None = None,
) -> ArchiveStats:
    output_root = output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    total_size = 0
    entry_count = 0
    seen: set[str] = set()

    decompressor = zstandard.ZstdDecompressor()
    with decompressor.stream_reader(source, closefd=False) as decompressed:
        with tarfile.open(fileobj=decompressed, mode="r|") as archive:
            for member in archive:
                _check_cancelled(cancelled)
                entry_count += 1
                if entry_count > expected_entries or entry_count > MAX_ARCHIVE_ENTRIES:
                    raise UnsafeArchiveError("Archive contains too many entries")
                target = validate_archive_target(member.name, output_root)
                collision_key = "/".join(archive_name_collision_key(member.name.rstrip("/")))
                if collision_key in seen:
                    raise UnsafeArchiveError("Duplicate archive output path")
                seen.add(collision_key)

                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.islnk() or member.issym() or getattr(member, "sparse", None):
                    raise UnsafeArchiveError("Unsafe archive entry type")
                if member.size < 0 or member.size > expected_size - total_size:
                    raise UnsafeArchiveError("Archive expands beyond declared limits")
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise UnsafeArchiveError("Archive output path already exists")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise UnsafeArchiveError("Archive file data is missing")
                written = 0
                with extracted, target.open("xb") as destination:
                    while written < member.size:
                        _check_cancelled(cancelled)
                        chunk = extracted.read(min(ARCHIVE_COPY_CHUNK, member.size - written))
                        if not chunk:
                            raise UnsafeArchiveError("Archive file ended early")
                        destination.write(chunk)
                        written += len(chunk)
                    if extracted.read(1):
                        raise UnsafeArchiveError("Archive file exceeds its declared size")
                total_size += written
        while decompressed.read(ARCHIVE_COPY_CHUNK):
            _check_cancelled(cancelled)

    if entry_count != expected_entries:
        raise UnsafeArchiveError("Archive entry count does not match authenticated metadata")
    if total_size != expected_size:
        raise UnsafeArchiveError("Archive size does not match authenticated metadata")
    return ArchiveStats(
        compressed_size=0,
        uncompressed_size=total_size,
        entry_count=entry_count,
    )


def normalize_archive_name(name: str) -> str:
    normalized = name.replace("\\", "/").strip("/")
    if not normalized or "\x00" in normalized or any(ord(char) < 32 for char in normalized):
        raise UnsafeArchiveError("Unsafe archive entry name")
    if PureWindowsPath(normalized).drive or PureWindowsPath(normalized).is_absolute():
        raise UnsafeArchiveError("Unsafe archive entry path")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafeArchiveError("Unsafe archive entry path")
    for part in path.parts:
        validate_filename_part(part)
    return path.as_posix()


def validate_archive_target(name: str, output_root: Path) -> Path:
    normalized = normalize_archive_name(name.rstrip("/"))
    path = PurePosixPath(normalized)
    target = (output_root / Path(*path.parts)).resolve(strict=False)
    if not target.is_relative_to(output_root):
        raise UnsafeArchiveError("Archive entry escapes output directory")
    return target


def validate_filename_part(part: str) -> None:
    if part.rstrip(" .") != part or any(character in _WINDOWS_INVALID_FILENAME_CHARS for character in part):
        raise UnsafeArchiveError("Unsafe archive entry name")
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
        raise UnsafeArchiveError("Unsafe archive entry name")


def archive_name_collision_key(name: str) -> tuple[str, ...]:
    normalized = normalize_archive_name(name)
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in normalized.split("/"))


def _tar_info(entry: SourceEntry) -> tarfile.TarInfo:
    name = f"{entry.archive_name}/" if entry.is_dir else entry.archive_name
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if entry.is_dir else tarfile.REGTYPE
    info.size = 0 if entry.is_dir else entry.size
    info.mode = entry.mode
    info.mtime = entry.mtime
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _verify_source_entry(entry: SourceEntry) -> None:
    current = entry.path.lstat()
    expected_type = stat.S_ISDIR(current.st_mode) if entry.is_dir else stat.S_ISREG(current.st_mode)
    if (
        not expected_type
        or stat.S_ISLNK(current.st_mode)
        or current.st_dev != entry.device
        or current.st_ino != entry.inode
        or current.st_mtime_ns != entry.mtime_ns
        or current.st_ctime_ns != entry.ctime_ns
        or (not entry.is_dir and current.st_size != entry.size)
    ):
        raise ValueError(f"Source item changed while archiving: {entry.path}")


def _open_verified_source(entry: SourceEntry):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(entry.path, flags)
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != entry.device
            or current.st_ino != entry.inode
            or current.st_size != entry.size
            or current.st_mtime_ns != entry.mtime_ns
            or current.st_ctime_ns != entry.ctime_ns
        ):
            raise ValueError(f"Source item changed while archiving: {entry.path}")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _verify_open_source(entry: SourceEntry, descriptor: int) -> None:
    current = os.fstat(descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != entry.device
        or current.st_ino != entry.inode
        or current.st_size != entry.size
        or current.st_mtime_ns != entry.mtime_ns
        or current.st_ctime_ns != entry.ctime_ns
    ):
        raise ValueError(f"Source item changed while archiving: {entry.path}")


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise InterruptedError("Operation cancelled")
