from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO

import pyzipper
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


DEFAULT_CONTAINER_SIZE_MB = 100
DEFAULT_SLOT_COUNT = 4

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
SLOT_META_LEN = SALT_LEN + NONCE_LEN

PAYLOAD_MAGIC = b"PAYL"
PAYLOAD_VERSION = 2
PAYLOAD_HEADER_LEN = 48
PAYLOAD_HEADER_STRUCT = struct.Struct(">4sHHQ32s")

KDF_NAME = "scrypt"
SCRYPT_N = 2**18
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

RAW_DUMP_SIZE = 1024 * 1024
RANDOM_WRITE_CHUNK = 1024 * 1024
MAX_ZIP_FILES = 10_000
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
ZIP_EOCD_LEN = 22
ZIP_MAX_COMMENT_LEN = 65_535
ZIP_ENTRY_MODE_ARCHIVE = "archive"
ZIP_ENTRY_MODE_FILES = "files"
DEFAULT_WRAPPER_ENTRY_NAME = "Documents.zip"

SUCCESS_MESSAGE = "Extraction complete."
RAW_DUMP_MESSAGE = "Extraction complete. File system signatures not recognized; output dumped as raw binary."


class UnsafeZipError(ValueError):
    """Raised internally when an archive entry is unsafe to extract."""


@dataclass(frozen=True)
class ExtractionResult:
    message: str
    raw_dumped: bool
    output_dir: Path


@dataclass(frozen=True)
class ZipWrapperOptions:
    enabled: bool = False
    visible_source_dir: Path | None = None
    encrypted_entry_source_dir: Path | None = None
    encrypted_entry_name: str = DEFAULT_WRAPPER_ENTRY_NAME
    encrypted_entry_password: str | None = None
    encrypted_entry_mode: str = ZIP_ENTRY_MODE_ARCHIVE


class DeniableArchiver:
    def initialize_container(
        self,
        container_path: str | Path,
        size_mb: int = DEFAULT_CONTAINER_SIZE_MB,
        slot_count: int = DEFAULT_SLOT_COUNT,
        zip_wrapper: ZipWrapperOptions | None = None,
    ) -> None:
        if size_mb <= 0:
            raise ValueError("size_mb must be greater than 0")
        self._validate_slot_count(slot_count)

        slot_region_size = int(size_mb) * 1024 * 1024
        if slot_region_size % slot_count != 0:
            raise ValueError("Container size must be divisible by slot count")
        self._validate_slot_size(slot_region_size // slot_count)

        path = Path(container_path)
        with path.open("wb") as handle:
            self._write_random_region(handle, slot_region_size)
            if zip_wrapper is not None and zip_wrapper.enabled:
                handle.write(self._build_zip_wrapper(zip_wrapper, slot_region_size))

    def write_payload(
        self,
        container_path: str | Path,
        source_dir: str | Path,
        password: str,
        slot_index: int,
        slot_count: int = DEFAULT_SLOT_COUNT,
        compress: bool = True,
    ) -> None:
        container = Path(container_path)
        source = Path(source_dir)
        if not container.exists():
            raise FileNotFoundError(f"Container file does not exist: {container}")
        if not source.exists() or not source.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source}")

        slot_region_size = self.slot_region_size(container)
        slot_size = self._get_slot_size(slot_region_size, slot_count)
        if not 0 <= slot_index < slot_count:
            raise ValueError("slot_index out of range")

        zip_bytes = self._zip_directory(source, compress=compress)
        blob_len = self._slot_plaintext_len(slot_size)
        payload_blob = self._build_payload_blob(zip_bytes, blob_len)

        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = self._derive_key(password, salt)
        aad = self._make_aad(slot_index, slot_size)
        encrypted_blob = ChaCha20Poly1305(key).encrypt(nonce, payload_blob, aad)
        slot_bytes = salt + nonce + encrypted_blob
        if len(slot_bytes) != slot_size:
            raise AssertionError("Encrypted slot length does not match slot size")

        with container.open("r+b") as handle:
            handle.seek(self._get_slot_offset(slot_index, slot_size))
            handle.write(slot_bytes)

    def extract_payload(
        self,
        container_path: str | Path,
        password: str,
        output_dir: str | Path,
        slot_count: int = DEFAULT_SLOT_COUNT,
    ) -> ExtractionResult:
        container = Path(container_path)
        if not container.exists():
            raise FileNotFoundError(f"Container file does not exist: {container}")

        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        slot_region_size = self.slot_region_size(container)
        slot_size = self._get_slot_size(slot_region_size, slot_count)
        blob_len = self._slot_plaintext_len(slot_size)

        first_valid_zip: bytes | None = None
        with container.open("rb") as handle:
            for slot_index in range(slot_count):
                slot_bytes = self._read_slot(handle, slot_index, slot_size)
                parsed = self._try_decrypt_slot(slot_bytes, password, slot_index, slot_size)
                if parsed is None:
                    continue
                try:
                    self._validate_zip(parsed, output, blob_len)
                except (UnsafeZipError, zipfile.BadZipFile, OSError):
                    continue
                if first_valid_zip is None:
                    first_valid_zip = parsed

        if first_valid_zip is not None:
            try:
                self._safe_extract_zip(first_valid_zip, output, blob_len)
            except (UnsafeZipError, zipfile.BadZipFile):
                return self._blind_raw_dump(container, password, output)
            return ExtractionResult(message=SUCCESS_MESSAGE, raw_dumped=False, output_dir=output)

        return self._blind_raw_dump(container, password, output)

    def slot_region_size(self, container_path: str | Path) -> int:
        container = Path(container_path)
        container_size = container.stat().st_size
        zip_offset = self.zip_suffix_offset(container)
        if zip_offset is None:
            return container_size
        return zip_offset

    def zip_suffix_offset(self, container_path: str | Path) -> int | None:
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
            offset = self._parse_zip_suffix_offset(container, file_size, tail, index)
            if offset is not None:
                return offset
            search_end = index

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(password.encode("utf-8"))

    def _write_random_region(self, handle: BinaryIO, size: int) -> None:
        remaining = size
        while remaining:
            chunk_size = min(RANDOM_WRITE_CHUNK, remaining)
            handle.write(os.urandom(chunk_size))
            remaining -= chunk_size

    def _parse_zip_suffix_offset(self, container: Path, file_size: int, tail: bytes, eocd_tail_index: int) -> int | None:
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
        if central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            return None
        central_start = eocd_abs - central_size
        if central_start < 0:
            return None
        if total_entries and not self._has_central_directory_signature(container, central_start):
            return None
        prefix_offset = self._prefix_offset_from_central_directory(container, central_start, central_size, central_offset, total_entries)
        if prefix_offset is None:
            return None
        try:
            with zipfile.ZipFile(container) as archive:
                archive.infolist()
        except zipfile.BadZipFile:
            return None
        return prefix_offset

    def _has_central_directory_signature(self, container: Path, offset: int) -> bool:
        try:
            with container.open("rb") as handle:
                handle.seek(offset)
                return handle.read(4) == ZIP_CENTRAL_DIRECTORY_SIGNATURE
        except OSError:
            return False

    def _prefix_offset_from_central_directory(
        self,
        container: Path,
        central_start: int,
        central_size: int,
        central_offset: int,
        total_entries: int,
    ) -> int | None:
        if total_entries == 0:
            prefix_offset = central_start - central_offset
            return prefix_offset if prefix_offset >= 0 else None

        entries = self._central_directory_local_offsets(container, central_start, central_size, total_entries)
        if not entries:
            return None

        relative_prefix = central_start - central_offset
        if relative_prefix >= 0 and (relative_prefix > 0 or entries[0] == 0) and self._has_local_file_signature(container, relative_prefix + entries[0]):
            return relative_prefix

        absolute_prefix = min(entries)
        if absolute_prefix >= 0 and self._has_local_file_signature(container, absolute_prefix):
            return absolute_prefix
        return None

    def _central_directory_local_offsets(self, container: Path, central_start: int, central_size: int, total_entries: int) -> list[int]:
        offsets: list[int] = []
        with container.open("rb") as handle:
            handle.seek(central_start)
            consumed = 0
            while consumed < central_size and len(offsets) < total_entries:
                fixed = handle.read(46)
                if len(fixed) != 46 or fixed[:4] != ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                    return []
                name_len, extra_len, comment_len = struct.unpack("<HHH", fixed[28:34])
                local_offset = struct.unpack("<L", fixed[42:46])[0]
                skip_len = name_len + extra_len + comment_len
                handle.seek(skip_len, io.SEEK_CUR)
                consumed += 46 + skip_len
                offsets.append(local_offset)
        return offsets

    def _has_local_file_signature(self, container: Path, offset: int) -> bool:
        if offset < 0:
            return False
        try:
            with container.open("rb") as handle:
                handle.seek(offset)
                return handle.read(4) == b"PK\x03\x04"
        except OSError:
            return False

    def _validate_slot_count(self, slot_count: int) -> None:
        if slot_count < 2:
            raise ValueError("slot_count must be at least 2")

    def _validate_slot_size(self, slot_size: int) -> None:
        if slot_size <= SLOT_META_LEN + TAG_LEN + PAYLOAD_HEADER_LEN:
            raise ValueError("Slot size is too small")

    def _get_slot_size(self, container_size: int, slot_count: int) -> int:
        self._validate_slot_count(slot_count)
        if container_size <= 0:
            raise ValueError("Container size must be greater than 0")
        if container_size % slot_count != 0:
            raise ValueError("Invalid container size for selected slot count")
        slot_size = container_size // slot_count
        self._validate_slot_size(slot_size)
        return slot_size

    def _get_slot_offset(self, slot_index: int, slot_size: int) -> int:
        return slot_index * slot_size

    def _slot_plaintext_len(self, slot_size: int) -> int:
        return slot_size - SALT_LEN - NONCE_LEN - TAG_LEN

    def _build_payload_blob(self, zip_bytes: bytes, blob_len: int) -> bytes:
        if PAYLOAD_HEADER_LEN + len(zip_bytes) > blob_len:
            raise ValueError("Payload too large for selected slot")
        zip_sha256 = hashlib.sha256(zip_bytes).digest()
        header = PAYLOAD_HEADER_STRUCT.pack(PAYLOAD_MAGIC, PAYLOAD_VERSION, PAYLOAD_HEADER_LEN, len(zip_bytes), zip_sha256)
        padding_len = blob_len - len(header) - len(zip_bytes)
        return header + zip_bytes + os.urandom(padding_len)

    def _parse_payload_blob(self, blob: bytes) -> bytes | None:
        if len(blob) < PAYLOAD_HEADER_LEN:
            return None
        try:
            magic, version, header_len, zip_len, expected_hash = PAYLOAD_HEADER_STRUCT.unpack(blob[:PAYLOAD_HEADER_LEN])
        except struct.error:
            return None
        if magic != PAYLOAD_MAGIC or version != PAYLOAD_VERSION or header_len != PAYLOAD_HEADER_LEN:
            return None
        if zip_len > len(blob) - PAYLOAD_HEADER_LEN:
            return None
        zip_bytes = blob[PAYLOAD_HEADER_LEN : PAYLOAD_HEADER_LEN + zip_len]
        if hashlib.sha256(zip_bytes).digest() != expected_hash:
            return None
        return zip_bytes

    def _zip_directory(self, source_dir: Path, compress: bool = True) -> bytes:
        buffer = io.BytesIO()
        compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
        with zipfile.ZipFile(buffer, "w", compression=compression, allowZip64=False) as archive:
            self._write_directory_entries(archive, source_dir)
        return buffer.getvalue()

    def _build_zip_wrapper(self, options: ZipWrapperOptions, prefix_len: int) -> bytes:
        buffer = io.BytesIO()
        written_names: set[str] = set()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
            if options.visible_source_dir is not None:
                self._write_directory_entries(archive, options.visible_source_dir, written_names)

        if options.encrypted_entry_source_dir is not None:
            if not options.encrypted_entry_password:
                raise ValueError("ZIP entry password is required")
            if options.encrypted_entry_mode == ZIP_ENTRY_MODE_ARCHIVE:
                entry_name = self._normalize_zip_entry_name(options.encrypted_entry_name)
                if entry_name in written_names:
                    raise ValueError("ZIP entry name duplicates a visible file")
                inner_zip = self._zip_directory(Path(options.encrypted_entry_source_dir), compress=True)
                self._append_encrypted_zip_entry(buffer, entry_name, inner_zip, options.encrypted_entry_password)
                written_names.add(entry_name)
            elif options.encrypted_entry_mode == ZIP_ENTRY_MODE_FILES:
                self._append_encrypted_directory_entries(
                    buffer,
                    options.encrypted_entry_source_dir,
                    options.encrypted_entry_password,
                    written_names,
                )
            else:
                raise ValueError("Unsupported ZIP entry mode")

        wrapper = buffer.getvalue()
        if written_names:
            return self._adjust_zip_offsets(wrapper, prefix_len)
        return wrapper

    def _append_encrypted_directory_entries(
        self,
        buffer: io.BytesIO,
        source_dir: str | Path,
        password: str,
        written_names: set[str],
    ) -> None:
        source_root = Path(source_dir).resolve()
        if not source_root.exists() or not source_root.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_root}")
        buffer.seek(0, io.SEEK_END)
        with pyzipper.AESZipFile(
            buffer,
            "a",
            compression=zipfile.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
            allowZip64=False,
        ) as archive:
            archive.setpassword(password.encode("utf-8"))
            for item in sorted(source_root.rglob("*")):
                if item.is_symlink():
                    raise ValueError(f"Source directory contains an unsupported symlink: {item}")
                if item.is_dir():
                    continue
                if not item.is_file():
                    raise ValueError(f"Source directory contains an unsupported file type: {item}")
                arcname = self._normalize_zip_entry_name(item.resolve().relative_to(source_root).as_posix())
                if arcname in written_names:
                    raise ValueError("ZIP entry name duplicates a visible file")
                archive.write(item, arcname)
                written_names.add(arcname)

    def _append_encrypted_zip_entry(self, buffer: io.BytesIO, name: str, data: bytes, password: str) -> None:
        buffer.seek(0, io.SEEK_END)
        with pyzipper.AESZipFile(
            buffer,
            "a",
            compression=zipfile.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
            allowZip64=False,
        ) as archive:
            archive.setpassword(password.encode("utf-8"))
            archive.writestr(name, data)

    def _adjust_zip_offsets(self, zip_bytes: bytes, prefix_len: int) -> bytes:
        if prefix_len <= 0:
            return zip_bytes
        data = bytearray(zip_bytes)
        eocd_offset = data.rfind(ZIP_EOCD_SIGNATURE)
        if eocd_offset < 0 or eocd_offset + ZIP_EOCD_LEN > len(data):
            raise ValueError("ZIP wrapper is missing an end record")
        total_entries = struct.unpack("<H", data[eocd_offset + 10 : eocd_offset + 12])[0]
        central_size = struct.unpack("<L", data[eocd_offset + 12 : eocd_offset + 16])[0]
        central_offset = struct.unpack("<L", data[eocd_offset + 16 : eocd_offset + 20])[0]
        if central_offset + central_size > len(data):
            raise ValueError("ZIP wrapper central directory is invalid")
        self._write_u32(data, eocd_offset + 16, central_offset + prefix_len)

        cursor = central_offset
        for _index in range(total_entries):
            if cursor + 46 > len(data) or bytes(data[cursor : cursor + 4]) != ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                raise ValueError("ZIP wrapper central directory is invalid")
            name_len, extra_len, comment_len = struct.unpack("<HHH", data[cursor + 28 : cursor + 34])
            local_offset = struct.unpack("<L", data[cursor + 42 : cursor + 46])[0]
            self._write_u32(data, cursor + 42, local_offset + prefix_len)
            cursor += 46 + name_len + extra_len + comment_len
        return bytes(data)

    def _write_u32(self, data: bytearray, offset: int, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("ZIP wrapper is too large for non-ZIP64 offsets")
        data[offset : offset + 4] = struct.pack("<L", value)

    def _write_directory_entries(
        self,
        archive: zipfile.ZipFile,
        source_dir: str | Path,
        written_names: set[str] | None = None,
    ) -> None:
        source_root = Path(source_dir).resolve()
        if not source_root.exists() or not source_root.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_root}")
        for item in sorted(source_root.rglob("*")):
            if item.is_symlink():
                raise ValueError(f"Source directory contains an unsupported symlink: {item}")
            if item.is_dir():
                continue
            if not item.is_file():
                raise ValueError(f"Source directory contains an unsupported file type: {item}")
            arcname = self._normalize_zip_entry_name(item.resolve().relative_to(source_root).as_posix())
            if written_names is not None:
                if arcname in written_names:
                    raise ValueError("ZIP entry name duplicates a visible file")
                written_names.add(arcname)
            archive.write(item, arcname)

    def _normalize_zip_entry_name(self, name: str) -> str:
        normalized = name.replace("\\", "/").strip("/")
        if not normalized or "\x00" in normalized or any(ord(char) < 32 for char in normalized):
            raise ValueError("Unsafe ZIP entry name")
        if normalized.startswith("../") or "/../" in normalized:
            raise ValueError("Unsafe ZIP entry path")
        if PureWindowsPath(normalized).drive or PureWindowsPath(normalized).is_absolute():
            raise ValueError("Unsafe ZIP entry path")
        path = PurePosixPath(normalized)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("Unsafe ZIP entry path")
        for part in path.parts:
            self._validate_filename_part(part)
        return path.as_posix()

    def _safe_extract_zip(self, zip_bytes: bytes, output_dir: Path, max_total_size: int) -> None:
        entries = self._validate_zip(zip_bytes, output_dir, max_total_size)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            for info, target in entries:
                if self._zip_info_is_dir(info):
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() and target.is_symlink():
                    raise UnsafeZipError("Unsafe existing output path")
                written = 0
                with archive.open(info, "r") as source, target.open("wb") as dest:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size or written > max_total_size:
                            raise UnsafeZipError("Zip entry expanded beyond declared limits")
                        dest.write(chunk)

    def _make_aad(self, slot_index: int, slot_size: int) -> bytes:
        return b"DeniableArchiverV2" + struct.pack(">I", slot_index) + struct.pack(">Q", slot_size)

    def _blind_raw_dump(self, container_path: Path, password: str, output_dir: Path) -> ExtractionResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        with container_path.open("rb") as handle:
            raw = handle.read(RAW_DUMP_SIZE)
        raw = raw.ljust(RAW_DUMP_SIZE, b"\x00")
        salt = raw[:SALT_LEN]
        key = self._derive_key(password, salt)
        transformed = self._xor_stream(raw, key)
        (output_dir / "decrypted_raw.bin").write_bytes(transformed)
        return ExtractionResult(message=RAW_DUMP_MESSAGE, raw_dumped=True, output_dir=output_dir)

    def _read_slot(self, handle: BinaryIO, slot_index: int, slot_size: int) -> bytes:
        handle.seek(self._get_slot_offset(slot_index, slot_size))
        slot_bytes = handle.read(slot_size)
        if len(slot_bytes) != slot_size:
            raise ValueError("Could not read full slot")
        return slot_bytes

    def _try_decrypt_slot(self, slot_bytes: bytes, password: str, slot_index: int, slot_size: int) -> bytes | None:
        if len(slot_bytes) != slot_size:
            return None
        salt = slot_bytes[:SALT_LEN]
        nonce = slot_bytes[SALT_LEN:SLOT_META_LEN]
        encrypted_blob = slot_bytes[SLOT_META_LEN:]
        key = self._derive_key(password, salt)
        aad = self._make_aad(slot_index, slot_size)
        try:
            blob = ChaCha20Poly1305(key).decrypt(nonce, encrypted_blob, aad)
        except InvalidTag:
            return None
        except Exception:
            return None
        return self._parse_payload_blob(blob)

    def _validate_zip(self, zip_bytes: bytes, output_dir: Path, max_total_size: int) -> list[tuple[zipfile.ZipInfo, Path]]:
        output_root = output_dir.resolve()
        total_size = 0
        file_count = 0
        seen_targets: set[Path] = set()
        entries: list[tuple[zipfile.ZipInfo, Path]] = []
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            for info in archive.infolist():
                target = self._validate_zip_entry(info, output_root)
                if target in seen_targets:
                    raise UnsafeZipError("Duplicate zip output path")
                seen_targets.add(target)
                if self._zip_info_is_dir(info):
                    entries.append((info, target))
                    continue
                file_count += 1
                if file_count > MAX_ZIP_FILES:
                    raise UnsafeZipError("Too many files in archive")
                if info.file_size > max_total_size:
                    raise UnsafeZipError("Zip entry is too large")
                total_size += info.file_size
                if total_size > max_total_size:
                    raise UnsafeZipError("Zip archive is too large")
                entries.append((info, target))
        return entries

    def _validate_zip_entry(self, info: zipfile.ZipInfo, output_root: Path) -> Path:
        raw_name = info.filename
        if not raw_name or "\x00" in raw_name or any(ord(char) < 32 for char in raw_name):
            raise UnsafeZipError("Unsafe zip entry name")
        if PureWindowsPath(raw_name).drive or PureWindowsPath(raw_name).is_absolute():
            raise UnsafeZipError("Unsafe zip entry path")

        normalized = raw_name.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            raise UnsafeZipError("Unsafe zip entry path")
        normalized = normalized.rstrip("/")
        if not normalized:
            raise UnsafeZipError("Unsafe zip entry name")

        path = PurePosixPath(normalized)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise UnsafeZipError("Unsafe zip entry path")
        for part in path.parts:
            self._validate_filename_part(part)

        mode = self._zip_mode(info)
        file_type = stat.S_IFMT(mode)
        if file_type in {stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK}:
            raise UnsafeZipError("Unsafe zip entry type")
        if file_type and file_type not in {stat.S_IFREG, stat.S_IFDIR}:
            raise UnsafeZipError("Unsafe zip entry type")

        target = (output_root / Path(*path.parts)).resolve(strict=False)
        if not target.is_relative_to(output_root):
            raise UnsafeZipError("Zip entry escapes output directory")
        return target

    def _zip_mode(self, info: zipfile.ZipInfo) -> int:
        return (info.external_attr >> 16) & 0xFFFF

    def _zip_info_is_dir(self, info: zipfile.ZipInfo) -> bool:
        return info.is_dir() or stat.S_IFMT(self._zip_mode(info)) == stat.S_IFDIR

    def _validate_filename_part(self, part: str) -> None:
        if part.rstrip(" .") != part:
            raise UnsafeZipError("Unsafe zip entry name")
        stem = part.split(".", 1)[0].upper()
        reserved_names = {"CON", "PRN", "AUX", "NUL", *(f"COM{index}" for index in range(1, 10)), *(f"LPT{index}" for index in range(1, 10))}
        if stem in reserved_names:
            raise UnsafeZipError("Unsafe zip entry name")

    def _xor_stream(self, data: bytes, key: bytes) -> bytes:
        output = bytearray(len(data))
        offset = 0
        counter = 0
        while offset < len(data):
            block = hashlib.sha256(key + struct.pack(">Q", counter)).digest()
            for index, value in enumerate(block):
                if offset + index >= len(data):
                    break
                output[offset + index] = data[offset + index] ^ value
            offset += len(block)
            counter += 1
        return bytes(output)
