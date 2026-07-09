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

SUCCESS_MESSAGE = "Extraction complete."
RAW_DUMP_MESSAGE = "Extraction complete. File system signatures not recognized; output dumped as raw binary."


class UnsafeZipError(ValueError):
    """Raised internally when an archive entry is unsafe to extract."""


@dataclass(frozen=True)
class ExtractionResult:
    message: str
    raw_dumped: bool
    output_dir: Path


class DeniableArchiver:
    def initialize_container(self, container_path: str | Path, size_mb: int = DEFAULT_CONTAINER_SIZE_MB, slot_count: int = DEFAULT_SLOT_COUNT) -> None:
        if size_mb <= 0:
            raise ValueError("size_mb must be greater than 0")
        self._validate_slot_count(slot_count)

        container_size = int(size_mb) * 1024 * 1024
        if container_size % slot_count != 0:
            raise ValueError("Container size must be divisible by slot count")
        self._validate_slot_size(container_size // slot_count)

        remaining = container_size
        path = Path(container_path)
        with path.open("wb") as handle:
            while remaining:
                chunk_size = min(RANDOM_WRITE_CHUNK, remaining)
                handle.write(os.urandom(chunk_size))
                remaining -= chunk_size

    def write_payload(
        self,
        container_path: str | Path,
        source_dir: str | Path,
        password: str,
        slot_index: int,
        slot_count: int = DEFAULT_SLOT_COUNT,
    ) -> None:
        container = Path(container_path)
        source = Path(source_dir)
        if not container.exists():
            raise FileNotFoundError(f"Container file does not exist: {container}")
        if not source.exists() or not source.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source}")

        container_size = container.stat().st_size
        slot_size = self._get_slot_size(container_size, slot_count)
        if not 0 <= slot_index < slot_count:
            raise ValueError("slot_index out of range")

        zip_bytes = self._zip_directory(source)
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
        container_size = container.stat().st_size
        slot_size = self._get_slot_size(container_size, slot_count)
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

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(password.encode("utf-8"))

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

    def _zip_directory(self, source_dir: Path) -> bytes:
        source_root = source_dir.resolve()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in sorted(source_root.rglob("*")):
                if item.is_symlink():
                    raise ValueError(f"Source directory contains an unsupported symlink: {item}")
                if item.is_dir():
                    continue
                if not item.is_file():
                    raise ValueError(f"Source directory contains an unsupported file type: {item}")
                arcname = item.resolve().relative_to(source_root).as_posix()
                archive.write(item, arcname)
        return buffer.getvalue()

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
