from __future__ import annotations

import hashlib
import io
import os
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 3
FORMAT_MAGIC = b"DARC3PAY"
ARCHIVE_CODEC_TAR_ZSTD = 1

SALT_LEN = 16
NONCE_PREFIX_LEN = 8
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
LAYOUT_COMMITMENT_LEN = 32

CONTROL_PLAINTEXT_LEN = 128
CONTROL_CIPHERTEXT_LEN = CONTROL_PLAINTEXT_LEN + TAG_LEN
SLOT_PREFIX_LEN = SALT_LEN + NONCE_PREFIX_LEN + CONTROL_CIPHERTEXT_LEN
DATA_CHUNK_PLAINTEXT_LEN = 1024 * 1024

SCRYPT_N = 2**18
SCRYPT_R = 8
SCRYPT_P = 1

CONTROL_STRUCT = struct.Struct(">8sHHHIQQQ32s")
CONTROL_HEADER_LEN = CONTROL_STRUCT.size
AAD_PREFIX = b"DARCv3\x00"
LAYOUT_COMMITMENT_PREFIX = b"DARCv3-layout\x00"


class FormatError(ValueError):
    pass


class FormatCapacityError(FormatError):
    pass


class FormatAuthenticationError(FormatError):
    pass


@dataclass(frozen=True)
class ControlRecord:
    archive_length: int
    uncompressed_size: int
    entry_count: int
    archive_sha256: bytes
    chunk_count: int
    codec: int = ARCHIVE_CODEC_TAR_ZSTD


@dataclass(frozen=True)
class SlotCredentials:
    slot_index: int
    slot_size: int
    key: bytes
    nonce_prefix: bytes
    layout_commitment: bytes
    control: ControlRecord


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def record_plaintext_lengths(slot_size: int) -> tuple[int, ...]:
    remaining = slot_size - SLOT_PREFIX_LEN
    if remaining <= TAG_LEN:
        raise ValueError("Slot size is too small for the v3 format")

    record_cipher_capacity = DATA_CHUNK_PLAINTEXT_LEN + TAG_LEN
    record_count = (remaining + record_cipher_capacity - 1) // record_cipher_capacity
    total_plaintext = remaining - record_count * TAG_LEN
    if total_plaintext < record_count:
        raise ValueError("Slot size cannot be represented as authenticated records")

    lengths: list[int] = []
    plaintext_left = total_plaintext
    for index in range(record_count):
        records_left = record_count - index
        length = min(DATA_CHUNK_PLAINTEXT_LEN, plaintext_left - (records_left - 1))
        lengths.append(length)
        plaintext_left -= length
    if plaintext_left != 0 or sum(length + TAG_LEN for length in lengths) != remaining:
        raise AssertionError("Invalid v3 record plan")
    return tuple(lengths)


def archive_capacity_for_slot(slot_size: int) -> int:
    return sum(record_plaintext_lengths(slot_size))


def make_nonce(nonce_prefix: bytes, record_index: int) -> bytes:
    if len(nonce_prefix) != NONCE_PREFIX_LEN:
        raise ValueError("Invalid nonce prefix")
    if not 0 <= record_index <= 0xFFFFFFFF:
        raise ValueError("Record index is out of range")
    return nonce_prefix + struct.pack(">I", record_index)


def make_layout_commitment(layout: Sequence[int]) -> bytes:
    if not layout or len(layout) > 0xFFFFFFFF:
        raise ValueError("Invalid slot layout length")
    digest = hashlib.sha256()
    digest.update(LAYOUT_COMMITMENT_PREFIX)
    digest.update(struct.pack(">I", len(layout)))
    for slot_size in layout:
        if isinstance(slot_size, bool) or not isinstance(slot_size, int) or not 0 < slot_size <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Invalid slot size in layout")
        digest.update(struct.pack(">Q", slot_size))
    return digest.digest()


def make_aad(
    slot_index: int,
    slot_size: int,
    record_index: int,
    plaintext_length: int,
    layout_commitment: bytes,
) -> bytes:
    if not 0 <= slot_index <= 0xFFFFFFFF:
        raise ValueError("Slot index is out of range")
    if not 0 <= plaintext_length <= 0xFFFFFFFF:
        raise ValueError("Record length is out of range")
    if len(layout_commitment) != LAYOUT_COMMITMENT_LEN:
        raise ValueError("Invalid layout commitment")
    return AAD_PREFIX + layout_commitment + struct.pack(">IQII", slot_index, slot_size, record_index, plaintext_length)


def encode_control(control: ControlRecord) -> bytes:
    if len(control.archive_sha256) != 32:
        raise ValueError("Invalid archive digest")
    header = CONTROL_STRUCT.pack(
        FORMAT_MAGIC,
        FORMAT_VERSION,
        CONTROL_HEADER_LEN,
        control.codec,
        control.chunk_count,
        control.archive_length,
        control.uncompressed_size,
        control.entry_count,
        control.archive_sha256,
    )
    return header + os.urandom(CONTROL_PLAINTEXT_LEN - len(header))


def decode_control(data: bytes, slot_size: int) -> ControlRecord:
    if len(data) != CONTROL_PLAINTEXT_LEN:
        raise FormatError("Invalid control record length")
    try:
        magic, version, header_len, codec, chunk_count, archive_len, total_size, entry_count, digest = (
            CONTROL_STRUCT.unpack(data[:CONTROL_HEADER_LEN])
        )
    except struct.error as exc:
        raise FormatError("Invalid control record") from exc
    expected_chunks = len(record_plaintext_lengths(slot_size))
    if magic != FORMAT_MAGIC or version != FORMAT_VERSION or header_len != CONTROL_HEADER_LEN:
        raise FormatError("Unsupported payload format")
    if codec != ARCHIVE_CODEC_TAR_ZSTD:
        raise FormatError("Unsupported archive codec")
    if chunk_count != expected_chunks:
        raise FormatError("Invalid payload chunk count")
    if archive_len > archive_capacity_for_slot(slot_size):
        raise FormatError("Invalid archive length")
    return ControlRecord(
        archive_length=archive_len,
        uncompressed_size=total_size,
        entry_count=entry_count,
        archive_sha256=digest,
        chunk_count=chunk_count,
        codec=codec,
    )


class SlotEncryptingWriter:
    """File-like sink that encrypts compressed archive bytes into one fixed-size slot."""

    def __init__(
        self,
        handle: BinaryIO,
        *,
        slot_offset: int,
        slot_size: int,
        slot_index: int,
        layout_commitment: bytes,
        password: str,
        progress: Callable[[int, int], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        if not password:
            raise ValueError("Password must not be empty")
        self.handle = handle
        self.slot_offset = slot_offset
        self.slot_size = slot_size
        self.slot_index = slot_index
        if len(layout_commitment) != LAYOUT_COMMITMENT_LEN:
            raise ValueError("Invalid layout commitment")
        self.layout_commitment = bytes(layout_commitment)
        self.plaintext_lengths = record_plaintext_lengths(slot_size)
        self.capacity = sum(self.plaintext_lengths)
        self.progress = progress
        self.cancelled = cancelled

        self.salt = os.urandom(SALT_LEN)
        self.nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        self.key = derive_key(password, self.salt)
        self.cipher = ChaCha20Poly1305(self.key)
        self.handle.seek(slot_offset)
        self.handle.write(self.salt + self.nonce_prefix)

        self.record_index = 0
        self.record_offset = slot_offset + SLOT_PREFIX_LEN
        self.buffer = bytearray()
        self.archive_length = 0
        self.archive_hash = hashlib.sha256()
        self.finished = False

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.archive_length

    def flush(self) -> None:
        return None

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self.finished:
            raise ValueError("Slot writer is already finished")
        raw = bytes(data)
        if self.archive_length + len(raw) > self.capacity:
            raise FormatCapacityError("Payload too large for selected slot")
        self.archive_hash.update(raw)
        self.archive_length += len(raw)

        cursor = 0
        while cursor < len(raw):
            self._check_cancelled()
            expected = self.plaintext_lengths[self.record_index]
            amount = min(expected - len(self.buffer), len(raw) - cursor)
            self.buffer.extend(raw[cursor : cursor + amount])
            cursor += amount
            if len(self.buffer) == expected:
                self._write_current_record()
        return len(raw)

    def finish(self, *, uncompressed_size: int, entry_count: int) -> ControlRecord:
        if self.finished:
            raise ValueError("Slot writer is already finished")
        while self.record_index < len(self.plaintext_lengths):
            self._check_cancelled()
            expected = self.plaintext_lengths[self.record_index]
            missing = expected - len(self.buffer)
            while missing:
                amount = min(missing, DATA_CHUNK_PLAINTEXT_LEN)
                self.buffer.extend(os.urandom(amount))
                missing -= amount
            self._write_current_record()

        control = ControlRecord(
            archive_length=self.archive_length,
            uncompressed_size=uncompressed_size,
            entry_count=entry_count,
            archive_sha256=self.archive_hash.digest(),
            chunk_count=len(self.plaintext_lengths),
        )
        plaintext = encode_control(control)
        ciphertext = self.cipher.encrypt(
            make_nonce(self.nonce_prefix, 0),
            plaintext,
            make_aad(
                self.slot_index,
                self.slot_size,
                0,
                CONTROL_PLAINTEXT_LEN,
                self.layout_commitment,
            ),
        )
        self.handle.seek(self.slot_offset + SALT_LEN + NONCE_PREFIX_LEN)
        self.handle.write(ciphertext)
        self.finished = True
        return control

    def _write_current_record(self) -> None:
        expected = self.plaintext_lengths[self.record_index]
        if len(self.buffer) != expected:
            raise AssertionError("Attempted to write an incomplete v3 record")
        external_index = self.record_index + 1
        ciphertext = self.cipher.encrypt(
            make_nonce(self.nonce_prefix, external_index),
            bytes(self.buffer),
            make_aad(
                self.slot_index,
                self.slot_size,
                external_index,
                expected,
                self.layout_commitment,
            ),
        )
        self.handle.seek(self.record_offset)
        self.handle.write(ciphertext)
        self.record_offset += len(ciphertext)
        self.record_index += 1
        self.buffer.clear()
        if self.progress is not None:
            self.progress(self.record_index, len(self.plaintext_lengths))

    def _check_cancelled(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("Operation cancelled")


def try_read_control(
    handle: BinaryIO,
    *,
    slot_offset: int,
    slot_size: int,
    slot_index: int,
    layout_commitment: bytes,
    password: str,
) -> SlotCredentials | None:
    if not password:
        raise ValueError("Password must not be empty")
    handle.seek(slot_offset)
    prefix = handle.read(SALT_LEN + NONCE_PREFIX_LEN)
    encrypted_control = handle.read(CONTROL_CIPHERTEXT_LEN)
    if len(prefix) != SALT_LEN + NONCE_PREFIX_LEN or len(encrypted_control) != CONTROL_CIPHERTEXT_LEN:
        raise ValueError("Could not read full slot control record")
    salt = prefix[:SALT_LEN]
    nonce_prefix = prefix[SALT_LEN:]
    key = derive_key(password, salt)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            make_nonce(nonce_prefix, 0),
            encrypted_control,
            make_aad(
                slot_index,
                slot_size,
                0,
                CONTROL_PLAINTEXT_LEN,
                layout_commitment,
            ),
        )
        control = decode_control(plaintext, slot_size)
    except (InvalidTag, FormatError, ValueError, struct.error):
        return None
    return SlotCredentials(
        slot_index=slot_index,
        slot_size=slot_size,
        key=key,
        nonce_prefix=nonce_prefix,
        layout_commitment=bytes(layout_commitment),
        control=control,
    )


class SlotArchiveReader(io.RawIOBase):
    """Sequential reader for the authenticated archive portion of a v3 slot."""

    def __init__(
        self,
        handle: BinaryIO,
        *,
        slot_offset: int,
        credentials: SlotCredentials,
        progress: Callable[[int, int], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__()
        self.handle = handle
        self.slot_offset = slot_offset
        self.credentials = credentials
        self.progress = progress
        self.cancelled = cancelled
        self.plaintext_lengths = record_plaintext_lengths(credentials.slot_size)
        self.record_offsets: list[int] = []
        cursor = slot_offset + SLOT_PREFIX_LEN
        for length in self.plaintext_lengths:
            self.record_offsets.append(cursor)
            cursor += length + TAG_LEN

        self.cipher = ChaCha20Poly1305(credentials.key)
        self.record_index = 0
        self.archive_left = credentials.control.archive_length
        self.current = memoryview(b"")
        self.digest = hashlib.sha256()
        self.verified_padding = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if self.archive_left == 0:
            return 0
        target = memoryview(buffer).cast("B")
        written = 0
        while written < len(target) and self.archive_left:
            self._check_cancelled()
            if not self.current:
                self.current = memoryview(self._decrypt_next_record())
            amount = min(len(target) - written, len(self.current), self.archive_left)
            chunk = self.current[:amount]
            target[written : written + amount] = chunk
            self.digest.update(chunk)
            self.current = self.current[amount:]
            self.archive_left -= amount
            written += amount
        return written

    def verify_complete(self) -> None:
        scratch = bytearray(DATA_CHUNK_PLAINTEXT_LEN)
        while self.archive_left:
            self.readinto(scratch)
        while self.record_index < len(self.plaintext_lengths):
            self._check_cancelled()
            self._decrypt_next_record()
        if self.digest.digest() != self.credentials.control.archive_sha256:
            raise FormatAuthenticationError("Archive digest mismatch")
        self.verified_padding = True

    def _decrypt_next_record(self) -> bytes:
        if self.record_index >= len(self.plaintext_lengths):
            raise FormatAuthenticationError("Encrypted archive ended early")
        expected = self.plaintext_lengths[self.record_index]
        offset = self.record_offsets[self.record_index]
        self.handle.seek(offset)
        ciphertext = self.handle.read(expected + TAG_LEN)
        if len(ciphertext) != expected + TAG_LEN:
            raise FormatAuthenticationError("Encrypted archive ended early")
        external_index = self.record_index + 1
        try:
            plaintext = self.cipher.decrypt(
                make_nonce(self.credentials.nonce_prefix, external_index),
                ciphertext,
                make_aad(
                    self.credentials.slot_index,
                    self.credentials.slot_size,
                    external_index,
                    expected,
                    self.credentials.layout_commitment,
                ),
            )
        except InvalidTag as exc:
            raise FormatAuthenticationError("Encrypted archive record is invalid") from exc
        self.record_index += 1
        if self.progress is not None:
            self.progress(self.record_index, len(self.plaintext_lengths))
        return plaintext

    def _check_cancelled(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("Operation cancelled")
