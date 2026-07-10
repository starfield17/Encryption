from __future__ import annotations

import io
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

import zstandard

from core.archive_stream import (
    MAX_ARCHIVE_ENTRIES,
    ArchiveStats,
    UnsafeArchiveError,
    estimate_tar_zstd_size,
    safe_extract_tar_zstd,
    scan_source_directory,
    write_tar_zstd,
)
from core.format_v3 import (
    DATA_CHUNK_PLAINTEXT_LEN,
    FORMAT_VERSION,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    FormatAuthenticationError,
    FormatCapacityError,
    SlotArchiveReader,
    SlotEncryptingWriter,
    archive_capacity_for_slot,
    derive_key,
    make_layout_commitment,
    try_read_control,
)
from core.layout import DEFAULT_SLOT_COUNT, MAX_SLOT_COUNT, MIB, normalize_layout, resolve_layout, slot_offset
from core.storage import (
    atomic_copy_for_update,
    atomic_new_file,
    container_lock,
    paths_overlap,
    publish_directory,
    temporary_output_directory,
    validate_destination_outside_sources,
    validate_disjoint_sources,
)
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

DEFAULT_CONTAINER_SIZE_MB = 100
MAX_CONTAINER_SIZE_MB = 16 * 1024
RANDOM_WRITE_CHUNK = 1024 * 1024

KDF_NAME = "scrypt"
PAYLOAD_VERSION = FORMAT_VERSION

SUCCESS_MESSAGE = "Extraction complete."
NO_MATCH_MESSAGE = "No extractable payload was found."
# Kept as an import compatibility alias. v3 no longer writes an unauthenticated raw artifact.
RAW_DUMP_MESSAGE = NO_MATCH_MESSAGE
RAW_DUMP_SIZE = 0


class ExtractionStatus(StrEnum):
    EXTRACTED = "extracted"
    NO_MATCH = "no_match"
    CANCELLED = "cancelled"


class ConflictPolicy(StrEnum):
    FAIL = "fail"
    REPLACE = "replace"


class OperationStage(StrEnum):
    INITIALIZING = "initializing"
    SCANNING = "scanning"
    ARCHIVING = "archiving"
    ENCRYPTING = "encrypting"
    EXTRACTING = "extracting"
    COMMITTING = "committing"


class OperationCancelled(RuntimeError):
    pass


@dataclass(frozen=True)
class OperationProgress:
    stage: OperationStage
    current: int
    total: int


ProgressCallback = Callable[[OperationProgress], None]
CancelCallback = Callable[[], bool]


@dataclass(frozen=True)
class ExtractionResult:
    message: str
    status: ExtractionStatus
    output_dir: Path | None

    @property
    def raw_dumped(self) -> bool:
        """Compatibility shim for callers that used the v2 fallback flag."""
        return self.status is ExtractionStatus.NO_MATCH


@dataclass(frozen=True)
class PayloadSpec:
    slot_index: int
    source_dir: Path
    password: str
    compress: bool = True


@dataclass(frozen=True)
class ContainerSpec:
    layout: tuple[int, ...]
    zip_wrapper: ZipWrapperOptions | None = None

    def __post_init__(self) -> None:
        normalize_layout(self.layout)

    @property
    def size_bytes(self) -> int:
        return sum(self.layout)


class DeniableArchiver:
    def initialize_container(
        self,
        container_path: str | Path,
        size_mb: int = DEFAULT_CONTAINER_SIZE_MB,
        slot_count: int | None = None,
        zip_wrapper: ZipWrapperOptions | None = None,
        layout: Sequence[int] | None = None,
        *,
        replace_existing: bool = False,
        progress: ProgressCallback | None = None,
        cancelled: CancelCallback | None = None,
    ) -> None:
        slot_region_size = self._validated_region_size(size_mb)
        resolve_layout(
            slot_region_size,
            layout=layout,
            slot_count=DEFAULT_SLOT_COUNT if layout is None and slot_count is None else slot_count,
        )
        wrapper = zip_wrapper if zip_wrapper is not None and zip_wrapper.enabled else None
        self._validate_new_destination(Path(container_path), replace_existing)
        self._validate_create_paths(Path(container_path), (), wrapper)
        if wrapper is not None:
            validate_wrapper_options(wrapper, prefix_len=slot_region_size)

        with container_lock(container_path):
            self._validate_new_destination(Path(container_path), replace_existing)
            with atomic_new_file(container_path, replace_existing=replace_existing) as temp_path:
                self._initialize_file(temp_path, slot_region_size, wrapper, progress, cancelled)

    def create_container(
        self,
        container_path: str | Path,
        spec: ContainerSpec,
        payloads: Sequence[PayloadSpec],
        *,
        replace_existing: bool = False,
        progress: ProgressCallback | None = None,
        cancelled: CancelCallback | None = None,
    ) -> None:
        layout = normalize_layout(spec.layout)
        if sum(layout) > MAX_CONTAINER_SIZE_MB * MIB:
            raise ValueError(f"Container size must not exceed {MAX_CONTAINER_SIZE_MB} MiB")
        wrapper = spec.zip_wrapper if spec.zip_wrapper is not None and spec.zip_wrapper.enabled else None
        materialized = tuple(payloads)
        self._validate_new_destination(Path(container_path), replace_existing)
        self._validate_payload_specs(layout, materialized)
        self._validate_create_paths(Path(container_path), materialized, wrapper)
        if wrapper is not None:
            validate_wrapper_options(wrapper, prefix_len=sum(layout))

        with container_lock(container_path):
            self._validate_new_destination(Path(container_path), replace_existing)
            with atomic_new_file(container_path, replace_existing=replace_existing) as temp_path:
                self._initialize_file(temp_path, sum(layout), wrapper, progress, cancelled)
                with temp_path.open("r+b") as handle:
                    for payload_index, payload in enumerate(materialized):
                        self._check_cancelled(cancelled)
                        self._emit(progress, OperationStage.ARCHIVING, payload_index, len(materialized))
                        self._write_payload_to_handle(
                            handle,
                            layout,
                            payload,
                            progress=progress,
                            cancelled=cancelled,
                        )
                    handle.flush()
                self._emit(progress, OperationStage.COMMITTING, 1, 1)

    def write_payload(
        self,
        container_path: str | Path,
        source_dir: str | Path,
        password: str,
        slot_index: int,
        slot_count: int | None = None,
        compress: bool = True,
        layout: Sequence[int] | None = None,
        *,
        progress: ProgressCallback | None = None,
        cancelled: CancelCallback | None = None,
    ) -> None:
        del compress  # v3 always uses streaming zstd compression.
        if not password:
            raise ValueError("Password must not be empty")
        container = Path(container_path)
        source = Path(source_dir)
        if not container.exists() or not container.is_file() or container.is_symlink():
            raise FileNotFoundError(f"Container file does not exist or is unsafe: {container}")
        if not source.exists() or not source.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source}")
        validate_destination_outside_sources(container, (source,))
        self.slot_region_size(container)

        with container_lock(container):
            self.slot_region_size(container)
            with atomic_copy_for_update(container) as temp_path:
                region_size = self.slot_region_size(temp_path)
                resolved = resolve_layout(
                    region_size,
                    layout=layout,
                    slot_count=DEFAULT_SLOT_COUNT if layout is None and slot_count is None else slot_count,
                )
                if not 0 <= slot_index < len(resolved):
                    raise ValueError("slot_index out of range")
                with temp_path.open("r+b") as handle:
                    self._write_payload_to_handle(
                        handle,
                        resolved,
                        PayloadSpec(slot_index=slot_index, source_dir=source, password=password),
                        progress=progress,
                        cancelled=cancelled,
                    )
                    handle.flush()
                self._emit(progress, OperationStage.COMMITTING, 1, 1)

    def update_slot(
        self,
        container_path: str | Path,
        layout: Sequence[int],
        slot_index: int,
        source_dir: str | Path,
        password: str,
        *,
        progress: ProgressCallback | None = None,
        cancelled: CancelCallback | None = None,
    ) -> None:
        self.write_payload(
            container_path,
            source_dir,
            password,
            slot_index,
            layout=layout,
            progress=progress,
            cancelled=cancelled,
        )

    def extract_payload(
        self,
        container_path: str | Path,
        password: str,
        output_dir: str | Path,
        slot_count: int | None = None,
        layout: Sequence[int] | None = None,
        *,
        conflict_policy: ConflictPolicy = ConflictPolicy.FAIL,
        progress: ProgressCallback | None = None,
        cancelled: CancelCallback | None = None,
    ) -> ExtractionResult:
        if not password:
            raise ValueError("Password must not be empty")
        container = Path(container_path)
        output = Path(output_dir)
        if not container.exists() or not container.is_file() or container.is_symlink():
            raise FileNotFoundError(f"Container file does not exist or is unsafe: {container}")
        if paths_overlap(container, output):
            raise ValueError("Output directory must not contain or replace the input container")
        if output.exists() and (output.is_symlink() or not output.is_dir()):
            raise FileExistsError(f"Output path is not a safe directory: {output}")
        if output.exists() and conflict_policy is ConflictPolicy.FAIL and any(output.iterdir()):
            raise FileExistsError(f"Output directory is not empty: {output}")

        region_size = self.slot_region_size(container)
        resolved = resolve_layout(
            region_size,
            layout=layout,
            slot_count=DEFAULT_SLOT_COUNT if layout is None and slot_count is None else slot_count,
        )
        layout_auth = make_layout_commitment(resolved)
        match = None
        try:
            with container.open("rb") as handle:
                for index, size in enumerate(resolved):
                    self._check_cancelled(cancelled)
                    self._emit(progress, OperationStage.SCANNING, index, len(resolved))
                    credentials = try_read_control(
                        handle,
                        slot_offset=slot_offset(resolved, index),
                        slot_size=size,
                        slot_index=index,
                        layout_commitment=layout_auth,
                        password=password,
                    )
                    if credentials is None:
                        continue
                    if (
                        credentials.control.entry_count > MAX_ARCHIVE_ENTRIES
                        or credentials.control.archive_length > archive_capacity_for_slot(size)
                    ):
                        continue
                    if match is None:
                        match = credentials
                self._emit(progress, OperationStage.SCANNING, len(resolved), len(resolved))
        except InterruptedError as exc:
            raise OperationCancelled("Operation cancelled") from exc

        if match is None:
            return ExtractionResult(NO_MATCH_MESSAGE, ExtractionStatus.NO_MATCH, None)

        try:
            with temporary_output_directory(output) as temp_output, container.open("rb") as handle:
                reader = SlotArchiveReader(
                    handle,
                    slot_offset=slot_offset(resolved, match.slot_index),
                    credentials=match,
                    progress=lambda current, total: self._emit(progress, OperationStage.EXTRACTING, current, total),
                    cancelled=cancelled,
                )
                buffered = io.BufferedReader(reader, buffer_size=DATA_CHUNK_PLAINTEXT_LEN)
                safe_extract_tar_zstd(
                    buffered,
                    temp_output,
                    expected_size=match.control.uncompressed_size,
                    expected_entries=match.control.entry_count,
                    cancelled=cancelled,
                )
                reader.verify_complete()
                self._emit(progress, OperationStage.COMMITTING, 0, 1)
                published = publish_directory(
                    temp_output,
                    output,
                    replace=conflict_policy is ConflictPolicy.REPLACE,
                )
                self._emit(progress, OperationStage.COMMITTING, 1, 1)
        except InterruptedError as exc:
            raise OperationCancelled("Operation cancelled") from exc
        except (FormatAuthenticationError, UnsafeArchiveError, zstandard.ZstdError):
            return ExtractionResult(NO_MATCH_MESSAGE, ExtractionStatus.NO_MATCH, None)
        return ExtractionResult(SUCCESS_MESSAGE, ExtractionStatus.EXTRACTED, published)

    def estimate_payload(
        self,
        source_dir: str | Path,
        *,
        cancelled: CancelCallback | None = None,
    ) -> ArchiveStats:
        try:
            return estimate_tar_zstd_size(source_dir, cancelled=cancelled)
        except InterruptedError as exc:
            raise OperationCancelled("Operation cancelled") from exc

    def estimate_zip_size(self, source_dir: str | Path, compress: bool = True) -> int:
        del compress
        return self.estimate_payload(source_dir).compressed_size

    def slot_region_size(self, container_path: str | Path) -> int:
        container = Path(container_path)
        maximum = MAX_CONTAINER_SIZE_MB * MIB
        if container.stat().st_size > maximum:
            raise ValueError(f"Container file must not exceed {MAX_CONTAINER_SIZE_MB} MiB")
        region_size = detect_slot_region_size(container)
        if region_size <= 0:
            raise ValueError("Container slot region must be greater than 0 bytes")
        if region_size > maximum:
            raise ValueError(f"Container slot region must not exceed {MAX_CONTAINER_SIZE_MB} MiB")
        return region_size

    def zip_suffix_offset(self, container_path: str | Path) -> int | None:
        return detect_zip_prefix_offset(Path(container_path))

    def _initialize_file(
        self,
        path: Path,
        region_size: int,
        wrapper: ZipWrapperOptions | None,
        progress: ProgressCallback | None,
        cancelled: CancelCallback | None,
    ) -> None:
        with path.open("wb") as handle:
            self._write_random_region(handle, region_size, progress, cancelled)
            if wrapper is not None:
                self._check_cancelled(cancelled)
                handle.write(build_prefixed_zip_suffix(wrapper, region_size))
            handle.flush()

    def _write_payload_to_handle(
        self,
        handle: BinaryIO,
        layout: Sequence[int],
        payload: PayloadSpec,
        *,
        progress: ProgressCallback | None,
        cancelled: CancelCallback | None,
    ) -> None:
        entries = scan_source_directory(payload.source_dir)
        writer = SlotEncryptingWriter(
            handle,
            slot_offset=slot_offset(layout, payload.slot_index),
            slot_size=layout[payload.slot_index],
            slot_index=payload.slot_index,
            layout_commitment=make_layout_commitment(layout),
            password=payload.password,
            progress=lambda current, total: self._emit(progress, OperationStage.ENCRYPTING, current, total),
            cancelled=cancelled,
        )
        try:
            stats = write_tar_zstd(entries, writer, cancelled=cancelled)
            writer.finish(uncompressed_size=stats.uncompressed_size, entry_count=stats.entry_count)
        except InterruptedError as exc:
            raise OperationCancelled("Operation cancelled") from exc

    def _validated_region_size(self, size_mb: int) -> int:
        if size_mb <= 0:
            raise ValueError("size_mb must be greater than 0")
        if size_mb > MAX_CONTAINER_SIZE_MB:
            raise ValueError(f"size_mb must not exceed {MAX_CONTAINER_SIZE_MB}")
        return int(size_mb) * MIB

    def _validate_payload_specs(self, layout: Sequence[int], payloads: Sequence[PayloadSpec]) -> None:
        slots: set[int] = set()
        passwords: set[str] = set()
        sources: list[Path] = []
        for payload in payloads:
            if not 0 <= payload.slot_index < len(layout):
                raise ValueError("slot_index out of range")
            if payload.slot_index in slots:
                raise ValueError("Payload slots must be unique")
            if not payload.password:
                raise ValueError("Password must not be empty")
            if payload.password in passwords:
                raise ValueError("Payload passwords must be unique")
            if not payload.source_dir.exists() or not payload.source_dir.is_dir():
                raise FileNotFoundError(f"Source directory does not exist: {payload.source_dir}")
            for other in sources:
                if paths_overlap(other, payload.source_dir):
                    raise ValueError("Payload source directories must not overlap")
            slots.add(payload.slot_index)
            passwords.add(payload.password)
            sources.append(payload.source_dir)

    def _validate_new_destination(self, container: Path, replace_existing: bool) -> None:
        if container.is_symlink():
            raise ValueError("Container destination must not be a symbolic link")
        if not container.exists():
            return
        if not container.is_file():
            raise FileExistsError("Container destination exists and is not a regular file")
        if not replace_existing:
            raise FileExistsError("Container destination already exists")

    def _validate_create_paths(
        self,
        container: Path,
        payloads: Sequence[PayloadSpec],
        wrapper: ZipWrapperOptions | None,
    ) -> None:
        payload_sources = [payload.source_dir for payload in payloads]
        visible_sources: list[Path] = []
        encrypted_wrapper_sources: list[Path] = []
        if wrapper is not None:
            if wrapper.visible_source_dir is not None:
                visible_sources.append(Path(wrapper.visible_source_dir))
            if wrapper.encrypted_entry_source_dir is not None:
                encrypted_wrapper_sources.append(Path(wrapper.encrypted_entry_source_dir))
        all_sources = [*payload_sources, *visible_sources, *encrypted_wrapper_sources]
        validate_destination_outside_sources(container, all_sources)
        validate_disjoint_sources(visible_sources, [*payload_sources, *encrypted_wrapper_sources])
        validate_disjoint_sources(encrypted_wrapper_sources, payload_sources)

    def _write_random_region(
        self,
        handle: BinaryIO,
        size: int,
        progress: ProgressCallback | None,
        cancelled: CancelCallback | None,
    ) -> None:
        written = 0
        while written < size:
            self._check_cancelled(cancelled)
            amount = min(RANDOM_WRITE_CHUNK, size - written)
            handle.write(os.urandom(amount))
            written += amount
            self._emit(progress, OperationStage.INITIALIZING, written, size)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        return derive_key(password, salt)

    def _emit(
        self,
        callback: ProgressCallback | None,
        stage: OperationStage,
        current: int,
        total: int,
    ) -> None:
        if callback is not None:
            callback(OperationProgress(stage=stage, current=current, total=total))

    def _check_cancelled(self, cancelled: CancelCallback | None) -> None:
        if cancelled is not None and cancelled():
            raise OperationCancelled("Operation cancelled")


__all__ = [
    "ConflictPolicy",
    "ContainerSpec",
    "DEFAULT_CONTAINER_SIZE_MB",
    "DEFAULT_SLOT_COUNT",
    "DEFAULT_WRAPPER_ENTRY_NAME",
    "DeniableArchiver",
    "ExtractionResult",
    "ExtractionStatus",
    "FormatCapacityError",
    "KDF_NAME",
    "MAX_CONTAINER_SIZE_MB",
    "MAX_SLOT_COUNT",
    "NO_MATCH_MESSAGE",
    "OperationCancelled",
    "OperationProgress",
    "OperationStage",
    "PAYLOAD_VERSION",
    "PayloadSpec",
    "RAW_DUMP_MESSAGE",
    "RAW_DUMP_SIZE",
    "SCRYPT_N",
    "SCRYPT_P",
    "SCRYPT_R",
    "SUCCESS_MESSAGE",
    "UnsafeArchiveError",
    "ZIP_ENTRY_MODE_ARCHIVE",
    "ZIP_ENTRY_MODE_FILES",
    "ZipWrapperOptions",
]
