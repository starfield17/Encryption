from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from core.archiver import (
    ConflictPolicy,
    ContainerSpec,
    DeniableArchiver,
    ExtractionResult,
    ExtractionStatus,
    OperationCancelled,
    OperationProgress,
    PayloadSpec,
    ZipWrapperOptions,
)
from core.layout import MIB, equal_layout

CANCELLED_MESSAGE = "Operation cancelled."


@dataclass(frozen=True)
class PayloadInput:
    slot_index: int
    source_dir: Path
    password: str
    compress: bool = True


@dataclass(frozen=True)
class PayloadEstimate:
    row_index: int
    source_dir: Path
    zip_size: int | None
    uncompressed_size: int | None = None
    error: str | None = None


class _OperationThread(QThread):
    progress = Signal(object)
    cancelled = Signal(str)

    def cancel(self) -> None:
        self.requestInterruption()

    def _emit_progress(self, progress: OperationProgress) -> None:
        self.progress.emit(progress)

    def _is_cancelled(self) -> bool:
        return self.isInterruptionRequested()


class AnalyzePayloadsWorker(_OperationThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, payload_sources: list[tuple[int, Path]], compress: bool = True) -> None:
        super().__init__()
        self.payload_sources = payload_sources
        self.compress = compress

    def run(self) -> None:
        try:
            archiver = DeniableArchiver()
            estimates: list[PayloadEstimate] = []
            for row_index, source_dir in self.payload_sources:
                if self._is_cancelled():
                    raise OperationCancelled(CANCELLED_MESSAGE)
                try:
                    stats = archiver.estimate_payload(source_dir, cancelled=self._is_cancelled)
                    estimates.append(
                        PayloadEstimate(
                            row_index=row_index,
                            source_dir=source_dir,
                            zip_size=stats.compressed_size,
                            uncompressed_size=stats.uncompressed_size,
                        )
                    )
                except OperationCancelled:
                    raise
                except Exception as exc:
                    estimates.append(
                        PayloadEstimate(
                            row_index=row_index,
                            source_dir=source_dir,
                            zip_size=None,
                            error=str(exc),
                        )
                    )
            self.completed.emit(estimates)
        except OperationCancelled:
            self.cancelled.emit(CANCELLED_MESSAGE)
        except Exception as exc:
            self.failed.emit(str(exc))


class CreateContainerWorker(_OperationThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        size_mb: int,
        slot_count: int | None,
        payloads: list[PayloadInput],
        zip_wrapper: ZipWrapperOptions | None,
        success_message: str,
        layout: Sequence[int] | None = None,
        replace_existing: bool = False,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.size_mb = size_mb
        self.slot_count = slot_count if layout is None else None
        self.layout = tuple(layout) if layout is not None else None
        self.payloads = payloads
        self.zip_wrapper = zip_wrapper
        self.success_message = success_message
        self.replace_existing = replace_existing

    def run(self) -> None:
        try:
            layout = (
                self.layout
                if self.layout is not None
                else equal_layout(self.size_mb * MIB, self.slot_count if self.slot_count is not None else 4)
            )
            payloads = [
                PayloadSpec(
                    slot_index=payload.slot_index,
                    source_dir=payload.source_dir,
                    password=payload.password,
                    compress=payload.compress,
                )
                for payload in self.payloads
            ]
            DeniableArchiver().create_container(
                self.container_path,
                ContainerSpec(layout=tuple(layout), zip_wrapper=self.zip_wrapper),
                payloads,
                replace_existing=self.replace_existing,
                progress=self._emit_progress,
                cancelled=self._is_cancelled,
            )
            self.completed.emit(self.success_message)
        except OperationCancelled:
            self.cancelled.emit(CANCELLED_MESSAGE)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.payloads = []
            self.zip_wrapper = None


class WriteWorker(_OperationThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        source_dir: Path,
        password: str,
        slot_index: int,
        slot_count: int | None,
        compress: bool,
        success_message: str,
        layout: Sequence[int] | None = None,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.source_dir = source_dir
        self.password = password
        self.slot_index = slot_index
        self.slot_count = slot_count if layout is None else None
        self.layout = tuple(layout) if layout is not None else None
        self.compress = compress
        self.success_message = success_message

    def run(self) -> None:
        try:
            DeniableArchiver().write_payload(
                self.container_path,
                self.source_dir,
                self.password,
                self.slot_index,
                slot_count=self.slot_count,
                layout=self.layout,
                compress=self.compress,
                progress=self._emit_progress,
                cancelled=self._is_cancelled,
            )
            self.completed.emit(self.success_message)
        except OperationCancelled:
            self.cancelled.emit(CANCELLED_MESSAGE)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.password = ""


class ExtractWorker(_OperationThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        password: str,
        output_dir: Path,
        slot_count: int | None = None,
        try_common_slot_counts: bool = False,
        layout: Sequence[int] | None = None,
        conflict_policy: ConflictPolicy = ConflictPolicy.FAIL,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.password = password
        self.output_dir = output_dir
        self.slot_count = slot_count if layout is None else None
        self.layout = tuple(layout) if layout is not None else None
        self.try_common_slot_counts = try_common_slot_counts
        self.conflict_policy = conflict_policy

    def run(self) -> None:
        try:
            if self.try_common_slot_counts and self.layout is None:
                result = self._extract_with_common_slot_counts()
            else:
                result = DeniableArchiver().extract_payload(
                    self.container_path,
                    self.password,
                    self.output_dir,
                    slot_count=self.slot_count,
                    layout=self.layout,
                    conflict_policy=self.conflict_policy,
                    progress=self._emit_progress,
                    cancelled=self._is_cancelled,
                )
            self.completed.emit(result.message)
        except OperationCancelled:
            self.cancelled.emit(CANCELLED_MESSAGE)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.password = ""

    def _extract_with_common_slot_counts(self) -> ExtractionResult:
        archiver = DeniableArchiver()
        for slot_count in self._candidate_slot_counts():
            if self._is_cancelled():
                raise OperationCancelled(CANCELLED_MESSAGE)
            try:
                result = archiver.extract_payload(
                    self.container_path,
                    self.password,
                    self.output_dir,
                    slot_count=slot_count,
                    conflict_policy=self.conflict_policy,
                    progress=self._emit_progress,
                    cancelled=self._is_cancelled,
                )
            except ValueError:
                continue
            if result.status is ExtractionStatus.EXTRACTED:
                return result
        return ExtractionResult(
            message="No extractable payload was found.",
            status=ExtractionStatus.NO_MATCH,
            output_dir=None,
        )

    def _candidate_slot_counts(self) -> list[int]:
        try:
            slot_region_size = DeniableArchiver().slot_region_size(self.container_path)
        except OSError:
            return [self.slot_count or 4]
        preferred = self.slot_count if self.slot_count is not None else 4
        candidates: list[int] = []
        for slot_count in [preferred, 2, 4, 6, 8, 12, 16]:
            if slot_count < 2 or slot_count in candidates:
                continue
            if slot_region_size % slot_count != 0:
                continue
            candidates.append(slot_count)
        return candidates or [preferred]
