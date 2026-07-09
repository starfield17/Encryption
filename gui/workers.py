from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from core.archiver import DeniableArchiver, ZipWrapperOptions


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
    error: str | None = None


class AnalyzePayloadsWorker(QThread):
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
                try:
                    zip_bytes = archiver._zip_directory(source_dir, compress=self.compress)
                    estimates.append(PayloadEstimate(row_index=row_index, source_dir=source_dir, zip_size=len(zip_bytes)))
                except Exception as exc:
                    estimates.append(PayloadEstimate(row_index=row_index, source_dir=source_dir, zip_size=None, error=str(exc)))
            self.completed.emit(estimates)
        except Exception as exc:
            self.failed.emit(str(exc))


class InitWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        size_mb: int,
        slot_count: int,
        success_message: str,
        zip_wrapper: ZipWrapperOptions | None = None,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.size_mb = size_mb
        self.slot_count = slot_count
        self.success_message = success_message
        self.zip_wrapper = zip_wrapper

    def run(self) -> None:
        try:
            DeniableArchiver().initialize_container(self.container_path, self.size_mb, self.slot_count, self.zip_wrapper)
            self.completed.emit(self.success_message)
        except Exception as exc:
            self.failed.emit(str(exc))


class CreateContainerWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        size_mb: int,
        slot_count: int,
        payloads: list[PayloadInput],
        zip_wrapper: ZipWrapperOptions | None,
        success_message: str,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.size_mb = size_mb
        self.slot_count = slot_count
        self.payloads = payloads
        self.zip_wrapper = zip_wrapper
        self.success_message = success_message

    def run(self) -> None:
        temp_path: Path | None = None
        try:
            self.container_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                prefix=f".{self.container_path.name}.",
                suffix=".tmp",
                dir=self.container_path.parent,
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)

            archiver = DeniableArchiver()
            archiver.initialize_container(temp_path, self.size_mb, self.slot_count, self.zip_wrapper)
            for payload in self.payloads:
                archiver.write_payload(
                    temp_path,
                    payload.source_dir,
                    payload.password,
                    payload.slot_index,
                    slot_count=self.slot_count,
                    compress=payload.compress,
                )
            os.replace(temp_path, self.container_path)
            temp_path = None
            self.completed.emit(self.success_message)
        except Exception as exc:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass
            self.failed.emit(str(exc))


class WriteWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        source_dir: Path,
        password: str,
        slot_index: int,
        slot_count: int,
        compress: bool,
        success_message: str,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.source_dir = source_dir
        self.password = password
        self.slot_index = slot_index
        self.slot_count = slot_count
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
                compress=self.compress,
            )
            self.completed.emit(self.success_message)
        except Exception as exc:
            self.failed.emit(str(exc))


class ExtractWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        container_path: Path,
        password: str,
        output_dir: Path,
        slot_count: int,
        try_common_slot_counts: bool = False,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.password = password
        self.output_dir = output_dir
        self.slot_count = slot_count
        self.try_common_slot_counts = try_common_slot_counts

    def run(self) -> None:
        try:
            if self.try_common_slot_counts:
                result = self._extract_with_common_slot_counts()
                self.completed.emit(result.message)
                return
            result = DeniableArchiver().extract_payload(
                self.container_path,
                self.password,
                self.output_dir,
                slot_count=self.slot_count,
            )
            self.completed.emit(result.message)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _extract_with_common_slot_counts(self):
        output_parent = self.output_dir.parent
        output_parent.mkdir(parents=True, exist_ok=True)
        archiver = DeniableArchiver()
        candidates = self._candidate_slot_counts()
        with tempfile.TemporaryDirectory(prefix=f".{self.output_dir.name}.", suffix=".extract", dir=output_parent) as temp_root_raw:
            temp_root = Path(temp_root_raw)
            for slot_count in candidates:
                temp_output = temp_root / f"slots-{slot_count}"
                try:
                    result = archiver.extract_payload(
                        self.container_path,
                        self.password,
                        temp_output,
                        slot_count=slot_count,
                    )
                except ValueError:
                    continue
                if result.raw_dumped:
                    continue
                self._merge_directory_contents(temp_output, self.output_dir)
                return result

        fallback_slot_count = self.slot_count if self._slot_count_is_compatible(self.slot_count) else candidates[0]
        return archiver.extract_payload(
            self.container_path,
            self.password,
            self.output_dir,
            slot_count=fallback_slot_count,
        )

    def _candidate_slot_counts(self) -> list[int]:
        try:
            slot_region_size = DeniableArchiver().slot_region_size(self.container_path)
        except OSError:
            return [self.slot_count]
        candidates: list[int] = []
        for slot_count in [self.slot_count, 2, 4, 6, 8]:
            if slot_count < 2 or slot_count in candidates:
                continue
            if not self._slot_count_is_compatible(slot_count, slot_region_size):
                continue
            candidates.append(slot_count)
        return candidates or [self.slot_count]

    def _slot_count_is_compatible(self, slot_count: int, slot_region_size: int | None = None) -> bool:
        if slot_count < 2:
            return False
        try:
            size = DeniableArchiver().slot_region_size(self.container_path) if slot_region_size is None else slot_region_size
        except OSError:
            return True
        return size % slot_count == 0

    def _merge_directory_contents(self, source: Path, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        for child in source.iterdir():
            target = destination / child.name
            if target.exists() and target.is_symlink():
                raise RuntimeError("Unsafe existing output path")
            if child.is_dir():
                if target.exists() and not target.is_dir():
                    target.unlink()
                self._merge_directory_contents(child, target)
                shutil.rmtree(child)
                continue
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            shutil.move(str(child), str(target))
