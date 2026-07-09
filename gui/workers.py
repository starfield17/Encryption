from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from core.archiver import DeniableArchiver


@dataclass(frozen=True)
class PayloadInput:
    slot_index: int
    source_dir: Path
    password: str


@dataclass(frozen=True)
class PayloadEstimate:
    row_index: int
    source_dir: Path
    zip_size: int | None
    error: str | None = None


class AnalyzePayloadsWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, payload_sources: list[tuple[int, Path]]) -> None:
        super().__init__()
        self.payload_sources = payload_sources

    def run(self) -> None:
        try:
            archiver = DeniableArchiver()
            estimates: list[PayloadEstimate] = []
            for row_index, source_dir in self.payload_sources:
                try:
                    zip_bytes = archiver._zip_directory(source_dir)
                    estimates.append(PayloadEstimate(row_index=row_index, source_dir=source_dir, zip_size=len(zip_bytes)))
                except Exception as exc:
                    estimates.append(PayloadEstimate(row_index=row_index, source_dir=source_dir, zip_size=None, error=str(exc)))
            self.completed.emit(estimates)
        except Exception as exc:
            self.failed.emit(str(exc))


class InitWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, container_path: Path, size_mb: int, slot_count: int, success_message: str) -> None:
        super().__init__()
        self.container_path = container_path
        self.size_mb = size_mb
        self.slot_count = slot_count
        self.success_message = success_message

    def run(self) -> None:
        try:
            DeniableArchiver().initialize_container(self.container_path, self.size_mb, self.slot_count)
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
        success_message: str,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.size_mb = size_mb
        self.slot_count = slot_count
        self.payloads = payloads
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
            archiver.initialize_container(temp_path, self.size_mb, self.slot_count)
            for payload in self.payloads:
                archiver.write_payload(
                    temp_path,
                    payload.source_dir,
                    payload.password,
                    payload.slot_index,
                    slot_count=self.slot_count,
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
        success_message: str,
    ) -> None:
        super().__init__()
        self.container_path = container_path
        self.source_dir = source_dir
        self.password = password
        self.slot_index = slot_index
        self.slot_count = slot_count
        self.success_message = success_message

    def run(self) -> None:
        try:
            DeniableArchiver().write_payload(
                self.container_path,
                self.source_dir,
                self.password,
                self.slot_index,
                slot_count=self.slot_count,
            )
            self.completed.emit(self.success_message)
        except Exception as exc:
            self.failed.emit(str(exc))


class ExtractWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, container_path: Path, password: str, output_dir: Path, slot_count: int) -> None:
        super().__init__()
        self.container_path = container_path
        self.password = password
        self.output_dir = output_dir
        self.slot_count = slot_count

    def run(self) -> None:
        try:
            result = DeniableArchiver().extract_payload(
                self.container_path,
                self.password,
                self.output_dir,
                slot_count=self.slot_count,
            )
            self.completed.emit(result.message)
        except Exception as exc:
            self.failed.emit(str(exc))
