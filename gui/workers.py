from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from core.archiver import DeniableArchiver


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

