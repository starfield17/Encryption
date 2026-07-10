from __future__ import annotations

from pathlib import Path

import pytest

import core.format_v3 as format_v3
from core.app_paths import source_root
from core.archiver import DeniableArchiver, ExtractionStatus, OperationStage
from gui.workers import CreateContainerWorker, ExtractWorker, PayloadInput, WriteWorker


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(format_v3, "SCRYPT_N", 2**12)


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    return source


def test_create_worker_reports_real_stages_and_releases_password_references(tmp_path):
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    worker = CreateContainerWorker(
        vault,
        1,
        4,
        [PayloadInput(slot_index=0, source_dir=source, password="long unique passphrase")],
        None,
        "done",
    )
    completed: list[str] = []
    progress = []
    worker.completed.connect(completed.append)
    worker.progress.connect(progress.append)

    worker.run()

    assert completed == ["done"]
    assert worker.payloads == []
    stages = {item.stage for item in progress}
    assert {OperationStage.INITIALIZING, OperationStage.ARCHIVING, OperationStage.ENCRYPTING} <= stages
    result = DeniableArchiver().extract_payload(vault, "long unique passphrase", tmp_path / "out", slot_count=4)
    assert result.status is ExtractionStatus.EXTRACTED


def test_cancelled_write_worker_preserves_container_and_clears_password(tmp_path, monkeypatch):
    source = _source(tmp_path)
    vault = tmp_path / "vault.darc"
    DeniableArchiver().initialize_container(vault, size_mb=1, slot_count=4)
    before = vault.read_bytes()
    worker = WriteWorker(
        vault,
        source,
        "long unique passphrase",
        0,
        4,
        True,
        "done",
    )
    cancelled: list[str] = []
    completed: list[str] = []
    worker.cancelled.connect(cancelled.append)
    worker.completed.connect(completed.append)
    monkeypatch.setattr(worker, "_is_cancelled", lambda: True)

    worker.run()

    assert cancelled == ["Operation cancelled."]
    assert completed == []
    assert worker.password == ""
    assert vault.read_bytes() == before
    assert not list(tmp_path.glob(f".{vault.name}.*.tmp"))


def test_main_window_clears_persistent_task_password_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    source = _source(tmp_path)
    try:
        write_worker = WriteWorker(
            tmp_path / "vault.darc",
            source,
            "write password",
            0,
            4,
            True,
            "done",
        )
        window.write_page.password_group.set_password("write password", "write password")
        window.active_worker = write_worker
        window._finish_worker("done")
        assert window.write_page.password_group.password() == ""
        assert window.write_page.password_group.confirm() == ""

        extract_worker = ExtractWorker(
            tmp_path / "vault.darc",
            "extract password",
            tmp_path / "output",
            slot_count=4,
        )
        window.extract_page.password_group.set_password("extract password")
        window.active_worker = extract_worker
        window._finish_worker("done")
        assert window.extract_page.password_group.password() == ""
    finally:
        window.close()
        app.processEvents()
