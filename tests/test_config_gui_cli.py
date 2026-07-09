from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import core.archiver as archiver_module
from cli.cli_entry import run_cli
from core.app_paths import ensure_runtime_layout, source_root
from core.config_store import load_app_config, load_preset, save_app_config
from core.i18n import get_translator


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(archiver_module, "SCRYPT_N", 2**12)


def test_language_pack_and_preset_load():
    config_dir, _workdir = ensure_runtime_layout()
    zh = get_translator("zh_cn", config_dir)
    en = get_translator("en", config_dir)

    assert zh.t("app.title") == "可否认加密归档器"
    assert en.t("app.title") == "Deniable Archiver"
    assert en.t("missing.key") == "missing.key"

    preset = load_preset("default_standard", config_dir)
    assert preset["container_size_mb"] == 100
    assert preset["slot_count"] == 4
    assert archiver_module.SCRYPT_N == 2**12


def test_app_config_has_defaults():
    config_dir, _workdir = ensure_runtime_layout()
    config = load_app_config(config_dir)

    assert config["language"] == "en"
    assert config["default_preset_name"] == "default_standard"
    assert config["remember_recent_paths"] is False
    assert "recent_paths" not in config


def test_app_config_drops_legacy_recent_paths():
    config_dir, _workdir = ensure_runtime_layout()

    save_app_config(
        config_dir,
        {
            "language": "en",
            "default_preset_name": "default_standard",
            "recent_paths": ["/tmp/example.darc"],
        },
    )
    config = load_app_config(config_dir)

    assert config["remember_recent_paths"] is False
    assert "recent_paths" not in config


def test_cli_init_smoke(tmp_path):
    vault = tmp_path / "cli.darc"

    assert run_cli(["init", str(vault), "--size-mb", "1", "--slots", "4"]) == 0
    assert vault.stat().st_size == 1024 * 1024


def test_cli_write_no_compress_roundtrip(monkeypatch, tmp_path):
    vault = tmp_path / "cli-no-compress.darc"
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "long unique passphrase")

    assert run_cli(["init", str(vault), "--size-mb", "1", "--slots", "4"]) == 0
    assert run_cli(["write", str(vault), str(source), "--slot", "0", "--slots", "4", "--no-compress"]) == 0
    assert run_cli(["extract", str(vault), str(output), "--slots", "4"]) == 0

    assert (output / "file.txt").read_text(encoding="utf-8") == "payload"


def test_darc_cli_help_smoke():
    result = subprocess.run(
        [sys.executable, "darc.py", "--help"],
        cwd=source_root(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    assert "Deniable encryption archiver" in result.stdout


def test_gui_window_instantiates_offscreen(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    try:
        assert window.windowTitle()
        assert window.tabs.count() == 4
        assert window.tabs.currentIndex() == 0
        assert window.tabs.tabText(0) == "Create"
        assert window.tabs.tabText(1) == "Write Slot"
        assert window.payload_table.rowCount() == 1
        assert window.payload_table.columnCount() == 5
        assert window.payload_detail_box.title() == "Selected payload"
        assert window.add_payload_button.text() == "Add Folder"
        assert window.create_compress_check.isChecked()
        assert window.write_compress_check.isChecked()
        assert not window.detail_show_password_check.isChecked()
        assert not window.detail_skip_confirm_check.isChecked()
        assert not window.extract_try_common_slots_check.isChecked()
        assert window.extract_slots_label.text() == "Slot count used when created"
        assert not hasattr(window, "runtime_box")
        assert window.tabs.widget(3) is window.settings_tab
    finally:
        window.close()
        app.processEvents()


def test_gui_create_validation_helpers(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    source_a = tmp_path / "a"
    source_b = tmp_path / "b"
    source_a.mkdir()
    source_b.mkdir()
    try:
        window.payload_table.selectRow(0)
        window._remove_selected_payload()
        payloads, error = window._collect_create_payloads()
        assert payloads is None
        assert error == window.tr.t("gui.message.no_payloads")

        window._add_payload_row(0, str(source_a), "alpha", "alpha")
        window._add_payload_row(0, str(source_b), "beta", "beta")
        payloads, error = window._collect_create_payloads()
        assert payloads is None
        assert error == window.tr.t("gui.message.duplicate_slots")

        window.payload_table.clearSelection()
        window._auto_assign_slots()
        slots = [window._payload_slot_spin(row).value() for row in range(window.payload_table.rowCount())]
        assert slots == [0, 2]

        window._payload_confirms[1] = "different"
        payloads, error = window._collect_create_payloads()
        assert payloads is None
        assert error == window.tr.t("gui.message.password_mismatch")
    finally:
        window.close()
        app.processEvents()


def test_gui_adds_multiple_payload_folders_and_filters_drop_urls(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QMimeData, QUrl
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    source_a = tmp_path / "a"
    source_b = tmp_path / "b"
    ignored_file = tmp_path / "file.txt"
    source_a.mkdir()
    source_b.mkdir()
    ignored_file.write_text("not a directory", encoding="utf-8")
    try:
        added = window._add_payload_sources([source_a, ignored_file, source_b])

        assert added == 2
        assert window.payload_table.rowCount() == 2
        assert window._payload_source_edit(0).text() == str(source_a)
        assert window._payload_source_edit(1).text() == str(source_b)
        slots = [window._payload_slot_spin(row).value() for row in range(window.payload_table.rowCount())]
        assert len(slots) == len(set(slots))

        mime = QMimeData()
        mime.setUrls([QUrl.fromLocalFile(str(source_a)), QUrl.fromLocalFile(str(ignored_file))])

        assert window.payload_table._dropped_directories(mime) == [source_a]
    finally:
        window.close()
        app.processEvents()


def test_gui_password_visibility_hint_and_skip_confirm(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QLineEdit

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    try:
        window._payload_source_edit(0).setText(str(source))
        window._payload_estimates[0] = 1
        window.detail_password_edit.setText("short")
        window.detail_confirm_edit.setText("different")

        assert window.tr.t("gui.message.weak_password_hint") in window.detail_password_hint_label.text()
        payloads, error = window._collect_create_payloads()
        assert payloads is None
        assert error == window.tr.t("gui.message.password_mismatch")

        window.detail_show_password_check.setChecked(True)
        assert window.detail_password_edit.echoMode() == QLineEdit.Normal
        window.detail_skip_confirm_check.setChecked(True)
        assert not window.detail_confirm_edit.isEnabled()

        payloads, error = window._collect_create_payloads()
        assert error is None
        assert payloads is not None
        assert payloads[0].password == "short"

        window.create_compress_check.setChecked(False)
        assert window._payload_estimates[0] is None

        window.write_password_edit.setText("short")
        assert window.tr.t("gui.message.weak_password_hint") in window.write_password_hint_label.text()
        window.write_show_password_check.setChecked(True)
        assert window.write_password_edit.echoMode() == QLineEdit.Normal
        window.write_skip_confirm_check.setChecked(True)
        assert not window.write_confirm_edit.isEnabled()

        window.extract_show_password_check.setChecked(True)
        assert window.extract_password_edit.echoMode() == QLineEdit.Normal
    finally:
        window.close()
        app.processEvents()


def test_gui_analyze_and_auto_plan_helpers(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QMessageBox

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root())
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.bin").write_bytes(b"a" * 300_000)
    try:
        window.create_size_spin.setValue(1)
        window._payload_source_edit(0).setText(str(source))
        window._payload_estimates[0] = 300_000
        window._refresh_payload_planning()
        assert window.payload_table.item(0, 4).text() == window.tr.t("gui.status_payload.too_large")

        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
        original_size = window.create_size_spin.value()
        window._apply_auto_plan()

        assert window.create_size_spin.value() > original_size
        assert window.payload_table.item(0, 4).text() == window.tr.t("gui.status_payload.ok")
    finally:
        window.close()
        app.processEvents()


def test_analyze_payloads_worker_estimates_zip_size(tmp_path):
    from PySide6.QtWidgets import QApplication

    from gui.workers import AnalyzePayloadsWorker

    app = QApplication.instance() or QApplication([])
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("hello" * 1000, encoding="utf-8")
    compressed_results = []
    stored_results = []

    worker = AnalyzePayloadsWorker([(0, source)])
    worker.completed.connect(compressed_results.append)
    worker.run()
    stored_worker = AnalyzePayloadsWorker([(0, source)], compress=False)
    stored_worker.completed.connect(stored_results.append)
    stored_worker.run()
    app.processEvents()

    assert len(compressed_results) == 1
    assert len(stored_results) == 1
    assert compressed_results[0][0].row_index == 0
    assert compressed_results[0][0].zip_size is not None
    assert stored_results[0][0].zip_size is not None
    assert compressed_results[0][0].zip_size > 0
    assert stored_results[0][0].zip_size > compressed_results[0][0].zip_size


def test_create_container_worker_writes_multiple_payloads(tmp_path):
    from gui.workers import CreateContainerWorker, PayloadInput

    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    source_a.mkdir()
    source_b.mkdir()
    (source_a / "a.txt").write_text("alpha", encoding="utf-8")
    (source_b / "b.txt").write_text("beta", encoding="utf-8")

    vault = tmp_path / "multi.darc"
    worker = CreateContainerWorker(
        vault,
        1,
        4,
        [
            PayloadInput(slot_index=0, source_dir=source_a, password="alpha password"),
            PayloadInput(slot_index=2, source_dir=source_b, password="beta password"),
        ],
        "done",
    )
    worker.run()

    archiver = archiver_module.DeniableArchiver()
    output_a = tmp_path / "out-a"
    output_b = tmp_path / "out-b"
    output_raw = tmp_path / "out-raw"
    result_a = archiver.extract_payload(vault, "alpha password", output_a, slot_count=4)
    result_b = archiver.extract_payload(vault, "beta password", output_b, slot_count=4)
    result_raw = archiver.extract_payload(vault, "unrelated password", output_raw, slot_count=4)

    assert result_a.raw_dumped is False
    assert result_b.raw_dumped is False
    assert result_raw.raw_dumped is True
    assert (output_a / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (output_b / "b.txt").read_text(encoding="utf-8") == "beta"
    assert (output_raw / "decrypted_raw.bin").exists()


def test_extract_worker_try_common_slot_counts_stays_blind(tmp_path):
    from PySide6.QtWidgets import QApplication

    from gui.workers import ExtractWorker

    app = QApplication.instance() or QApplication([])
    archiver = archiver_module.DeniableArchiver()
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    vault = tmp_path / "vault.darc"
    archiver.initialize_container(vault, size_mb=1, slot_count=4)
    archiver.write_payload(vault, source, "long unique passphrase", 2, slot_count=4)

    output = tmp_path / "output"
    completed = []
    worker = ExtractWorker(vault, "long unique passphrase", output, slot_count=2, try_common_slot_counts=True)
    worker.completed.connect(completed.append)
    worker.run()
    app.processEvents()

    assert completed == [archiver_module.SUCCESS_MESSAGE]
    assert (output / "file.txt").read_text(encoding="utf-8") == "payload"
    assert not (output / "decrypted_raw.bin").exists()
    assert not list(tmp_path.glob(".output.*.extract"))

    raw_output = tmp_path / "raw-output"
    raw_completed = []
    raw_worker = ExtractWorker(vault, "unrelated passphrase", raw_output, slot_count=2, try_common_slot_counts=True)
    raw_worker.completed.connect(raw_completed.append)
    raw_worker.run()
    app.processEvents()

    assert raw_completed == [archiver_module.RAW_DUMP_MESSAGE]
    assert (raw_output / "decrypted_raw.bin").exists()
    assert not list(tmp_path.glob(".raw-output.*.extract"))


def test_create_container_worker_failure_preserves_existing_container(tmp_path):
    from gui.workers import CreateContainerWorker, PayloadInput

    existing = tmp_path / "existing.darc"
    existing.write_bytes(b"existing-data")
    before = existing.read_bytes()
    source = tmp_path / "large-source"
    source.mkdir()
    (source / "large.dat").write_bytes(os.urandom(300_000))
    failures = []

    worker = CreateContainerWorker(
        existing,
        1,
        4,
        [PayloadInput(slot_index=0, source_dir=source, password="password")],
        "done",
    )
    worker.failed.connect(failures.append)
    worker.run()

    assert failures
    assert existing.read_bytes() == before
    assert not list(tmp_path.glob(f".{existing.name}.*.tmp"))


def test_pyinstaller_build_script_help():
    script = Path("scripts/build_pyinstaller.py").resolve()
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=source_root(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    assert "Build the app with PyInstaller" in result.stdout


def test_readme_uses_generic_commands_only():
    readme = (source_root() / "README.md").read_text(encoding="utf-8")

    forbidden = [
        "/" + "home",
        "ha" + "zel",
        "mini" + "conda",
        "/" + "home" + "/" + "ha" + "zel" + "/" + "mini" + "conda3" + "/" + "envs" + "/" + "La" + "b",
        "Use the requested conda environment",
    ]
    for text in forbidden:
        assert text not in readme
    assert "python darc.py init vault.darc --size-mb 100 --slots 4" in readme
