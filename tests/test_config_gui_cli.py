from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import core.archiver as archiver_module
from cli.cli_entry import run_cli
from core.app_paths import ensure_runtime_layout, source_root
from core.config_store import load_app_config, load_preset
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


def test_cli_init_smoke(tmp_path):
    vault = tmp_path / "cli.darc"

    assert run_cli(["init", str(vault), "--size-mb", "1", "--slots", "4"]) == 0
    assert vault.stat().st_size == 1024 * 1024


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
        window.payload_table.removeRow(0)
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
        assert slots == [0, 1]

        window._payload_confirm_edit(1).setText("different")
        payloads, error = window._collect_create_payloads()
        assert payloads is None
        assert error == window.tr.t("gui.message.password_mismatch")
    finally:
        window.close()
        app.processEvents()


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
