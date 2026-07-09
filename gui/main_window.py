from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStatusBar,
    QStyle,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QComboBox,
)

from core.archiver import DEFAULT_CONTAINER_SIZE_MB, DEFAULT_SLOT_COUNT
from core.config_store import load_app_config, load_preset, update_app_config
from core.i18n import get_translator
from gui.theme import apply_theme
from gui.window_geometry import clamped_window_size
from gui.workers import ExtractWorker, InitWorker, WriteWorker


CONTAINER_FILTER = "DARC containers (*.darc *.bin *.img);;All files (*)"


class MainWindow(QMainWindow):
    def __init__(self, repo_root: Path, language: str | None = None) -> None:
        super().__init__()
        self.repo_root = repo_root
        self.config_dir = repo_root / "config"
        self.app_config = load_app_config(self.config_dir)
        self.language = language or str(self.app_config.get("language", "zh_cn"))
        self.tr = get_translator(self.language, self.config_dir)
        self.active_worker = None
        self._language_guard = False

        preset = self._load_default_preset()
        self.default_container_size_mb = int(preset.get("container_size_mb", DEFAULT_CONTAINER_SIZE_MB))
        self.default_slot_count = int(preset.get("slot_count", DEFAULT_SLOT_COUNT))
        self.default_extension = str(preset.get("default_extension", ".darc"))

        self._build_ui()
        self._connect_signals()
        self._apply_translations()
        self._sync_slot_index_limit()
        self._set_busy(False)

    def _load_default_preset(self) -> dict[str, object]:
        name = str(self.app_config.get("default_preset_name", "default_standard"))
        try:
            return load_preset(name, self.config_dir)
        except Exception:
            return {
                "container_size_mb": DEFAULT_CONTAINER_SIZE_MB,
                "slot_count": DEFAULT_SLOT_COUNT,
                "default_extension": ".darc",
            }

    def _build_ui(self) -> None:
        apply_theme(self)
        self.resize(clamped_window_size(900, 580, minimum_width=720, minimum_height=480))

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(Qt.TopToolBarArea, toolbar)
        self.about_action = QAction(self.style().standardIcon(QStyle.SP_MessageBoxInformation), "", self)
        toolbar.addAction(self.about_action)

        central = QScrollArea(self)
        central.setWidgetResizable(True)
        central.setFrameShape(QFrame.NoFrame)
        central.setSizeAdjustPolicy(QAbstractScrollArea.AdjustIgnored)
        self.setCentralWidget(central)

        content = QWidget(self)
        central.setWidget(content)
        root_layout = QVBoxLayout(content)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        self.runtime_box = QGroupBox()
        runtime_layout = QGridLayout(self.runtime_box)
        self.language_label = QLabel()
        self.language_combo = QComboBox()
        self.language_combo.addItem("中文 (简体)", "zh_cn")
        self.language_combo.addItem("English", "en")
        self._set_language_combo(self.language)
        runtime_layout.addWidget(self.language_label, 0, 0)
        runtime_layout.addWidget(self.language_combo, 0, 1)
        runtime_layout.setColumnStretch(2, 1)
        root_layout.addWidget(self.runtime_box)

        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs)

        self.init_tab = QWidget()
        self.write_tab = QWidget()
        self.extract_tab = QWidget()
        self.tabs.addTab(self.init_tab, "")
        self.tabs.addTab(self.write_tab, "")
        self.tabs.addTab(self.extract_tab, "")

        self._build_init_tab()
        self._build_write_tab()
        self._build_extract_tab()

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        root_layout.addWidget(self.progress_bar)

        status = QStatusBar(self)
        self.setStatusBar(status)
        self.status_label = QLabel()
        status.addWidget(self.status_label, 1)

    def _build_init_tab(self) -> None:
        layout = QVBoxLayout(self.init_tab)
        self.init_box = QGroupBox()
        form = QGridLayout(self.init_box)
        self.init_container_label = QLabel()
        self.init_container_edit = QLineEdit()
        self.init_container_button = QPushButton()
        self.init_size_label = QLabel()
        self.init_size_spin = QSpinBox()
        self.init_size_spin.setRange(1, 1024 * 1024)
        self.init_size_spin.setValue(self.default_container_size_mb)
        self.init_slots_label = QLabel()
        self.init_slots_spin = QSpinBox()
        self.init_slots_spin.setRange(2, 256)
        self.init_slots_spin.setValue(self.default_slot_count)
        self.init_run_button = QPushButton()

        self._add_path_row(form, 0, self.init_container_label, self.init_container_edit, self.init_container_button)
        form.addWidget(self.init_size_label, 1, 0)
        form.addWidget(self.init_size_spin, 1, 1)
        form.addWidget(self.init_slots_label, 2, 0)
        form.addWidget(self.init_slots_spin, 2, 1)
        form.addWidget(self.init_run_button, 3, 1)
        form.setColumnStretch(1, 1)
        layout.addWidget(self.init_box)
        layout.addStretch(1)

    def _build_write_tab(self) -> None:
        layout = QVBoxLayout(self.write_tab)
        self.write_box = QGroupBox()
        form = QGridLayout(self.write_box)
        self.write_container_label = QLabel()
        self.write_container_edit = QLineEdit()
        self.write_container_button = QPushButton()
        self.write_source_label = QLabel()
        self.write_source_edit = QLineEdit()
        self.write_source_button = QPushButton()
        self.write_slots_label = QLabel()
        self.write_slots_spin = QSpinBox()
        self.write_slots_spin.setRange(2, 256)
        self.write_slots_spin.setValue(self.default_slot_count)
        self.write_slot_label = QLabel()
        self.write_slot_index_spin = QSpinBox()
        self.write_slot_index_spin.setRange(0, max(0, self.default_slot_count - 1))
        self.write_password_label = QLabel()
        self.write_password_edit = QLineEdit()
        self.write_password_edit.setEchoMode(QLineEdit.Password)
        self.write_confirm_label = QLabel()
        self.write_confirm_edit = QLineEdit()
        self.write_confirm_edit.setEchoMode(QLineEdit.Password)
        self.write_run_button = QPushButton()

        self._add_path_row(form, 0, self.write_container_label, self.write_container_edit, self.write_container_button)
        self._add_path_row(form, 1, self.write_source_label, self.write_source_edit, self.write_source_button)
        form.addWidget(self.write_slots_label, 2, 0)
        form.addWidget(self.write_slots_spin, 2, 1)
        form.addWidget(self.write_slot_label, 3, 0)
        form.addWidget(self.write_slot_index_spin, 3, 1)
        form.addWidget(self.write_password_label, 4, 0)
        form.addWidget(self.write_password_edit, 4, 1)
        form.addWidget(self.write_confirm_label, 5, 0)
        form.addWidget(self.write_confirm_edit, 5, 1)
        form.addWidget(self.write_run_button, 6, 1)
        form.setColumnStretch(1, 1)
        layout.addWidget(self.write_box)
        layout.addStretch(1)

    def _build_extract_tab(self) -> None:
        layout = QVBoxLayout(self.extract_tab)
        self.extract_box = QGroupBox()
        form = QGridLayout(self.extract_box)
        self.extract_container_label = QLabel()
        self.extract_container_edit = QLineEdit()
        self.extract_container_button = QPushButton()
        self.extract_output_label = QLabel()
        self.extract_output_edit = QLineEdit()
        self.extract_output_button = QPushButton()
        self.extract_slots_label = QLabel()
        self.extract_slots_spin = QSpinBox()
        self.extract_slots_spin.setRange(2, 256)
        self.extract_slots_spin.setValue(self.default_slot_count)
        self.extract_password_label = QLabel()
        self.extract_password_edit = QLineEdit()
        self.extract_password_edit.setEchoMode(QLineEdit.Password)
        self.extract_run_button = QPushButton()

        self._add_path_row(form, 0, self.extract_container_label, self.extract_container_edit, self.extract_container_button)
        self._add_path_row(form, 1, self.extract_output_label, self.extract_output_edit, self.extract_output_button)
        form.addWidget(self.extract_slots_label, 2, 0)
        form.addWidget(self.extract_slots_spin, 2, 1)
        form.addWidget(self.extract_password_label, 3, 0)
        form.addWidget(self.extract_password_edit, 3, 1)
        form.addWidget(self.extract_run_button, 4, 1)
        form.setColumnStretch(1, 1)
        layout.addWidget(self.extract_box)
        layout.addStretch(1)

    def _add_path_row(
        self,
        layout: QGridLayout,
        row: int,
        label: QLabel,
        edit: QLineEdit,
        button: QPushButton,
    ) -> None:
        wrapper = QWidget()
        path_layout = QHBoxLayout(wrapper)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.addWidget(edit, 1)
        path_layout.addWidget(button)
        layout.addWidget(label, row, 0)
        layout.addWidget(wrapper, row, 1)

    def _connect_signals(self) -> None:
        self.about_action.triggered.connect(self._show_about)
        self.language_combo.currentIndexChanged.connect(self._language_changed)
        self.init_container_button.clicked.connect(self._browse_init_container)
        self.write_container_button.clicked.connect(lambda: self._browse_open_file(self.write_container_edit))
        self.write_source_button.clicked.connect(lambda: self._browse_directory(self.write_source_edit))
        self.extract_container_button.clicked.connect(lambda: self._browse_open_file(self.extract_container_edit))
        self.extract_output_button.clicked.connect(lambda: self._browse_directory(self.extract_output_edit))
        self.write_slots_spin.valueChanged.connect(self._sync_slot_index_limit)
        self.init_run_button.clicked.connect(self._run_init)
        self.write_run_button.clicked.connect(self._run_write)
        self.extract_run_button.clicked.connect(self._run_extract)

    def _apply_translations(self) -> None:
        self.setWindowTitle(self.tr.t("app.title"))
        self.about_action.setText(self.tr.t("gui.button.about"))
        self.runtime_box.setTitle(self.tr.t("gui.group.runtime"))
        self.language_label.setText(self.tr.t("gui.label.language"))
        self.tabs.setTabText(0, self.tr.t("gui.tab.init"))
        self.tabs.setTabText(1, self.tr.t("gui.tab.write"))
        self.tabs.setTabText(2, self.tr.t("gui.tab.extract"))

        self.init_box.setTitle(self.tr.t("gui.group.init"))
        self.init_container_label.setText(self.tr.t("gui.label.container"))
        self.init_size_label.setText(self.tr.t("gui.label.size_mb"))
        self.init_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.init_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.init_run_button.setText(self.tr.t("gui.button.init"))

        self.write_box.setTitle(self.tr.t("gui.group.write"))
        self.write_container_label.setText(self.tr.t("gui.label.container"))
        self.write_source_label.setText(self.tr.t("gui.label.source_dir"))
        self.write_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.write_slot_label.setText(self.tr.t("gui.label.slot_index"))
        self.write_password_label.setText(self.tr.t("gui.label.password"))
        self.write_confirm_label.setText(self.tr.t("gui.label.confirm_password"))
        self.write_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.write_source_button.setText(self.tr.t("gui.button.browse_dir"))
        self.write_run_button.setText(self.tr.t("gui.button.write"))

        self.extract_box.setTitle(self.tr.t("gui.group.extract"))
        self.extract_container_label.setText(self.tr.t("gui.label.container"))
        self.extract_output_label.setText(self.tr.t("gui.label.output_dir"))
        self.extract_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.extract_password_label.setText(self.tr.t("gui.label.password"))
        self.extract_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.extract_output_button.setText(self.tr.t("gui.button.browse_dir"))
        self.extract_run_button.setText(self.tr.t("gui.button.extract"))

        for edit, key in [
            (self.init_container_edit, "gui.placeholder.container_new"),
            (self.write_container_edit, "gui.placeholder.container_existing"),
            (self.write_source_edit, "gui.placeholder.source_dir"),
            (self.extract_container_edit, "gui.placeholder.container_existing"),
            (self.extract_output_edit, "gui.placeholder.output_dir"),
        ]:
            edit.setPlaceholderText(self.tr.t(key))
        self._set_status(self.tr.t("gui.status.ready"))

    def _set_language_combo(self, language: str) -> None:
        self._language_guard = True
        for index in range(self.language_combo.count()):
            if self.language_combo.itemData(index) == language:
                self.language_combo.setCurrentIndex(index)
                break
        self._language_guard = False

    def _language_changed(self) -> None:
        if self._language_guard:
            return
        language = str(self.language_combo.currentData())
        self.language = language

        def updater(data: dict[str, object]) -> dict[str, object]:
            return {**data, "language": language}

        update_app_config(self.config_dir, updater)
        self.tr = get_translator(language, self.config_dir)
        self._apply_translations()

    def _browse_init_container(self) -> None:
        path, _selected = QFileDialog.getSaveFileName(
            self,
            self.tr.t("gui.dialog.select_container_save"),
            str(self.repo_root / f"vault{self.default_extension}"),
            CONTAINER_FILTER,
        )
        if path:
            self.init_container_edit.setText(path)

    def _browse_open_file(self, edit: QLineEdit) -> None:
        path, _selected = QFileDialog.getOpenFileName(
            self,
            self.tr.t("gui.dialog.select_container_open"),
            str(self.repo_root),
            CONTAINER_FILTER,
        )
        if path:
            edit.setText(path)

    def _browse_directory(self, edit: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, self.tr.t("gui.dialog.select_dir"), str(self.repo_root))
        if path:
            edit.setText(path)

    def _run_init(self) -> None:
        path = self._required_path(self.init_container_edit, "gui.message.select_container")
        if path is None:
            return
        if path.exists():
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.overwrite_container"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
                return
        worker = InitWorker(
            path,
            self.init_size_spin.value(),
            self.init_slots_spin.value(),
            self.tr.t("gui.message.init_complete"),
        )
        self._start_worker(worker, self.tr.t("gui.status.initializing"))

    def _run_write(self) -> None:
        container = self._required_path(self.write_container_edit, "gui.message.select_container")
        source = self._required_path(self.write_source_edit, "gui.message.select_source")
        if container is None or source is None:
            return
        password = self.write_password_edit.text()
        if password != self.write_confirm_edit.text():
            self._show_warning(self.tr.t("gui.message.password_mismatch"))
            return
        worker = WriteWorker(
            container,
            source,
            password,
            self.write_slot_index_spin.value(),
            self.write_slots_spin.value(),
            self.tr.t("gui.message.write_complete"),
        )
        self._start_worker(worker, self.tr.t("gui.status.writing"))

    def _run_extract(self) -> None:
        container = self._required_path(self.extract_container_edit, "gui.message.select_container")
        output = self._required_path(self.extract_output_edit, "gui.message.select_output")
        if container is None or output is None:
            return
        worker = ExtractWorker(
            container,
            self.extract_password_edit.text(),
            output,
            self.extract_slots_spin.value(),
        )
        self._start_worker(worker, self.tr.t("gui.status.extracting"))

    def _required_path(self, edit: QLineEdit, message_key: str) -> Path | None:
        raw = edit.text().strip()
        if not raw:
            self._show_warning(self.tr.t(message_key))
            return None
        return Path(raw)

    def _start_worker(self, worker, status_text: str) -> None:
        if self.active_worker is not None:
            self._show_warning(self.tr.t("gui.message.busy"))
            return
        self.active_worker = worker
        worker.completed.connect(self._worker_completed)
        worker.failed.connect(self._worker_failed)
        worker.finished.connect(worker.deleteLater)
        self._set_busy(True)
        self._set_status(status_text)
        worker.start()

    def _worker_completed(self, message: str) -> None:
        self._finish_worker(message)
        self._show_info(message)

    def _worker_failed(self, message: str) -> None:
        sanitized = self._sanitize_error(message)
        self._finish_worker(sanitized)
        self._show_error(sanitized)

    def _finish_worker(self, message: str) -> None:
        self.active_worker = None
        self._set_busy(False)
        self._set_status(message)

    def _set_busy(self, busy: bool) -> None:
        for widget in [
            self.init_run_button,
            self.write_run_button,
            self.extract_run_button,
            self.language_combo,
        ]:
            widget.setEnabled(not busy)
        if busy:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)

    def _sync_slot_index_limit(self) -> None:
        self.write_slot_index_spin.setMaximum(max(0, self.write_slots_spin.value() - 1))

    def _set_status(self, message: str) -> None:
        self.status_label.setText(message)

    def _show_warning(self, message: str) -> None:
        QMessageBox.warning(self, self.tr.t("gui.message.warning"), message)

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, self.tr.t("gui.message.error"), message)

    def _show_info(self, message: str) -> None:
        QMessageBox.information(self, self.tr.t("gui.message.info"), message)

    def _show_about(self) -> None:
        QMessageBox.information(self, self.tr.t("gui.message.info"), self.tr.t("gui.message.about"))

    def _sanitize_error(self, message: str) -> str:
        lower = message.lower()
        forbidden = ["invalidtag", "invalid tag", "wrong password", "bad password", "decryption failed"]
        if any(item in lower for item in forbidden):
            return self.tr.t("gui.message.operation_failed")
        return message

