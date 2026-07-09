from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStatusBar,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.archiver import DEFAULT_CONTAINER_SIZE_MB, DEFAULT_SLOT_COUNT
from core.config_store import load_app_config, load_preset, update_app_config
from core.i18n import get_translator
from gui.theme import apply_theme
from gui.window_geometry import clamped_window_size
from gui.workers import CreateContainerWorker, ExtractWorker, PayloadInput, WriteWorker


CONTAINER_FILTER = "DARC containers (*.darc *.bin *.img);;All files (*)"
PAYLOAD_SLOT_COL = 0
PAYLOAD_SOURCE_COL = 1
PAYLOAD_PASSWORD_COL = 2
PAYLOAD_CONFIRM_COL = 3


class MainWindow(QMainWindow):
    def __init__(self, repo_root: Path, language: str | None = None) -> None:
        super().__init__()
        self.repo_root = repo_root
        self.config_dir = repo_root / "config"
        self.app_config = load_app_config(self.config_dir)
        self.language = language or str(self.app_config.get("language", "en"))
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
        self._sync_slot_index_limits()
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
        self.resize(clamped_window_size(800, 560, minimum_width=720, minimum_height=500))

        central = QScrollArea(self)
        central.setWidgetResizable(True)
        central.setFrameShape(QFrame.NoFrame)
        central.setSizeAdjustPolicy(QAbstractScrollArea.AdjustIgnored)
        self.setCentralWidget(central)

        content = QWidget(self)
        central.setWidget(content)
        root_layout = QVBoxLayout(content)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(8)

        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs, 1)

        self.create_tab = QWidget()
        self.write_tab = QWidget()
        self.extract_tab = QWidget()
        self.settings_tab = QWidget()
        self.tabs.addTab(self.create_tab, "")
        self.tabs.addTab(self.write_tab, "")
        self.tabs.addTab(self.extract_tab, "")
        self.tabs.addTab(self.settings_tab, "")
        self.tabs.setCurrentIndex(0)

        self._build_create_tab()
        self._build_write_tab()
        self._build_extract_tab()
        self._build_settings_tab()

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        root_layout.addWidget(self.progress_bar)

        status = QStatusBar(self)
        self.setStatusBar(status)
        self.status_label = QLabel()
        status.addWidget(self.status_label, 1)

    def _build_create_tab(self) -> None:
        layout = QVBoxLayout(self.create_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.create_box = QGroupBox()
        form = QGridLayout(self.create_box)
        self.create_container_label = QLabel()
        self.create_container_edit = QLineEdit()
        self.create_container_button = QPushButton()
        self.create_size_label = QLabel()
        self.create_size_spin = QSpinBox()
        self.create_size_spin.setRange(1, 1024 * 1024)
        self.create_size_spin.setValue(self.default_container_size_mb)
        self.create_slots_label = QLabel()
        self.create_slots_spin = QSpinBox()
        self.create_slots_spin.setRange(2, 256)
        self.create_slots_spin.setValue(self.default_slot_count)

        self._add_path_row(form, 0, self.create_container_label, self.create_container_edit, self.create_container_button)
        form.addWidget(self.create_size_label, 1, 0)
        form.addWidget(self.create_size_spin, 1, 1)
        form.addWidget(self.create_slots_label, 2, 0)
        form.addWidget(self.create_slots_spin, 2, 1)
        form.setColumnStretch(1, 1)
        layout.addWidget(self.create_box)

        self.payload_box = QGroupBox()
        payload_layout = QVBoxLayout(self.payload_box)
        self.payload_table = QTableWidget(0, 4)
        self.payload_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.payload_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.payload_table.verticalHeader().setVisible(False)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_SLOT_COL, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_SOURCE_COL, QHeaderView.Stretch)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_PASSWORD_COL, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_CONFIRM_COL, QHeaderView.ResizeToContents)
        self.payload_table.setMinimumHeight(170)
        payload_layout.addWidget(self.payload_table)

        payload_buttons = QHBoxLayout()
        self.add_payload_button = QPushButton()
        self.remove_payload_button = QPushButton()
        self.auto_assign_button = QPushButton()
        payload_buttons.addWidget(self.add_payload_button)
        payload_buttons.addWidget(self.remove_payload_button)
        payload_buttons.addWidget(self.auto_assign_button)
        payload_buttons.addStretch(1)
        payload_layout.addLayout(payload_buttons)
        layout.addWidget(self.payload_box, 1)

        bottom_layout = QHBoxLayout()
        self.create_hint_label = QLabel()
        self.create_hint_label.setWordWrap(True)
        self.create_run_button = QPushButton()
        bottom_layout.addWidget(self.create_hint_label, 1)
        bottom_layout.addWidget(self.create_run_button)
        layout.addLayout(bottom_layout)

        self._add_payload_row(0)

    def _build_write_tab(self) -> None:
        layout = QVBoxLayout(self.write_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        self.write_box = QGroupBox()
        form = QGridLayout(self.write_box)
        self.write_container_label = QLabel()
        self.write_container_edit = QLineEdit()
        self.write_container_button = QPushButton()
        self.write_slots_label = QLabel()
        self.write_slots_spin = QSpinBox()
        self.write_slots_spin.setRange(2, 256)
        self.write_slots_spin.setValue(self.default_slot_count)
        self.write_slot_label = QLabel()
        self.write_slot_index_spin = QSpinBox()
        self.write_slot_index_spin.setRange(0, max(0, self.default_slot_count - 1))
        self.write_source_label = QLabel()
        self.write_source_edit = QLineEdit()
        self.write_source_button = QPushButton()
        self.write_password_label = QLabel()
        self.write_password_edit = QLineEdit()
        self.write_password_edit.setEchoMode(QLineEdit.Password)
        self.write_confirm_label = QLabel()
        self.write_confirm_edit = QLineEdit()
        self.write_confirm_edit.setEchoMode(QLineEdit.Password)
        self.write_run_button = QPushButton()

        self._add_path_row(form, 0, self.write_container_label, self.write_container_edit, self.write_container_button)
        form.addWidget(self.write_slots_label, 1, 0)
        form.addWidget(self.write_slots_spin, 1, 1)
        form.addWidget(self.write_slot_label, 2, 0)
        form.addWidget(self.write_slot_index_spin, 2, 1)
        self._add_path_row(form, 3, self.write_source_label, self.write_source_edit, self.write_source_button)
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
        layout.setContentsMargins(10, 10, 10, 10)
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

    def _build_settings_tab(self) -> None:
        layout = QVBoxLayout(self.settings_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.settings_box = QGroupBox()
        form = QGridLayout(self.settings_box)
        self.language_label = QLabel()
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("中文 (简体)", "zh_cn")
        self._set_language_combo(self.language)
        form.addWidget(self.language_label, 0, 0)
        form.addWidget(self.language_combo, 0, 1)
        form.setColumnStretch(2, 1)
        layout.addWidget(self.settings_box)

        self.about_box = QGroupBox()
        about_layout = QVBoxLayout(self.about_box)
        self.about_label = QLabel()
        self.about_label.setWordWrap(True)
        self.about_button = QPushButton()
        about_layout.addWidget(self.about_label)
        about_layout.addWidget(self.about_button, alignment=Qt.AlignLeft)
        layout.addWidget(self.about_box)
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
        self.about_button.clicked.connect(self._show_about)
        self.language_combo.currentIndexChanged.connect(self._language_changed)
        self.create_container_button.clicked.connect(self._browse_create_container)
        self.add_payload_button.clicked.connect(self._add_payload_from_button)
        self.remove_payload_button.clicked.connect(self._remove_selected_payload)
        self.auto_assign_button.clicked.connect(self._auto_assign_slots)
        self.create_slots_spin.valueChanged.connect(self._sync_slot_index_limits)
        self.create_run_button.clicked.connect(self._run_create)
        self.write_container_button.clicked.connect(lambda: self._browse_open_file(self.write_container_edit))
        self.write_source_button.clicked.connect(lambda: self._browse_directory(self.write_source_edit))
        self.write_slots_spin.valueChanged.connect(self._sync_slot_index_limits)
        self.write_run_button.clicked.connect(self._run_write)
        self.extract_container_button.clicked.connect(lambda: self._browse_open_file(self.extract_container_edit))
        self.extract_output_button.clicked.connect(lambda: self._browse_directory(self.extract_output_edit))
        self.extract_run_button.clicked.connect(self._run_extract)

    def _apply_translations(self) -> None:
        self.setWindowTitle(self.tr.t("app.title"))
        self.tabs.setTabText(0, self.tr.t("gui.tab.create"))
        self.tabs.setTabText(1, self.tr.t("gui.tab.write_slot"))
        self.tabs.setTabText(2, self.tr.t("gui.tab.extract"))
        self.tabs.setTabText(3, self.tr.t("gui.tab.settings"))

        self.create_box.setTitle(self.tr.t("gui.group.create"))
        self.create_container_label.setText(self.tr.t("gui.label.container"))
        self.create_size_label.setText(self.tr.t("gui.label.size_mb"))
        self.create_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.create_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.payload_box.setTitle(self.tr.t("gui.group.payload_slots"))
        self.add_payload_button.setText(self.tr.t("gui.button.add_payload"))
        self.remove_payload_button.setText(self.tr.t("gui.button.remove_payload"))
        self.auto_assign_button.setText(self.tr.t("gui.button.auto_assign_slot"))
        self.create_run_button.setText(self.tr.t("gui.button.create"))
        self.create_hint_label.setText(self.tr.t("gui.hint.payloads"))
        self.payload_table.setHorizontalHeaderLabels(
            [
                self.tr.t("gui.table.slot"),
                self.tr.t("gui.table.source_dir"),
                self.tr.t("gui.table.password"),
                self.tr.t("gui.table.confirm_password"),
            ]
        )
        self._sync_payload_row_translations()

        self.write_box.setTitle(self.tr.t("gui.group.write_slot"))
        self.write_container_label.setText(self.tr.t("gui.label.container"))
        self.write_source_label.setText(self.tr.t("gui.label.source_dir"))
        self.write_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.write_slot_label.setText(self.tr.t("gui.label.slot_index"))
        self.write_password_label.setText(self.tr.t("gui.label.password"))
        self.write_confirm_label.setText(self.tr.t("gui.label.confirm_password"))
        self.write_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.write_source_button.setText(self.tr.t("gui.button.browse_dir"))
        self.write_run_button.setText(self.tr.t("gui.button.write_slot"))

        self.extract_box.setTitle(self.tr.t("gui.group.extract"))
        self.extract_container_label.setText(self.tr.t("gui.label.container"))
        self.extract_output_label.setText(self.tr.t("gui.label.output_dir"))
        self.extract_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.extract_password_label.setText(self.tr.t("gui.label.password"))
        self.extract_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.extract_output_button.setText(self.tr.t("gui.button.browse_dir"))
        self.extract_run_button.setText(self.tr.t("gui.button.extract"))

        self.settings_box.setTitle(self.tr.t("gui.group.settings"))
        self.language_label.setText(self.tr.t("gui.label.language"))
        self.about_box.setTitle(self.tr.t("gui.group.about"))
        self.about_label.setText(self.tr.t("gui.message.about"))
        self.about_button.setText(self.tr.t("gui.button.about"))

        for edit, key in [
            (self.create_container_edit, "gui.placeholder.container_new"),
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

    def _browse_create_container(self) -> None:
        path, _selected = QFileDialog.getSaveFileName(
            self,
            self.tr.t("gui.dialog.select_container_save"),
            str(self.repo_root / f"vault{self.default_extension}"),
            CONTAINER_FILTER,
        )
        if path:
            self.create_container_edit.setText(path)

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

    def _add_payload_from_button(self) -> None:
        slot_index = self._next_unused_slot()
        if slot_index is None:
            self._show_warning(self.tr.t("gui.message.no_unused_slots"))
            return
        self._add_payload_row(slot_index)

    def _add_payload_row(self, slot_index: int | None = None, source_dir: str = "", password: str = "", confirm: str = "") -> None:
        row = self.payload_table.rowCount()
        self.payload_table.insertRow(row)

        slot_spin = QSpinBox()
        slot_spin.setRange(0, max(0, self.create_slots_spin.value() - 1))
        slot_spin.setValue(0 if slot_index is None else slot_index)
        self.payload_table.setCellWidget(row, PAYLOAD_SLOT_COL, slot_spin)

        source_wrapper = QWidget()
        source_layout = QHBoxLayout(source_wrapper)
        source_layout.setContentsMargins(0, 0, 0, 0)
        source_edit = QLineEdit(source_dir)
        source_edit.setPlaceholderText(self.tr.t("gui.placeholder.source_dir"))
        source_button = QPushButton(self.tr.t("gui.button.browse_dir"))
        source_button.clicked.connect(lambda _checked=False, edit=source_edit: self._browse_directory(edit))
        source_layout.addWidget(source_edit, 1)
        source_layout.addWidget(source_button)
        self.payload_table.setCellWidget(row, PAYLOAD_SOURCE_COL, source_wrapper)

        password_edit = QLineEdit(password)
        password_edit.setEchoMode(QLineEdit.Password)
        self.payload_table.setCellWidget(row, PAYLOAD_PASSWORD_COL, password_edit)

        confirm_edit = QLineEdit(confirm)
        confirm_edit.setEchoMode(QLineEdit.Password)
        self.payload_table.setCellWidget(row, PAYLOAD_CONFIRM_COL, confirm_edit)
        self.payload_table.selectRow(row)

    def _remove_selected_payload(self) -> None:
        row = self.payload_table.currentRow()
        if row < 0:
            self._show_warning(self.tr.t("gui.message.select_payload"))
            return
        self.payload_table.removeRow(row)

    def _auto_assign_slots(self) -> None:
        rows = self._selected_payload_rows() or list(range(self.payload_table.rowCount()))
        slot_count = self.create_slots_spin.value()
        used_slots = {
            self._payload_slot_spin(row).value()
            for row in range(self.payload_table.rowCount())
            if row not in rows
        }
        available_slots = [slot for slot in range(slot_count) if slot not in used_slots]
        if len(available_slots) < len(rows):
            self._show_warning(self.tr.t("gui.message.not_enough_slots"))
            return
        for row, slot in zip(rows, available_slots):
            self._payload_slot_spin(row).setValue(slot)

    def _selected_payload_rows(self) -> list[int]:
        return sorted({index.row() for index in self.payload_table.selectedIndexes()})

    def _next_unused_slot(self) -> int | None:
        used = {self._payload_slot_spin(row).value() for row in range(self.payload_table.rowCount())}
        for slot in range(self.create_slots_spin.value()):
            if slot not in used:
                return slot
        return None

    def _payload_slot_spin(self, row: int) -> QSpinBox:
        widget = self.payload_table.cellWidget(row, PAYLOAD_SLOT_COL)
        if not isinstance(widget, QSpinBox):
            raise RuntimeError("Payload slot cell is not a spin box")
        return widget

    def _payload_source_edit(self, row: int) -> QLineEdit:
        wrapper = self.payload_table.cellWidget(row, PAYLOAD_SOURCE_COL)
        if wrapper is None or wrapper.layout() is None:
            raise RuntimeError("Payload source cell is invalid")
        edit = wrapper.layout().itemAt(0).widget()
        if not isinstance(edit, QLineEdit):
            raise RuntimeError("Payload source cell is not a line edit")
        return edit

    def _payload_source_button(self, row: int) -> QPushButton:
        wrapper = self.payload_table.cellWidget(row, PAYLOAD_SOURCE_COL)
        if wrapper is None or wrapper.layout() is None:
            raise RuntimeError("Payload source cell is invalid")
        button = wrapper.layout().itemAt(1).widget()
        if not isinstance(button, QPushButton):
            raise RuntimeError("Payload source cell is not a button")
        return button

    def _payload_password_edit(self, row: int) -> QLineEdit:
        widget = self.payload_table.cellWidget(row, PAYLOAD_PASSWORD_COL)
        if not isinstance(widget, QLineEdit):
            raise RuntimeError("Payload password cell is not a line edit")
        return widget

    def _payload_confirm_edit(self, row: int) -> QLineEdit:
        widget = self.payload_table.cellWidget(row, PAYLOAD_CONFIRM_COL)
        if not isinstance(widget, QLineEdit):
            raise RuntimeError("Payload confirmation cell is not a line edit")
        return widget

    def _sync_payload_row_translations(self) -> None:
        for row in range(self.payload_table.rowCount()):
            self._payload_source_edit(row).setPlaceholderText(self.tr.t("gui.placeholder.source_dir"))
            self._payload_source_button(row).setText(self.tr.t("gui.button.browse_dir"))

    def _collect_create_payloads(self) -> tuple[list[PayloadInput] | None, str | None]:
        if self.payload_table.rowCount() == 0:
            return None, self.tr.t("gui.message.no_payloads")
        payloads: list[PayloadInput] = []
        seen_slots: set[int] = set()
        slot_count = self.create_slots_spin.value()
        for row in range(self.payload_table.rowCount()):
            slot_index = self._payload_slot_spin(row).value()
            if not 0 <= slot_index < slot_count:
                return None, self.tr.t("gui.message.slot_out_of_range")
            if slot_index in seen_slots:
                return None, self.tr.t("gui.message.duplicate_slots")
            seen_slots.add(slot_index)

            source_raw = self._payload_source_edit(row).text().strip()
            if not source_raw:
                return None, self.tr.t("gui.message.select_source")
            source_dir = Path(source_raw)
            if not source_dir.exists() or not source_dir.is_dir():
                return None, self.tr.t("gui.message.source_missing")

            password = self._payload_password_edit(row).text()
            if password != self._payload_confirm_edit(row).text():
                return None, self.tr.t("gui.message.password_mismatch")
            payloads.append(PayloadInput(slot_index=slot_index, source_dir=source_dir, password=password))
        return payloads, None

    def _run_create(self) -> None:
        container = self._required_path(self.create_container_edit, "gui.message.select_container")
        if container is None:
            return
        payloads, error = self._collect_create_payloads()
        if error is not None:
            self._show_warning(error)
            return
        if payloads is None:
            return
        if container.exists():
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.overwrite_container"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
                return
        worker = CreateContainerWorker(
            container,
            self.create_size_spin.value(),
            self.create_slots_spin.value(),
            payloads,
            self.tr.t("gui.message.create_complete"),
        )
        self._start_worker(worker, self.tr.t("gui.status.creating"))

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
        self.tabs.setEnabled(not busy)
        if busy:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)

    def _sync_slot_index_limits(self) -> None:
        max_create_slot = max(0, self.create_slots_spin.value() - 1)
        for row in range(self.payload_table.rowCount()):
            self._payload_slot_spin(row).setMaximum(max_create_slot)
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
