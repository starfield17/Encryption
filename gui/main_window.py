from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QCheckBox,
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
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.archiver import (
    DEFAULT_CONTAINER_SIZE_MB,
    DEFAULT_SLOT_COUNT,
    DEFAULT_WRAPPER_ENTRY_NAME,
    NONCE_LEN,
    PAYLOAD_HEADER_LEN,
    SALT_LEN,
    TAG_LEN,
    ZIP_ENTRY_MODE_ARCHIVE,
    ZIP_ENTRY_MODE_FILES,
    ZipWrapperOptions,
)
from core.config_store import load_app_config, load_preset, update_app_config
from core.i18n import get_translator
from gui.theme import apply_theme
from gui.window_geometry import clamped_window_size
from gui.workers import AnalyzePayloadsWorker, CreateContainerWorker, ExtractWorker, PayloadEstimate, PayloadInput, WriteWorker


CONTAINER_FILTER = "ZIP-compatible containers (*.zip);;DARC containers (*.darc *.bin *.img);;All files (*)"
PAYLOAD_SLOT_COL = 0
PAYLOAD_SOURCE_COL = 1
PAYLOAD_ESTIMATE_COL = 2
PAYLOAD_CAPACITY_COL = 3
PAYLOAD_STATUS_COL = 4
MIB = 1024 * 1024
SLOT_OVERHEAD = SALT_LEN + NONCE_LEN + TAG_LEN + PAYLOAD_HEADER_LEN


class PayloadTableWidget(QTableWidget):
    def __init__(self, drop_handler, *args) -> None:
        super().__init__(*args)
        self._drop_handler = drop_handler
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)

    def dragEnterEvent(self, event) -> None:
        if self._dropped_directories(event.mimeData()):
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        self.dragEnterEvent(event)

    def dropEvent(self, event) -> None:
        directories = self._dropped_directories(event.mimeData())
        if directories:
            self._drop_handler(directories)
            event.acceptProposedAction()
            return
        event.ignore()

    def _dropped_directories(self, mime_data) -> list[Path]:
        if not mime_data.hasUrls():
            return []
        directories: list[Path] = []
        for url in mime_data.urls():
            if not url.isLocalFile():
                continue
            path = Path(url.toLocalFile())
            if path.exists() and path.is_dir():
                directories.append(path)
        return directories


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
        self._payload_passwords: list[str] = []
        self._payload_confirms: list[str] = []
        self._payload_estimates: list[int | None] = []
        self._payload_estimate_errors: list[str | None] = []
        self._payload_detail_row: int | None = None
        self._payload_detail_guard = False
        self._auto_plan_after_analysis = False

        preset = self._load_default_preset()
        self.default_container_size_mb = int(preset.get("container_size_mb", DEFAULT_CONTAINER_SIZE_MB))
        self.default_slot_count = int(preset.get("slot_count", DEFAULT_SLOT_COUNT))
        self.default_extension = str(preset.get("default_extension", ".zip"))

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
                "default_extension": ".zip",
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
        self.create_compress_check = QCheckBox()
        self.create_compress_check.setChecked(True)

        self._add_path_row(form, 0, self.create_container_label, self.create_container_edit, self.create_container_button)
        form.addWidget(self.create_size_label, 1, 0)
        form.addWidget(self.create_size_spin, 1, 1)
        form.addWidget(self.create_slots_label, 2, 0)
        form.addWidget(self.create_slots_spin, 2, 1)
        form.addWidget(self.create_compress_check, 3, 1)
        form.setColumnStretch(1, 1)
        layout.addWidget(self.create_box)

        self.zip_wrapper_box = QGroupBox()
        wrapper_form = QGridLayout(self.zip_wrapper_box)
        self.zip_wrapper_check = QCheckBox()
        self.zip_wrapper_check.setChecked(True)
        self.zip_visible_source_label = QLabel()
        self.zip_visible_source_edit = QLineEdit()
        self.zip_visible_source_button = QPushButton()
        self.zip_entry_source_label = QLabel()
        self.zip_entry_source_edit = QLineEdit()
        self.zip_entry_source_button = QPushButton()
        self.zip_entry_mode_label = QLabel()
        self.zip_entry_mode_combo = QComboBox()
        self.zip_entry_mode_combo.addItem("", ZIP_ENTRY_MODE_ARCHIVE)
        self.zip_entry_mode_combo.addItem("", ZIP_ENTRY_MODE_FILES)
        self.zip_entry_name_label = QLabel()
        self.zip_entry_name_edit = QLineEdit(DEFAULT_WRAPPER_ENTRY_NAME)
        self.zip_entry_password_label = QLabel()
        self.zip_entry_password_edit = QLineEdit()
        self.zip_entry_password_edit.setEchoMode(QLineEdit.Password)
        self.zip_entry_confirm_label = QLabel()
        self.zip_entry_confirm_edit = QLineEdit()
        self.zip_entry_confirm_edit.setEchoMode(QLineEdit.Password)
        self.zip_entry_show_password_check = QCheckBox()

        wrapper_form.addWidget(self.zip_wrapper_check, 0, 1)
        self._add_path_row(wrapper_form, 1, self.zip_visible_source_label, self.zip_visible_source_edit, self.zip_visible_source_button)
        self._add_path_row(wrapper_form, 2, self.zip_entry_source_label, self.zip_entry_source_edit, self.zip_entry_source_button)
        wrapper_form.addWidget(self.zip_entry_mode_label, 3, 0)
        wrapper_form.addWidget(self.zip_entry_mode_combo, 3, 1)
        wrapper_form.addWidget(self.zip_entry_name_label, 4, 0)
        wrapper_form.addWidget(self.zip_entry_name_edit, 4, 1)
        wrapper_form.addWidget(self.zip_entry_password_label, 5, 0)
        wrapper_form.addWidget(self.zip_entry_password_edit, 5, 1)
        wrapper_form.addWidget(self.zip_entry_confirm_label, 6, 0)
        wrapper_form.addWidget(self.zip_entry_confirm_edit, 6, 1)
        wrapper_form.addWidget(self.zip_entry_show_password_check, 7, 1)
        wrapper_form.setColumnStretch(1, 1)
        layout.addWidget(self.zip_wrapper_box)

        self.payload_box = QGroupBox()
        payload_layout = QVBoxLayout(self.payload_box)
        self.payload_table = PayloadTableWidget(self._add_payload_sources, 0, 5)
        self.payload_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.payload_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.payload_table.verticalHeader().setVisible(False)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_SLOT_COL, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_SOURCE_COL, QHeaderView.Stretch)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_ESTIMATE_COL, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_CAPACITY_COL, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(PAYLOAD_STATUS_COL, QHeaderView.ResizeToContents)
        self.payload_table.setMinimumHeight(170)
        payload_layout.addWidget(self.payload_table)

        payload_buttons = QHBoxLayout()
        self.add_payload_button = QPushButton()
        self.remove_payload_button = QPushButton()
        self.analyze_payloads_button = QPushButton()
        self.auto_plan_button = QPushButton()
        self.auto_assign_button = QPushButton()
        payload_buttons.addWidget(self.add_payload_button)
        payload_buttons.addWidget(self.remove_payload_button)
        payload_buttons.addWidget(self.analyze_payloads_button)
        payload_buttons.addWidget(self.auto_plan_button)
        payload_buttons.addWidget(self.auto_assign_button)
        payload_buttons.addStretch(1)
        payload_layout.addLayout(payload_buttons)
        layout.addWidget(self.payload_box, 1)

        self.payload_detail_box = QGroupBox()
        detail_layout = QGridLayout(self.payload_detail_box)
        self.detail_password_label = QLabel()
        self.detail_password_edit = QLineEdit()
        self.detail_password_edit.setEchoMode(QLineEdit.Password)
        self.detail_confirm_label = QLabel()
        self.detail_confirm_edit = QLineEdit()
        self.detail_confirm_edit.setEchoMode(QLineEdit.Password)
        self.detail_show_password_check = QCheckBox()
        self.detail_skip_confirm_check = QCheckBox()
        self.detail_password_hint_label = QLabel()
        self.detail_password_hint_label.setWordWrap(True)
        detail_layout.addWidget(self.detail_password_label, 0, 0)
        detail_layout.addWidget(self.detail_password_edit, 0, 1)
        detail_layout.addWidget(self.detail_confirm_label, 1, 0)
        detail_layout.addWidget(self.detail_confirm_edit, 1, 1)
        detail_options = QHBoxLayout()
        detail_options.addWidget(self.detail_show_password_check)
        detail_options.addWidget(self.detail_skip_confirm_check)
        detail_options.addStretch(1)
        detail_layout.addLayout(detail_options, 2, 1)
        detail_layout.addWidget(self.detail_password_hint_label, 3, 1)
        detail_layout.setColumnStretch(1, 1)
        layout.addWidget(self.payload_detail_box)

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
        self.write_compress_check = QCheckBox()
        self.write_compress_check.setChecked(True)
        self.write_password_label = QLabel()
        self.write_password_edit = QLineEdit()
        self.write_password_edit.setEchoMode(QLineEdit.Password)
        self.write_confirm_label = QLabel()
        self.write_confirm_edit = QLineEdit()
        self.write_confirm_edit.setEchoMode(QLineEdit.Password)
        self.write_show_password_check = QCheckBox()
        self.write_skip_confirm_check = QCheckBox()
        self.write_password_hint_label = QLabel()
        self.write_password_hint_label.setWordWrap(True)
        self.write_run_button = QPushButton()

        self._add_path_row(form, 0, self.write_container_label, self.write_container_edit, self.write_container_button)
        form.addWidget(self.write_slots_label, 1, 0)
        form.addWidget(self.write_slots_spin, 1, 1)
        form.addWidget(self.write_slot_label, 2, 0)
        form.addWidget(self.write_slot_index_spin, 2, 1)
        self._add_path_row(form, 3, self.write_source_label, self.write_source_edit, self.write_source_button)
        form.addWidget(self.write_compress_check, 4, 1)
        form.addWidget(self.write_password_label, 5, 0)
        form.addWidget(self.write_password_edit, 5, 1)
        form.addWidget(self.write_confirm_label, 6, 0)
        form.addWidget(self.write_confirm_edit, 6, 1)
        write_options = QHBoxLayout()
        write_options.addWidget(self.write_show_password_check)
        write_options.addWidget(self.write_skip_confirm_check)
        write_options.addStretch(1)
        form.addLayout(write_options, 7, 1)
        form.addWidget(self.write_password_hint_label, 8, 1)
        form.addWidget(self.write_run_button, 9, 1)
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
        self.extract_show_password_check = QCheckBox()
        self.extract_try_common_slots_check = QCheckBox()
        self.extract_run_button = QPushButton()

        self._add_path_row(form, 0, self.extract_container_label, self.extract_container_edit, self.extract_container_button)
        self._add_path_row(form, 1, self.extract_output_label, self.extract_output_edit, self.extract_output_button)
        form.addWidget(self.extract_slots_label, 2, 0)
        form.addWidget(self.extract_slots_spin, 2, 1)
        form.addWidget(self.extract_password_label, 3, 0)
        form.addWidget(self.extract_password_edit, 3, 1)
        form.addWidget(self.extract_show_password_check, 4, 1)
        form.addWidget(self.extract_try_common_slots_check, 5, 1)
        form.addWidget(self.extract_run_button, 6, 1)
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
        self.zip_wrapper_check.stateChanged.connect(self._update_zip_wrapper_controls)
        self.zip_visible_source_button.clicked.connect(lambda: self._browse_directory(self.zip_visible_source_edit))
        self.zip_entry_source_button.clicked.connect(lambda: self._browse_directory(self.zip_entry_source_edit))
        self.zip_entry_mode_combo.currentIndexChanged.connect(self._update_zip_wrapper_controls)
        self.zip_entry_show_password_check.stateChanged.connect(self._update_zip_wrapper_controls)
        self.add_payload_button.clicked.connect(self._add_payload_from_button)
        self.remove_payload_button.clicked.connect(self._remove_selected_payload)
        self.analyze_payloads_button.clicked.connect(self._run_analyze_payloads)
        self.auto_plan_button.clicked.connect(self._run_auto_plan)
        self.auto_assign_button.clicked.connect(self._auto_assign_slots)
        self.create_slots_spin.valueChanged.connect(self._sync_slot_index_limits)
        self.create_slots_spin.valueChanged.connect(self._refresh_payload_planning)
        self.create_size_spin.valueChanged.connect(self._refresh_payload_planning)
        self.create_compress_check.stateChanged.connect(self._payload_sources_changed)
        self.payload_table.itemSelectionChanged.connect(self._payload_selection_changed)
        self.detail_password_edit.textChanged.connect(self._detail_password_changed)
        self.detail_confirm_edit.textChanged.connect(self._detail_confirm_changed)
        self.detail_show_password_check.stateChanged.connect(self._update_create_password_controls)
        self.detail_skip_confirm_check.stateChanged.connect(self._update_create_password_controls)
        self.create_run_button.clicked.connect(self._run_create)
        self.write_container_button.clicked.connect(lambda: self._browse_open_file(self.write_container_edit))
        self.write_source_button.clicked.connect(lambda: self._browse_directory(self.write_source_edit))
        self.write_slots_spin.valueChanged.connect(self._sync_slot_index_limits)
        self.write_password_edit.textChanged.connect(self._update_write_password_controls)
        self.write_show_password_check.stateChanged.connect(self._update_write_password_controls)
        self.write_skip_confirm_check.stateChanged.connect(self._update_write_password_controls)
        self.extract_show_password_check.stateChanged.connect(self._update_extract_password_controls)
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

        self.create_box.setTitle(self.tr.t("gui.group.container_file"))
        self.create_container_label.setText(self.tr.t("gui.label.container"))
        self.create_size_label.setText(self.tr.t("gui.label.size_mb"))
        self.create_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.create_compress_check.setText(self.tr.t("gui.label.compress_payload"))
        self.create_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.zip_wrapper_box.setTitle(self.tr.t("gui.group.zip_layer"))
        self.zip_wrapper_check.setText(self.tr.t("gui.label.zip_wrapper"))
        self.zip_visible_source_label.setText(self.tr.t("gui.label.visible_source_dir"))
        self.zip_entry_source_label.setText(self.tr.t("gui.label.passworded_entry_source_dir"))
        self.zip_entry_mode_label.setText(self.tr.t("gui.label.passworded_entry_mode"))
        self.zip_entry_mode_combo.setItemText(0, self.tr.t("gui.option.passworded_entry_mode_archive"))
        self.zip_entry_mode_combo.setItemText(1, self.tr.t("gui.option.passworded_entry_mode_files"))
        self.zip_entry_name_label.setText(self.tr.t("gui.label.passworded_entry_name"))
        self.zip_entry_password_label.setText(self.tr.t("gui.label.passworded_entry_password"))
        self.zip_entry_confirm_label.setText(self.tr.t("gui.label.confirm_password"))
        self.zip_entry_show_password_check.setText(self.tr.t("gui.label.show_password"))
        self.zip_visible_source_button.setText(self.tr.t("gui.button.browse_dir"))
        self.zip_entry_source_button.setText(self.tr.t("gui.button.browse_dir"))
        self._update_zip_wrapper_controls()
        self.payload_box.setTitle(self.tr.t("gui.group.payload_slots"))
        self.add_payload_button.setText(self.tr.t("gui.button.add_folder"))
        self.remove_payload_button.setText(self.tr.t("gui.button.remove_payload"))
        self.analyze_payloads_button.setText(self.tr.t("gui.button.analyze_payloads"))
        self.auto_plan_button.setText(self.tr.t("gui.button.auto_plan"))
        self.auto_assign_button.setText(self.tr.t("gui.button.auto_assign_slots"))
        self.create_run_button.setText(self.tr.t("gui.button.create"))
        self.create_hint_label.setText(self.tr.t("gui.hint.payloads"))
        self.payload_table.setHorizontalHeaderLabels(
            [
                self.tr.t("gui.table.slot"),
                self.tr.t("gui.table.source_dir"),
                self.tr.t("gui.table.estimated_archive"),
                self.tr.t("gui.table.slot_capacity"),
                self.tr.t("gui.table.status"),
            ]
        )
        self.payload_detail_box.setTitle(self.tr.t("gui.group.selected_payload"))
        self.detail_password_label.setText(self.tr.t("gui.label.password"))
        self.detail_confirm_label.setText(self.tr.t("gui.label.confirm_password"))
        self.detail_show_password_check.setText(self.tr.t("gui.label.show_password"))
        self.detail_skip_confirm_check.setText(self.tr.t("gui.label.skip_confirmation"))
        self._sync_payload_row_translations()
        self._refresh_payload_planning()
        self._update_create_password_controls()

        self.write_box.setTitle(self.tr.t("gui.group.write_slot"))
        self.write_container_label.setText(self.tr.t("gui.label.container"))
        self.write_source_label.setText(self.tr.t("gui.label.source_dir"))
        self.write_slots_label.setText(self.tr.t("gui.label.slot_count"))
        self.write_slot_label.setText(self.tr.t("gui.label.slot_index"))
        self.write_compress_check.setText(self.tr.t("gui.label.compress_payload"))
        self.write_password_label.setText(self.tr.t("gui.label.password"))
        self.write_confirm_label.setText(self.tr.t("gui.label.confirm_password"))
        self.write_show_password_check.setText(self.tr.t("gui.label.show_password"))
        self.write_skip_confirm_check.setText(self.tr.t("gui.label.skip_confirmation"))
        self.write_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.write_source_button.setText(self.tr.t("gui.button.browse_dir"))
        self.write_run_button.setText(self.tr.t("gui.button.write_slot"))
        self._update_write_password_controls()

        self.extract_box.setTitle(self.tr.t("gui.group.extract"))
        self.extract_container_label.setText(self.tr.t("gui.label.container"))
        self.extract_output_label.setText(self.tr.t("gui.label.output_dir"))
        self.extract_slots_label.setText(self.tr.t("gui.label.slot_count_created"))
        self.extract_password_label.setText(self.tr.t("gui.label.password"))
        self.extract_show_password_check.setText(self.tr.t("gui.label.show_password"))
        self.extract_try_common_slots_check.setText(self.tr.t("gui.label.try_common_slot_counts"))
        self.extract_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.extract_output_button.setText(self.tr.t("gui.button.browse_dir"))
        self.extract_run_button.setText(self.tr.t("gui.button.extract"))
        self._update_extract_password_controls()

        self.settings_box.setTitle(self.tr.t("gui.group.settings"))
        self.language_label.setText(self.tr.t("gui.label.language"))
        self.about_box.setTitle(self.tr.t("gui.group.about"))
        self.about_label.setText(self.tr.t("gui.message.about"))
        self.about_button.setText(self.tr.t("gui.button.about"))

        for edit, key in [
            (self.create_container_edit, "gui.placeholder.container_new"),
            (self.zip_visible_source_edit, "gui.placeholder.visible_source_dir"),
            (self.zip_entry_source_edit, "gui.placeholder.passworded_entry_source_dir"),
            (self.zip_entry_name_edit, "gui.placeholder.passworded_entry_name"),
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
        paths = self._browse_add_payload_folders()
        if not paths:
            return
        added = self._add_payload_sources(paths)
        if added == 0:
            self._show_warning(self.tr.t("gui.message.no_usable_folders"))

    def _browse_add_payload_folders(self) -> list[Path]:
        dialog = QFileDialog(self, self.tr.t("gui.dialog.select_dirs"), str(self.repo_root))
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setOption(QFileDialog.ShowDirsOnly, True)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        for view in dialog.findChildren(QAbstractItemView):
            view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        if not dialog.exec():
            return []
        return [Path(path) for path in dialog.selectedFiles()]

    def _add_payload_sources(self, paths: list[Path]) -> int:
        added = 0
        for path in paths:
            if not path.exists() or not path.is_dir():
                continue
            row = self._first_empty_payload_row()
            if row is None:
                slot_index = self._next_unused_slot()
                if slot_index is None:
                    self._show_warning(self.tr.t("gui.message.no_unused_slots"))
                    break
                self._add_payload_row(slot_index, str(path))
                added += 1
                continue
            self._payload_source_edit(row).setText(str(path))
            self._payload_estimates[row] = None
            self._payload_estimate_errors[row] = None
            self.payload_table.selectRow(row)
            self._load_payload_detail(row)
            added += 1
        self._refresh_payload_planning()
        return added

    def _first_empty_payload_row(self) -> int | None:
        for row in range(self.payload_table.rowCount()):
            if self._payload_source_edit(row).text().strip():
                continue
            if row < len(self._payload_passwords) and self._payload_passwords[row]:
                continue
            if row < len(self._payload_confirms) and self._payload_confirms[row]:
                continue
            return row
        return None

    def _add_payload_row(self, slot_index: int | None = None, source_dir: str = "", password: str = "", confirm: str = "") -> None:
        row = self.payload_table.rowCount()
        self.payload_table.insertRow(row)
        self._payload_passwords.append(password)
        self._payload_confirms.append(confirm)
        self._payload_estimates.append(None)
        self._payload_estimate_errors.append(None)

        slot_spin = QSpinBox()
        slot_spin.setRange(0, max(0, self.create_slots_spin.value() - 1))
        slot_spin.setValue(0 if slot_index is None else slot_index)
        self.payload_table.setCellWidget(row, PAYLOAD_SLOT_COL, slot_spin)

        source_wrapper = QWidget()
        source_layout = QHBoxLayout(source_wrapper)
        source_layout.setContentsMargins(0, 0, 0, 0)
        source_edit = QLineEdit(source_dir)
        source_edit.setPlaceholderText(self.tr.t("gui.placeholder.source_dir"))
        source_edit.textChanged.connect(self._payload_sources_changed)
        source_button = QPushButton(self.tr.t("gui.button.browse_dir"))
        source_button.clicked.connect(lambda _checked=False, edit=source_edit: self._browse_directory(edit))
        source_layout.addWidget(source_edit, 1)
        source_layout.addWidget(source_button)
        self.payload_table.setCellWidget(row, PAYLOAD_SOURCE_COL, source_wrapper)

        for column in (PAYLOAD_ESTIMATE_COL, PAYLOAD_CAPACITY_COL, PAYLOAD_STATUS_COL):
            item = QTableWidgetItem()
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.payload_table.setItem(row, column, item)
        self._refresh_payload_row(row)
        self.payload_table.selectRow(row)
        self._load_payload_detail(row)

    def _remove_selected_payload(self) -> None:
        row = self.payload_table.currentRow()
        if row < 0:
            self._show_warning(self.tr.t("gui.message.select_payload"))
            return
        self.payload_table.removeRow(row)
        del self._payload_passwords[row]
        del self._payload_confirms[row]
        del self._payload_estimates[row]
        del self._payload_estimate_errors[row]
        if self.payload_table.rowCount() == 0:
            self._load_payload_detail(None)
        else:
            self.payload_table.selectRow(min(row, self.payload_table.rowCount() - 1))
            self._load_payload_detail(self.payload_table.currentRow())

    def _auto_assign_slots(self) -> None:
        rows = list(range(self.payload_table.rowCount()))
        slot_count = self.create_slots_spin.value()
        if len(rows) > slot_count:
            self._show_warning(self.tr.t("gui.message.not_enough_slots"))
            return
        for row, slot in zip(rows, self._spread_slot_indexes(len(rows), slot_count)):
            self._payload_slot_spin(row).setValue(slot)
        self._refresh_payload_planning()

    def _next_unused_slot(self) -> int | None:
        used = {self._payload_slot_spin(row).value() for row in range(self.payload_table.rowCount())}
        for slot in range(self.create_slots_spin.value()):
            if slot not in used:
                return slot
        return None

    def _spread_slot_indexes(self, payload_count: int, slot_count: int) -> list[int]:
        if payload_count <= 0:
            return []
        if payload_count > slot_count:
            return []
        if payload_count == 1:
            return [0]
        if payload_count == 2:
            if slot_count == 4:
                return [0, 2]
            if slot_count >= 8:
                return [1, max(1, (slot_count * 3 // 4) - 1)]
            return [0, slot_count - 1]

        slots = [round(index * max(1, slot_count - 2) / (payload_count - 1)) for index in range(payload_count)]
        used: set[int] = set()
        result: list[int] = []
        for slot in slots:
            slot = max(0, min(slot_count - 1, slot))
            while slot in used and slot + 1 < slot_count:
                slot += 1
            while slot in used and slot > 0:
                slot -= 1
            used.add(slot)
            result.append(slot)
        return result

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

    def _sync_payload_row_translations(self) -> None:
        for row in range(self.payload_table.rowCount()):
            self._payload_source_edit(row).setPlaceholderText(self.tr.t("gui.placeholder.source_dir"))
            self._payload_source_button(row).setText(self.tr.t("gui.button.browse_dir"))
            self._refresh_payload_row(row)

    def _payload_selection_changed(self) -> None:
        row = self.payload_table.currentRow()
        self._load_payload_detail(row if row >= 0 else None)

    def _load_payload_detail(self, row: int | None) -> None:
        self._payload_detail_guard = True
        self._payload_detail_row = row
        if row is None or row >= len(self._payload_passwords):
            self.detail_password_edit.clear()
            self.detail_confirm_edit.clear()
            self.detail_password_edit.setEnabled(False)
            self.detail_confirm_edit.setEnabled(False)
        else:
            self.detail_password_edit.setEnabled(True)
            self.detail_confirm_edit.setEnabled(True)
            self.detail_password_edit.setText(self._payload_passwords[row])
            self.detail_confirm_edit.setText(self._payload_confirms[row])
        self._payload_detail_guard = False
        self._update_create_password_controls()

    def _detail_password_changed(self, text: str) -> None:
        if self._payload_detail_guard or self._payload_detail_row is None:
            return
        if self._payload_detail_row < len(self._payload_passwords):
            self._payload_passwords[self._payload_detail_row] = text
            if self.detail_skip_confirm_check.isChecked():
                self._payload_confirms[self._payload_detail_row] = text
                self.detail_confirm_edit.setText(text)
        self._update_create_password_controls()

    def _detail_confirm_changed(self, text: str) -> None:
        if self._payload_detail_guard or self._payload_detail_row is None:
            return
        if self._payload_detail_row < len(self._payload_confirms):
            self._payload_confirms[self._payload_detail_row] = text

    def _update_create_password_controls(self, *_args) -> None:
        echo_mode = QLineEdit.Normal if self.detail_show_password_check.isChecked() else QLineEdit.Password
        self.detail_password_edit.setEchoMode(echo_mode)
        self.detail_confirm_edit.setEchoMode(echo_mode)
        has_row = self._payload_detail_row is not None and self._payload_detail_row < len(self._payload_passwords)
        confirm_enabled = has_row and not self.detail_skip_confirm_check.isChecked()
        self.detail_password_edit.setEnabled(has_row)
        self.detail_confirm_edit.setEnabled(confirm_enabled)
        self.detail_confirm_label.setEnabled(confirm_enabled)
        if has_row and self.detail_skip_confirm_check.isChecked():
            password = self.detail_password_edit.text()
            self._payload_confirms[self._payload_detail_row] = password
            if self.detail_confirm_edit.text() != password:
                self.detail_confirm_edit.setText(password)
        password = self.detail_password_edit.text() if has_row else ""
        self.detail_password_hint_label.setText(
            self.tr.t("gui.message.weak_password_hint") if self._password_looks_weak(password) else ""
        )

    def _update_write_password_controls(self, *_args) -> None:
        echo_mode = QLineEdit.Normal if self.write_show_password_check.isChecked() else QLineEdit.Password
        self.write_password_edit.setEchoMode(echo_mode)
        self.write_confirm_edit.setEchoMode(echo_mode)
        confirm_enabled = not self.write_skip_confirm_check.isChecked()
        self.write_confirm_edit.setEnabled(confirm_enabled)
        self.write_confirm_label.setEnabled(confirm_enabled)
        if self.write_skip_confirm_check.isChecked():
            self.write_confirm_edit.setText(self.write_password_edit.text())
        self.write_password_hint_label.setText(
            self.tr.t("gui.message.weak_password_hint")
            if self._password_looks_weak(self.write_password_edit.text())
            else ""
        )

    def _update_extract_password_controls(self, *_args) -> None:
        echo_mode = QLineEdit.Normal if self.extract_show_password_check.isChecked() else QLineEdit.Password
        self.extract_password_edit.setEchoMode(echo_mode)

    def _update_zip_wrapper_controls(self, *_args) -> None:
        enabled = self.zip_wrapper_check.isChecked()
        echo_mode = QLineEdit.Normal if self.zip_entry_show_password_check.isChecked() else QLineEdit.Password
        archive_mode = self._zip_entry_mode() == ZIP_ENTRY_MODE_ARCHIVE
        for widget in [
            self.zip_visible_source_label,
            self.zip_visible_source_edit,
            self.zip_visible_source_button,
            self.zip_entry_source_label,
            self.zip_entry_source_edit,
            self.zip_entry_source_button,
            self.zip_entry_mode_label,
            self.zip_entry_mode_combo,
            self.zip_entry_name_label,
            self.zip_entry_name_edit,
            self.zip_entry_password_label,
            self.zip_entry_password_edit,
            self.zip_entry_confirm_label,
            self.zip_entry_confirm_edit,
            self.zip_entry_show_password_check,
        ]:
            widget.setEnabled(enabled)
        self.zip_entry_name_label.setEnabled(enabled and archive_mode)
        self.zip_entry_name_edit.setEnabled(enabled and archive_mode)
        self.zip_entry_password_edit.setEchoMode(echo_mode)
        self.zip_entry_confirm_edit.setEchoMode(echo_mode)

    def _zip_entry_mode(self) -> str:
        mode = str(self.zip_entry_mode_combo.currentData())
        if mode in {ZIP_ENTRY_MODE_ARCHIVE, ZIP_ENTRY_MODE_FILES}:
            return mode
        return ZIP_ENTRY_MODE_ARCHIVE

    def _password_looks_weak(self, password: str) -> bool:
        if not password:
            return False
        if len(password) >= 20:
            return False
        if len([part for part in password.split() if part]) >= 6:
            return False
        return True

    def _payload_sources_changed(self) -> None:
        for row in range(self.payload_table.rowCount()):
            self._payload_estimates[row] = None
            self._payload_estimate_errors[row] = None
        self._refresh_payload_planning()

    def _container_size_bytes(self) -> int:
        return self.create_size_spin.value() * MIB

    def _slot_capacity_bytes(self, size_mb: int | None = None, slot_count: int | None = None) -> int:
        size_bytes = (self.create_size_spin.value() if size_mb is None else size_mb) * MIB
        slots = self.create_slots_spin.value() if slot_count is None else slot_count
        if slots <= 0:
            return 0
        return max(0, size_bytes // slots - SLOT_OVERHEAD)

    def _format_size(self, size_bytes: int | None) -> str:
        if size_bytes is None:
            return "-"
        return f"{size_bytes / MIB:.2f} MiB"

    def _status_text_for_row(self, row: int) -> str:
        if self._payload_estimate_errors[row]:
            return self.tr.t("gui.status_payload.error")
        estimate = self._payload_estimates[row]
        if estimate is None:
            return self.tr.t("gui.status_payload.not_analyzed")
        if estimate <= self._slot_capacity_bytes():
            return self.tr.t("gui.status_payload.ok")
        return self.tr.t("gui.status_payload.too_large")

    def _refresh_payload_row(self, row: int) -> None:
        estimate = self._payload_estimates[row] if row < len(self._payload_estimates) else None
        values = {
            PAYLOAD_ESTIMATE_COL: self._format_size(estimate),
            PAYLOAD_CAPACITY_COL: self._format_size(self._slot_capacity_bytes()),
            PAYLOAD_STATUS_COL: self._status_text_for_row(row),
        }
        for column, value in values.items():
            item = self.payload_table.item(row, column)
            if item is None:
                item = QTableWidgetItem()
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.payload_table.setItem(row, column, item)
            item.setText(value)

    def _refresh_payload_planning(self) -> None:
        for row in range(self.payload_table.rowCount()):
            self._refresh_payload_row(row)

    def _analysis_sources(self) -> tuple[list[tuple[int, Path]] | None, str | None]:
        if self.payload_table.rowCount() == 0:
            return None, self.tr.t("gui.message.no_payloads")
        sources: list[tuple[int, Path]] = []
        for row in range(self.payload_table.rowCount()):
            source_raw = self._payload_source_edit(row).text().strip()
            if not source_raw:
                return None, self.tr.t("gui.message.select_source")
            source_dir = Path(source_raw)
            if not source_dir.exists() or not source_dir.is_dir():
                return None, self.tr.t("gui.message.source_missing")
            sources.append((row, source_dir))
        return sources, None

    def _run_analyze_payloads(self) -> None:
        sources, error = self._analysis_sources()
        if error is not None:
            self._auto_plan_after_analysis = False
            self._show_warning(error)
            return
        if sources is None:
            self._auto_plan_after_analysis = False
            return
        worker = AnalyzePayloadsWorker(sources, compress=self.create_compress_check.isChecked())
        self._start_worker(worker, self.tr.t("gui.status.analyzing"), completed_handler=self._analysis_completed)

    def _analysis_completed(self, estimates: list[PayloadEstimate]) -> None:
        for estimate in estimates:
            if estimate.row_index >= self.payload_table.rowCount():
                continue
            current_source = Path(self._payload_source_edit(estimate.row_index).text().strip())
            if current_source != estimate.source_dir:
                continue
            self._payload_estimates[estimate.row_index] = estimate.zip_size
            self._payload_estimate_errors[estimate.row_index] = estimate.error
        self._refresh_payload_planning()
        self._finish_worker(self.tr.t("gui.message.analysis_complete"))
        if self._auto_plan_after_analysis:
            self._auto_plan_after_analysis = False
            self._apply_auto_plan()

    def _run_auto_plan(self) -> None:
        if self.payload_table.rowCount() == 0:
            self._show_warning(self.tr.t("gui.message.no_payloads"))
            return
        if any(estimate is None for estimate in self._payload_estimates):
            self._auto_plan_after_analysis = True
            self._run_analyze_payloads()
            return
        self._apply_auto_plan()

    def _recommended_slot_count(self, payload_count: int) -> int:
        if payload_count <= 2:
            return 4
        if payload_count == 3:
            return 6
        value = payload_count + 2
        return value if value % 2 == 0 else value + 1

    def _compatible_size_mib(self, size_mib: int, slot_count: int) -> int:
        size_mib = max(1, size_mib)
        while (size_mib * MIB) % slot_count != 0:
            size_mib += 1
        return size_mib

    def _recommended_size_mib(self, max_zip_size: int, slot_count: int) -> int:
        required_slot_size = int((max_zip_size + SLOT_OVERHEAD) * 1.10) + 1
        raw_size_mib = (required_slot_size * slot_count + MIB - 1) // MIB
        if raw_size_mib > 10:
            raw_size_mib = ((raw_size_mib + 9) // 10) * 10
        return self._compatible_size_mib(raw_size_mib, slot_count)

    def _apply_auto_plan(self) -> None:
        payload_count = self.payload_table.rowCount()
        if payload_count == 0:
            self._show_warning(self.tr.t("gui.message.no_payloads"))
            return
        errors = [error for error in self._payload_estimate_errors if error]
        if errors:
            self._show_warning(self.tr.t("gui.message.analysis_has_errors"))
            return

        current_slots = self.create_slots_spin.value()
        recommended_slots = max(current_slots, self._recommended_slot_count(payload_count)) if current_slots < payload_count else current_slots
        estimates = [estimate for estimate in self._payload_estimates if estimate is not None]
        max_zip_size = max(estimates) if estimates else 0
        current_size = self.create_size_spin.value()
        recommended_size = current_size
        if max_zip_size > self._slot_capacity_bytes(current_size, recommended_slots):
            recommended_size = max(current_size, self._recommended_size_mib(max_zip_size, recommended_slots))
        recommended_size = self._compatible_size_mib(recommended_size, recommended_slots)

        changes: list[str] = []
        if recommended_slots != current_slots:
            changes.append(self.tr.t("gui.message.recommend_slot_count", count=recommended_slots))
        if recommended_size != current_size:
            changes.append(self.tr.t("gui.message.recommend_size", size=recommended_size))
        if not changes:
            self._set_status(self.tr.t("gui.message.plan_fits"))
            return

        message = "\n".join(changes + [self.tr.t("gui.message.apply_recommendation")])
        result = QMessageBox.question(
            self,
            self.tr.t("gui.message.info"),
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if result == QMessageBox.Yes:
            self.create_slots_spin.setValue(recommended_slots)
            self.create_size_spin.setValue(recommended_size)
            self._auto_assign_slots()
            self._set_status(self.tr.t("gui.message.plan_applied"))

    def _collect_create_payloads(self) -> tuple[list[PayloadInput] | None, str | None]:
        if self.payload_table.rowCount() == 0:
            return None, self.tr.t("gui.message.no_payloads")
        payloads: list[PayloadInput] = []
        seen_slots: set[int] = set()
        slot_count = self.create_slots_spin.value()
        if self._container_size_bytes() % slot_count != 0:
            return None, self.tr.t("gui.message.container_size_not_divisible")
        slot_capacity = self._slot_capacity_bytes()
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

            password = self._payload_passwords[row]
            if not self.detail_skip_confirm_check.isChecked() and password != self._payload_confirms[row]:
                return None, self.tr.t("gui.message.password_mismatch")
            payloads.append(
                PayloadInput(
                    slot_index=slot_index,
                    source_dir=source_dir,
                    password=password,
                    compress=self.create_compress_check.isChecked(),
                )
            )

        for row in range(self.payload_table.rowCount()):
            if self._payload_estimate_errors[row]:
                return None, self.tr.t("gui.message.analysis_has_errors")
            estimate = self._payload_estimates[row]
            if estimate is None:
                return None, self.tr.t("gui.message.analysis_required")
            if estimate > slot_capacity:
                return None, self.tr.t("gui.message.payload_too_large_for_plan")
        return payloads, None

    def _collect_zip_wrapper_options(self) -> tuple[ZipWrapperOptions | None, str | None]:
        if not self.zip_wrapper_check.isChecked():
            return None, None

        visible_source = self._optional_directory(self.zip_visible_source_edit, "gui.message.visible_source_missing")
        if isinstance(visible_source, str):
            return None, visible_source

        entry_source = self._optional_directory(self.zip_entry_source_edit, "gui.message.passworded_entry_source_missing")
        if isinstance(entry_source, str):
            return None, entry_source

        entry_password = self.zip_entry_password_edit.text()
        entry_confirm = self.zip_entry_confirm_edit.text()
        if entry_source is not None:
            if not entry_password:
                return None, self.tr.t("gui.message.passworded_entry_password_required")
            if entry_password != entry_confirm:
                return None, self.tr.t("gui.message.password_mismatch")
        elif entry_password or entry_confirm:
            return None, self.tr.t("gui.message.passworded_entry_source_required")

        entry_mode = self._zip_entry_mode()
        entry_name = self.zip_entry_name_edit.text().strip() or DEFAULT_WRAPPER_ENTRY_NAME
        return (
            ZipWrapperOptions(
                enabled=True,
                visible_source_dir=visible_source,
                encrypted_entry_source_dir=entry_source,
                encrypted_entry_name=entry_name,
                encrypted_entry_password=entry_password if entry_source is not None else None,
                encrypted_entry_mode=entry_mode,
            ),
            None,
        )

    def _optional_directory(self, edit: QLineEdit, missing_message_key: str) -> Path | str | None:
        raw = edit.text().strip()
        if not raw:
            return None
        path = Path(raw)
        if not path.exists() or not path.is_dir():
            return self.tr.t(missing_message_key)
        return path

    def _has_duplicate_passwords(self, payloads: list[PayloadInput]) -> bool:
        seen: set[str] = set()
        for payload in payloads:
            if payload.password in seen:
                return True
            seen.add(payload.password)
        return False

    def _zip_entry_password_matches_payload(self, zip_wrapper: ZipWrapperOptions | None, payloads: list[PayloadInput]) -> bool:
        if zip_wrapper is None or not zip_wrapper.encrypted_entry_password:
            return False
        return any(payload.password == zip_wrapper.encrypted_entry_password for payload in payloads)

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
        zip_wrapper, error = self._collect_zip_wrapper_options()
        if error is not None:
            self._show_warning(error)
            return
        if self._has_duplicate_passwords(payloads):
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.duplicate_passwords"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
                return
        if self._zip_entry_password_matches_payload(zip_wrapper, payloads):
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.zip_entry_password_matches_payload"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
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
            zip_wrapper,
            self.tr.t("gui.message.create_complete"),
        )
        self._start_worker(worker, self.tr.t("gui.status.creating"))

    def _run_write(self) -> None:
        container = self._required_path(self.write_container_edit, "gui.message.select_container")
        source = self._required_path(self.write_source_edit, "gui.message.select_source")
        if container is None or source is None:
            return
        password = self.write_password_edit.text()
        if not self.write_skip_confirm_check.isChecked() and password != self.write_confirm_edit.text():
            self._show_warning(self.tr.t("gui.message.password_mismatch"))
            return
        worker = WriteWorker(
            container,
            source,
            password,
            self.write_slot_index_spin.value(),
            self.write_slots_spin.value(),
            self.write_compress_check.isChecked(),
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
            self.extract_try_common_slots_check.isChecked(),
        )
        self._start_worker(worker, self.tr.t("gui.status.extracting"))

    def _required_path(self, edit: QLineEdit, message_key: str) -> Path | None:
        raw = edit.text().strip()
        if not raw:
            self._show_warning(self.tr.t(message_key))
            return None
        return Path(raw)

    def _start_worker(self, worker, status_text: str, completed_handler=None) -> None:
        if self.active_worker is not None:
            self._show_warning(self.tr.t("gui.message.busy"))
            return
        self.active_worker = worker
        worker.completed.connect(completed_handler or self._worker_completed)
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
