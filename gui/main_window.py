from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QCheckBox,
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
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from core.archiver import DEFAULT_CONTAINER_SIZE_MB, DEFAULT_SLOT_COUNT, DEFAULT_WRAPPER_ENTRY_NAME
from core.config_store import load_app_config, load_preset, update_app_config
from core.i18n import get_translator
from core.layout import MIB, equal_layout, format_slot_sizes_mib, zip_capacity_for_slot
from gui.extract_dialog import ExtractDialog
from gui.layout_fields import LayoutFieldGroup
from gui.payload_editor_dialog import PayloadEditorDialog
from gui.settings_dialog import SettingsDialog
from gui.theme import apply_theme
from gui.window_geometry import clamped_window_size
from gui.workers import AnalyzePayloadsWorker, CreateContainerWorker, PayloadEstimate, PayloadInput
from gui.write_dialog import WriteSlotDialog
from gui.zip_layer_dialog import ZipLayerDialog, ZipLayerState

CONTAINER_FILTER = "Containers (*.zip *.darc *.bin *.img);;All files (*)"
PAYLOAD_SLOT_COL = 0
PAYLOAD_SOURCE_COL = 1
PAYLOAD_ESTIMATE_COL = 2
PAYLOAD_CAPACITY_COL = 3
PAYLOAD_STATUS_COL = 4
SLOT_OVERHEAD = 16 + 12 + 16 + 48


@dataclass
class PayloadRow:
    slot_index: int
    source_dir: str
    password: str
    confirm: str
    estimate: int | None = None
    estimate_error: str | None = None


class PayloadTableWidget(QTableWidget):
    def __init__(self, drop_handler, *args) -> None:
        super().__init__(*args)
        self._drop_handler = drop_handler
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)
        self.setDefaultDropAction(Qt.CopyAction)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:
        paths = self._dropped_directories(event.mimeData())
        if paths:
            self._drop_handler(paths)
            event.acceptProposedAction()
            return
        super().dropEvent(event)

    def _dropped_directories(self, mime_data) -> list[Path]:
        result: list[Path] = []
        for url in mime_data.urls():
            path = Path(url.toLocalFile())
            if path.exists() and path.is_dir():
                result.append(path)
        return result


class MainWindow(QMainWindow):
    def __init__(self, repo_root: Path, language: str | None = None) -> None:
        super().__init__()
        self.repo_root = repo_root
        self.config_dir = repo_root / "config"
        self.app_config = load_app_config(self.config_dir)
        self.language = language or str(self.app_config.get("language", "en"))
        self.tr = get_translator(self.language, self.config_dir)
        self.active_worker = None
        self._payload_rows: list[PayloadRow] = []
        self._auto_plan_after_analysis = False
        self._zip_state = ZipLayerState(
            enabled=True,
            visible_source="",
            entry_source="",
            entry_mode="archive",
            entry_name=DEFAULT_WRAPPER_ENTRY_NAME,
            entry_password="",
            entry_confirm="",
            show_password=False,
        )
        preset = self._load_default_preset()
        self.default_container_size_mb = int(preset.get("container_size_mb", DEFAULT_CONTAINER_SIZE_MB))
        self.default_slot_count = int(preset.get("slot_count", DEFAULT_SLOT_COUNT))
        self.default_extension = str(preset.get("default_extension", ".zip"))
        self._build_ui()
        self._connect_signals()
        self._apply_translations()
        self._set_busy(False)
        self._add_payload_row()

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
        self.resize(clamped_window_size(860, 620, minimum_width=740, minimum_height=520))
        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(Qt.TopToolBarArea, toolbar)
        self.toolbar = toolbar
        style = self.style()
        self.write_action = QAction(style.standardIcon(QStyle.SP_DialogSaveButton), "", self)
        self.extract_action = QAction(style.standardIcon(QStyle.SP_DialogOpenButton), "", self)
        self.settings_action = QAction(style.standardIcon(QStyle.SP_FileDialogDetailedView), "", self)
        toolbar.addAction(self.write_action)
        toolbar.addAction(self.extract_action)
        toolbar.addSeparator()
        toolbar.addAction(self.settings_action)

        central = QScrollArea(self)
        central.setWidgetResizable(True)
        central.setFrameShape(QFrame.NoFrame)
        central.setSizeAdjustPolicy(QAbstractScrollArea.AdjustIgnored)
        self.setCentralWidget(central)
        content = QWidget(self)
        central.setWidget(content)
        root = QVBoxLayout(content)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        self.create_box = QGroupBox()
        form = QGridLayout(self.create_box)
        self.create_container_label = QLabel()
        self.create_container_edit = QLineEdit()
        self.create_container_button = QPushButton()
        self.create_size_label = QLabel()
        self.create_size_spin = QSpinBox()
        self.create_size_spin.setRange(1, 1024 * 1024)
        self.create_size_spin.setValue(self.default_container_size_mb)
        self.create_compress_check = QCheckBox()
        self.create_compress_check.setChecked(True)
        self._add_path_row(
            form, 0, self.create_container_label, self.create_container_edit, self.create_container_button
        )
        form.addWidget(self.create_size_label, 1, 0)
        form.addWidget(self.create_size_spin, 1, 1)
        form.addWidget(self.create_compress_check, 2, 1)
        form.setColumnStretch(1, 1)
        root.addWidget(self.create_box)

        self.layout_box = QGroupBox()
        layout_form = QVBoxLayout(self.layout_box)
        self.layout_fields = LayoutFieldGroup(self.tr, default_slots=self.default_slot_count)
        self.layout_hint = QLabel()
        self.layout_hint.setWordWrap(True)
        layout_form.addWidget(self.layout_fields)
        layout_form.addWidget(self.layout_hint)
        root.addWidget(self.layout_box)

        zip_row = QHBoxLayout()
        self.zip_summary_label = QLabel()
        self.zip_configure_button = QPushButton()
        zip_row.addWidget(self.zip_summary_label, 1)
        zip_row.addWidget(self.zip_configure_button)
        root.addLayout(zip_row)

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
        self.payload_table.setMinimumHeight(200)
        payload_layout.addWidget(self.payload_table)
        buttons = QHBoxLayout()
        self.add_payload_button = QPushButton()
        self.edit_payload_button = QPushButton()
        self.remove_payload_button = QPushButton()
        self.analyze_payloads_button = QPushButton()
        self.auto_plan_button = QPushButton()
        self.auto_assign_button = QPushButton()
        for button in [
            self.add_payload_button,
            self.edit_payload_button,
            self.remove_payload_button,
            self.analyze_payloads_button,
            self.auto_plan_button,
            self.auto_assign_button,
        ]:
            buttons.addWidget(button)
        buttons.addStretch(1)
        payload_layout.addLayout(buttons)
        root.addWidget(self.payload_box, 1)

        bottom = QHBoxLayout()
        self.create_hint_label = QLabel()
        self.create_hint_label.setWordWrap(True)
        self.create_run_button = QPushButton()
        bottom.addWidget(self.create_hint_label, 1)
        bottom.addWidget(self.create_run_button)
        root.addLayout(bottom)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        root.addWidget(self.progress_bar)
        status = QStatusBar(self)
        self.setStatusBar(status)
        self.status_label = QLabel()
        status.addWidget(self.status_label, 1)

    def _add_path_row(self, layout, row, label, edit, button) -> None:
        wrapper = QWidget()
        path_layout = QHBoxLayout(wrapper)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.addWidget(edit, 1)
        path_layout.addWidget(button)
        layout.addWidget(label, row, 0)
        layout.addWidget(wrapper, row, 1)

    def _connect_signals(self) -> None:
        self.write_action.triggered.connect(self._open_write_dialog)
        self.extract_action.triggered.connect(self._open_extract_dialog)
        self.settings_action.triggered.connect(self._open_settings_dialog)
        self.create_container_button.clicked.connect(self._browse_create_container)
        self.zip_configure_button.clicked.connect(self._open_zip_dialog)
        self.add_payload_button.clicked.connect(self._add_payload_from_button)
        self.edit_payload_button.clicked.connect(self._edit_selected_payload)
        self.remove_payload_button.clicked.connect(self._remove_selected_payload)
        self.analyze_payloads_button.clicked.connect(self._run_analyze_payloads)
        self.auto_plan_button.clicked.connect(self._run_auto_plan)
        self.auto_assign_button.clicked.connect(self._auto_assign_slots)
        self.create_run_button.clicked.connect(self._run_create)
        self.create_size_spin.valueChanged.connect(self._refresh_payload_planning)
        self.create_compress_check.stateChanged.connect(self._payload_sources_changed)
        self.layout_fields.mode_combo.currentIndexChanged.connect(self._refresh_payload_planning)
        self.layout_fields.slots_spin.valueChanged.connect(self._refresh_payload_planning)
        self.layout_fields.sizes_edit.textChanged.connect(self._refresh_payload_planning)
        self.payload_table.doubleClicked.connect(lambda _i: self._edit_selected_payload())

    def _apply_translations(self) -> None:
        self.setWindowTitle(self.tr.t("app.title"))
        self.write_action.setText(self.tr.t("gui.action.write"))
        self.extract_action.setText(self.tr.t("gui.action.extract"))
        self.settings_action.setText(self.tr.t("gui.action.settings"))
        for action in [self.write_action, self.extract_action, self.settings_action]:
            action.setToolTip(action.text())
        self.create_box.setTitle(self.tr.t("gui.group.container_file"))
        self.create_container_label.setText(self.tr.t("gui.label.container"))
        self.create_size_label.setText(self.tr.t("gui.label.size_mb"))
        self.create_compress_check.setText(self.tr.t("gui.label.compress_payload"))
        self.create_container_button.setText(self.tr.t("gui.button.browse_file"))
        self.create_container_edit.setPlaceholderText(self.tr.t("gui.placeholder.container_new"))
        self.layout_box.setTitle(self.tr.t("gui.group.layout"))
        self.layout_fields.apply_translations(self.tr)
        self.layout_hint.setText(self.tr.t("gui.hint.layout_secret"))
        self._refresh_zip_summary()
        self.payload_box.setTitle(self.tr.t("gui.group.payload_slots"))
        self.add_payload_button.setText(self.tr.t("gui.button.add_folder"))
        self.edit_payload_button.setText(self.tr.t("gui.button.edit_payload"))
        self.remove_payload_button.setText(self.tr.t("gui.button.remove_payload"))
        self.analyze_payloads_button.setText(self.tr.t("gui.button.analyze_payloads"))
        self.auto_plan_button.setText(self.tr.t("gui.button.auto_plan"))
        self.auto_assign_button.setText(self.tr.t("gui.button.auto_assign_slots"))
        self.create_run_button.setText(self.tr.t("gui.button.create"))
        self.create_hint_label.setText(self.tr.t("gui.hint.payloads"))
        self.zip_configure_button.setText(self.tr.t("gui.button.configure_zip_layer"))
        self.payload_table.setHorizontalHeaderLabels(
            [
                self.tr.t("gui.table.slot"),
                self.tr.t("gui.table.source_dir"),
                self.tr.t("gui.table.estimated_archive"),
                self.tr.t("gui.table.slot_capacity"),
                self.tr.t("gui.table.status"),
            ]
        )
        self._refresh_payload_planning()
        self._set_status(self.tr.t("gui.status.ready"))

    def _refresh_zip_summary(self) -> None:
        key = "gui.summary.zip_on" if self._zip_state.enabled else "gui.summary.zip_off"
        self.zip_summary_label.setText(self.tr.t(key))

    def _browse_create_container(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            self.tr.t("gui.dialog.select_container_save"),
            str(self.repo_root / f"vault{self.default_extension}"),
            CONTAINER_FILTER,
        )
        if path:
            self.create_container_edit.setText(path)

    def _open_settings_dialog(self) -> None:
        dialog = SettingsDialog(self.tr, self.language, self.tr.t("gui.message.about"), self)
        dialog.about_button.clicked.connect(self._show_about)
        if dialog.exec() != SettingsDialog.Accepted:
            return
        language = dialog.selected_language()
        if language == self.language:
            return
        self.language = language
        update_app_config(self.config_dir, lambda data: {**data, "language": language})
        self.tr = get_translator(language, self.config_dir)
        self._apply_translations()

    def _open_zip_dialog(self) -> None:
        dialog = ZipLayerDialog(self.tr, self._zip_state, self.repo_root, self)
        if dialog.exec() == ZipLayerDialog.Accepted:
            self._zip_state = dialog.state()
            self._refresh_zip_summary()

    def _open_write_dialog(self) -> None:
        WriteSlotDialog(self.tr, self.repo_root, self.default_slot_count, self._start_worker, self).exec()

    def _open_extract_dialog(self) -> None:
        ExtractDialog(self.tr, self.repo_root, self.default_slot_count, self._start_worker, self).exec()

    def _current_layout(self) -> tuple[int, ...]:
        return self.layout_fields.resolve_for_size_mb(self.create_size_spin.value())

    def _current_layout_safe(self) -> tuple[int, ...]:
        try:
            return self._current_layout()
        except Exception:
            return equal_layout(self.create_size_spin.value() * MIB, self.default_slot_count)

    def _slot_capacity_for_index(self, slot_index: int) -> int:
        try:
            layout = self._current_layout()
        except Exception:
            return 0
        if not 0 <= slot_index < len(layout):
            return 0
        return zip_capacity_for_slot(layout[slot_index])

    def _add_payload_from_button(self) -> None:
        dialog = QFileDialog(self, self.tr.t("gui.dialog.select_dirs"), str(self.repo_root))
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setOption(QFileDialog.ShowDirsOnly, True)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        for view in dialog.findChildren(QAbstractItemView):
            view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        if not dialog.exec():
            return
        paths = [Path(p) for p in dialog.selectedFiles()]
        if self._add_payload_sources(paths, edit=True) == 0:
            self._show_warning(self.tr.t("gui.message.no_usable_folders"))

    def _add_payload_sources(self, paths: list[Path], *, edit: bool = False) -> int:
        added = 0
        for path in paths:
            if not path.exists() or not path.is_dir():
                continue
            slot = self._next_unused_slot()
            if slot is None:
                self._show_warning(self.tr.t("gui.message.no_unused_slots"))
                break
            if edit:
                editor = PayloadEditorDialog(
                    self.tr,
                    self.repo_root,
                    source_dir=str(path),
                    slot_index=slot,
                    max_slot=max(0, len(self._current_layout_safe()) - 1),
                    parent=self,
                )
                if editor.exec() != PayloadEditorDialog.Accepted:
                    continue
                values = editor.result_values()
                self._payload_rows.append(
                    PayloadRow(
                        slot_index=values.slot_index,
                        source_dir=values.source_dir,
                        password=values.password,
                        confirm=values.confirm,
                    )
                )
            else:
                self._payload_rows.append(PayloadRow(slot_index=slot, source_dir=str(path), password="", confirm=""))
            self._sync_table_from_rows()
            added += 1
        return added

    def _add_payload_row(self, slot_index=None, source_dir="", password="", confirm="") -> None:
        if slot_index is None:
            slot_index = self._next_unused_slot() or 0
        self._payload_rows.append(
            PayloadRow(slot_index=slot_index, source_dir=source_dir, password=password, confirm=confirm)
        )
        self._sync_table_from_rows()

    def _edit_selected_payload(self) -> None:
        row = self.payload_table.currentRow()
        if row < 0 or row >= len(self._payload_rows):
            self._show_warning(self.tr.t("gui.message.select_payload"))
            return
        current = self._payload_rows[row]
        editor = PayloadEditorDialog(
            self.tr,
            self.repo_root,
            source_dir=current.source_dir,
            password=current.password,
            confirm=current.confirm,
            slot_index=current.slot_index,
            max_slot=max(0, len(self._current_layout_safe()) - 1),
            parent=self,
        )
        if editor.exec() != PayloadEditorDialog.Accepted:
            return
        values = editor.result_values()
        current.slot_index = values.slot_index
        current.source_dir = values.source_dir
        current.password = values.password
        current.confirm = values.confirm
        current.estimate = None
        current.estimate_error = None
        self._sync_table_from_rows()

    def _remove_selected_payload(self) -> None:
        row = self.payload_table.currentRow()
        if row < 0 or row >= len(self._payload_rows):
            self._show_warning(self.tr.t("gui.message.select_payload"))
            return
        del self._payload_rows[row]
        self._sync_table_from_rows()

    def _sync_table_from_rows(self) -> None:
        self.payload_table.setRowCount(0)
        for index, payload in enumerate(self._payload_rows):
            self.payload_table.insertRow(index)
            values = [
                (PAYLOAD_SLOT_COL, str(payload.slot_index)),
                (PAYLOAD_SOURCE_COL, payload.source_dir or "-"),
                (PAYLOAD_ESTIMATE_COL, self._format_size(payload.estimate)),
                (PAYLOAD_CAPACITY_COL, self._format_size(self._slot_capacity_for_index(payload.slot_index))),
                (PAYLOAD_STATUS_COL, self._status_text_for_row(index)),
            ]
            for column, text in values:
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.payload_table.setItem(index, column, item)
        if self._payload_rows:
            current = self.payload_table.currentRow()
            self.payload_table.selectRow(0 if current < 0 else min(current, len(self._payload_rows) - 1))

    def _next_unused_slot(self):
        layout = self._current_layout_safe()
        used = {row.slot_index for row in self._payload_rows}
        for slot in range(len(layout)):
            if slot not in used:
                return slot
        return None

    def _needed_slot_mib(self, estimate: int) -> int:
        required = int((max(0, estimate) + SLOT_OVERHEAD) * 1.10) + 1
        return max(1, (required + MIB - 1) // MIB)

    def _has_any_estimate(self) -> bool:
        return any(row.estimate is not None for row in self._payload_rows)

    def _capacity_aware_assignment(self, layout: tuple[int, ...]) -> list[int]:
        """Return slot_index for each payload row (capacity-aware greedy)."""
        n = len(self._payload_rows)
        if n == 0:
            return []
        if n > len(layout):
            raise ValueError("not enough slots")
        free = list(range(len(layout)))
        free.sort(key=lambda i: zip_capacity_for_slot(layout[i]), reverse=True)
        order = sorted(
            range(n),
            key=lambda i: self._payload_rows[i].estimate or 0,
            reverse=True,
        )
        assignment = [0] * n
        for row_i in order:
            estimate = self._payload_rows[row_i].estimate or 0
            # Prefer smallest capacity that still fits (among free, sorted desc → scan reverse)
            candidates = sorted(free, key=lambda i: zip_capacity_for_slot(layout[i]))
            chosen = None
            for slot_i in candidates:
                if estimate <= zip_capacity_for_slot(layout[slot_i]):
                    chosen = slot_i
                    break
            if chosen is None:
                chosen = max(free, key=lambda i: zip_capacity_for_slot(layout[i]))
            assignment[row_i] = chosen
            free.remove(chosen)
        return assignment

    def _auto_assign_slots(self) -> None:
        layout = self._current_layout_safe()
        if len(self._payload_rows) > len(layout):
            self._show_warning(self.tr.t("gui.message.not_enough_slots"))
            return
        if self._has_any_estimate():
            slots = self._capacity_aware_assignment(layout)
        else:
            slots = self._spread_slot_indexes(len(self._payload_rows), len(layout))
        for row, slot in zip(self._payload_rows, slots, strict=True):
            row.slot_index = slot
        self._sync_table_from_rows()

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

    def _all_payloads_fit(self, layout: tuple[int, ...], assignment: list[int]) -> bool:
        for row, slot_i in zip(self._payload_rows, assignment, strict=True):
            estimate = row.estimate
            if estimate is None:
                continue
            if estimate > zip_capacity_for_slot(layout[slot_i]):
                return False
        return True

    def _format_size(self, size_bytes):
        if size_bytes is None:
            return "-"
        return f"{size_bytes / MIB:.2f} MiB"

    def _status_text_for_row(self, row: int) -> str:
        payload = self._payload_rows[row]
        if payload.estimate_error:
            return self.tr.t("gui.status_payload.error")
        if payload.estimate is None:
            return self.tr.t("gui.status_payload.not_analyzed")
        if payload.estimate <= self._slot_capacity_for_index(payload.slot_index):
            return self.tr.t("gui.status_payload.ok")
        return self.tr.t("gui.status_payload.too_large")

    def _refresh_payload_planning(self) -> None:
        self._sync_table_from_rows()

    def _payload_sources_changed(self) -> None:
        for row in self._payload_rows:
            row.estimate = None
            row.estimate_error = None
        self._refresh_payload_planning()

    def _run_analyze_payloads(self) -> None:
        if not self._payload_rows:
            self._auto_plan_after_analysis = False
            self._show_warning(self.tr.t("gui.message.no_payloads"))
            return
        sources = []
        for index, row in enumerate(self._payload_rows):
            if not row.source_dir:
                self._auto_plan_after_analysis = False
                self._show_warning(self.tr.t("gui.message.select_source"))
                return
            path = Path(row.source_dir)
            if not path.exists() or not path.is_dir():
                self._auto_plan_after_analysis = False
                self._show_warning(self.tr.t("gui.message.source_missing"))
                return
            sources.append((index, path))
        worker = AnalyzePayloadsWorker(sources, compress=self.create_compress_check.isChecked())
        self._start_worker(worker, self.tr.t("gui.status.analyzing"), completed_handler=self._analysis_completed)

    def _analysis_completed(self, estimates: list[PayloadEstimate]) -> None:
        for estimate in estimates:
            if estimate.row_index >= len(self._payload_rows):
                continue
            row = self._payload_rows[estimate.row_index]
            if Path(row.source_dir) != estimate.source_dir:
                continue
            row.estimate = estimate.zip_size
            row.estimate_error = estimate.error
        # Re-pair to slots by capacity once estimates exist (equal or custom).
        if self._payload_rows and all(row.estimate is not None or row.estimate_error for row in self._payload_rows):
            if any(row.estimate is not None for row in self._payload_rows):
                try:
                    self._auto_assign_slots()
                except Exception:
                    self._refresh_payload_planning()
            else:
                self._refresh_payload_planning()
        else:
            self._refresh_payload_planning()
        self._finish_worker(self.tr.t("gui.message.analysis_complete"))
        if self._auto_plan_after_analysis:
            self._auto_plan_after_analysis = False
            self._apply_auto_plan()

    def _run_auto_plan(self) -> None:
        if not self._payload_rows:
            self._show_warning(self.tr.t("gui.message.no_payloads"))
            return
        if any(row.estimate is None for row in self._payload_rows):
            self._auto_plan_after_analysis = True
            self._run_analyze_payloads()
            return
        self._apply_auto_plan()

    def _recommended_slot_count(self, payload_count: int) -> int:
        base = 4 if payload_count <= 2 else payload_count + 2
        slot_count = max(payload_count + (0 if payload_count % 2 == 0 else 1), base)
        if slot_count % 2:
            slot_count += 1
        return slot_count

    def _build_custom_sizes_mib(self, slot_count: int) -> list[int]:
        """Slot-index-ordered MiB sizes: payload needs placed on spread indexes, rest decoys."""
        payload_count = len(self._payload_rows)
        decoys = max(0, slot_count - payload_count)
        sizes = [1] * slot_count
        # Prefer spread indexes for occupied slots (deniability), fill largest needs first.
        preferred = self._spread_slot_indexes(payload_count, slot_count)
        order = sorted(
            range(payload_count),
            key=lambda i: self._payload_rows[i].estimate or 0,
            reverse=True,
        )
        # Map largest payloads onto preferred slots sorted by eventual size need:
        # place largest payload on first preferred index, etc.
        for rank, row_i in enumerate(order):
            slot_i = preferred[rank]
            sizes[slot_i] = self._needed_slot_mib(self._payload_rows[row_i].estimate or 0)
        # Ensure decoy slots stay at least 1 MiB (already).
        _ = decoys
        return sizes

    def _grow_custom_layout_to_fit(self, layout: tuple[int, ...]) -> list[int]:
        """Return MiB sizes (same length as layout) large enough after capacity-aware assign."""
        sizes_mib = [max(1, (size + MIB - 1) // MIB) for size in layout]
        # Iterate: assign, grow undersized slots, rebuild layout bytes, repeat.
        for _ in range(16):
            layout_bytes = tuple(s * MIB for s in sizes_mib)
            assignment = self._capacity_aware_assignment(layout_bytes)
            grew = False
            for row, slot_i in zip(self._payload_rows, assignment, strict=True):
                estimate = row.estimate or 0
                need = self._needed_slot_mib(estimate)
                if need > sizes_mib[slot_i]:
                    sizes_mib[slot_i] = need
                    grew = True
            if not grew:
                # Verify fit
                layout_bytes = tuple(s * MIB for s in sizes_mib)
                assignment = self._capacity_aware_assignment(layout_bytes)
                if self._all_payloads_fit(layout_bytes, assignment):
                    return sizes_mib
                # Force grow largest failing
                for row, slot_i in zip(self._payload_rows, assignment, strict=True):
                    estimate = row.estimate or 0
                    if estimate > zip_capacity_for_slot(layout_bytes[slot_i]):
                        sizes_mib[slot_i] = max(sizes_mib[slot_i] + 1, self._needed_slot_mib(estimate))
                        grew = True
            if not grew:
                break
        return sizes_mib

    def _apply_auto_plan(self) -> None:
        if not self._payload_rows:
            self._show_warning(self.tr.t("gui.message.no_payloads"))
            return
        if any(row.estimate_error for row in self._payload_rows):
            self._show_warning(self.tr.t("gui.message.analysis_has_errors"))
            return
        if any(row.estimate is None for row in self._payload_rows):
            self._show_warning(self.tr.t("gui.message.analysis_required"))
            return

        estimates = [row.estimate or 0 for row in self._payload_rows]
        max_zip = max(estimates) if estimates else 0
        payload_count = len(self._payload_rows)
        changes: list[str] = []

        # Path A: already custom — grow to fit, keep slot count.
        if self.layout_fields.is_custom():
            try:
                current_layout = self._current_layout()
            except Exception as exc:
                self._show_warning(str(exc))
                return
            assignment = self._capacity_aware_assignment(current_layout)
            if self._all_payloads_fit(current_layout, assignment):
                for row, slot in zip(self._payload_rows, assignment, strict=True):
                    row.slot_index = slot
                self._sync_table_from_rows()
                self._set_status(self.tr.t("gui.message.plan_fits"))
                return
            new_sizes = self._grow_custom_layout_to_fit(current_layout)
            changes.append(
                self.tr.t(
                    "gui.message.recommend_custom_layout",
                    sizes=format_slot_sizes_mib([s * MIB for s in new_sizes]),
                )
            )
            changes.append(self.tr.t("gui.message.recommend_size", size=sum(new_sizes)))
            message = "\n".join(changes + [self.tr.t("gui.message.apply_recommendation")])
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.info"),
                message,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if result == QMessageBox.Yes:
                self.layout_fields.set_custom_sizes_mib(new_sizes)
                self.create_size_spin.setValue(sum(new_sizes))
                self._auto_assign_slots()
                self._set_status(self.tr.t("gui.message.plan_applied"))
            else:
                self._set_status(self.tr.t("gui.message.plan_fits"))
            return

        # Path B: equal mode — plan from scratch.
        slot_count = self._recommended_slot_count(payload_count)
        required_slot = int((max_zip + SLOT_OVERHEAD) * 1.10) + 1
        equal_size_mib = max(1, (required_slot * slot_count + MIB - 1) // MIB)
        while (equal_size_mib * MIB) % slot_count != 0:
            equal_size_mib += 1
        avg = sum(estimates) / max(len(estimates), 1)
        use_custom = max_zip > 0 and max(estimates) > 2 * avg and payload_count >= 2

        # If equal already fits after capacity-aware assign on current equal layout, done.
        try:
            current_layout = self._current_layout()
            assignment = self._capacity_aware_assignment(current_layout)
            if self._all_payloads_fit(current_layout, assignment) and not use_custom:
                for row, slot in zip(self._payload_rows, assignment, strict=True):
                    row.slot_index = slot
                self._sync_table_from_rows()
                self._set_status(self.tr.t("gui.message.plan_fits"))
                return
        except Exception:
            pass

        if use_custom:
            sizes = self._build_custom_sizes_mib(slot_count)
            total_mib = max(equal_size_mib, sum(sizes))
            # Pad largest slot until sum matches total_mib
            while sum(sizes) < total_mib:
                sizes[sizes.index(max(sizes))] += 1
            changes.append(
                self.tr.t(
                    "gui.message.recommend_custom_layout",
                    sizes=format_slot_sizes_mib([s * MIB for s in sizes]),
                )
            )
            changes.append(self.tr.t("gui.message.recommend_size", size=sum(sizes)))
            message = "\n".join(changes + [self.tr.t("gui.message.apply_recommendation")])
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.info"),
                message,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if result == QMessageBox.Yes:
                self.layout_fields.set_custom_sizes_mib(sizes)
                self.create_size_spin.setValue(sum(sizes))
                self._auto_assign_slots()
                self._set_status(self.tr.t("gui.message.plan_applied"))
            else:
                self._set_status(self.tr.t("gui.message.plan_fits"))
            return

        changes.append(self.tr.t("gui.message.recommend_slot_count", count=slot_count))
        changes.append(self.tr.t("gui.message.recommend_size", size=equal_size_mib))
        message = "\n".join(changes + [self.tr.t("gui.message.apply_recommendation")])
        result = QMessageBox.question(
            self,
            self.tr.t("gui.message.info"),
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if result == QMessageBox.Yes:
            self.layout_fields.set_equal_slots(slot_count)
            self.create_size_spin.setValue(equal_size_mib)
            self._auto_assign_slots()
            self._set_status(self.tr.t("gui.message.plan_applied"))
        else:
            self._set_status(self.tr.t("gui.message.plan_fits"))

    def _collect_create_payloads(self):
        if not self._payload_rows:
            return None, self.tr.t("gui.message.no_payloads")
        try:
            layout = self._current_layout()
        except Exception as exc:
            return None, str(exc)
        payloads = []
        seen = set()
        for row in self._payload_rows:
            if not 0 <= row.slot_index < len(layout):
                return None, self.tr.t("gui.message.slot_out_of_range")
            if row.slot_index in seen:
                return None, self.tr.t("gui.message.duplicate_slots")
            seen.add(row.slot_index)
            if not row.source_dir:
                return None, self.tr.t("gui.message.select_source")
            source = Path(row.source_dir)
            if not source.exists() or not source.is_dir():
                return None, self.tr.t("gui.message.source_missing")
            if row.password != row.confirm:
                return None, self.tr.t("gui.message.password_mismatch")
            payloads.append(
                PayloadInput(
                    slot_index=row.slot_index,
                    source_dir=source,
                    password=row.password,
                    compress=self.create_compress_check.isChecked(),
                )
            )
        for row in self._payload_rows:
            if row.estimate_error:
                return None, self.tr.t("gui.message.analysis_has_errors")
            if row.estimate is None:
                return None, self.tr.t("gui.message.analysis_required")
            if row.estimate > self._slot_capacity_for_index(row.slot_index):
                return None, self.tr.t("gui.message.payload_too_large_for_plan")
        return payloads, None

    def _run_create(self) -> None:
        container_raw = self.create_container_edit.text().strip()
        if not container_raw:
            self._show_warning(self.tr.t("gui.message.select_container"))
            return
        payloads, error = self._collect_create_payloads()
        if error is not None:
            self._show_warning(error)
            return
        if payloads is None:
            return
        temp = ZipLayerDialog(self.tr, self._zip_state, self.repo_root, self)
        zip_wrapper, error = temp.to_options()
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
        if self._zip_password_matches(zip_wrapper, payloads):
            result = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.zip_entry_password_matches_payload"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
                return
        container = Path(container_raw)
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
        try:
            kwargs = self.layout_fields.layout_kwargs(self.create_size_spin.value() * MIB)
        except Exception as exc:
            self._show_warning(str(exc))
            return
        worker = CreateContainerWorker(
            container,
            self.create_size_spin.value(),
            kwargs.get("slot_count"),
            payloads,
            zip_wrapper,
            self.tr.t("gui.message.create_complete"),
            layout=kwargs.get("layout"),
        )
        self._start_worker(worker, self.tr.t("gui.status.creating"))

    def _has_duplicate_passwords(self, payloads) -> bool:
        seen = set()
        for payload in payloads:
            if payload.password in seen:
                return True
            seen.add(payload.password)
        return False

    def _zip_password_matches(self, zip_wrapper, payloads) -> bool:
        if zip_wrapper is None or not zip_wrapper.encrypted_entry_password:
            return False
        return any(p.password == zip_wrapper.encrypted_entry_password for p in payloads)

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
        self.toolbar.setEnabled(not busy)
        self.create_box.setEnabled(not busy)
        self.layout_box.setEnabled(not busy)
        self.payload_box.setEnabled(not busy)
        self.create_run_button.setEnabled(not busy)
        self.zip_configure_button.setEnabled(not busy)
        if busy:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)

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
