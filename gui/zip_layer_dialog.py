from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.archiver import (
    DEFAULT_WRAPPER_ENTRY_NAME,
    ZIP_ENTRY_MODE_ARCHIVE,
    ZIP_ENTRY_MODE_FILES,
    ZipWrapperOptions,
)
from core.i18n import Translator
from gui.password_fields import PasswordFieldGroup


@dataclass
class ZipLayerState:
    enabled: bool
    visible_source: str
    entry_source: str
    entry_mode: str
    entry_name: str
    entry_password: str
    entry_confirm: str
    show_password: bool


class ZipLayerDialog(QDialog):
    def __init__(self, tr: Translator, state: ZipLayerState, repo_root: Path, parent=None) -> None:
        super().__init__(parent)
        self.tr = tr
        self.repo_root = repo_root
        self._build_ui()
        self._load_state(state)
        self.apply_translations(tr)

    def _build_ui(self) -> None:
        self.resize(560, 360)
        root = QVBoxLayout(self)
        form = QGridLayout()

        self.enabled_check = QCheckBox()
        form.addWidget(self.enabled_check, 0, 1)

        self.visible_label = QLabel()
        self.visible_edit = QLineEdit()
        self.visible_button = QPushButton()
        form.addWidget(self.visible_label, 1, 0)
        form.addWidget(self._path_row(self.visible_edit, self.visible_button), 1, 1)

        self.entry_source_label = QLabel()
        self.entry_source_edit = QLineEdit()
        self.entry_source_button = QPushButton()
        form.addWidget(self.entry_source_label, 2, 0)
        form.addWidget(self._path_row(self.entry_source_edit, self.entry_source_button), 2, 1)

        self.mode_label = QLabel()
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("", ZIP_ENTRY_MODE_ARCHIVE)
        self.mode_combo.addItem("", ZIP_ENTRY_MODE_FILES)
        form.addWidget(self.mode_label, 3, 0)
        form.addWidget(self.mode_combo, 3, 1)

        self.name_label = QLabel()
        self.name_edit = QLineEdit(DEFAULT_WRAPPER_ENTRY_NAME)
        form.addWidget(self.name_label, 4, 0)
        form.addWidget(self.name_edit, 4, 1)

        self.password_group = PasswordFieldGroup(self.tr, include_confirm=True)
        form.addWidget(self.password_group, 5, 0, 1, 2)
        form.setColumnStretch(1, 1)
        root.addLayout(form)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        root.addWidget(self.button_box)

        self.visible_button.clicked.connect(lambda: self._browse_dir(self.visible_edit))
        self.entry_source_button.clicked.connect(lambda: self._browse_dir(self.entry_source_edit))
        self.enabled_check.stateChanged.connect(self._sync_enabled)
        self.mode_combo.currentIndexChanged.connect(self._sync_enabled)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

    def _path_row(self, edit: QLineEdit, button: QPushButton) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return wrapper

    def _load_state(self, state: ZipLayerState) -> None:
        self.enabled_check.setChecked(state.enabled)
        self.visible_edit.setText(state.visible_source)
        self.entry_source_edit.setText(state.entry_source)
        index = self.mode_combo.findData(state.entry_mode)
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
        self.name_edit.setText(state.entry_name or DEFAULT_WRAPPER_ENTRY_NAME)
        self.password_group.set_password(state.entry_password, state.entry_confirm)
        self.password_group.show_password_check.setChecked(state.show_password)
        self._sync_enabled()

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.setWindowTitle(tr.t("gui.dialog.zip_layer_title"))
        self.enabled_check.setText(tr.t("gui.label.zip_wrapper"))
        self.visible_label.setText(tr.t("gui.label.visible_source_dir"))
        self.entry_source_label.setText(tr.t("gui.label.passworded_entry_source_dir"))
        self.mode_label.setText(tr.t("gui.label.passworded_entry_mode"))
        self.mode_combo.setItemText(0, tr.t("gui.option.passworded_entry_mode_archive"))
        self.mode_combo.setItemText(1, tr.t("gui.option.passworded_entry_mode_files"))
        self.name_label.setText(tr.t("gui.label.passworded_entry_name"))
        self.visible_button.setText(tr.t("gui.button.browse_dir"))
        self.entry_source_button.setText(tr.t("gui.button.browse_dir"))
        self.visible_edit.setPlaceholderText(tr.t("gui.placeholder.visible_source_dir"))
        self.entry_source_edit.setPlaceholderText(tr.t("gui.placeholder.passworded_entry_source_dir"))
        self.name_edit.setPlaceholderText(tr.t("gui.placeholder.passworded_entry_name"))
        self.password_group.apply_translations(tr)
        self._sync_enabled()

    def state(self) -> ZipLayerState:
        return ZipLayerState(
            enabled=self.enabled_check.isChecked(),
            visible_source=self.visible_edit.text().strip(),
            entry_source=self.entry_source_edit.text().strip(),
            entry_mode=str(self.mode_combo.currentData()),
            entry_name=self.name_edit.text().strip() or DEFAULT_WRAPPER_ENTRY_NAME,
            entry_password=self.password_group.password(),
            entry_confirm=self.password_group.confirm(),
            show_password=self.password_group.show_password_check.isChecked(),
        )

    def to_options(self) -> tuple[ZipWrapperOptions | None, str | None]:
        state = self.state()
        if not state.enabled:
            return None, None
        visible = Path(state.visible_source) if state.visible_source else None
        if visible is not None and (not visible.exists() or not visible.is_dir()):
            return None, self.tr.t("gui.message.visible_source_missing")
        entry = Path(state.entry_source) if state.entry_source else None
        if entry is not None and (not entry.exists() or not entry.is_dir()):
            return None, self.tr.t("gui.message.passworded_entry_source_missing")
        if entry is not None:
            if not state.entry_password:
                return None, self.tr.t("gui.message.passworded_entry_password_required")
            if not self.password_group.passwords_match():
                return None, self.tr.t("gui.message.password_mismatch")
        elif state.entry_password or state.entry_confirm:
            return None, self.tr.t("gui.message.passworded_entry_source_required")
        if visible is None and entry is None:
            return None, self.tr.t("gui.message.zip_wrapper_source_required")
        return (
            ZipWrapperOptions(
                enabled=True,
                visible_source_dir=visible,
                encrypted_entry_source_dir=entry,
                encrypted_entry_name=state.entry_name,
                encrypted_entry_password=state.entry_password if entry is not None else None,
                encrypted_entry_mode=state.entry_mode
                if state.entry_mode in {ZIP_ENTRY_MODE_ARCHIVE, ZIP_ENTRY_MODE_FILES}
                else ZIP_ENTRY_MODE_ARCHIVE,
            ),
            None,
        )

    def _browse_dir(self, edit: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, self.tr.t("gui.dialog.select_dir"), str(self.repo_root))
        if path:
            edit.setText(path)

    def _sync_enabled(self) -> None:
        enabled = self.enabled_check.isChecked()
        archive_mode = str(self.mode_combo.currentData()) == ZIP_ENTRY_MODE_ARCHIVE
        for widget in [
            self.visible_label,
            self.visible_edit,
            self.visible_button,
            self.entry_source_label,
            self.entry_source_edit,
            self.entry_source_button,
            self.mode_label,
            self.mode_combo,
            self.name_label,
            self.name_edit,
            self.password_group,
        ]:
            widget.setEnabled(enabled)
        self.name_label.setEnabled(enabled and archive_mode)
        self.name_edit.setEnabled(enabled and archive_mode)
