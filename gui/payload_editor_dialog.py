from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.i18n import Translator
from gui.password_fields import PasswordFieldGroup


@dataclass
class PayloadEditorResult:
    source_dir: str
    password: str
    confirm: str
    slot_index: int


class PayloadEditorDialog(QDialog):
    def __init__(
        self,
        tr: Translator,
        repo_root: Path,
        *,
        source_dir: str = "",
        password: str = "",
        confirm: str = "",
        slot_index: int = 0,
        max_slot: int = 1,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.tr = tr
        self.repo_root = repo_root
        self._build_ui(max_slot)
        self.source_edit.setText(source_dir)
        self.slot_spin.setValue(slot_index + 1)
        self.password_group.set_password(password, confirm)
        self.apply_translations(tr)

    def _build_ui(self, max_slot: int) -> None:
        self.resize(520, 280)
        root = QVBoxLayout(self)
        form = QGridLayout()

        self.slot_label = QLabel()
        self.slot_spin = QSpinBox()
        self.slot_spin.setRange(1, max(1, max_slot + 1))
        form.addWidget(self.slot_label, 0, 0)
        form.addWidget(self.slot_spin, 0, 1)

        self.source_label = QLabel()
        self.source_edit = QLineEdit()
        self.source_button = QPushButton()
        wrapper = QWidget()
        path_layout = QHBoxLayout(wrapper)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.addWidget(self.source_edit, 1)
        path_layout.addWidget(self.source_button)
        form.addWidget(self.source_label, 1, 0)
        form.addWidget(wrapper, 1, 1)

        self.password_group = PasswordFieldGroup(self.tr, include_confirm=True)
        form.addWidget(self.password_group, 2, 0, 1, 2)
        form.setColumnStretch(1, 1)
        root.addLayout(form)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        root.addWidget(self.button_box)
        self.source_button.clicked.connect(self._browse)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.setWindowTitle(tr.t("gui.dialog.payload_editor_title"))
        self.slot_label.setText(tr.t("gui.label.slot_index"))
        self.source_label.setText(tr.t("gui.label.source_dir"))
        self.source_button.setText(tr.t("gui.button.browse_dir"))
        self.source_edit.setPlaceholderText(tr.t("gui.placeholder.source_dir"))
        self.password_group.apply_translations(tr)

    def result_values(self) -> PayloadEditorResult:
        return PayloadEditorResult(
            source_dir=self.source_edit.text().strip(),
            password=self.password_group.password(),
            confirm=self.password_group.confirm(),
            slot_index=self.slot_spin.value() - 1,
        )

    def validate_values(self) -> str | None:
        values = self.result_values()
        if not values.source_dir:
            return self.tr.t("gui.message.select_source")
        path = Path(values.source_dir)
        if not path.exists() or not path.is_dir():
            return self.tr.t("gui.message.source_missing")
        if not self.password_group.passwords_match():
            return self.tr.t("gui.message.password_mismatch")
        if not self.password_group.password():
            return self.tr.t("gui.message.password_required")
        return None

    def accept(self) -> None:
        error = self.validate_values()
        if error:
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.warning(self, self.tr.t("gui.message.warning"), error)
            return
        super().accept()

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.tr.t("gui.dialog.select_dir"), str(self.repo_root))
        if path:
            self.source_edit.setText(path)
