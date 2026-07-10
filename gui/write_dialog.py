from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.i18n import Translator
from core.layout import MAX_SLOT_COUNT
from gui.layout_fields import LayoutFieldGroup
from gui.password_fields import PasswordFieldGroup
from gui.workers import WriteWorker

CONTAINER_FILTER = "Containers (*.zip *.darc *.bin *.img);;All files (*)"


class WriteSlotDialog(QDialog):
    def __init__(
        self,
        tr: Translator,
        repo_root: Path,
        default_slots: int,
        start_worker,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.tr = tr
        self.repo_root = repo_root
        self.start_worker = start_worker
        self._build_ui(default_slots)
        self.apply_translations(tr)

    def _build_ui(self, default_slots: int) -> None:
        self.resize(560, 420)
        root = QVBoxLayout(self)
        form = QGridLayout()

        self.container_label = QLabel()
        self.container_edit = QLineEdit()
        self.container_button = QPushButton()
        form.addWidget(self.container_label, 0, 0)
        form.addWidget(self._path_row(self.container_edit, self.container_button), 0, 1)

        self.layout_fields = LayoutFieldGroup(self.tr, default_slots=default_slots)
        form.addWidget(self.layout_fields, 1, 0, 1, 2)

        self.slot_label = QLabel()
        self.slot_spin = QSpinBox()
        self.slot_spin.setRange(1, MAX_SLOT_COUNT)
        form.addWidget(self.slot_label, 2, 0)
        form.addWidget(self.slot_spin, 2, 1)

        self.source_label = QLabel()
        self.source_edit = QLineEdit()
        self.source_button = QPushButton()
        form.addWidget(self.source_label, 3, 0)
        form.addWidget(self._path_row(self.source_edit, self.source_button), 3, 1)

        self.compress_check = QCheckBox()
        self.compress_check.setChecked(True)
        form.addWidget(self.compress_check, 4, 1)

        self.password_group = PasswordFieldGroup(self.tr, include_confirm=True)
        form.addWidget(self.password_group, 5, 0, 1, 2)
        form.setColumnStretch(1, 1)
        root.addLayout(form)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        root.addWidget(self.button_box)

        self.container_button.clicked.connect(self._browse_container)
        self.source_button.clicked.connect(self._browse_source)
        self.button_box.accepted.connect(self._run)
        self.button_box.rejected.connect(self.reject)

    def _path_row(self, edit: QLineEdit, button: QPushButton) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return wrapper

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.setWindowTitle(tr.t("gui.dialog.write_title"))
        self.container_label.setText(tr.t("gui.label.container"))
        self.slot_label.setText(tr.t("gui.label.slot_index"))
        self.source_label.setText(tr.t("gui.label.source_dir"))
        self.compress_check.setText(tr.t("gui.label.compress_payload"))
        self.container_button.setText(tr.t("gui.button.browse_file"))
        self.source_button.setText(tr.t("gui.button.browse_dir"))
        self.container_edit.setPlaceholderText(tr.t("gui.placeholder.container_existing"))
        self.source_edit.setPlaceholderText(tr.t("gui.placeholder.source_dir"))
        self.layout_fields.apply_translations(tr)
        self.password_group.apply_translations(tr)
        self.button_box.button(QDialogButtonBox.Ok).setText(tr.t("gui.button.write_slot"))

    def _browse_container(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self.tr.t("gui.dialog.select_container_open"), str(self.repo_root), CONTAINER_FILTER
        )
        if path:
            self.container_edit.setText(path)

    def _browse_source(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.tr.t("gui.dialog.select_dir"), str(self.repo_root))
        if path:
            self.source_edit.setText(path)

    def _run(self) -> None:
        container_raw = self.container_edit.text().strip()
        source_raw = self.source_edit.text().strip()
        if not container_raw:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.select_container"))
            return
        if not source_raw:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.select_source"))
            return
        if not self.password_group.passwords_match():
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.password_mismatch"))
            return
        if not self.password_group.password():
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.password_required"))
            return
        container = Path(container_raw)
        source = Path(source_raw)
        try:
            from core.archiver import DeniableArchiver

            region = DeniableArchiver().slot_region_size(container)
            kwargs = self.layout_fields.layout_kwargs(region)
            resolved_layout = self.layout_fields.resolve(region)
        except Exception as exc:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), str(exc))
            return

        slot_index = self.slot_spin.value() - 1
        if slot_index >= len(resolved_layout):
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.slot_out_of_range"))
            return
        confirmation = QMessageBox.question(
            self,
            self.tr.t("gui.message.warning"),
            self.tr.t("gui.message.confirm_slot_replace", slot=self.slot_spin.value()),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirmation != QMessageBox.Yes:
            return

        worker = WriteWorker(
            container,
            source,
            self.password_group.password(),
            slot_index,
            kwargs.get("slot_count"),  # type: ignore[arg-type]
            self.compress_check.isChecked(),
            self.tr.t("gui.message.write_complete"),
            layout=kwargs.get("layout"),  # type: ignore[arg-type]
        )
        self.start_worker(worker, self.tr.t("gui.status.writing"))
        self.accept()
