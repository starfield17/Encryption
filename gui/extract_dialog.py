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
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.archiver import ConflictPolicy
from core.i18n import Translator
from gui.layout_fields import LayoutFieldGroup
from gui.password_fields import PasswordFieldGroup
from gui.workers import ExtractWorker

CONTAINER_FILTER = "Containers (*.zip *.darc *.bin *.img);;All files (*)"


class ExtractDialog(QDialog):
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
        self.resize(560, 360)
        root = QVBoxLayout(self)
        form = QGridLayout()

        self.container_label = QLabel()
        self.container_edit = QLineEdit()
        self.container_button = QPushButton()
        form.addWidget(self.container_label, 0, 0)
        form.addWidget(self._path_row(self.container_edit, self.container_button), 0, 1)

        self.output_label = QLabel()
        self.output_edit = QLineEdit()
        self.output_button = QPushButton()
        form.addWidget(self.output_label, 1, 0)
        form.addWidget(self._path_row(self.output_edit, self.output_button), 1, 1)

        self.layout_fields = LayoutFieldGroup(self.tr, default_slots=default_slots)
        form.addWidget(self.layout_fields, 2, 0, 1, 2)

        self.password_group = PasswordFieldGroup(self.tr, include_confirm=False)
        form.addWidget(self.password_group, 3, 0, 1, 2)

        self.try_common_check = QCheckBox()
        form.addWidget(self.try_common_check, 4, 1)
        form.setColumnStretch(1, 1)
        root.addLayout(form)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        root.addWidget(self.button_box)

        self.container_button.clicked.connect(self._browse_container)
        self.output_button.clicked.connect(self._browse_output)
        self.layout_fields.mode_combo.currentIndexChanged.connect(self._sync_try_common)
        self.button_box.accepted.connect(self._run)
        self.button_box.rejected.connect(self.reject)
        self._sync_try_common()

    def _path_row(self, edit: QLineEdit, button: QPushButton) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return wrapper

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.setWindowTitle(tr.t("gui.dialog.extract_title"))
        self.container_label.setText(tr.t("gui.label.container"))
        self.output_label.setText(tr.t("gui.label.output_dir"))
        self.try_common_check.setText(tr.t("gui.label.try_common_slot_counts"))
        self.container_button.setText(tr.t("gui.button.browse_file"))
        self.output_button.setText(tr.t("gui.button.browse_dir"))
        self.container_edit.setPlaceholderText(tr.t("gui.placeholder.container_existing"))
        self.output_edit.setPlaceholderText(tr.t("gui.placeholder.output_dir"))
        self.layout_fields.apply_translations(tr)
        self.password_group.apply_translations(tr)
        self.button_box.button(QDialogButtonBox.Ok).setText(tr.t("gui.button.extract"))
        self._sync_try_common()

    def _sync_try_common(self) -> None:
        equal = not self.layout_fields.is_custom()
        self.try_common_check.setEnabled(equal)
        if not equal:
            self.try_common_check.setChecked(False)

    def _browse_container(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self.tr.t("gui.dialog.select_container_open"), str(self.repo_root), CONTAINER_FILTER
        )
        if path:
            self.container_edit.setText(path)

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.tr.t("gui.dialog.select_dir"), str(self.repo_root))
        if path:
            self.output_edit.setText(path)

    def _run(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        container_raw = self.container_edit.text().strip()
        output_raw = self.output_edit.text().strip()
        if not container_raw:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.select_container"))
            return
        if not output_raw:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.select_output"))
            return
        if not self.password_group.password():
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), self.tr.t("gui.message.password_required"))
            return
        container = Path(container_raw)
        output = Path(output_raw)
        try:
            from core.archiver import DeniableArchiver

            region = DeniableArchiver().slot_region_size(container)
            kwargs = self.layout_fields.layout_kwargs(region)
        except Exception as exc:
            QMessageBox.warning(self, self.tr.t("gui.message.warning"), str(exc))
            return

        conflict_policy = ConflictPolicy.FAIL
        if output.exists() and output.is_dir() and any(output.iterdir()):
            confirmation = QMessageBox.question(
                self,
                self.tr.t("gui.message.warning"),
                self.tr.t("gui.message.replace_output"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if confirmation != QMessageBox.Yes:
                return
            conflict_policy = ConflictPolicy.REPLACE

        worker = ExtractWorker(
            container,
            self.password_group.password(),
            output,
            slot_count=kwargs.get("slot_count"),  # type: ignore[arg-type]
            try_common_slot_counts=self.try_common_check.isChecked(),
            layout=kwargs.get("layout"),  # type: ignore[arg-type]
            conflict_policy=conflict_policy,
        )
        self.start_worker(worker, self.tr.t("gui.status.extracting"))
        self.accept()
