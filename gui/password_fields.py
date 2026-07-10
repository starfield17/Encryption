from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QWidget,
)

from core.i18n import Translator


def password_looks_weak(password: str) -> bool:
    if not password:
        return False
    if len(password) >= 20:
        return False
    return len([part for part in password.split() if part]) < 6


class PasswordFieldGroup(QWidget):
    """Shared password + confirm + show/skip/hint controls."""

    def __init__(self, tr: Translator, *, include_confirm: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.tr = tr
        self.include_confirm = include_confirm
        layout = QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.password_label = QLabel()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label, 0, 0)
        layout.addWidget(self.password_edit, 0, 1)

        self.confirm_label = QLabel()
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        if include_confirm:
            layout.addWidget(self.confirm_label, 1, 0)
            layout.addWidget(self.confirm_edit, 1, 1)

        options = QHBoxLayout()
        self.show_password_check = QCheckBox()
        self.skip_confirm_check = QCheckBox()
        options.addWidget(self.show_password_check)
        if include_confirm:
            options.addWidget(self.skip_confirm_check)
        options.addStretch(1)
        layout.addLayout(options, 2 if include_confirm else 1, 1)

        self.hint_label = QLabel()
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label, 3 if include_confirm else 2, 1)
        layout.setColumnStretch(1, 1)

        self.show_password_check.stateChanged.connect(self.refresh)
        if include_confirm:
            self.skip_confirm_check.stateChanged.connect(self.refresh)
            self.password_edit.textChanged.connect(self._maybe_sync_confirm)
        self.password_edit.textChanged.connect(self.refresh)

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.password_label.setText(tr.t("gui.label.password"))
        self.confirm_label.setText(tr.t("gui.label.confirm_password"))
        self.show_password_check.setText(tr.t("gui.label.show_password"))
        self.skip_confirm_check.setText(tr.t("gui.label.skip_confirmation"))
        self.refresh()

    def password(self) -> str:
        return self.password_edit.text()

    def confirm(self) -> str:
        return self.confirm_edit.text()

    def set_password(self, password: str, confirm: str | None = None) -> None:
        self.password_edit.setText(password)
        if self.include_confirm:
            self.confirm_edit.setText(password if confirm is None else confirm)

    def passwords_match(self) -> bool:
        if not self.include_confirm:
            return True
        if self.skip_confirm_check.isChecked():
            return True
        return self.password() == self.confirm()

    def _maybe_sync_confirm(self, text: str) -> None:
        if self.include_confirm and self.skip_confirm_check.isChecked():
            self.confirm_edit.setText(text)

    def refresh(self) -> None:
        echo = QLineEdit.Normal if self.show_password_check.isChecked() else QLineEdit.Password
        self.password_edit.setEchoMode(echo)
        if self.include_confirm:
            self.confirm_edit.setEchoMode(echo)
            confirm_enabled = not self.skip_confirm_check.isChecked()
            self.confirm_edit.setEnabled(confirm_enabled)
            self.confirm_label.setEnabled(confirm_enabled)
            if self.skip_confirm_check.isChecked():
                self.confirm_edit.setText(self.password())
        self.hint_label.setText(
            self.tr.t("gui.message.weak_password_hint") if password_looks_weak(self.password()) else ""
        )
