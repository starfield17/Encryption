from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from core.i18n import Translator


class SettingsDialog(QDialog):
    def __init__(self, tr: Translator, language: str, about_text: str, parent=None) -> None:
        super().__init__(parent)
        self.tr = tr
        self._language = language
        self._about_text = about_text
        self._build_ui()
        self.apply_translations(tr)

    def _build_ui(self) -> None:
        self.resize(420, 220)
        root = QVBoxLayout(self)
        form = QGridLayout()
        self.language_label = QLabel()
        from PySide6.QtWidgets import QComboBox

        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("中文 (简体)", "zh_cn")
        index = self.language_combo.findData(self._language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        form.addWidget(self.language_label, 0, 0)
        form.addWidget(self.language_combo, 0, 1)
        root.addLayout(form)

        self.about_label = QLabel(self._about_text)
        self.about_label.setWordWrap(True)
        root.addWidget(self.about_label)

        self.about_button = QPushButton()
        root.addWidget(self.about_button)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        root.addWidget(self.button_box)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.setWindowTitle(tr.t("gui.dialog.settings_title"))
        self.language_label.setText(tr.t("gui.label.language"))
        self.about_button.setText(tr.t("gui.button.about"))
        self.about_label.setText(tr.t("gui.message.about"))

    def selected_language(self) -> str:
        return str(self.language_combo.currentData())
