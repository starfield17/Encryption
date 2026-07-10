from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QWidget,
)

from core.i18n import Translator
from core.layout import MIB, equal_layout, parse_slot_sizes_mib, resolve_layout


class LayoutFieldGroup(QWidget):
    """Equal slot count or custom MiB sizes (layout secret)."""

    def __init__(self, tr: Translator, *, default_slots: int = 4, parent=None) -> None:
        super().__init__(parent)
        self.tr = tr
        layout = QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.mode_label = QLabel()
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("", "equal")
        self.mode_combo.addItem("", "custom")

        self.slots_label = QLabel()
        self.slots_spin = QSpinBox()
        self.slots_spin.setRange(2, 256)
        self.slots_spin.setValue(default_slots)

        self.sizes_label = QLabel()
        self.sizes_edit = QLineEdit()
        self.sizes_edit.setPlaceholderText("10,40,30,20")

        layout.addWidget(self.mode_label, 0, 0)
        layout.addWidget(self.mode_combo, 0, 1)
        layout.addWidget(self.slots_label, 1, 0)
        layout.addWidget(self.slots_spin, 1, 1)
        layout.addWidget(self.sizes_label, 2, 0)
        layout.addWidget(self.sizes_edit, 2, 1)
        layout.setColumnStretch(1, 1)

        self.mode_combo.currentIndexChanged.connect(self._sync_mode)
        self._sync_mode()

    def apply_translations(self, tr: Translator) -> None:
        self.tr = tr
        self.mode_label.setText(tr.t("gui.label.layout_mode"))
        self.mode_combo.setItemText(0, tr.t("gui.option.layout_equal"))
        self.mode_combo.setItemText(1, tr.t("gui.option.layout_custom"))
        self.slots_label.setText(tr.t("gui.label.slot_count"))
        self.sizes_label.setText(tr.t("gui.label.slot_sizes_mib"))
        self.sizes_edit.setPlaceholderText(tr.t("gui.placeholder.slot_sizes_mib"))

    def is_custom(self) -> bool:
        return str(self.mode_combo.currentData()) == "custom"

    def set_equal_slots(self, slot_count: int) -> None:
        self.mode_combo.setCurrentIndex(0)
        self.slots_spin.setValue(slot_count)
        self._sync_mode()

    def set_custom_sizes_mib(self, sizes_mib: Sequence[int] | str) -> None:
        self.mode_combo.setCurrentIndex(1)
        if isinstance(sizes_mib, str):
            self.sizes_edit.setText(sizes_mib)
        else:
            self.sizes_edit.setText(",".join(str(size) for size in sizes_mib))
        self._sync_mode()

    def resolve(self, region_size: int) -> tuple[int, ...]:
        if self.is_custom():
            layout = parse_slot_sizes_mib(self.sizes_edit.text().strip())
            return resolve_layout(region_size, layout=layout)
        return equal_layout(region_size, self.slots_spin.value())

    def resolve_for_size_mb(self, size_mb: int) -> tuple[int, ...]:
        return self.resolve(size_mb * MIB)

    def layout_kwargs(self, region_size: int) -> dict[str, object]:
        if self.is_custom():
            return {"layout": self.resolve(region_size), "slot_count": None}
        return {"layout": None, "slot_count": self.slots_spin.value()}

    def _sync_mode(self) -> None:
        custom = self.is_custom()
        self.slots_spin.setEnabled(not custom)
        self.slots_label.setEnabled(not custom)
        self.sizes_edit.setEnabled(custom)
        self.sizes_label.setEnabled(custom)
