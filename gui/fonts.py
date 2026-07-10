from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from core.app_paths import bundle_root

FONT_NAME = "NotoSansSC-UI.ttf"


def bundled_font_candidates() -> tuple[Path, ...]:
    root = bundle_root()
    return (
        root / "fonts" / FONT_NAME,
        root / "packaging" / "assets" / "fonts" / FONT_NAME,
    )


def load_bundled_ui_font(app: QApplication) -> str | None:
    for path in bundled_font_candidates():
        if not path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id < 0:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if not families:
            continue
        family = families[0]
        current = app.font()
        font = QFont(family, current.pointSize())
        font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
        app.setFont(font)
        return family
    return None
