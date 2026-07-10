from __future__ import annotations

import pytest

from core.app_paths import source_root


@pytest.mark.parametrize(
    ("language", "tab_labels"),
    [
        ("en", ["Create", "Update Slot", "Extract"]),
        ("zh_cn", ["创建", "更新 Slot", "提取"]),
    ],
)
def test_main_window_task_tabs_fit_minimum_viewport(monkeypatch, language, tab_labels):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSize
    from PySide6.QtWidgets import QApplication, QDialogButtonBox

    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow(repo_root=source_root(), language=language)
    try:
        window.resize(740, 520)
        window.show()
        app.processEvents()

        assert window.tabs.count() == 3
        assert window.size() == QSize(740, 520)
        assert [window.tabs.tabText(index) for index in range(3)] == tab_labels
        assert window.tabs.currentWidget() is window.create_page
        assert window.payload_table.rowCount() == 0
        assert window.default_extension == ".darc"
        assert window._zip_state.enabled is False
        assert window.advanced_panel.isHidden()
        assert window.analyze_payloads_button.isHidden()
        assert window.auto_assign_button.isHidden()
        assert not window.create_scroll.verticalScrollBar().isVisible()
        assert window.create_run_button.isVisible()
        assert (
            window.create_run_button.mapTo(window, window.create_run_button.rect().bottomRight()).y() < window.height()
        )

        window.advanced_button.click()
        app.processEvents()
        assert window.advanced_panel.isVisible()
        assert window.create_run_button.isVisible()

        for tab_index, page in (
            (window.write_tab_index, window.write_page),
            (window.extract_tab_index, window.extract_page),
        ):
            window.tabs.setCurrentIndex(tab_index)
            app.processEvents()
            primary_button = page.button_box.button(QDialogButtonBox.Ok)
            assert page.isVisible()
            assert primary_button.isVisible()
            assert primary_button.mapTo(window, primary_button.rect().bottomRight()).y() < window.height()
            assert page.button_box.button(QDialogButtonBox.Cancel).isHidden()
    finally:
        window.close()
        app.processEvents()


def test_bundled_font_covers_simplified_chinese_ui(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QFontMetrics
    from PySide6.QtWidgets import QApplication

    from gui.fonts import load_bundled_ui_font

    app = QApplication.instance() or QApplication([])
    family = load_bundled_ui_font(app)

    assert family == "Noto Sans SC"
    metrics = QFontMetrics(app.font())
    for character in "可否认加密归档器创建更新提取密码":
        assert metrics.inFontUcs4(ord(character))
