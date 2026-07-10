from __future__ import annotations

from PySide6.QtWidgets import QWidget


def apply_theme(widget: QWidget) -> None:
    widget.setStyleSheet(
        """
        QMainWindow, QDialog {
            background: #F6F8FB;
            color: #111827;
        }
        QToolBar {
            background: #FFFFFF;
            border: none;
            border-bottom: 1px solid #D6DEE9;
            spacing: 4px;
            padding: 2px 8px;
        }
        QGroupBox {
            background: #FFFFFF;
            border: 1px solid #D6DEE9;
            border-radius: 8px;
            margin-top: 10px;
            padding: 7px 9px 7px 9px;
            font-weight: 600;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #1F3A5F;
        }
        QLineEdit, QComboBox, QSpinBox {
            background: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 5px;
            min-height: 24px;
            padding: 2px 7px;
            selection-background-color: #2563EB;
            selection-color: #FFFFFF;
        }
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
            border: 1px solid #2563EB;
        }
        QPushButton {
            background: #F8FAFC;
            border: 1px solid #CBD5E1;
            border-radius: 5px;
            min-height: 26px;
            padding: 2px 10px;
        }
        QPushButton:hover {
            background: #EAF1FB;
            border-color: #9DB7D8;
        }
        QPushButton:pressed {
            background: #DDEAF8;
        }
        QPushButton:disabled {
            color: #94A3B8;
            background: #F1F5F9;
        }
        QPushButton#primaryAction {
            background: #176B4D;
            border-color: #176B4D;
            color: #FFFFFF;
            font-weight: 600;
            padding-left: 14px;
            padding-right: 14px;
        }
        QPushButton#primaryAction:hover {
            background: #125C41;
            border-color: #125C41;
        }
        QPushButton#primaryAction:pressed {
            background: #0E4E37;
        }
        QToolButton {
            background: transparent;
            border: none;
            border-radius: 4px;
            min-height: 26px;
            padding: 2px 6px;
            color: #334155;
        }
        QToolButton:hover {
            background: #EAF1FB;
        }
        QTabWidget::pane {
            border: 1px solid #D6DEE9;
            border-radius: 8px;
            background: #FFFFFF;
            top: -1px;
        }
        QTabBar::tab {
            background: #EEF3F8;
            border: 1px solid #D6DEE9;
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            padding: 7px 14px;
            margin-right: 2px;
            color: #334155;
        }
        QTabBar::tab:selected {
            background: #FFFFFF;
            color: #111827;
            font-weight: 600;
        }
        QTableWidget {
            background: #FFFFFF;
            alternate-background-color: #F8FAFC;
            border: 1px solid #D6DEE9;
            border-radius: 5px;
            gridline-color: #E2E8F0;
            selection-background-color: #DCE8F5;
            selection-color: #111827;
        }
        QHeaderView::section {
            background: #EEF3F8;
            border: none;
            border-right: 1px solid #D6DEE9;
            border-bottom: 1px solid #D6DEE9;
            padding: 5px 7px;
            color: #334155;
            font-weight: 600;
        }
        QScrollArea {
            background: transparent;
            border: none;
        }
        QProgressBar {
            background: #E8EEF6;
            border: none;
            border-radius: 3px;
            min-height: 6px;
            max-height: 6px;
            text-align: center;
            color: #111827;
        }
        QProgressBar::chunk {
            background: #176B4D;
            border-radius: 3px;
        }
        QStatusBar {
            background: #FFFFFF;
            border-top: 1px solid #D6DEE9;
            color: #334155;
        }
        """
    )
