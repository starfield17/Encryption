from __future__ import annotations

from PySide6.QtWidgets import QWidget


def apply_theme(widget: QWidget) -> None:
    widget.setStyleSheet(
        """
        QMainWindow, QDialog {
            background: #F6F8FB;
            color: #111827;
        }
        QGroupBox {
            background: #FFFFFF;
            border: 1px solid #D6DEE9;
            border-radius: 8px;
            margin-top: 14px;
            padding: 14px 12px 12px 12px;
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
            min-height: 28px;
            padding: 3px 7px;
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
            min-height: 28px;
            padding: 4px 10px;
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
        QProgressBar {
            background: #E8EEF6;
            border: 1px solid #D6DEE9;
            border-radius: 5px;
            min-height: 14px;
            text-align: center;
            color: #111827;
        }
        QProgressBar::chunk {
            background: #2563EB;
            border-radius: 4px;
        }
        QStatusBar {
            background: #FFFFFF;
            border-top: 1px solid #D6DEE9;
            color: #334155;
        }
        """
    )

