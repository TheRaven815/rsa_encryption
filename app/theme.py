"""PySide6 dark theme tokens and stylesheet."""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

BG = "#0b1020"
SURFACE = "#11172a"
SURFACE_ALT = "#151e35"
CARD = "#1c2744"
BORDER = "#2a3658"
ACCENT = "#6d7cff"
ACCENT_HOVER = "#8b97ff"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
ERROR = "#ef4444"
TEXT_PRIMARY = "#e8ecff"
TEXT_SECONDARY = "#a8b2d8"
TEXT_MUTED = "#7d89b3"


def app_stylesheet() -> str:
    return f"""
    QWidget {{
        color: {TEXT_PRIMARY};
        font-family: 'Segoe UI';
        font-size: 10pt;
    }}

    QMainWindow, QDialog {{
        background: {BG};
    }}

    QWidget#Header,
    QWidget#StatusBarWrap,
    QTabWidget,
    QTabWidget > QWidget,
    QTabWidget QWidget,
    QFrame,
    QDialog,
    QMainWindow {{
        background: {BG};
    }}

    QLabel {{
        background: transparent;
    }}

    #Header, #StatusBarWrap {{
        background: {SURFACE};
        border: none;
    }}

    #Card {{
        background: {SURFACE_ALT};
        border: 1px solid {BORDER};
        border-radius: 12px;
    }}

    #SectionTitle {{
        color: {ACCENT};
        font-weight: 700;
        font-size: 11pt;
        padding: 0;
    }}

    QLabel[muted='true'] {{
        color: {TEXT_MUTED};
    }}

    QLabel[secondary='true'] {{
        color: {TEXT_SECONDARY};
    }}

    QRadioButton, QCheckBox, QGroupBox {{
        background: transparent;
    }}

    QRadioButton::indicator, QCheckBox::indicator {{
        width: 14px;
        height: 14px;
    }}

    QPushButton {{
        background: {ACCENT};
        color: {TEXT_PRIMARY};
        border: none;
        border-radius: 10px;
        padding: 8px 14px;
        font-weight: 600;
    }}

    QPushButton:hover {{
        background: {ACCENT_HOVER};
    }}

    QPushButton:pressed {{
        padding-top: 9px;
        padding-bottom: 7px;
    }}

    QPushButton[flatVariant='true'] {{
        background: {CARD};
        border: 1px solid {BORDER};
    }}

    QPushButton[flatVariant='true']:hover {{
        background: {BORDER};
    }}

    QLineEdit, QTextEdit, QPlainTextEdit {{
        background: {CARD};
        border: 1px solid {BORDER};
        border-radius: 10px;
        color: {TEXT_PRIMARY};
        selection-background-color: {ACCENT};
        selection-color: {TEXT_PRIMARY};
        padding: 8px;
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid {ACCENT};
    }}

    QTabWidget::pane {{
        border: none;
        top: -1px;
    }}

    QTabBar::tab {{
        background: {SURFACE};
        color: {TEXT_SECONDARY};
        border: 1px solid {BORDER};
        padding: 8px 16px;
        margin-right: 6px;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
    }}

    QTabBar::tab:selected {{
        color: {ACCENT};
        background: {CARD};
        border-bottom-color: {CARD};
    }}

    QStatusBar {{
        background: {SURFACE};
        border-top: 1px solid {BORDER};
    }}

    QScrollBar:vertical {{
        background: {SURFACE};
        width: 12px;
        border-radius: 6px;
        margin: 2px;
    }}

    QScrollBar::handle:vertical {{
        background: {BORDER};
        border-radius: 6px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {ACCENT};
    }}

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    """


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(app_stylesheet())
    app.setFont(QFont("Segoe UI", 10))
