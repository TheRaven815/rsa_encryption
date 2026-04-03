"""Reusable PySide6 UI component helpers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def make_card() -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setObjectName("Card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    return card, layout


def section_title(text: str) -> QWidget:
    wrapper = QWidget()
    row = QHBoxLayout(wrapper)
    row.setContentsMargins(0, 2, 0, 2)
    row.setSpacing(10)

    label = QLabel(f"● {text}")
    label.setObjectName("SectionTitle")
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Plain)
    line.setFixedHeight(1)
    line.setStyleSheet("background: #2a3658; border: none;")

    row.addWidget(label)
    row.addWidget(line, 1)
    return wrapper


def make_button(text: str, *, flat: bool = False) -> QPushButton:
    button = QPushButton(text)
    button.setProperty("flatVariant", flat)
    return button


def make_textbox(*, readonly: bool = False, placeholder: str = "") -> QTextEdit:
    text = QTextEdit()
    text.setReadOnly(readonly)
    text.setPlaceholderText(placeholder)
    text.setAcceptRichText(False)
    text.setLineWrapMode(QTextEdit.WidgetWidth)
    text.setMinimumHeight(140)
    return text


def small_hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setProperty("muted", True)
    label.setWordWrap(True)
    label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return label
