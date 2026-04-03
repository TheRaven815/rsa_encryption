"""Dialog helpers for the PySide6 application."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class PasswordDialog(QDialog):
    def __init__(self, parent: QWidget | None, message: str):
        super().__init__(parent)
        self.setWindowTitle("Password")
        self.setModal(True)
        self.resize(420, 150)

        layout = QVBoxLayout(self)

        label = QLabel(message)
        label.setWordWrap(True)
        layout.addWidget(label)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Password (optional)")
        layout.addWidget(self.password_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def get_password(parent: QWidget | None, message: str) -> bytes | None:
        dialog = PasswordDialog(parent, message)
        if dialog.exec() == QDialog.Accepted:
            value = dialog.password_edit.text().strip()
            return value.encode() if value else None
        return None


class PasteDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, hint: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(760, 480)

        layout = QVBoxLayout(self)

        label = QLabel(f"Paste your {hint} PEM content below:")
        layout.addWidget(label)

        self.text_edit = QTextEdit()
        self.text_edit.setAcceptRichText(False)
        self.text_edit.setPlaceholderText("-----BEGIN ... KEY-----")
        layout.addWidget(self.text_edit, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def get_text(parent: QWidget | None, title: str, hint: str) -> str | None:
        dialog = PasteDialog(parent, title, hint)
        if dialog.exec() == QDialog.Accepted:
            value = dialog.text_edit.toPlainText().strip()
            return value if value else None
        return None
