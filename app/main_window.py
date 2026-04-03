"""Main PySide6 window for RSA Encryption Studio."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QRadioButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .crypto_core import RSACore
from .dialogs import PasteDialog, PasswordDialog
from .ui_components import make_button, make_card, make_textbox, section_title, small_hint


class RSAWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.core = RSACore()
        self._info_rows: dict[str, QLabel] = {}

        self.setWindowTitle("RSA Encryption Studio")
        self.resize(1080, 760)
        self.setMinimumSize(920, 640)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(14, 14, 14, 10)
        root_layout.setSpacing(10)
        self.setCentralWidget(root)

        root_layout.addWidget(self._build_header())
        root_layout.addWidget(self._build_tabs(), 1)
        root_layout.addWidget(self._build_statusbar())

        self._update_badge()
        self.set_status("Ready — generate or import keys to begin.", "info")

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("Header")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)

        icon = QLabel("🔐")
        icon.setFont(QFont("Segoe UI Emoji", 20))
        layout.addWidget(icon)

        title_col = QVBoxLayout()
        title = QLabel("RSA Encryption Studio")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        subtitle = QLabel("PySide6 · Compact Dark UI · OAEP-SHA256 · PEM Import/Export")
        subtitle.setProperty("muted", True)
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        layout.addLayout(title_col, 1)

        self.key_badge = QLabel("No Keys Loaded")
        self.key_badge.setStyleSheet(
            f"padding: 6px 10px; border-radius: 8px; color: {theme.BG}; background: {theme.WARNING}; font-weight: 700;"
        )
        layout.addWidget(self.key_badge, 0, Qt.AlignRight | Qt.AlignVCenter)
        return frame

    def _build_tabs(self) -> QWidget:
        self.tabs = QTabWidget()
        self.tab_keys = QWidget()
        self.tab_encrypt = QWidget()
        self.tab_decrypt = QWidget()
        self.tab_info = QWidget()

        self.tabs.addTab(self.tab_keys, "🔑 Key Management")
        self.tabs.addTab(self.tab_encrypt, "🔒 Encrypt")
        self.tabs.addTab(self.tab_decrypt, "🔓 Decrypt")
        self.tabs.addTab(self.tab_info, "ℹ Key Info")

        self._build_keys_tab()
        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_info_tab()
        return self.tabs

    def _build_keys_tab(self) -> None:
        layout = QVBoxLayout(self.tab_keys)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        layout.addWidget(section_title("Generate RSA Key Pair"))
        card, card_lay = make_card()

        row = QHBoxLayout()
        row.addWidget(QLabel("Key Size:"))
        self.rb_1024 = QRadioButton("1024-bit")
        self.rb_2048 = QRadioButton("2048-bit")
        self.rb_4096 = QRadioButton("4096-bit")
        self.rb_2048.setChecked(True)
        row.addWidget(self.rb_1024)
        row.addWidget(self.rb_2048)
        row.addWidget(self.rb_4096)
        row.addStretch(1)
        card_lay.addLayout(row)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Private Key Password (optional):"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Leave empty for unencrypted private key")
        pw_row.addWidget(self.password_input, 1)
        card_lay.addLayout(pw_row)

        btn_row = QHBoxLayout()
        self.generate_btn = make_button("⚙ Generate Key Pair")
        self.generate_btn.clicked.connect(self._generate_keys)
        self.generate_state = QLabel("")
        self.generate_state.setProperty("muted", True)
        btn_row.addWidget(self.generate_btn)
        btn_row.addWidget(self.generate_state)
        btn_row.addStretch(1)
        card_lay.addLayout(btn_row)

        layout.addWidget(card)

        layout.addWidget(section_title("Export / Import"))
        io_card, io_lay = make_card()
        io_row1 = QHBoxLayout()
        pub_export = make_button("💾 Export Public", flat=True)
        prv_export = make_button("💾 Export Private", flat=True)
        copy_pub = make_button("📋 Copy Public", flat=True)
        copy_prv = make_button("📋 Copy Private", flat=True)
        pub_export.clicked.connect(self._export_public)
        prv_export.clicked.connect(self._export_private)
        copy_pub.clicked.connect(self._copy_public)
        copy_prv.clicked.connect(self._copy_private)
        for w in [pub_export, prv_export, copy_pub, copy_prv]:
            io_row1.addWidget(w)
        io_row1.addStretch(1)
        io_lay.addLayout(io_row1)

        io_row2 = QHBoxLayout()
        pub_import = make_button("📂 Import Public", flat=True)
        prv_import = make_button("📂 Import Private", flat=True)
        pub_paste = make_button("✏ Paste Public", flat=True)
        prv_paste = make_button("✏ Paste Private", flat=True)
        pub_import.clicked.connect(self._import_public)
        prv_import.clicked.connect(self._import_private)
        pub_paste.clicked.connect(self._paste_public)
        prv_paste.clicked.connect(self._paste_private)
        for w in [pub_import, prv_import, pub_paste, prv_paste]:
            io_row2.addWidget(w)
        io_row2.addStretch(1)
        io_lay.addLayout(io_row2)

        layout.addWidget(io_card)

        layout.addWidget(section_title("Key Preview"))
        self.key_preview = make_textbox(readonly=True)
        self.key_preview.setMinimumHeight(170)
        layout.addWidget(self.key_preview)

    def _build_encrypt_tab(self) -> None:
        layout = QVBoxLayout(self.tab_encrypt)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        layout.addWidget(section_title("Plaintext"))
        self.plain_text = make_textbox(placeholder="Enter text to encrypt...")
        layout.addWidget(self.plain_text)

        controls, controls_lay = make_card()
        row = QHBoxLayout()
        enc_btn = make_button("🔒 Encrypt")
        clr_btn = make_button("🧹 Clear", flat=True)
        cp_btn = make_button("📋 Copy Cipher", flat=True)
        enc_btn.clicked.connect(self._encrypt)
        clr_btn.clicked.connect(self._clear_encrypt)
        cp_btn.clicked.connect(self._copy_cipher)
        row.addWidget(enc_btn)
        row.addWidget(clr_btn)
        row.addWidget(cp_btn)
        row.addStretch(1)
        controls_lay.addLayout(row)
        controls_lay.addWidget(small_hint("For large messages, data is encrypted in OAEP-safe chunks."))
        layout.addWidget(controls)

        layout.addWidget(section_title("Ciphertext (Base64)"))
        self.cipher_text = make_textbox(readonly=True)
        layout.addWidget(self.cipher_text)

    def _build_decrypt_tab(self) -> None:
        layout = QVBoxLayout(self.tab_decrypt)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        layout.addWidget(section_title("Ciphertext (Base64)"))
        self.decrypt_input = make_textbox(placeholder="Paste ciphertext to decrypt...")
        layout.addWidget(self.decrypt_input)

        controls, controls_lay = make_card()
        row = QHBoxLayout()
        dec_btn = make_button("🔓 Decrypt")
        clr_btn = make_button("🧹 Clear", flat=True)
        cp_btn = make_button("📋 Copy Plaintext", flat=True)
        dec_btn.clicked.connect(self._decrypt)
        clr_btn.clicked.connect(self._clear_decrypt)
        cp_btn.clicked.connect(self._copy_plain)
        row.addWidget(dec_btn)
        row.addWidget(clr_btn)
        row.addWidget(cp_btn)
        row.addStretch(1)
        controls_lay.addLayout(row)
        layout.addWidget(controls)

        layout.addWidget(section_title("Plaintext"))
        self.decrypt_output = make_textbox(readonly=True)
        layout.addWidget(self.decrypt_output)

    def _build_info_tab(self) -> None:
        layout = QVBoxLayout(self.tab_info)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        layout.addWidget(section_title("Current Key Information"))
        card, card_lay = make_card()

        for key in [
            "Key Size",
            "Exponent",
            "Modulus",
            "Fingerprint (SHA-256)",
            "Has Private Key",
        ]:
            row = QHBoxLayout()
            label = QLabel(key)
            label.setProperty("secondary", True)
            label.setMinimumWidth(210)
            value = QLabel("—")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(label)
            row.addWidget(value, 1)
            card_lay.addLayout(row)
            self._info_rows[key] = value

        refresh_btn = make_button("🔄 Refresh Info", flat=True)
        refresh_btn.clicked.connect(self._refresh_info)
        card_lay.addWidget(refresh_btn, 0, Qt.AlignLeft)
        layout.addWidget(card)

        layout.addWidget(section_title("Public Key PEM"))
        self.public_pem_text = make_textbox(readonly=True)
        layout.addWidget(self.public_pem_text)

    def _build_statusbar(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("StatusBarWrap")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)

        self.status_dot = QLabel("●")
        self.status_text = QLabel("Ready")
        self.status_text.setProperty("secondary", True)
        right = QLabel("RSA Studio · PySide6")
        right.setProperty("muted", True)

        layout.addWidget(self.status_dot)
        layout.addWidget(self.status_text, 1)
        layout.addWidget(right)
        return frame

    def _selected_bits(self) -> int:
        if self.rb_4096.isChecked():
            return 4096
        if self.rb_1024.isChecked():
            return 1024
        return 2048

    def set_status(self, text: str, kind: str = "info") -> None:
        color = {
            "info": theme.ACCENT,
            "ok": theme.SUCCESS,
            "warn": theme.WARNING,
            "error": theme.ERROR,
        }.get(kind, theme.ACCENT)
        self.status_text.setText(text)
        self.status_dot.setStyleSheet(f"color: {color};")

    def _update_badge(self) -> None:
        if self.core.has_private:
            text, color = "🔐 Key Pair Loaded", theme.SUCCESS
        elif self.core.has_public:
            text, color = "🔑 Public Key Only", theme.WARNING
        else:
            text, color = "No Keys Loaded", theme.ERROR
        self.key_badge.setText(text)
        self.key_badge.setStyleSheet(
            f"padding: 6px 10px; border-radius: 8px; color: {theme.BG}; background: {color}; font-weight: 700;"
        )

    def _generate_keys(self) -> None:
        bits = self._selected_bits()
        self.generate_btn.setEnabled(False)
        self.generate_state.setText("Generating...")
        self.set_status(f"Generating {bits}-bit RSA key pair...", "info")
        QApplication.processEvents()

        try:
            password = self.password_input.text().encode() if self.password_input.text() else None
            self.core.generate(bits)
            public = self.core.export_public_pem().decode()
            private = self.core.export_private_pem(password).decode()
            preview = (
                f"{'─' * 56}\nPUBLIC KEY\n{'─' * 56}\n{public}\n"
                f"{'─' * 56}\nPRIVATE KEY\n{'─' * 56}\n{private}"
            )
            self.key_preview.setPlainText(preview)
            self.set_status(f"✓ {bits}-bit key pair generated successfully.", "ok")
            self._update_badge()
            self._refresh_info()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Key Generation Error", str(exc))
            self.set_status(f"✗ Generation failed: {exc}", "error")
        finally:
            self.generate_btn.setEnabled(True)
            self.generate_state.setText("Done")

    def _export_public(self) -> None:
        if not self.core.has_public:
            QMessageBox.warning(self, "No Public Key", "Generate or import keys first.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Public Key", "public_key.pem", "PEM files (*.pem)")
        if not path:
            return

        with open(path, "wb") as file:
            file.write(self.core.export_public_pem())
        self.set_status(f"✓ Public key exported → {path}", "ok")

    def _export_private(self) -> None:
        if not self.core.has_private:
            QMessageBox.warning(self, "No Private Key", "Generate or import a private key first.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Private Key", "private_key.pem", "PEM files (*.pem)")
        if not path:
            return

        password = self.password_input.text().encode() if self.password_input.text() else None
        with open(path, "wb") as file:
            file.write(self.core.export_private_pem(password))
        self.set_status(f"✓ Private key exported → {path}", "ok")

    def _copy_public(self) -> None:
        if not self.core.has_public:
            QMessageBox.warning(self, "No Public Key", "No public key available.")
            return
        QApplication.clipboard().setText(self.core.export_public_pem().decode())
        self.set_status("✓ Public key copied.", "ok")

    def _copy_private(self) -> None:
        if not self.core.has_private:
            QMessageBox.warning(self, "No Private Key", "No private key available.")
            return
        password = self.password_input.text().encode() if self.password_input.text() else None
        QApplication.clipboard().setText(self.core.export_private_pem(password).decode())
        self.set_status("✓ Private key copied.", "ok")

    def _import_public(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Public Key", "", "PEM files (*.pem)")
        if not path:
            return

        try:
            with open(path, "rb") as file:
                self.core.load_public_pem(file.read())
            self._update_badge()
            self._refresh_info()
            self.set_status(f"✓ Public key imported from {path}", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Import Error", str(exc))
            self.set_status(f"✗ Import failed: {exc}", "error")

    def _import_private(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Private Key", "", "PEM files (*.pem)")
        if not path:
            return

        password = PasswordDialog.get_password(self, "Enter private key password (blank if none):")
        try:
            with open(path, "rb") as file:
                self.core.load_private_pem(file.read(), password)
            self._update_badge()
            self._refresh_info()
            self.set_status(f"✓ Private key imported from {path}", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Import Error", str(exc))
            self.set_status(f"✗ Import failed: {exc}", "error")

    def _paste_public(self) -> None:
        text = PasteDialog.get_text(self, "Paste Public Key PEM", "PUBLIC KEY")
        if not text:
            return

        try:
            self.core.load_public_pem(text.encode())
            self._update_badge()
            self._refresh_info()
            self.set_status("✓ Public key loaded from pasted text.", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Parse Error", str(exc))
            self.set_status(f"✗ Parse failed: {exc}", "error")

    def _paste_private(self) -> None:
        text = PasteDialog.get_text(self, "Paste Private Key PEM", "PRIVATE KEY")
        if not text:
            return

        password = PasswordDialog.get_password(self, "Enter private key password (blank if none):")
        try:
            self.core.load_private_pem(text.encode(), password)
            self._update_badge()
            self._refresh_info()
            self.set_status("✓ Private key loaded from pasted text.", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Parse Error", str(exc))
            self.set_status(f"✗ Parse failed: {exc}", "error")

    def _encrypt(self) -> None:
        if not self.core.has_public:
            QMessageBox.warning(self, "No Public Key", "Load a public key first.")
            return

        plaintext = self.plain_text.toPlainText().strip()
        if not plaintext:
            QMessageBox.warning(self, "Empty", "Enter a message to encrypt.")
            return

        try:
            cipher = self.core.encrypt(plaintext)
            self.cipher_text.setPlainText(cipher)
            self.set_status(f"✓ Message encrypted ({len(plaintext)} chars).", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Encryption Error", str(exc))
            self.set_status(f"✗ Encryption failed: {exc}", "error")

    def _decrypt(self) -> None:
        if not self.core.has_private:
            QMessageBox.warning(self, "No Private Key", "Load a private key first.")
            return

        cipher = self.decrypt_input.toPlainText().strip()
        if not cipher:
            QMessageBox.warning(self, "Empty", "Enter ciphertext to decrypt.")
            return

        try:
            plaintext = self.core.decrypt(cipher)
            self.decrypt_output.setPlainText(plaintext)
            self.set_status(f"✓ Message decrypted ({len(plaintext)} chars).", "ok")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Decryption Error", str(exc))
            self.set_status(f"✗ Decryption failed: {exc}", "error")

    def _clear_encrypt(self) -> None:
        self.plain_text.clear()
        self.cipher_text.clear()

    def _clear_decrypt(self) -> None:
        self.decrypt_input.clear()
        self.decrypt_output.clear()

    def _copy_cipher(self) -> None:
        text = self.cipher_text.toPlainText().strip()
        if text:
            QApplication.clipboard().setText(text)
            self.set_status("✓ Ciphertext copied.", "ok")

    def _copy_plain(self) -> None:
        text = self.decrypt_output.toPlainText().strip()
        if text:
            QApplication.clipboard().setText(text)
            self.set_status("✓ Plaintext copied.", "ok")

    def _refresh_info(self) -> None:
        info = self.core.key_info()
        for key, label in self._info_rows.items():
            label.setText(info.get(key, "—"))

        if self.core.has_public:
            self.public_pem_text.setPlainText(self.core.export_public_pem().decode())
        else:
            self.public_pem_text.setPlainText("No public key loaded.")
