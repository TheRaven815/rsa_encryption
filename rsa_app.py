"""Application entry point for RSA Encryption Studio (PySide6)."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from app.main_window import RSAWindow
from app.theme import apply_theme


def main() -> int:
    app = QApplication(sys.argv)
    apply_theme(app)

    window = RSAWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
