import sys
import secrets
from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFrame, QVBoxLayout,
    QHBoxLayout, QLineEdit, QMessageBox, QSizePolicy, QGraphicsDropShadowEffect
)


class VyperAgentKeyWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.key_dir = Path.home() / ".vyper"
        self.key_file = self.key_dir / "agent_api_key"
        self.current_key = None

        self.setWindowTitle("Vyper Agent")
        self.setObjectName("window")
        self.resize(940, 640)
        self.setMinimumSize(860, 590)

        self.build_ui()

    def build_ui(self):
        self.setStyleSheet("""
            QWidget {
                background: transparent;
                color: #111827;
                font-family: "Segoe UI", Arial, sans-serif;
            }

            QWidget#window {
                background: #eef2f6;
            }

            QLabel {
                background: transparent;
            }

            QFrame#topbar {
                background: #ffffff;
                border-bottom: 1px solid #dce3eb;
            }

            QLabel#logo {
                background: #111827;
                color: #ffffff;
                border-radius: 8px;
                font-size: 12px;
                font-weight: 800;
                min-width: 34px;
                max-width: 34px;
                min-height: 34px;
                max-height: 34px;
            }

            QLabel#brand {
                font-size: 18px;
                font-weight: 800;
                color: #111827;
            }

            QLabel#brandSub {
                color: #6b7280;
                font-size: 11px;
            }

            QLabel#mode {
                color: #1d4ed8;
                background: #eff6ff;
                border: 1px solid #bfdbfe;
                border-radius: 14px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: 800;
            }

            QFrame#sidePanel {
                background: #111827;
                border-radius: 8px;
            }

            QLabel#sideEyebrow {
                color: #93c5fd;
                font-size: 10px;
                font-weight: 800;
            }

            QLabel#sideTitle {
                color: #ffffff;
                font-size: 28px;
                font-weight: 800;
            }

            QLabel#sideText {
                color: #cbd5e1;
                font-size: 12px;
                line-height: 150%;
            }

            QFrame#sideDivider {
                background: #263244;
                max-height: 1px;
                border: none;
            }

            QLabel#sideLabel {
                color: #94a3b8;
                font-size: 10px;
                font-weight: 800;
            }

            QLabel#sideValue {
                color: #f8fafc;
                font-size: 12px;
                font-weight: 650;
            }

            QLabel#pageTitle {
                font-size: 28px;
                font-weight: 800;
                color: #111827;
            }

            QLabel#pageSubtitle {
                color: #5b6472;
                font-size: 12px;
            }

            QFrame#credentialPanel,
            QFrame#step {
                background: #ffffff;
                border: 1px solid #dce3eb;
                border-radius: 8px;
            }

            QLabel#cardTitle {
                font-size: 17px;
                font-weight: 800;
                color: #111827;
            }

            QLabel#cardSubtitle {
                font-size: 12px;
                color: #6b7280;
            }

            QLabel#label {
                font-size: 10px;
                font-weight: 800;
                color: #4b5563;
            }

            QLineEdit#key {
                background: #f8fafc;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 12px 13px;
                color: #1f2937;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 12px;
                min-height: 22px;
                selection-background-color: #cfe2ff;
            }

            QLineEdit#key:focus {
                border: 1px solid #2563eb;
                background: #ffffff;
            }

            QPushButton#primary {
                background: #2563eb;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                min-height: 42px;
                padding: 0 20px;
                font-size: 12px;
                font-weight: 800;
            }

            QPushButton#primary:hover {
                background: #1d4ed8;
            }

            QPushButton#primary:pressed {
                background: #1e40af;
            }

            QPushButton#secondary {
                background: #ffffff;
                color: #1d4ed8;
                border: 1px solid #bfdbfe;
                border-radius: 6px;
                min-height: 40px;
                padding: 0 15px;
                font-size: 12px;
                font-weight: 800;
            }

            QPushButton#secondary:hover {
                background: #eff6ff;
            }

            QPushButton#secondary:disabled {
                background: #f8fafc;
                color: #9ca3af;
                border: 1px solid #e5e7eb;
            }

            QLabel#statusPill {
                color: #047857;
                background: #ecfdf5;
                border: 1px solid #a7f3d0;
                border-radius: 14px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: 800;
            }

            QLabel#statusPill[empty="true"] {
                color: #92400e;
                background: #fffbeb;
                border: 1px solid #fde68a;
            }

            QFrame#notice {
                background: #fff7ed;
                border: 1px solid #fed7aa;
                border-radius: 7px;
            }

            QLabel#small {
                color: #6b7280;
                font-size: 11px;
            }

            QLabel#noticeTitle {
                color: #9a3412;
                font-size: 11px;
                font-weight: 800;
            }

            QLabel#noticeText {
                color: #9a3412;
                font-size: 11px;
            }

            QLabel#stepNumber {
                background: #eff6ff;
                color: #2563eb;
                border-radius: 12px;
                min-width: 24px;
                max-width: 24px;
                min-height: 24px;
                max-height: 24px;
                font-size: 10px;
                font-weight: 800;
            }

            QLabel#stepTitle {
                font-size: 12px;
                font-weight: 800;
                color: #1f2937;
            }

            QLabel#stepBody,
            QLabel#pathValue {
                font-size: 11px;
                color: #6b7280;
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(64)

        nav = QHBoxLayout(topbar)
        nav.setContentsMargins(28, 0, 28, 0)
        nav.setSpacing(10)

        logo = QLabel("V")
        logo.setObjectName("logo")
        logo.setAlignment(Qt.AlignCenter)

        brand_block = QVBoxLayout()
        brand_block.setSpacing(0)

        brand = QLabel("Vyper Agent")
        brand.setObjectName("brand")

        brand_sub = QLabel("Local credential manager")
        brand_sub.setObjectName("brandSub")
        brand_block.addWidget(brand)
        brand_block.addWidget(brand_sub)

        mode = QLabel("LOCAL AGENT")
        mode.setObjectName("mode")
        mode.setFixedHeight(34)

        nav.addWidget(logo)
        nav.addLayout(brand_block)
        nav.addStretch()
        nav.addWidget(mode)

        root.addWidget(topbar)

        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(28, 22, 28, 24)
        content_layout.setSpacing(22)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 2, 0, 0)
        right_layout.setSpacing(14)

        page_header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(5)

        title = QLabel("Agent API Key")
        title.setObjectName("pageTitle")

        subtitle = QLabel(
            "Manage the secure credential that links this desktop agent to the dashboard."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)

        heading.addWidget(title)
        heading.addWidget(subtitle)

        self.status_pill = QLabel("NOT GENERATED")
        self.status_pill.setObjectName("statusPill")
        self.status_pill.setProperty("empty", True)

        page_header.addLayout(heading, 1)
        page_header.addWidget(self.status_pill, 0, Qt.AlignTop)
        right_layout.addLayout(page_header)

        card = QFrame()
        card.setObjectName("credentialPanel")
        self._add_shadow(card)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 22, 24, 22)
        card_layout.setSpacing(13)

        card_title = QLabel("Credential")
        card_title.setObjectName("cardTitle")

        card_subtitle = QLabel(
            "Generated keys are stored with user-only permissions on this computer."
        )
        card_subtitle.setObjectName("cardSubtitle")
        card_subtitle.setWordWrap(True)

        card_layout.addWidget(card_title)
        card_layout.addWidget(card_subtitle)

        label = QLabel("API KEY")
        label.setObjectName("label")
        card_layout.addWidget(label)

        key_row = QHBoxLayout()
        key_row.setSpacing(10)

        self.key_field = QLineEdit()
        self.key_field.setObjectName("key")
        self.key_field.setReadOnly(True)
        self.key_field.setPlaceholderText("No API key generated yet")
        self.key_field.setEchoMode(QLineEdit.Password)

        self.show_btn = QPushButton("Show")
        self.show_btn.setObjectName("secondary")
        self.show_btn.setFixedWidth(82)
        self.show_btn.setEnabled(False)
        self.show_btn.clicked.connect(self.toggle_key)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setFixedWidth(82)
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_key)

        key_row.addWidget(self.key_field, 1)
        key_row.addWidget(self.show_btn)
        key_row.addWidget(self.copy_btn)

        card_layout.addLayout(key_row)

        notice = QFrame()
        notice.setObjectName("notice")
        notice.setMinimumHeight(58)
        notice_layout = QVBoxLayout(notice)
        notice_layout.setContentsMargins(14, 12, 14, 12)
        notice_layout.setSpacing(3)

        notice_title = QLabel("Keep this key private")
        notice_title.setObjectName("noticeTitle")
        notice_text = QLabel(
            "Anyone with the key can authenticate as this agent until you regenerate it."
        )
        notice_text.setObjectName("noticeText")
        notice_text.setWordWrap(True)

        notice_layout.addWidget(notice_title)
        notice_layout.addWidget(notice_text)
        card_layout.addWidget(notice)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)

        self.generate_btn = QPushButton("Generate Secure API Key")
        self.generate_btn.setObjectName("primary")
        self.generate_btn.clicked.connect(self.generate_key)

        self.regenerate_btn = QPushButton("Regenerate")
        self.regenerate_btn.setObjectName("secondary")
        self.regenerate_btn.clicked.connect(self.regenerate_key)
        self.regenerate_btn.setEnabled(False)

        buttons.addWidget(self.generate_btn, 1)
        buttons.addWidget(self.regenerate_btn)

        card_layout.addLayout(buttons)

        right_layout.addWidget(card)

        right_layout.addStretch()

        content_layout.addWidget(right, 1)
        root.addWidget(content)
        self.load_existing_key()

    def _add_shadow(self, widget):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(26)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(15, 23, 42, 28))
        widget.setGraphicsEffect(shadow)

    def _add_side_stat(self, layout, label_text, value_text):
        block = QVBoxLayout()
        block.setSpacing(4)

        label = QLabel(label_text)
        label.setObjectName("sideLabel")

        value = QLabel(value_text)
        value.setObjectName("sideValue")
        value.setWordWrap(True)

        block.addWidget(label)
        block.addWidget(value)
        layout.addLayout(block)

        if label_text == "STATE":
            self.side_state_value = value

    def _refresh_dynamic_style(self, widget):
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def set_key_state(self, key):
        self.current_key = key
        has_key = bool(key)

        self.key_field.setText(key or "")
        self.key_field.setEchoMode(QLineEdit.Password)
        self.show_btn.setText("Show")
        self.show_btn.setEnabled(has_key)
        self.copy_btn.setEnabled(has_key)
        self.regenerate_btn.setEnabled(has_key)

        self.status_pill.setText("CONFIGURED" if has_key else "NOT GENERATED")
        self.status_pill.setProperty("empty", not has_key)
        self._refresh_dynamic_style(self.status_pill)

        self.generate_btn.setText(
            "Generate New API Key" if has_key else "Generate Secure API Key"
        )

    def load_existing_key(self):
        if not self.key_file.exists():
            self.set_key_state(None)
            return

        key = self.key_file.read_text(encoding="utf-8").strip()
        self.set_key_state(key or None)

    def generate_key(self):
        # 256 bits of cryptographically secure randomness.
        key = "vyp_" + secrets.token_urlsafe(32)

        self.key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Store only the generated credential locally so the agent can use it.
        # Restrict the file to the current user.
        self.key_file.write_text(key + "\n", encoding="utf-8")
        self.key_file.chmod(0o600)
        self.set_key_state(key)

    def regenerate_key(self):
        reply = QMessageBox.warning(
            self,
            "Regenerate API Key",
            "The current API key will stop being valid.\n\n"
            "If the website is already using this key, you will need to "
            "replace it with the new one.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.generate_key()

    def toggle_key(self):
        if not self.current_key:
            return

        if self.key_field.echoMode() == QLineEdit.Password:
            self.key_field.setEchoMode(QLineEdit.Normal)
            self.show_btn.setText("Hide")
        else:
            self.key_field.setEchoMode(QLineEdit.Password)
            self.show_btn.setText("Show")

    def copy_key(self):
        if not self.current_key:
            return

        QApplication.clipboard().setText(self.current_key)
        self.copy_btn.setText("Copied ✓")

        # Reset button label after a short delay without another dependency.
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(1200, lambda: self.copy_btn.setText("Copy"))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    window = VyperAgentKeyWindow()
    window.show()

    sys.exit(app.exec_())
