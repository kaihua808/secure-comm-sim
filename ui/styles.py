STYLE = """
QMainWindow { background: #f5f5f7; }
QWidget     { background: #f5f5f7; color: #1d1d1f; font-family: "SF Pro Text", "Helvetica Neue", "Menlo", sans-serif; }

QGroupBox {
    border: 1px solid #d2d2d7;
    border-radius: 10px;
    margin-top: 12px;
    padding: 10px 8px 8px 8px;
    font-weight: 600;
    font-size: 12px;
    color: #1d1d1f;
    background: #ffffff;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #6e6e73; }

QPushButton {
    background: #4A90D9;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 12px;
    font-weight: 500;
}
QPushButton:hover   { background: #357ABD; }
QPushButton:pressed { background: #2A6099; }
QPushButton:disabled { background: #d2d2d7; color: #aeaeb2; }

QPushButton#btn_alice,
QPushButton#btn_bob,
QPushButton#btn_danger,
QPushButton#btn_reset  { background: #4A90D9; }

QPushButton#btn_alice:hover,
QPushButton#btn_bob:hover,
QPushButton#btn_danger:hover,
QPushButton#btn_reset:hover  { background: #357ABD; }

QTextEdit, QLineEdit {
    background: #ffffff;
    color: #1d1d1f;
    border: 1px solid #d2d2d7;
    border-radius: 7px;
    padding: 6px;
    font-size: 11px;
    selection-background-color: #4A90D9;
    selection-color: #ffffff;
}
QTextEdit:focus, QLineEdit:focus { border-color: #4A90D9; }

QLabel { color: #6e6e73; font-size: 11px; }
QLabel#title { color: #1d1d1f; font-size: 20px; font-weight: 700; }
QLabel#subtitle { color: #aeaeb2; font-size: 11px; }

QSplitter::handle { background: #d2d2d7; width: 1px; }

QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #c7c7cc; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #aeaeb2; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""
