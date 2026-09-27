"""UI/Tray interface functions for Sakura Flow."""
import os
import subprocess
import sys
import threading
import ctypes
import logging

from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QAction, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel, QMessageBox, QShortcut)
from PyQt5.QtGui import QDesktopServices, QIcon, QFont, QCursor, QPixmap, QKeySequence, QPalette, QColor
from PyQt5.QtCore import QUrl, Qt, QTimer, QMetaObject, Q_ARG, pyqtSlot, QObject

try:
    myappid = 'ekcler.sakuraflow.v1.2'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception:
    pass

try:
    from .config import ICON_PATH, CHECK_ICON_PATH, BASE_DIR, LOG_FILE
    from . import service, autostart, state, tools
except ImportError:
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from src.config import ICON_PATH, CHECK_ICON_PATH, BASE_DIR, LOG_FILE
    from src import service, autostart, state, tools


_APP_ID = "Ekcler.SakuraFlow"

# Иконки меню Старт/Стоп фиксированного размера 16x16. QMenu резервирует колонку
# иконок, ТОЛЬКО если хотя бы у одного пункта есть иконка — при выкл (QIcon())
# колонка схлопывалась и весь текст меню «прыгал» влево (сносило табуляцию).
_START_PLACEHOLDER = None
_START_CHECK_ICON = None


def _start_menu_icons():
    global _START_PLACEHOLDER, _START_CHECK_ICON
    if _START_PLACEHOLDER is None:
        base = QPixmap(16, 16)
        base.fill(Qt.transparent)
        _START_PLACEHOLDER = QIcon(base)
    if _START_CHECK_ICON is None:
        pm = QPixmap()
        if CHECK_ICON_PATH.exists():
            pm = QPixmap(str(CHECK_ICON_PATH))
        if not pm.isNull():
            _START_CHECK_ICON = QIcon(pm.scaled(
                16, 16, Qt.IgnoreAspectRatio, Qt.SmoothTransformation))
        else:
            _START_CHECK_ICON = _START_PLACEHOLDER
    return _START_PLACEHOLDER, _START_CHECK_ICON


class _GuiBridge(QObject):
    """Мост «рабочий поток → GUI-поток»: @pyqtSlot(object) исполняет callable в
    потоке владельца (GUI). Используется воркерами (Start/Stop) для мгновенного
    вызова _finish вместо ожидания тика 1s sync-таймера — Qt доставляет
    QMetaCallEvent в event loop GUI-потока (QueuedConnection = thread-safe)."""

    @pyqtSlot(object)
    def _run(self, fn):
        try:
            fn()
        except Exception as e:
            logging.error(f"[bridge] {e}")


class ListEditorWindow(QWidget):
    """Редактор листов (blocklist / ignore list).

    Обычное ресайзное окно БЕЗ WindowStaysOnTopHint: подтверждение при
    несохранённых изменениях, счётчики доменов/строк, sort&dedupe,
    валидация строк и Ctrl+S."""

    def __init__(self, restart_func, list_type="general", start_menu=None, actions=None):
        super().__init__()
        self.restart_func = restart_func
        self.list_type = list_type
        self.start_menu = start_menu
        self.actions = actions
        self._original = ""
        self._dirty = False
        self.init_ui()

    def init_ui(self):
        if self.list_type == "general":
            base_title = "Sakura Blocklist Editor"
            self._file_name = "list-general.txt"
        else:
            base_title = "Sakura Ignore List Editor"
            self._file_name = "list-exclude.txt"
        self._base_title = base_title
        self.setWindowTitle(base_title)
        self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.setWindowFlags(Qt.Window)
        self.resize(600, 640)
        self.setMinimumSize(480, 520)
        self.setStyleSheet("""
            QWidget { background-color: #0f0a12; color: #ffffff; font-family: 'Segoe UI'; }
            QLabel { color: #c8c8d8; }
            QTextEdit { background-color: #1a141d; border: 1px solid #3d1b28; color: #ffffff; font-family: 'Consolas'; font-size: 12px; selection-background-color: #3d1b28; }
            QPushButton { background-color: #2d1621; border: 1px solid #3d1b28; color: #ffffff; padding: 5px 12px; border-radius: 3px; font-weight: bold; }
            QPushButton:hover { background-color: #3d1b28; }
            QPushButton:disabled { color: #5a5460; background-color: #1a141d; border-color: #241319; }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        header = QHBoxLayout()
        file_lbl = QLabel(f"Editing: {self._file_name}")
        file_lbl.setStyleSheet("font-weight: bold; color: #ff79c6; border: none;")
        self.count_lbl = QLabel("0 domains")
        self.count_lbl.setAlignment(Qt.AlignRight)
        header.addWidget(file_lbl)
        header.addStretch(1)
        header.addWidget(self.count_lbl)
        root.addLayout(header)

        bar = QHBoxLayout()
        sort_btn = QPushButton("Sort && Deduplicate")
        reload_btn = QPushButton("Reload")
        bar.addWidget(sort_btn)
        bar.addWidget(reload_btn)
        bar.addStretch(1)
        root.addLayout(bar)

        self.text_edit = QTextEdit()
        self.text_edit.setAcceptRichText(False)
        root.addWidget(self.text_edit, 1)

        self.status_lbl = QLabel("Entries: 0 | Domains: 0")
        root.addWidget(self.status_lbl)

        actions = QHBoxLayout()
        actions.addStretch(1)
        cancel_btn = QPushButton("Cancel")
        save_btn = QPushButton("SAVE AND RESTART SERVICE")
        actions.addWidget(cancel_btn)
        actions.addWidget(save_btn)
        root.addLayout(actions)

        self.text_edit.textChanged.connect(self._on_text_changed)
        sort_btn.clicked.connect(self.sort_dedupe)
        reload_btn.clicked.connect(self.reload)
        save_btn.clicked.connect(self.save_data)
        cancel_btn.clicked.connect(self.close)
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_data)

        self._load()

    def _load(self):
        if self.list_type == "general":
            self._original = tools.read_blocklist()
        else:
            self._original = tools.read_ignore_list()
        self.text_edit.setPlainText(self._original)
        self._dirty = False
        self._update_stats()
        self._update_title()

    def _on_text_changed(self):
        self._dirty = self.text_edit.toPlainText() != self._original
        self._update_stats()
        self._update_title()

    def _update_stats(self):
        entries = 0
        domains = 0
        for line in self.text_edit.toPlainText().splitlines():
            s = line.strip()
            if not s:
                continue
            entries += 1
            if not s.startswith("#"):
                domains += 1
        self.status_lbl.setText(f"Entries: {entries} | Domains: {domains}")
        self.count_lbl.setText(f"{domains} domains")

    def _update_title(self):
        self.setWindowTitle(self._base_title + (" *" if self._dirty else ""))

    def sort_dedupe(self):
        seen = set()
        out = []
        for line in self.text_edit.toPlainText().splitlines():
            s = line.strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        out.sort()
        self.text_edit.setPlainText("\n".join(out))

    def reload(self):
        if self._dirty:
            r = QMessageBox.question(self, "Reload", "Discard unsaved changes and reload from disk?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if r != QMessageBox.Yes:
                return
        self._load()

    @staticmethod
    def _validate_lines(text):
        bad = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if (" " in s or "\t" in s or "://" in s or "/" in s
                    or s.startswith(".") or s.endswith(".")):
                bad.append(s)
        return sorted(set(bad))

    def save_data(self):
        text = self.text_edit.toPlainText()

        bad = self._validate_lines(text)
        if bad:
            shown = "\n".join(bad[:8]) + ("\n..." if len(bad) > 8 else "")
            r = QMessageBox.warning(self, "Invalid lines",
                                    f"These lines don't look like domains:\n\n{shown}\n\nSave anyway?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if r != QMessageBox.Yes:
                return

        domains = [l.strip() for l in text.splitlines()
                   if l.strip() and not l.strip().startswith("#")]
        if not domains:
            r = QMessageBox.question(self, "Empty list",
                                     "The list will be empty. Are you sure?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if r != QMessageBox.Yes:
                return

        if self.list_type == "general":
            ok = tools.save_blocklist(text)
        else:
            ok = tools.save_ignore_list(text)
        if not ok:
            QMessageBox.critical(self, "Error", "Failed to write the list file.")
            return

        self._dirty = False
        self._update_title()
        service.stop_service()
        service.delete_service()
        if self.start_menu and self.actions:
            update_menu_styles(self.start_menu, self.actions, None)
        if self.restart_func:
            self.restart_func()
        QMessageBox.information(self, "Success", "List updated! Service restarted.")
        self.close()

    def closeEvent(self, event):
        if not self._dirty:
            super().closeEvent(event)
            return
        r = QMessageBox.question(self, "Unsaved changes",
                                 "Save changes before closing?",
                                 QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                                 QMessageBox.Save)
        if r == QMessageBox.Save:
            event.ignore()
            self.save_data()
        elif r == QMessageBox.Discard:
            self._dirty = False
            super().closeEvent(event)
        else:
            event.ignore()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)


class NetworkToolsWindow(QWidget):
    def __init__(self, restart_func, start_menu=None, actions=None):
        super().__init__()
        self.restart_func = restart_func
        self.start_menu = start_menu
        self.actions = actions
        self.best_dns_found = None
        self.list_editor = None
        self.ignore_list_editor = None
        self._tg_proxy_on = False
        self._mtproto_running = False
        self._ipv6_reapplied = False
        self._ipv6_sync_warned = False
        _saved = state.load_state()
        # Кнопка отражает намерение пользователя: если он выключал IPv6, показываем
        # «выключен» даже когда Windows сбросила настройку после обновления — иначе
        # авто-возврат в _sync_ipv6_btn не сработает.
        if _saved.get("ipv6_user_disabled"):
            self._ipv6_on = False
        else:
            self._ipv6_on = not tools.is_ipv6_disabled()
        state.save_state(ipv6_enabled=self._ipv6_on)
        self.init_ui()
        
        app_state = state.load_state()
        self.tg_port_input.setText(str(app_state.get("mtproto_port", 1443)))
        self.tg_host_input.setText(app_state.get("mtproto_host", "127.0.0.1"))
        secret_init = app_state.get("mtproto_secret") or tools.generate_secret()
        self.tg_secret_input.setText(secret_init)
        
        if app_state.get("mtproto_enabled", False):
            self._mtproto_running = True
            self.mtproto_toggle_btn.setText("STOP")
            self.mtproto_toggle_btn.setStyleSheet("""
                QPushButton { background-color: rgba(255, 77, 136, 0.25); border: 1px solid #ff4d88; color: #ff7aa2; font-weight: bold; padding: 10px; border-radius: 4px; }
                QPushButton:hover { background-color: rgba(255, 122, 162, 0.35); border: 1px solid #ff7aa2; }
            """)
        
        self.game_filter_btn.setText(self._get_game_filter_label())
        self.ipset_btn.setText(self._get_ipset_label())
        
        self.log_area.append("")
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def log_append(self, text, color=None):
        """Thread-safe log append. color: 'green', 'red' or None. Runs on the worker
        thread; the actual GUI write is queued to this window's slots (thread-safe)
        and the log is trimmed to keep QTextDocument from growing unboundedly."""
        if color:
            html = f'<span style="color: {color};">{text}</span>'
        else:
            html = text
        try:
            QMetaObject.invokeMethod(self.log_area, "append",
                                     Qt.QueuedConnection, Q_ARG(str, html))
            QMetaObject.invokeMethod(self, "_trim_log",
                                     Qt.QueuedConnection)
        except Exception as e:
            logging.error(f"[log] append failed: {e}")

    _MAX_LOG_BLOCKS = 4000

    _MTPROTO_START_STYLE = """
        QPushButton { background-color: rgba(45, 80, 60, 0.5); border: 1px solid rgba(123, 237, 159, 0.4); color: #7bed9f; font-weight: bold; padding: 8px; border-radius: 4px; }
        QPushButton:hover { background-color: rgba(46, 213, 115, 0.25); border: 1px solid #2ed573; }
        QPushButton:disabled { background-color: rgba(120, 120, 120, 0.22); border: 1px solid rgba(170, 170, 170, 0.45); color: rgba(180, 180, 180, 0.7); }
    """
    _MTPROTO_STOP_STYLE = """
        QPushButton { background-color: rgba(255, 77, 136, 0.25); border: 1px solid #ff4d88; color: #ff7aa2; font-weight: bold; padding: 8px; border-radius: 4px; }
        QPushButton:hover { background-color: rgba(255, 122, 162, 0.35); border: 1px solid #ff7aa2; }
        QPushButton:disabled { background-color: rgba(120, 120, 120, 0.22); border: 1px solid rgba(170, 170, 170, 0.45); color: rgba(180, 180, 180, 0.7); }
    """

    @pyqtSlot()
    def _trim_log(self):
        """Не даём логу-документу расти бесконечно: если строк (блоков) стало больше
        лимита, удаляем верхнюю часть. Иначе QTextDocument копит все строки в памяти
        и после многих запусков кнопки процесс «раздувается» (20 -> 36 МБ и выше)."""
        doc = self.log_area.document()
        try:
            while doc.blockCount() > self._MAX_LOG_BLOCKS:
                first = doc.begin()
                cur = self.log_area.textCursor()
                cur.setPosition(first.position())
                cur.setPosition(first.next().position(), cur.KeepAnchor)
                cur.removeSelectedText()
        except Exception as e:
            logging.error(f"[spinner] trim: {e}")

    def init_ui(self):
        self.setWindowTitle("Sakura Flow")
        self.setFixedSize(450, 800)
        self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.setWindowFlags(Qt.Window)
        self.setStyleSheet("""
            QWidget { background-color: #0b0a12; color: #e8e8f0; font-family: 'Segoe UI'; }
            QLineEdit { 
                background-color: rgba(45, 35, 60, 0.6); 
                border: 1px solid rgba(108, 92, 231, 0.3); 
                padding: 8px; border-radius: 4px; color: #e8e8f0;
            }
            QLineEdit:focus { border: 1px solid #ff7aa2; }
            QLineEdit::placeholder { color: #9a9aae; }
            QPushButton { 
                background-color: rgba(255, 122, 162, 0.12); 
                border: 1px solid rgba(255, 122, 162, 0.35); 
                color: #ff7aa2; padding: 8px; border-radius: 4px; font-weight: 500;
            }
            QPushButton:hover { 
                background-color: rgba(255, 122, 162, 0.22); 
                border: 1px solid #ff4d88; 
            }
            QPushButton:pressed { background-color: rgba(255, 77, 136, 0.35); }
            QTextEdit { 
                background-color: rgba(18, 11, 26, 0.8); 
                border: 1px solid rgba(108, 92, 231, 0.25); 
                font-family: 'Consolas'; font-size: 11px; color: #c8c8d8;
            }
            QLabel { color: #ff7aa2; font-weight: 600; }
            QScrollArea { background-color: #0b0a12; border: none; }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(3)

        layout.addWidget(QLabel("Blocklist Management:"))
        blocklist_row = QHBoxLayout()
        self.edit_list_btn = QPushButton("📝 Edit General Blocklist")
        self.edit_ignore_btn = QPushButton("📝 Edit Ignore List")
        blocklist_row.addWidget(self.edit_list_btn)
        blocklist_row.addWidget(self.edit_ignore_btn)
        layout.addLayout(blocklist_row)

        filter_row = QHBoxLayout()
        self.game_filter_btn = QPushButton(self._get_game_filter_label())
        self.game_filter_btn.setStyleSheet("""
            QPushButton { background-color: rgba(243, 156, 18, 0.2); border: 1px solid rgba(243, 156, 18, 0.5); color: #f1c40f; font-weight: bold; padding: 10px; border-radius: 4px; }
            QPushButton:hover { background-color: rgba(243, 156, 18, 0.35); border: 1px solid #f39c12; }
        """)
        self.ipset_btn = QPushButton(self._get_ipset_label())
        self.ipset_btn.setStyleSheet("""
            QPushButton { background-color: rgba(0, 210, 211, 0.2); border: 1px solid rgba(0, 210, 211, 0.5); color: #00d2d3; font-weight: bold; padding: 10px; border-radius: 4px; min-width: 60px; }
            QPushButton:hover { background-color: rgba(0, 210, 211, 0.35); border: 1px solid #00d2d3; }
            QPushButton:pressed { background-color: rgba(0, 210, 211, 0.45); }
            QPushButton:focus { outline: none; }
        """)
        filter_row.addWidget(self.game_filter_btn)
        filter_row.addWidget(self.ipset_btn)
        layout.addLayout(filter_row)

        layout.addSpacing(4)
        layout.addWidget(QLabel("Network Utilities:"))
        self.clear_discord_btn = QPushButton("🧹 Clear Discord Cache")
        self.clear_discord_btn.setStyleSheet("""
            QPushButton { background-color: rgba(50, 90, 180, 0.25); border: 1px solid rgba(70, 130, 255, 0.5); color: #7aa2ff; font-weight: bold; padding: 8px; border-radius: 4px; }
            QPushButton:hover { background-color: rgba(70, 130, 255, 0.35); border: 1px solid #5a8fff; }
        """)
        layout.addWidget(self.clear_discord_btn)

        layout.addSpacing(4)
        layout.addWidget(QLabel("MTPROTO PROXY:"))
        host_port_layout = QHBoxLayout()
        host_port_layout.addWidget(QLabel("Host:"))
        self.tg_host_input = QLineEdit()
        self.tg_host_input.setPlaceholderText("127.0.0.1")
        self.tg_host_input.setText("127.0.0.1")
        host_port_layout.addWidget(self.tg_host_input)
        host_port_layout.addWidget(QLabel("Port:"))
        self.tg_port_input = QLineEdit()
        self.tg_port_input.setPlaceholderText("1443")
        self.tg_port_input.setText("1443")
        host_port_layout.addWidget(self.tg_port_input)
        layout.addLayout(host_port_layout)

        secret_layout = QHBoxLayout()
        secret_layout.addWidget(QLabel("Secret:"))
        self.tg_secret_input = QLineEdit()
        self.tg_secret_input.setPlaceholderText(tools.generate_secret())
        self.tg_secret_input.setText(tools.generate_secret())
        secret_layout.addWidget(self.tg_secret_input)
        self.copy_secret_btn = QPushButton("Open in TG")
        self.copy_secret_btn.setFixedWidth(110)
        self.copy_secret_btn.setStyleSheet("""
            QPushButton { background-color: rgba(42, 171, 228, 0.25); border: 1px solid #26a5e4; color: #7dd3f0; font-weight: bold; padding: 8px; border-radius: 4px; }
            QPushButton:hover { background-color: rgba(110, 205, 255, 0.35); border: 1px solid #4fc3f0; }
        """)
        secret_layout.addWidget(self.copy_secret_btn)
        layout.addLayout(secret_layout)

        self.mtproto_toggle_btn = QPushButton("START")
        self.mtproto_toggle_btn.setStyleSheet(self._MTPROTO_START_STYLE)
        self._mtproto_busy = False
        layout.addWidget(self.mtproto_toggle_btn)

        layout.addSpacing(4)
        layout.addWidget(QLabel("DNS Optimizer & Tester:"))
        dns_input_layout = QHBoxLayout()
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("Enter IP (e.g. 1.1.1.1)")
        self.test_dns_btn = QPushButton("Test")
        dns_input_layout.addWidget(self.dns_input)
        dns_input_layout.addWidget(self.test_dns_btn)
        layout.addLayout(dns_input_layout)

        dns_ctrl_layout = QHBoxLayout()
        self.dns_best_btn = QPushButton("⚡ Find Best")
        self.reset_dns_btn = QPushButton("🔄 Reset DNS")
        dns_ctrl_layout.addWidget(self.dns_best_btn)
        dns_ctrl_layout.addWidget(self.reset_dns_btn)
        layout.addLayout(dns_ctrl_layout)

        self.apply_dns_btn = QPushButton("✅ Apply Best DNS")
        self.apply_dns_btn.hide()
        layout.addWidget(self.apply_dns_btn)

        layout.addSpacing(4)
        layout.addWidget(QLabel("IPv6:"))
        if self._ipv6_on:
            self.ipv6_toggle_btn = QPushButton("Turn OFF")
            self.ipv6_toggle_btn.setStyleSheet("""
                QPushButton { background-color: rgba(180, 60, 80, 0.4); border: 1px solid rgba(255, 85, 85, 0.4); color: #ff6b6b; font-weight: bold; padding: 8px; border-radius: 4px; }
                QPushButton:hover { background-color: rgba(255, 77, 136, 0.3); border: 1px solid #ff4d88; }
            """)
        else:
            self.ipv6_toggle_btn = QPushButton("Turn ON")
            self.ipv6_toggle_btn.setStyleSheet("""
                QPushButton { background-color: rgba(45, 80, 60, 0.5); border: 1px solid rgba(123, 237, 159, 0.4); color: #7bed9f; font-weight: bold; padding: 8px; border-radius: 4px; }
                QPushButton:hover { background-color: rgba(46, 213, 115, 0.25); border: 1px solid #2ed573; }
            """)
        layout.addWidget(self.ipv6_toggle_btn)
        
        ipv6_warning = QLabel("⚠️ turn off if bypass does not work")
        ipv6_warning.setStyleSheet("color: #ff6b6b; font-size: 10px;")
        layout.addWidget(ipv6_warning)

        layout.addSpacing(4)
        self.traffic_label = QLabel("📊 TRAFFIC | UP: 0.0 KB/s | DOWN: 0.0 KB/s")
        self.traffic_label.setStyleSheet("color: #50fa7b; font-family: 'Consolas'; font-size: 12px;")
        layout.addWidget(self.traffic_label)
        layout.addStretch(0)

        # лог — снизу, растёт с окном, скролла нигде нет
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMinimumHeight(150)

        self.log_area.setStyleSheet("""
            QTextEdit { background-color: rgba(18, 11, 26, 0.9); border: 1px solid rgba(108, 92, 231, 0.4); font-family: 'Consolas'; font-size: 11px; color: #c8c8d8; }
        """)
        layout.addWidget(self.log_area, 1)
        self.setLayout(layout)

        self.edit_list_btn.clicked.connect(self.open_list_editor)
        self.edit_ignore_btn.clicked.connect(self.open_ignore_editor)
        self.test_dns_btn.clicked.connect(self.run_custom_dns_test)
        self.dns_best_btn.clicked.connect(self.run_best_dns_test)
        self.reset_dns_btn.clicked.connect(self.run_reset_dns)
        self.apply_dns_btn.clicked.connect(self.apply_best_dns)
        self.mtproto_toggle_btn.clicked.connect(self.toggle_mtproto_proxy)
        self.copy_secret_btn.clicked.connect(self.open_proxy_link)
        self.ipv6_toggle_btn.clicked.connect(self.toggle_ipv6)
        self.clear_discord_btn.clicked.connect(self.clear_discord_cache)
        self.game_filter_btn.clicked.connect(self.toggle_game_filter)
        self.ipset_btn.clicked.connect(self.toggle_ipset)

        self.log_append(f"📄 Лог: {LOG_FILE}")

    def toggle_ipv6(self):
        new_state = not self._ipv6_on
        if new_state:
            ok = tools.enable_ipv6()
            self.log_append("IPv6 enabled")
            for name in tools.get_ipv6_interface_names():
                tools.set_ipv6_interface(name, True)
        else:
            ok = tools.disable_ipv6()
            self.log_append("IPv6 disabled")
            # реестра (DisabledComponents) мало: он действует только после
            # перезагрузки, а интерфейсы продолжают работать, затем _sync_ipv6_btn
            # считает это «самовключением». Отключаем интерфейсы netsh сразу —
            # как это делает скрытая автонастройка.
            for name in tools.get_ipv6_interface_names():
                tools.set_ipv6_interface(name, False)
        if not ok:
            self.log_append("IPv6: не удалось изменить (нужны права администратора)", "red")
            return
        self._ipv6_on = new_state
        state.save_state(ipv6_enabled=self._ipv6_on,
                         ipv6_user_disabled=not self._ipv6_on)
        self._ipv6_reapplied = False
        self._ipv6_sync_warned = False
        if self._ipv6_on:
            self.ipv6_toggle_btn.setText("Turn OFF")
            self.ipv6_toggle_btn.setStyleSheet("""
                QPushButton { background-color: rgba(180, 60, 80, 0.4); border: 1px solid rgba(255, 85, 85, 0.4); color: #ff6b6b; font-weight: bold; padding: 10px; border-radius: 4px; }
                QPushButton:hover { background-color: rgba(255, 77, 136, 0.3); border: 1px solid #ff4d88; }
            """)
        else:
            self.ipv6_toggle_btn.setText("Turn ON")
            self.ipv6_toggle_btn.setStyleSheet("""
                QPushButton { background-color: rgba(45, 80, 60, 0.5); border: 1px solid rgba(123, 237, 159, 0.4); color: #7bed9f; font-weight: bold; padding: 10px; border-radius: 4px; }
                QPushButton:hover { background-color: rgba(46, 213, 115, 0.25); border: 1px solid #2ed573; }
            """)
        self.log_append("Restart required for changes to take effect")

    def _get_game_filter_label(self):
        mode = tools.get_game_filter_mode()
        return {"disabled": "OFF", "all": "TCP+UDP", "tcp": "TCP", "udp": "UDP"}.get(mode, "OFF")

    def _get_ipset_label(self):
        return tools.get_ipset_status()

    def toggle_game_filter(self):
        current = tools.get_game_filter_mode()
        order = ["disabled", "all", "tcp", "udp"]
        next_mode = order[(order.index(current) + 1) % 4]
        if not tools.set_game_filter_mode(next_mode):
            self.log_append(f"[GameFilter] Warning: verification failed for {next_mode}", "red")
        self.game_filter_btn.setText(self._get_game_filter_label())
        state.save_state(game_filter_mode=next_mode)
        self.log_append(f"GameFilter: {next_mode}")
        self.log_append("Restart required to apply")

    def toggle_ipset(self):
        current = tools.get_ipset_status()
        order = ["any", "none", "loaded"]
        next_mode = order[(order.index(current) + 1) % 3]
        if tools.set_ipset_mode(next_mode):
            self.ipset_btn.setText(self._get_ipset_label())
            state.save_state(ipset_mode=next_mode)
            self.log_append(f"IPSet: {next_mode}")
        else:
            self.log_append(f"[IPSet] Failed to switch to {next_mode}", "red")
        self.log_append("Restart required to apply")

    def clear_discord_cache(self):
        self.log_append("Clearing Discord cache...")
        def _task():
            result = tools.clear_discord_cache()
            self.log_append(f"[Discord] {result}")
        threading.Thread(target=_task, daemon=True).start()

    def open_proxy_link(self):
        # та же защита от повторного клика, что и у toggle
        if getattr(self, "_mtproto_busy", False):
            return
        self._mtproto_busy = True
        self.mtproto_toggle_btn.setEnabled(False)
        host = self.tg_host_input.text().strip() or "127.0.0.1"
        port = self.tg_port_input.text().strip() or "1443"
        secret = self.tg_secret_input.text().strip() or tools.generate_secret()
        link = f"tg://proxy?server={host}&port={port}&secret={secret}"
        self.log_append("Starting MTPROTO proxy...")
        def _task():
            try:
                if not tools.is_mtproto_proxy_running(port=int(port), host=host):
                    ok = tools.start_mtproto_proxy(port=int(port), host=host, secret=secret)
                    if not ok:
                        self.log_append(f"Failed to start MTPROTO proxy on {host}:{port}", "red")
                        return
                state.save_state(mtproto_enabled=True, mtproto_port=port, mtproto_host=host, mtproto_secret=secret)
                QMetaObject.invokeMethod(self, "_open_proxy_url",
                                         Qt.QueuedConnection, Q_ARG(str, link))
            except Exception as e:
                self.log_append(f"ERROR: {e}", "red")
            finally:
                QMetaObject.invokeMethod(self, "_finalize_mtproto",
                                         Qt.QueuedConnection)
        threading.Thread(target=_task, daemon=True).start()

    @pyqtSlot(str)
    def _open_proxy_url(self, link):
        if not QDesktopServices.openUrl(QUrl(link)):
            self.log_append(f"Failed to open link: {link}", "red")
        else:
            self.log_append("Opening Telegram...")

    def toggle_mtproto_proxy(self):
        # таймаут: пока вкл/выкл в процессе, повторные клики игнорируем
        if getattr(self, "_mtproto_busy", False):
            return
        try:
            port = int(self.tg_port_input.text().strip() or "1080")
        except ValueError:
            self.log_append(f"Invalid port: {self.tg_port_input.text().strip()}", "red")
            return
        host = self.tg_host_input.text().strip() or "127.0.0.1"
        secret = self.tg_secret_input.text().strip() or tools.generate_secret()

        # только disable (кнопка сереет через :disabled в стеке), без изменения
        # текста/размера — иначе кнопка «прыгает» из-за смены padding
        self._mtproto_busy = True
        self.mtproto_toggle_btn.setEnabled(False)

        if self.mtproto_toggle_btn.text() == "STOP":
            self.log_append("Stopping MTPROTO proxy...")
            def do_stop():
                try:
                    tools.stop_mtproto_proxy(port=port, host=host)
                    state.save_state(mtproto_enabled=False)
                    self.log_append("MTPROTO proxy stopped", "green")
                except Exception as e:
                    self.log_append(f"ERROR: {e}", "red")
                finally:
                    QMetaObject.invokeMethod(self, "_finalize_mtproto",
                                             Qt.QueuedConnection)
            threading.Thread(target=do_stop, daemon=True).start()
        else:
            self.log_append("Starting MTPROTO proxy...")
            def do_start():
                try:
                    ok = tools.start_mtproto_proxy(port=port, host=host, secret=secret)
                    if ok:
                        state.save_state(
                            mtproto_enabled=True,
                            mtproto_port=port,
                            mtproto_host=host,
                            mtproto_secret=secret
                        )
                        self.log_append("MTPROTO proxy started", "green")
                    else:
                        self.log_append(f"Failed to start MTPROTO proxy on {host}:{port}", "red")
                except Exception as e:
                    self.log_append(f"ERROR: {e}", "red")
                finally:
                    QMetaObject.invokeMethod(self, "_finalize_mtproto",
                                             Qt.QueuedConnection)
            threading.Thread(target=do_start, daemon=True).start()

    @pyqtSlot()
    def _finalize_mtproto(self):
        """Разблокирует кнопку прокси после вкл/выкл и возвращает ей текст по
        фактическому состоянию (а не по тому, что надеялись сделать)."""
        self._mtproto_busy = False
        self.mtproto_toggle_btn.setEnabled(True)
        try:
            port = int(self.tg_port_input.text().strip() or "1080")
            host = self.tg_host_input.text().strip() or "127.0.0.1"
            running = tools.is_mtproto_proxy_running(port=port, host=host)
        except Exception:
            running = False
        if running:
            self.mtproto_toggle_btn.setText("STOP")
            self.mtproto_toggle_btn.setStyleSheet(self._MTPROTO_STOP_STYLE)
        else:
            self.mtproto_toggle_btn.setText("START")
            self.mtproto_toggle_btn.setStyleSheet(self._MTPROTO_START_STYLE)

    def open_list_editor(self):
        self._open_editor("general")

    def open_ignore_editor(self):
        self._open_editor("ignore")

    def _open_editor(self, list_type):
        attr = "list_editor" if list_type == "general" else "ignore_list_editor"
        editor = getattr(self, attr, None)
        if editor is None or not editor.isVisible():
            editor = ListEditorWindow(self.restart_func, list_type, self.start_menu, self.actions)
            setattr(self, attr, editor)
            editor.show()
            qr = editor.frameGeometry()
            cp = QApplication.desktop().availableGeometry().center()
            qr.moveCenter(cp)
            editor.move(qr.topLeft())
        editor.activateWindow()
        editor.raise_()

    def closeEvent(self, event):
        # Окно НЕ уничтожается: close → hide (переиспользуется через tools_window).
        # Статистику (update_stats/timer) НЕ гасим — иначе при повторном открытии
        # счётчик трафика мёртв. Лог чистим (экономия RAM), как при hideEvent.
        self.log_area.clear()
        super().closeEvent(event)

    def hideEvent(self, event):
        """Окно прячется (в трей), но НЕ удаляется — объект NetworkToolsWindow
        живёт между открытиями, а QTextEdit (log_area) копит весь лог после fix.
        clear() освобождает QTextDocument, чтобы память не «застревала» на +12 МБ
        при повторных открытиях меню без полного закрытия приложения."""
        try:
            self.log_area.clear()
        except Exception:
            pass
        super().hideEvent(event)

    def update_stats(self):
        up, down = tools.get_traffic_stats()
        self.traffic_label.setText(f"TRAFFIC | UP: {up} KB/s | DOWN: {down} KB/s")
        self._ipv6_check_accum = getattr(self, "_ipv6_check_accum", 0) + 1
        if self._ipv6_check_accum >= 5:
            self._ipv6_check_accum = 0
            self._sync_ipv6_btn()

    def _sync_ipv6_btn(self):
        """Keep the IPv6 toggle in sync with the REAL system state (button must not lie)."""
        real_enabled = tools.real_ipv6_enabled()
        if real_enabled == self._ipv6_on:
            self._ipv6_sync_warned = False
            return
        # Пользователь явно выключал IPv6, но система снова его включила
        # (Windows сбрасывает DisabledComponents после крупного обновления).
        # Возвращаем отключку: один раз за запуск, чтобы не спамить в лог.
        intent_disabled = bool(
            state.load_state().get("ipv6_user_disabled", False))
        if intent_disabled and real_enabled and not getattr(
                self, "_ipv6_reapplied", False):
            self._ipv6_reapplied = True
            if tools.disable_ipv6():
                for name in tools.get_ipv6_interface_names():
                    tools.set_ipv6_interface(name, False)
                self._ipv6_sync_warned = True
                self.log_append(
                    "IPv6: система снова включила IPv6 (сброс после обновления "
                    "Windows) — отключаем заново")
                return
        # Расхождение: реестровая отключка IPv6 (DisabledComponents) применяется
        # только после перезагрузки Windows, поэтому кнопку НЕ откатываем —
        # она отражает выбранный режим. Просто уведомляем об этом один раз.
        if not getattr(self, "_ipv6_sync_warned", False):
            self._ipv6_sync_warned = True
            self.log_append("IPv6: смена режима вступит в силу после перезагрузки Windows (кнопка показывает выбранный режим)")

    def run_custom_dns_test(self):
        dns = self.dns_input.text().strip()
        if dns:
            res = tools.get_ping(dns)
            self.log_area.append(f"DNS {dns}: {res} ms")
            if isinstance(res, (float, int)):
                self.best_dns_found = dns
                self.apply_dns_btn.show()

    def run_best_dns_test(self):
        self.log_area.append("Scanning DNS...")
        ip, info = tools.find_best_dns()
        self.log_area.append(f"Best: {info}")
        if ip:
            self.best_dns_found = ip
            self.apply_dns_btn.show()

    def apply_best_dns(self):
        if self.best_dns_found:
            s, i = tools.set_system_dns(self.best_dns_found)
            self.log_area.append(f"DNS Set: {s} ({i})")
            self.apply_dns_btn.hide()

    def run_reset_dns(self):
        s, i = tools.reset_system_dns()
        self.log_area.append(f"DNS Reset: {s} ({i})")


tools_window = None


def _tag_top_windows():
    """Проставляет каждому верхнеуровневому окну свой AppUserModelID через
    SHGetPropertyStoreForWindow (PKEY_AppUserModel_ID). Без этого ПКМ-меню
    панели задач берёт имя из exe и пишет «python» — даже при установленном
    AppUserModelID процесса. С тегом меню показывает «Sakura Flow»."""
    try:
        from ctypes import (POINTER, Structure, Union, CFUNCTYPE, byref, cast,
                            c_void_p, c_wchar_p, c_ulong, c_long, windll)
        from ctypes import wintypes

        class GUID(Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]

        class PROPERTYKEY(Structure):
            _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]

        class _PV_UNION(Union):
            _fields_ = [("pwszVal", c_wchar_p)]

        class PROPVARIANT(Structure):
            _anonymous_ = ("_u",)
            _fields_ = [("vt", wintypes.WORD),
                        ("wReserved1", wintypes.WORD),
                        ("wReserved2", wintypes.WORD),
                        ("wReserved3", wintypes.WORD),
                        ("_u", _PV_UNION)]

        IID_IPropertyStore = GUID(
            0x886d8eeb, 0x8cf2, 0x4446,
            (0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99))
        PKEY_AppUserModel_ID = PROPERTYKEY(
            GUID(0x9f4c2855, 0x9f79, 0x4b39,
                 (0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1, 0xd5, 0x03)), 5)

        for w in QApplication.topLevelWidgets():
            if not w.isWindow() or getattr(w, "_taskbar_tagged", False):
                continue
            hwnd = int(w.winId())
            if not hwnd:
                continue
            ps = c_void_p()
            hr = windll.shell32.SHGetPropertyStoreForWindow(
                hwnd, byref(IID_IPropertyStore), byref(ps))
            if hr != 0 or not ps.value:
                continue
            vtbl = None
            try:
                vtbl = cast(ps, POINTER(POINTER(c_void_p))).contents
                pv = PROPVARIANT()
                pv.vt = 31  # VT_LPWSTR
                pv.pwszVal = _APP_ID
                setvalue = cast(vtbl[6], CFUNCTYPE(
                    c_long, c_void_p, POINTER(PROPERTYKEY), POINTER(PROPVARIANT)))
                setvalue(ps, byref(PKEY_AppUserModel_ID), byref(pv))
                w._taskbar_tagged = True
            finally:
                if vtbl:
                    release = cast(vtbl[2], CFUNCTYPE(c_ulong, c_void_p))
                    release(ps)
    except Exception as e:
        logging.warning(f"[TASKBAR] tag windows: {e}")


def open_tools(restart_func, start_menu=None, actions=None):
    global tools_window
    if tools_window is None:
        tools_window = NetworkToolsWindow(restart_func, start_menu, actions)
    tools_window.show()
    tools_window.activateWindow()


def update_menu_styles(start_menu, actions, active_version):
    ph, check = _start_menu_icons()
    for bat, action in actions.items():
        if bat.stem == active_version:
            font = QFont()
            font.setBold(True)
            action.setFont(font)
            action.setIcon(check)
        else:
            action.setFont(QFont())
            action.setIcon(ph)


class StickyMenu(QMenu):
    """Tray menu that stays open when an item is clicked."""
    def mouseReleaseEvent(self, event):
        action = self.actionAt(event.pos())
        if action is not None and not action.isSeparator():
            action.activate(QAction.Trigger)
            event.accept()
            return
        super().mouseReleaseEvent(event)


def _show_first_run():
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLabel, QCheckBox,
                                 QPushButton)

    class _ReadBlock(QDialog):
        """Диалог, который нельзя закрыть Esc/крестиком — только через «Принять»."""
        def reject(self):
            pass

    first_run_html = (
        "<b>\U0001F338 Sakura Flow запущен</b><br><br>"
        "Приложение свернуто в <b>системный трей</b> \U0001F4CD<br>"
        "(область уведомлений рядом с часами).<br><br>"
        "\u2460 Нажми на иконку \U0001F338 \u2014 откроется меню<br>"
        "\u2461 Выбери <b>\u26A1 Start</b> \u2014 включится обход блокировок<br>"
        "\u2462 Готово \u2705 YouTube, Discord, Rocket League \u2014 вс\u0451 работает.<br>"
        "&nbsp;&nbsp;&nbsp;<b>GameFilter:</b> TCP+UDP (рекомендуется) \u2699\uFE0F<br>"
        "&nbsp;&nbsp;&nbsp;<b>IPSet:</b> any (рекомендуется) \u2699\uFE0F<br>"
        "&nbsp;&nbsp;&nbsp;Настройки в \U0001F6E0\uFE0F Network Tools \u2192 GameFilter / IPSet<br><br>"
        "<b>Для Telegram:</b><br>"
        "\u2463 Открой \U0001F6E0\uFE0F Network Tools<br>"
        "\u2464 Нажми <b>Open in TG</b> \U0001F517 \u2014 прокси запустится сам и в Telegram откроется ссылка подключения<br>"
        "\u2465 В Telegram подтверди <b>Connect</b> \u2714\uFE0F"
    )
    dlg = _ReadBlock()
    dlg.setWindowTitle("Sakura Flow")
    dlg.setWindowIcon(QIcon(str(ICON_PATH)))
    dlg.setModal(True)
    dlg.setFixedWidth(480)
    # без крестика и без закрытия по Esc — читать придётся
    dlg.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint)
    lay = QVBoxLayout()
    label = QLabel(first_run_html)
    label.setTextFormat(Qt.RichText)
    label.setWordWrap(True)
    lay.addWidget(label)

    check = QCheckBox("Я прочитал(а) и понял(а) инструкцию")
    lay.addWidget(check)

    btn_ok = QPushButton("Принять")
    btn_ok.setEnabled(False)
    btn_ok.setMinimumHeight(36)
    lay.addWidget(btn_ok)
    dlg.setLayout(lay)

    def on_toggle():
        btn_ok.setEnabled(check.isChecked())

    check.toggled.connect(on_toggle)
    btn_ok.clicked.connect(dlg.accept)

    dlg.exec_()
    state.save_state(first_run=False)


def create_tray_app(bat_files, register_sleep_handler=None):
    logging.info("[TRAY] creating QApplication...")
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(str(ICON_PATH)))
    pal = app.palette()
    pal.setColor(QPalette.PlaceholderText, QColor("#9a9aae"))
    app.setPalette(pal)

    logging.info("[TRAY] creating tray icon...")
    tray = QSystemTrayIcon(QIcon(str(ICON_PATH)))
    tray.show()
    logging.info("[TRAY] tray shown")

    app_state = state.load_state()
    if app_state.get("first_run", False):
        logging.info("[TRAY] first run detected, scheduling welcome box")
        QTimer.singleShot(500, _show_first_run)

    logging.info("[TRAY] building menu...")
    menu = StickyMenu()
    menu.setStyleSheet("""
        QMenu { background-color: #0f0a12; color: #ffffff; border: 1px solid #3d1b28; font-size: 14px; }
        QMenu::item { padding: 8px 32px 8px 12px; }
        QMenu::item:selected { background-color: #2d1621; }
        QMenu::separator { height: 1px; background: #3d1b28; margin: 4px; }
    """)

    if register_sleep_handler:
        app_state = state.load_state()
        current_bat = app_state.get("last_bat")
        bat_path = None
        for b in bat_files:
            if b.stem == current_bat:
                bat_path = b
                break
        def restart_for_wake():
            if bat_path:
                service.restart_service(bat_path, bat_path.stem)
        register_sleep_handler(restart_for_wake, current_bat)

    def quick_restart():
        app_state = state.load_state()
        if app_state["last_bat"]:
            for b in bat_files:
                if b.stem == app_state["last_bat"]:
                    threading.Thread(target=lambda b=b: service.start_service(b, b.stem), daemon=True).start()
                    break

    # флаг занятости: пока вкл/выкл стратегии в процессе, повторные клики и
    # sync-таймер кнопку НЕ трогают — иначе лейбл «мигает» (Start→Stop→Start).
    # done сигналит, что рабочий поток закончил; _finish вызывается в GUI-потоке:
    # воркер будит его через QMetaObject.invokeMethod(_bridge, "_run") (queued в
    # event loop GUI-потока, thread-safe), sync-таймер — фолбэк, если иначе не дошло.
    _bridge = _GuiBridge()
    _strategy_busy = {"on": False, "done": False}

    def _finish():
        _strategy_busy["on"] = False
        _strategy_busy["done"] = False
        # состояние берём по факту после операции, а не по оптимистичному
        # предположению (успешный start_service не обязан дать RUNNING сразу)
        update_start_btn(start_btn, tools.is_winws_running())

    def toggle_strategy(btn):
        """Toggle strategy on/off. All slow work (service start/stop) runs in
        background threads so the UI never freezes; completion signals the GUI
        thread via QMetaObject.invokeMethod(_bridge, "_run") — queued
        cross-thread (pyqtSlot исполняется в event loop GUI-потока)."""
        if _strategy_busy["on"]:
            return
        running = tools.is_winws_running()
        _strategy_busy["on"] = True
        _strategy_busy["done"] = False

        def _notify_done():
            _strategy_busy["done"] = True
            QMetaObject.invokeMethod(_bridge, "_run",
                                     Qt.QueuedConnection,
                                     Q_ARG(object, _finish))

        if running:
            def do_stop():
                try:
                    service.stop_service()
                    service.delete_service()
                    state.save_state(last_bat=None, stopped=True)
                except Exception as e:
                    logging.error(f"[toggle_strategy] Stop error: {e}")
                finally:
                    _notify_done()
            threading.Thread(target=do_stop, daemon=True).start()
        else:
            def do_start():
                try:
                    app_state = state.load_state()
                    last_bat = app_state.get("last_bat")
                    bat_path = tools.pick_strategy_bat(bat_files, last_bat)
                    if not bat_path:
                        logging.error("[toggle_strategy] No strategy .bat found")
                    else:
                        state.save_state(last_bat=bat_path.stem, stopped=False)
                        service.start_service(bat_path, bat_path.stem)
                except Exception as e:
                    logging.error(f"[toggle_strategy] Start error: {e}")
                finally:
                    _notify_done()
            threading.Thread(target=do_start, daemon=True).start()

    def update_start_btn(btn, running, force=False):
        """Update Start button based on winws running state. Обновляется сразу,
        даже когда меню открыто (свежее состояние видно без переоткрытия).
        Защита от «мигания» Start→Stop→Start: при совпадении текста ничего не
        трогаем — повторного setText не происходит. Иконка ВСЕГДА задаётся
        фиксированного 16x16 размера (чек при запуске, прозрачная заглушка при
        стопе), чтобы QMenu не схлопывал колонку иконок и текст не «прыгал»."""
        new_text = "  ⏹️ Stop" if running else "  ⚡ Start"
        if not force and btn.text() == new_text:
            return
        ph, check = _start_menu_icons()
        btn.setIcon(check if running else ph)
        btn.setText(new_text)

    start_btn = QAction("  ⚡ Start", menu)
    update_start_btn(start_btn, tools.is_winws_running(), force=True)
    start_btn.triggered.connect(lambda: toggle_strategy(start_btn))
    menu.addAction(start_btn)
    menu.addAction("  🌐 Internet Settings", lambda: subprocess.Popen("control ncpa.cpl", shell=True))
    menu.addAction("  🛠️ Network Tools", lambda: open_tools(quick_restart, None, {}))
    menu.addSeparator()

    autostart_action = menu.addAction("  🔄 Autostart")
    autostart_action.setCheckable(True)
    autostart_action.setChecked(autostart.is_autostart_enabled())
    autostart_action.toggled.connect(lambda chk: autostart.enable_autostart() if chk else autostart.disable_autostart())

    menu.addSeparator()

    def app_restart():
        subprocess.Popen([sys.executable] + sys.argv)
        service.stop_service()
        QApplication.quit()

    menu.addAction("  🔁 Restart", app_restart)
    menu.addSeparator()
    menu.addAction("  🚪 Exit", lambda: (service.stop_service(), QApplication.quit()))

    tray.activated.connect(lambda r: menu.popup(QCursor.pos()) if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
    tray.setContextMenu(menu)

    # winws может кратко пропадать при перезапуске службы (после сна/редактирования
    # списков/смены стратегии) — мгновенный флип кнопки выглядит как
    # «сам вырубился». Меняем на Off только после 3 тиков подряд без процесса.
    _absent_ticks = {"n": 0}

    def sync_start_btn():
        # рабочий поток завершился -> финализируем ТОЛЬКО тут, в GUI-потоке
        if _strategy_busy["on"] and _strategy_busy["done"]:
            _finish()
        if _strategy_busy["on"]:
            _absent_ticks["n"] = 0
            return
        running = tools.is_winws_running()
        if running:
            _absent_ticks["n"] = 0
        else:
            _absent_ticks["n"] += 1
            if _absent_ticks["n"] < 3:
                return
        update_start_btn(start_btn, running)

    # как только меню трея закрывается — сразу свежее состояние кнопки,
    # а не через ждать следующий тик (1с)
    menu.aboutToHide.connect(lambda: QTimer.singleShot(0, sync_start_btn))

    sync_timer = QTimer()
    sync_timer.timeout.connect(sync_start_btn)
    sync_timer.start(1000)

    tag_timer = QTimer()
    tag_timer.timeout.connect(_tag_top_windows)
    tag_timer.start(2000)

    logging.info("[TRAY] entering event loop")
    return app.exec_()