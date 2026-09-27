"""Configuration constants for Sakura Flow application."""
import sys
import os
from pathlib import Path

# Названия
SERVICE_NAME = "SakuraFlowService"
TASK_NAME = "SakuraFlowAutostart"

# КОРРЕКТНОЕ ОПРЕДЕЛЕНИЕ ПУТИ
if getattr(sys, 'frozen', False):
    # Если запущен EXE, берем путь к папке, где лежит сам EXE
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    # Если запущен скрипт, берем корень проекта
    BASE_DIR = Path(__file__).resolve().parent.parent

# Пути к файлам (теперь они будут искаться рядом с SakuraFlow.exe)
ICON_PATH = BASE_DIR / "icons" / "sakura.ico"
CHECK_ICON_PATH = BASE_DIR / "icons" / "check.ico"
BAT_DIR = BASE_DIR / "zapret"

# --- ПЕРЕИМЕНОВЫВАЕМ ТУТ ---
# Все рабочие файлы (лог, краш, состояние) — в отдельной папке, а не рядом с exe
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
LOG_FILE = DATA_DIR / "sakura_flow.log"
STATE_FILE = DATA_DIR / "sakura_state.json"
CRASH_FILE = DATA_DIR / "sakura_flow.crash"
# ---------------------------

# Кодировка для вывода консольных команд Windows (sc.exe и т.д.)
CONSOLE_ENCODING = "cp866"
# Кодировка для файлов (стратегии, списки, game_filter)
FILE_ENCODING = "utf-8"
