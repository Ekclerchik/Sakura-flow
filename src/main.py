"""Main entry point for Sakura Flow application."""
import sys
import os
import logging
import threading
import time
from pathlib import Path

try:
    import win32con
    import win32gui
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).resolve().parent
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))
    internal_dir = BASE_DIR / "_internal"
    if str(internal_dir) not in sys.path:
        sys.path.insert(0, str(internal_dir))
else: 
    file_path = Path(__file__).resolve()    
    BASE_DIR = file_path.parent.parent
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

try:
    import src  
    sys.modules['src'] = src    
    from src import admin, ui, config, service, tools, state, autostart
except ImportError:
    import admin, ui, config, service, tools, state, autostart

def _set_defaults():
    app_state = state.load_state()
    if app_state.get("game_filter_mode") is None:
        tools.set_game_filter_mode("all")
        state.save_state(game_filter_mode="all")
    if app_state.get("ipset_mode") is None:
        tools.set_ipset_mode("any")
        state.save_state(ipset_mode="any")

try:
    import tg_ws_proxy 
except ImportError:
    try:
        from src import tg_ws_proxy
    except ImportError:
        tg_ws_proxy = None

try:
    import faulthandler
    from pathlib import Path
    import config as _cfg
    Path(_cfg.CRASH_FILE).parent.mkdir(exist_ok=True)
    fh = open(_cfg.CRASH_FILE, "a", encoding="utf-8", errors="replace")
    faulthandler.enable(fh)
    # exit=False: снимаем дамп заблокированного потока, но НЕ убиваем приложение.
    faulthandler.dump_traceback_later(3600, exit=False)
except Exception:
    pass

logging.basicConfig(
    filename=config.LOG_FILE,
    filemode="w",
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Dev-запуск (например, из VSCode): дублируем лог в консоль, чтобы ошибки
# («winws не запустился …», список причин) были видны сразу, без чтения файла.
# В собранном exe консоли нет (sys.stdout = None) — там ничего не добавляем.
if not getattr(sys, "frozen", False) and sys.stdout is not None:
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    _console.setLevel(os.environ.get("SAKURA_CONSOLE_LEVEL", "INFO"))
    logging.getLogger().addHandler(_console)

_current_bat = None
_restart_func = None

def on_wake():
    logging.info("Компьютер проснулся! Проверяю службу...")
    
    if _current_bat and _restart_func:
        time.sleep(2)
        try:
            service.stop_service()
            _restart_func()
            logging.info("Служба перезапущена после пробуждения")
        except Exception as e:
            logging.error(f"Ошибка перезапуска службы: {e}")
    
    app_state = state.load_state()
    if app_state.get("mtproto_enabled", False):
        time.sleep(3)
        try:
            port = app_state.get("mtproto_port", 1443)
            host = app_state.get("mtproto_host", "127.0.0.1")
            secret = app_state.get("mtproto_secret", None)
            tools.stop_mtproto_proxy(port=port, host=host)
            time.sleep(1)
            tools.start_mtproto_proxy(port=port, host=host, secret=secret)
            logging.info("MTProto прокси перезапущен после пробуждения")
        except Exception as e:
            logging.error(f"Ошибка перезапуска MTProto прокси: {e}")

def register_sleep_handler(restart_func, current_bat):
    global _current_bat, _restart_func
    _current_bat = current_bat
    _restart_func = restart_func
    
    if not HAS_WIN32:
        logging.info("win32api не установлен, обработка сна недоступна")
        return
    
    try:
        def WndProc(hwnd, msg, wParam, lParam):
            if msg == win32con.WM_POWERBROADCAST:
                if wParam == win32con.PBT_APMRESUMEAUTOMATIC:
                    logging.info("Событие пробуждения!")
                    threading.Thread(target=on_wake, daemon=True).start()
            return win32gui.DefWindowProc(hwnd, msg, wParam, lParam)
        
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = WndProc
        wc.lpszClassName = "SakuraFlowPower"
        win32gui.RegisterClass(wc)
        win32gui.CreateWindow("SakuraFlowPower", "SakuraFlow", 0, 0, 0, 0, 0, 0, 0, 0, None)
        
        logging.info("Обработчик сна зарегистрирован")
    except Exception as e:
        logging.error(f"Ошибка регистрации обработчика сна: {e}")

def main():
    try:
        _main_inner()
    except Exception as e:
        logging.error(f"FATAL: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

def _main_inner():
    logging.info(f"START SAKURA FLOW. CWD: {os.getcwd()}")
    
    # Паритет 3.3.9: приложение требует прав администратора (служба, winws,
    # отключение IPv6, задача автозапуска с RunLevel=Highest). Без этого блока
    # запуск «как есть» не может ни пересоздать службу, ни создать автозапуск
    # (RegisterTaskDefinition → Access denied), поэтому автозапуск «всегда выкл».
    if not admin.is_admin():
        logging.info("Запрос прав администратора...")
        admin.run_as_admin()
        return
    
    autostart.fix_autostart_path()
    
    _set_defaults()

    bat_files = [
        f for f in config.BAT_DIR.glob("*.bat") 
        if f.name.lower() not in ["service.bat", "general.bat", "_zapret_service.bat"]
    ]

    app_state = state.load_state()
    if app_state.get("mtproto_enabled", False):
        logging.info("[MTPROTO] Восстановление прокси после запуска")
        port = app_state.get("mtproto_port", 1443)
        host = app_state.get("mtproto_host", "127.0.0.1")
        secret = app_state.get("mtproto_secret")

        def _restore_mtproto():
            # Пока старый процесс (после рестарта приложения) ещё держит порт
            # прокси, первый старт может упасть с «Port already in use». Ретраим
            # до 10 раз с паузой 1с: старый процесс умирает, порт освобождается,
            # прокси поднимается. ВАЖНО: всё это в ФОНОВОМ потоке — иначе создание
            # трея блокируется до ~10с и при рестарте выглядит как «очень долго
            # грузит». Раньше цикл был синхронным здесь, до create_tray_app.
            if tools.start_mtproto_proxy(port=port, host=host, secret=secret):
                return
            logging.warning("[MTPROTO] Первая попытка восстановить прокси не удалась, ретраим...")
            for _ in range(10):
                time.sleep(1)
                if tools.start_mtproto_proxy(port=port, host=host, secret=secret):
                    logging.info("[MTPROTO] Прокси восстановлен повторной попыткой")
                    return
            logging.error("[MTPROTO] Не удалось восстановить прокси после 10 попыток")

        threading.Thread(target=_restore_mtproto, daemon=True).start()

    last_bat = app_state.get("last_bat")
    if last_bat:
        logging.info(f"[STRATEGY] Восстановление стратегии: {last_bat}")
        for b in bat_files:
            if b.stem == last_bat:
                threading.Thread(target=lambda b=b: service.start_service(b, b.stem), daemon=True).start()
                break

    exit_code = ui.create_tray_app(bat_files, register_sleep_handler)
    
    app_state = state.load_state()
    port = app_state.get("mtproto_port", 1443)
    host = app_state.get("mtproto_host", "127.0.0.1")
    tools.stop_mtproto_proxy(port=port, host=host, wait=False)
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()  # вызовет _main_inner через main()
