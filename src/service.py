"""Windows service management functions for Sakura Flow.

================================================================================
ИНВАРИАНТЫ START/STOP — НЕ ЛОМАТЬ (проверено эмпирически против Sakura-flow-3.3.9)
================================================================================

1) Драйвер WinDivert приложение НЕ останавливает НИКОГДА и НИГДЕ.
   Запрещено `sc stop "WinDivert"` (раньше был в _stop_locked и _start_locked).
   Гонка при остановке подвешивает драйвер в STOP_PENDING, после чего winws не
   стартует до ПЕРЕЗАГРУЗКИ ПК. Эталон 3.3.9 драйвер не трогает вообще.
   (Симптом в логе: «WinDivert залип в STOP_PENDING». Не «лечить» это повторной
   остановкой драйвера — только усугубит.)

2) windivert_stuck() == True ТОЛЬКО при STOP_PENDING.
   RUNNING + START_TYPE=disabled — это НОРМА: WinDivert.dll поднимает драйвер по
   требованию, winws на нём стартует. НЕ добавлять сюда проверки START_TYPE /
   DISABLED: прежняя ветка «RUNNING, но DISABLED = зомби» — ложное срабатывание,
   из-за которого winws не давали запустить на живом рабочем драйвере (а 3.3.9
   на том же драйвере работал).

3) `sc create` НЕ пересоздаёт существующую службу (ошибка 1073 «служба уже
   существует»). Поэтому sc delete (_delete_locked) ОБЯЗАТЕЛЕН перед
   create_service. В эталоне 3.3.9 удаление делает UI-Stop:
   `stop_service()` + `delete_service()`.

4) Остановка (_stop_locked) — строго и коротко: sc stop → ждать STOPPED →
   taskkill /F winws → sc delete. НЕ добавлять длинные ожидания
   (_wait_service_gone / _wait_winws_gone по 5–10 c) и НЕ уводить остановку в
   фоновый поток с мостом: это давало Stop ~24 c и висящее меню трея на Exit.

5) Любая операция со службой — под _service_lock. start/stop/delete/restart
   приходят из разных потоков (трей, редактор списков, обработчик сна) и без
   блокировки гоняются друг с другом (sc create/delete → 1072/183).

6) Exit/Restart в ui.py гасят службу СИНХРОННО в GUI-потоке (stop_service →
   QApplication.quit) — без фоновых потоков и без «моста»: трей и меню должны
   исчезать сразу.

7) winws.exe гасится `taskkill /F /IM winws.exe /T`; служба
   SakuraFlowService — через sc (stop/delete). Не путать эти сущности.

8) Служба создаётся с start= delayed-auto (НЕ auto): при автостарте Wi-Fi ещё
   ассоциируется, и winws, стартующий WinDivert-драйвер в первые секунды
   загрузки, ломал ассоциацию Wi-Fi («подключается, но без интернета»).
   Delayed-auto уводит старт службы на пару минут после загрузки — сетевой стек
   успевает подняться без костылей.

9) Подготовка окружения перед create/start — порт шагов service.bat, которые
   наш старт (прямая сборка команды winws) пропускал:
     - TCP timestamps  (:tcp_enable)    — нужны --dpi-desync-fooling=ts;
     - user-списки     (:load_user_lists) — winws падает на старте, если в
       аргументах есть --hostlist с несуществующим файлом.
   Оба шага (_prepare_start_environment) быстрые и с таймаутами: НЕ превращать
   их в «долгое ожидание», иначе задействуют и Stop из GUI-потока.

10) start_service(force=False) может НЕ пересоздавать службу, если она уже
   RUNNING с той же стратегией и живым winws (метка стратегии в реестре):
   логон-восстановление после ребута не должен дёргать рабочую службу.
   force=True — безусловный старт: quick_restart и перезапуск после сна.
================================================================================
"""
import subprocess
import re
import time
import logging
import threading
from pathlib import Path

try:
    from .config import SERVICE_NAME, BAT_DIR, CONSOLE_ENCODING
except ImportError:
    from src.config import SERVICE_NAME, BAT_DIR, CONSOLE_ENCODING

# psutil — определение типа активного подключения (Wi-Fi/Ethernet) для
# диагностики «на Wi-Fi работает, по проводу нет». Опционально.
try:
    import psutil
except ImportError:
    psutil = None

# winreg — метка текущей стратегии в реестре службы (см. start_service(force)).
try:
    import winreg
except ImportError:  # не-Windows окружение / тесты
    winreg = None


# GUI-процесс без консоли: дочерние sc.exe/cmd.exe без этого флага получают
# новое консольное окно, которое мелькает при каждой операции со службой.
_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW


# sc.exe query выдаёт статус на языке ОС (RU: РАБОТАЕТ/ОСТАНОВЛЕН).
_RUN_RE = re.compile(r"\b(RUNNING|РАБОТАЕТ)\b", re.IGNORECASE)
_STOP_RE = re.compile(r"\b(STOPPED|ОСТАНОВЛЕН\w*)\b", re.IGNORECASE)
# STOP_PENDING на RU-системе: «ОСТАНОВКА_ОЖИДАНИЕ» / «ОСТАНОВКА ОЖИДАНИЕ»
_STOP_PENDING_RE = re.compile(r"STOP_PENDING|ОСТАНОВ\w*\s*_?\s*ОЖИД", re.IGNORECASE)

# Запуск winws в стратегии .bat. Поддерживаются оба формата zapret:
#   старый:  start "zapret: %~n0" /min "%BIN%winws.exe" --debug ...
#   новый:   "%BIN%winws.exe" --debug ...            (Flowseal service.bat)
_WINWS_RE = re.compile(r'"?[^"\s]*winws\.exe"?', re.IGNORECASE)
# префикс `start "заголовок" /min` перед исполняемым файлом — выкидываем
_START_PREFIX_RE = re.compile(r'^\s*start\s+(?:"[^"]*"|\S+)?\s*(?:/[a-z]+\s+)*$', re.IGNORECASE)
# хвостовой редирект стратегии (`> "%LOG_FILE%" 2>&1`) — логирование делает
# create_service (winws.log), лишний редирект ломал бы и его
_TAIL_REDIRECT_RE = re.compile(
    r'(?:\s*(?:>>?|&>)\s*(?:"[^"]*"|[^\s]+)\s*(?:2>&1|1>&2|&>\s*[^\s]+)?\s*)+$', re.IGNORECASE)


def _wait_service_stopped(timeout=8):
    start = time.time()
    while time.time() - start < timeout:
        result = _sc_query()
        # 1060 — служба не существует (уже удалена) — считаем остановленной
        if result and (result.returncode == 1060 or (result.stdout and _STOP_RE.search(result.stdout))):
            return True
        time.sleep(0.5)
    return False


def _wait_service_running(timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        result = _sc_query()
        if result and (result.stdout and _RUN_RE.search(result.stdout)):
            return True
        time.sleep(0.5)
    return False


def _sc_query():
    """sc.exe query списком аргументов БЕЗ shell: run_cmd(shell=True) спавнит
    cmd.exe + sc.exe (2 процесса) на КАЖДЫЙ опрос, а опросы идут каждые 0.5с
    в циклах ожидания (до ~50 подпроцессов за один старт/стоп службы)."""
    try:
        return subprocess.run(
            ['sc.exe', 'query', SERVICE_NAME],
            capture_output=True, text=True, encoding=CONSOLE_ENCODING,
            timeout=10, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        logging.warning("[SERVICE] sc.exe query завис (10с)")
        return None
    except Exception as e:
        logging.error(f"[SERVICE] sc.exe query error: {e}")
        return None


def _winws_running():
    """Делегируем tools.is_winws_running(): там psutil-путь с PID-мемо и
    TTL-кэшированный tasklist; раньше тут был run_cmd(shell=True), т.е.
    cmd.exe + tasklist (~60мс) на каждый вызов."""
    try:
        from .tools import is_winws_running
    except ImportError:
        from src.tools import is_winws_running
    return is_winws_running()


# Признаки того, что winws не смог открыть фильтр WinDivert из-за залипших
# объектов WFP (FWP_E_IN_USE / 0x8032000A).
_WINDIVERT_FILTER_ERRORS = (
    "error opening filter",
    "referenced by other objects",
)

def winws_filter_error():
    """Конкретная строка ошибки открытия фильтра WinDivert из winws.log, если
    файл существует. В проекте лог winws не ведётся (стратегия не логирует), так
    что это запасной источник — например, старый/ручной лог."""
    try:
        data = (BAT_DIR / "winws.log").read_text(encoding="utf-8",
                                                 errors="replace")
    except OSError:
        return None
    for line in reversed(data.splitlines()[-80:]):
        low = line.lower()
        if any(marker in low for marker in _WINDIVERT_FILTER_ERRORS):
            return line.strip()
    return None


def _service_exit_code():
    """WIN32_EXIT_CODE службы (1067 = winws аварийно завершился на старте)."""
    q = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
    out = (q.stdout or "") if q else ""
    m = re.search(r"WIN32_EXIT_CODE\s*:\s*(\d+)", out)
    try:
        return int(m.group(1)) if m else None
    except (AttributeError, ValueError):
        return None


def describe_start_failure():
    """Разбор, почему winws не поднялся: факты окружения + вероятные причины.
    Идёт и в файловый лог, и в уведомление трея. Лога winws не требует (его в
    проекте нет), опирается на код выхода службы и состояние драйвера/файлов."""
    lines = ["winws не запустился (служба не дошла до RUNNING)."]

    facts = []
    code = _service_exit_code()
    if code not in (None, 0, 1073):
        facts.append(f"код выхода службы: {code} "
                     f"(1067 = winws аварийно завершился при старте)")
    if windivert_stuck():
        facts.append("драйвер WinDivert в состоянии STOP_PENDING")
    bin_dir = BAT_DIR / "bin"
    missing = [f for f in ("winws.exe", "WinDivert.dll", "WinDivert64.sys",
                           "cygwin1.dll") if not (bin_dir / f).exists()]
    if missing:
        facts.append("отсутствуют файлы: " + ", ".join(missing))
    werr = winws_filter_error()
    if werr:
        facts.append("winws: " + werr)

    if facts:
        lines.append("Факты:")
        lines.extend("  - " + f for f in facts)

    # Окружение на момент разбора (сеть/тип подключения/TCP timestamps/
    # WinDivert/BFE). Баги 2/3 («не десинкается», «Wi-Fi vs Ethernet») без
    # этих фактов в логе не отличить от ошибки стратегии.
    try:
        lines.append("Состояние на момент вызова:")
        lines.extend("  - " + l for l in _diag_environment_lines())
    except Exception as e:
        logging.debug(f"[SERVICE] Диагностика окружения недоступна: {e}")

    lines.append("Вероятные причины (по частоте):")
    lines.append("  - залипшие объекты WinDivert (FWP_E_IN_USE, «referenced by "
                 "other objects»): прошлый winws/драйвер не освободил WFP-фильтр "
                 "— обычно лечится ПЕРЕЗАГРУЗКОЙ ПК.")
    lines.append("  - фильтр держит другой winws.exe или «зависшая» служба "
                 "SakuraFlowService — нажми Stop и повтори старт.")
    lines.append("  - неполная/повреждённая папка zapret\\bin (нет winws.exe / "
                 "WinDivert.dll / WinDivert64.sys / cygwin1.dll).")
    lines.append("  - нет прав администратора, либо антивирус блокирует загрузку "
                 "WinDivert64.sys.")
    return "\n".join(lines)


def windivert_stuck():
    """True, если драйвер WinDivert завис в STOP_PENDING (winws не сможет стартовать).

    Как в эталонной 3.3.9: RUNNING-драйвер НЕ считаем зависшим, даже если у него
    START_TYPE=disabled. WinDivert.dll поднимает драйвер по требованию, и winws
    на таком драйвере стартует нормально (проверено: 3.3.9 работает). Раньше тут
    была ветка «RUNNING, но DISABLED = зомби» — это ложное срабатывание, из-за
    которого winws не давали запустить на живом рабочем драйвере.
    См. ИНВАРИАНТ 2: НЕ возвращать проверку START_TYPE/DISABLED.
    """
    result = run_cmd('sc.exe query "WinDivert"')
    return bool(result) and bool(_STOP_PENDING_RE.search(result.stdout or ""))


# ============================================================================
# ПОДГОТОВКА ОКРУЖЕНИЯ ПЕРЕД СТАРТОМ winws (порт шагов zapret/service.bat)
#
# Наш старт собирает команду winws напрямую (parse_bat_file + create_service),
# минуя service.bat, поэтому его подготовительные шаги никогда не выполнялись:
#   - :tcp_enable        — TCP timestamps. Штатная стратегия использует
#     --dpi-desync-fooling=ts: при выключенных метках времени winws не может
#     подделать поле Timestamps, и десинк МОЛЧА не срабатывает (симптом бага 2:
#     «служба RUNNING, winws жив, а обхода нет»). Раньше работало только если
#     пользователь сам гонял zapret service.bat — он и включал timestamps.
#   - :load_user_lists   — гарантия существования файлов user-списков. winws
#     падает на старте, если в его аргументах есть --hostlist с несуществующим
#     файлом; наши user-списки могли быть удалены «чисткой папки».
# ============================================================================

# Содержимое user-списков по умолчанию — как в service.bat :load_user_lists.
_USER_LIST_DEFAULTS = {
    "ipset-exclude-user.txt": "203.0.113.113/32",
    "list-general-user.txt": "domain.example.abc",
    "list-exclude-user.txt": "domain.example.abc",
}


def _ensure_user_lists():
    """Файлы user-списков обязаны существовать (порт :load_user_lists).
    Недостающие создаём с тем же содержимым-заглушкой, что и zapret."""
    lists_dir = BAT_DIR / "lists"
    try:
        lists_dir.mkdir(parents=True, exist_ok=True)
        for name, content in _USER_LIST_DEFAULTS.items():
            path = lists_dir / name
            if not path.exists():
                path.write_text(content + "\n", encoding="utf-8")
                logging.info(f"[SERVICE] Создан отсутствующий user-список: {path.name}")
    except OSError as e:
        logging.warning(f"[SERVICE] Не удалось проверить/создать user-списки: {e}")


def _tcp_timestamps_enabled():
    """True/False — включены ли TCP timestamps (netsh interface tcp show global).
    None — вывод не разобрался/команда не удалась. Значения на разных системах
    могут быть 'enabled'/'disabled' или 'включено'/'отключено'."""
    try:
        result = run_cmd("netsh interface tcp show global", timeout=15)
    except Exception:
        return None
    if not result:
        return None
    for line in (result.stdout or "").splitlines():
        low = line.lower()
        if "timestamp" not in low and "времени" not in low:
            continue
        if re.search(r"enabled|включ", line, re.IGNORECASE):
            return True
    return False


def _ensure_tcp_timestamps():
    """Порт :tcp_enable из service.bat: включаем TCP timestamps, если выключены.
    Стратегии с --dpi-desync-fooling=ts БЕЗ них не десинкают (баг 2)."""
    state = _tcp_timestamps_enabled()
    if state is True:
        return True
    logging.info("[SERVICE] TCP timestamps выключены — включаю "
                 "(порт :tcp_enable; без них --dpi-desync-fooling=ts не работает)")
    run_cmd("netsh interface tcp set global timestamps=enabled", timeout=15)
    if _tcp_timestamps_enabled() is False:
        logging.warning("[SERVICE] Не удалось подтвердить включение TCP timestamps "
                        "(проверь вручную: netsh interface tcp show global)")
        return False
    return True


def _prepare_start_environment():
    """Сводный шаг подготовки окружения перед create/start (см. блок выше).
    БЫСТРЫЙ и без 'долгого ожидания' — инвариант 9."""
    _ensure_tcp_timestamps()
    _ensure_user_lists()


# ============================================================================
# СЕТЬ И ДИАГНОСТИКА ОКРУЖЕНИЯ (баги 1/2/3)
# ============================================================================

# Wi-Fi-подсказки в имени интерфейса: psutil не даёт MediaType, а запускать
# ради этого нечто типа PowerShell при каждом старте не хочется.
_WIFI_HINTS = ("wi-fi", "wifi", "wlan", "wireless", "беспровод", "802.11")


def _active_connection_desc():
    """Короткое описание активного подключения для лога/диагностики:
    «Wi-Fi», «Ethernet», «Wi-Fi + Ethernet» или «нет интерфейса».
    Тип определяем ПО ИМЕНИ интерфейса. Нужен для бага 3 («стратегия ведёт себя
    по-разному на Wi-Fi и Ethernet»): без записи типа подключения в лог причину
    всегда ищут наугад, хотя чаще это просто ДРУГАЯ сеть (другой DPI на пути)."""
    if psutil is None:
        return "неизвестно (psutil недоступен)"
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        kinds = set()
        for name, s in stats.items():
            if not s.isup or name.lower().startswith("loopback"):
                continue
            # интерфейс должен иметь IPv4, отличный от 127.x — иначе media up без сети
            has_ip = any(a.family == 2 and not a.address.startswith("127.")
                         for a in addrs.get(name, []))
            if not has_ip:
                continue
            low = name.lower()
            kinds.add("Wi-Fi" if any(h in low for h in _WIFI_HINTS) else "Ethernet")
        return " + ".join(sorted(kinds)) if kinds else "нет интерфейса с IPv4"
    except Exception as e:
        return f"неизвестно ({e})"


def _has_default_route():
    """Есть ли маршрут по умолчанию (Wi-Fi уже ассоциировался и получил DHCP).
    GetBestInterface для внешнего адреса НЕ отправляет пакетов и мгновенно
    отвечает ошибкой, если шлюза нет / медиа отключены — то, что нужно."""
    try:
        import ctypes
        best_if = ctypes.c_ulong(0)
        # 8.8.8.8 (0x08080808) — заведомо внешний адрес: «достижим» только
        # через шлюз по умолчанию.
        rc = ctypes.windll.iphlpapi.GetBestInterface(0x08080808, ctypes.byref(best_if))
        return rc == 0 and best_if.value != 0
    except Exception:
        # Фолбэк: маршрут 0.0.0.0/0 со шлюзом не «0.0.0.0 / On-link».
        result = run_cmd("route print -4", timeout=15)
        out = (result.stdout or "") if result else ""
        for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)", out, re.MULTILINE):
            if m.group(1).lower() not in ("0.0.0.0", "on-link", "в_сети", "на связи"):
                return True
        return False


def _wait_for_network(timeout=60):
    """Ждать появления маршрута по умолчанию до timeout сек (баг 1: при
    автостарте Wi-Fi ещё ассоциируется; запущенный в этот момент winws ломал
    ассоциацию). Возвращает True, если сеть появилась. При таймауте НЕ блокируем
    старт навсегда — запускаем как есть (пользователь мог запустить без сети)."""
    if _has_default_route():
        return True
    logging.info(f"[SERVICE] Сети ещё нет — жду появления маршрута по умолчанию (до {timeout}с)...")
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(1.5)
        if _has_default_route():
            logging.info(f"[SERVICE] Сеть появилась через {time.time() - start:.0f}с ожидания")
            return True
    logging.warning("[SERVICE] Маршрут по умолчанию не появился за "
                    f"{timeout}с — запускаю winws как есть")
    return False


def _service_state(name):
    """Краткое состояние службы (RUNNING/STOPPED/STOP_PENDING/нет/None)."""
    result = run_cmd(f'sc.exe query "{name}"', timeout=10)
    if not result:
        return None
    out = result.stdout or ""
    if result.returncode == 1060:
        return "нет"
    if _STOP_PENDING_RE.search(out):
        return "STOP_PENDING"
    if _RUN_RE.search(out):
        return "RUNNING"
    if _STOP_RE.search(out):
        return "STOPPED"
    return "неизвестно"


def _diag_environment_lines():
    """Список строк-фактов окружения на момент старта winws. Логируется при
    каждом запуске и добавляется в describe_start_failure — разбор жалоб
    «не десинкается» не должен требовать вопросов к пользователю (баги 2/3)."""
    ts = _tcp_timestamps_enabled()
    ts_txt = ("включены" if ts else
              "ВЫКЛЮЧЕНЫ — --dpi-desync-fooling=ts не сработает" if ts is False else
              "не удалось проверить")
    lines = [
        f"маршрут по умолчанию: {'есть' if _has_default_route() else 'НЕТ'}",
        f"активное подключение: {_active_connection_desc()}",
        f"TCP timestamps: {ts_txt}",
        f"WinDivert: {_service_state('WinDivert')}; BFE: {_service_state('bfe')}",
    ]
    return lines


# Глобальная блокировка на все операции со службой: start/stop/delete/restart
# могут приходить из разных потоков (трей, редактор списков, обработчик
# пробуждения) и без неё гоняются друг с другом (sc create/delete → 1072/183).
_service_lock = threading.Lock()


def restart_service(batch_path, display_version):
    with _service_lock:
        if service_exists():
            _stop_locked()
        return _start_locked(batch_path, display_version)


def run_cmd(cmd, timeout=None):
    logging.info(f"Выполнение команды: {cmd}")
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              encoding=CONSOLE_ENCODING, timeout=timeout,
                              creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        logging.warning(f"Команда зависла ({timeout}с): {cmd}")
        return None
    except Exception as e:
        logging.error(f"Ошибка команды: {e}")
        return None


def service_exists():
    result = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
    return result and result.stdout


def _delete_locked():
    """Удалить SakuraFlowService (sc delete).

    ОБЯЗАТЕЛЬНА перед create_service: sc create не пересоздаёт существующую
    службу (1073). sc delete асинхронный — см. ретрай по 1073 в create_service.
    См. ИНВАРИАНТ 3 в шапке файла."""
    if service_exists():
        run_cmd(f'sc.exe delete "{SERVICE_NAME}"')


def _kill_winws():
    """Завершить winws.exe (taskkill /F). Вызывается из _start_locked после
    убийства «сироты». Драйвер WinDivert не трогаем — как в эталонной 3.3.9."""
    if not _winws_running():
        return
    logging.warning("[SERVICE] winws не завершился — принудительное завершение (taskkill /F)")
    run_cmd('taskkill /F /IM winws.exe /T', timeout=15)


def _stop_locked():
    """Остановка: служба SakuraFlowService + winws.exe.

    Механика — как в эталонной 3.3.9: sc stop → ждём STOPPED → taskkill /F winws
    → delete службы (эталон делает delete в UI Stop). Драйвер WinDivert намеренно
    НЕ останавливаем (sc stop "WinDivert"): гонка при остановке подвешивает его в
    STOP_PENDING, после чего winws не стартует до перезагрузки ПК.
    Порядок шагов — ИНВАРИАНТ 4; длинных ожиданий (_wait_service_gone и т.п.)
    и фоновых остановок сюда НЕ добавлять (дали Stop ~24 c)."""
    if service_exists():
        logging.info("Остановка SakuraFlowService...")
        run_cmd(f'sc.exe stop "{SERVICE_NAME}"', timeout=30)
        _wait_service_stopped()
        run_cmd('taskkill /F /IM winws.exe /T', timeout=15)
        # Удаляем службу (create_service создаёт её с delayed-auto): иначе после
        # Stop/Exit Windows всё равно поднимет winws через пару минут после
        # загрузки ПК. Это же обязательно перед следующим стартом — sc create не
        # пересоздаёт существующую службу и падал с 1073 «служба уже существует».
        _delete_locked()
        if windivert_stuck():
            logging.error("[SERVICE] WinDivert залип в STOP_PENDING — потребуется перезагрузка ПК")
    else:
        # Службы нет, а winws.exe мог остаться «сиротой» (служба удалена,
        # процесс жив). Без этого ветку Stop нечем погасить: кнопка навсегда
        # оставалась бы «Stop».
        if _winws_running():
            logging.warning("[SERVICE] Служба не найдена, а winws.exe работает — сирота, завершаю")
            run_cmd('taskkill /F /IM winws.exe /T', timeout=15)


def _extract_winws_command(bat_content):
    """Первая строка батника с вызовом winws.exe + её продолжения (`^` в конце
    строки) склеиваются в одну команду. Комментарии и пустые строки пропускаем."""
    command = None
    for raw_line in bat_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("::") or line.lower().startswith("rem "):
            continue
        continued = line.endswith("^")
        if continued:
            line = line[:-1].strip()
            if not line:
                continue
        if command is None:
            if not _WINWS_RE.search(line):
                continue
            command = line
            if not continued:
                break
            continue
        command = f"{command} {line}"
        if not continued:
            break
    return command


def _read_text_any(path):
    """Прочитать текст устойчивый к кодировке: стратегии .bat на RU-Windows
    часто сохранены в cp1251/ANSI, а не в UTF-8 (падало с UnicodeDecodeError)."""
    data = Path(path).read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1251", "cp866"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def parse_bat_file(batch_path):
    """Достаёт из стратегии .bat путь к winws.exe и его аргументы."""
    logging.info(f"Разбор стратегии: {batch_path}")
    bat_content = _read_text_any(batch_path)

    base_zapret = BAT_DIR
    bin_dir = base_zapret / "bin"
    lists_dir = base_zapret / "lists"

    game_filter_path = base_zapret / "utils" / "game_filter.enabled"
    if game_filter_path.exists():
        mode = game_filter_path.read_text("utf-8").strip().lower()
    else:
        mode = "disabled"

    if mode == "all":
        game_filter_tcp = "1024-65535"
        game_filter_udp = "1024-65535"
    elif mode == "tcp":
        game_filter_tcp = "1024-65535"
        game_filter_udp = "12"
    elif mode == "udp":
        game_filter_tcp = "12"
        game_filter_udp = "1024-65535"
    else:
        game_filter_tcp = "12"
        game_filter_udp = "12"

    game_filter = "1024-65535" if mode != "disabled" else "12"

    bat_content = bat_content.replace("%GameFilter%", game_filter)
    bat_content = bat_content.replace("%GameFilterTCP%", game_filter_tcp)
    bat_content = bat_content.replace("%GameFilterUDP%", game_filter_udp)

    command = _extract_winws_command(bat_content)
    if not command:
        raise ValueError(f"Ошибка: вызов winws.exe не найден в батнике {batch_path}")

    exe_match = _WINWS_RE.search(command)
    prefix = _START_PREFIX_RE.sub("", command[:exe_match.start()])
    args = (prefix + command[exe_match.end():]).strip()
    args = _TAIL_REDIRECT_RE.sub("", args).strip()

    executable = str(bin_dir / "winws.exe")
    if not Path(executable).exists():
        raise FileNotFoundError(f"Ошибка: {executable} не найден")

    replacements = {
        "%BIN%": str(bin_dir) + "\\",
        "%LISTS%": str(lists_dir) + "\\",
        "%~dp0": str(base_zapret) + "\\"
    }
    for macro, real_path in replacements.items():
        args = args.replace(macro, real_path)

    args = args.replace("\\\\", "\\")
    return executable, args


def create_service(batch_path, display_version):
    executable, args = parse_bat_file(batch_path)
    service_display = f"Sakura Flow version[{display_version}]"
    bin_dir = Path(executable).parent
    # Служба выполняется инлайн-командой cmd.exe, БЕЗ пакетного файла и БЕЗ
    # редиректа в файл: сами стратегию не логируем (winws пишет по пакету —
    # файл раздувается), а причину сбоя старта объясняем в describe_start_failure
    # (код выхода службы + состояние драйвера/файлов + список вероятных причин).
    cmd_line = f'cmd.exe /c "cd /d "{bin_dir}" && "{executable}" {args}"'

    cmd_args = [
        'sc.exe', 'create', SERVICE_NAME,
        # delayed-auto, а НЕ auto (ИНВАРИАНТ 8 / баг 1): при старте 'auto' в
        # начале загрузки ПК winws успевает поднять WinDivert-драйвер ДО того,
        # как Wi-Fi-адаптер ассоциировался, — Wi-Fi не подключался вовсе или
        # подключался «без интернета». Задержка старта службы на пару минут
        # снимает гонку с инициализацией сетевого стека.
        'start=', 'delayed-auto',
        'displayname=', service_display, 'binPath=', cmd_line
    ]
    # sc delete асинхронный: сразу после удаления служба ещё какое-то время
    # числится в SCM (marked for deletion), и первый sc create вернёт 1073
    # «служба уже существует». Ждём её исчезновения и пробуем снова.
    result = None
    for attempt in range(5):
        result = subprocess.run(cmd_args, capture_output=True, text=True,
                                encoding=CONSOLE_ENCODING, creationflags=_NO_WINDOW)
        if result.returncode == 0:
            # Метка созданной стратегии: по ней start_service(force=False)
            # узнаёт, что служба уже несёт нужную стратегию, и не пересоздаёт
            # её (логон-восстановление после ребута не дёргает рабочий winws).
            _set_running_strategy(batch_path.stem)
            return
        if result.returncode == 1073 and attempt < 4:
            time.sleep(0.4)
            continue
        break
    raise RuntimeError(
        f"sc.exe create не удался ({result.returncode if result else '?'}): "
        f"{((result.stderr or result.stdout or '') if result else '').strip()}")


def _start_locked(batch_path, display_version):
    # Последовательность старта (порядок не менять):
    #   служба есть            -> _stop_locked() (sc stop → taskkill → sc delete)
    #   иначе «сирота» winws    -> _kill_winws() (taskkill)
    #   драйвер STOP_PENDING?  -> отказ (см. ИНВАРИАНТ 2)
    #   create_service() -> sc start -> ждать RUNNING.
    # Драйвер WinDivert не трогаем (ИНВАРИАНТ 1); службу обязательно удалить
    # перед create (ИНВАРИАНТ 3).
    if service_exists():
        # _stop_locked() останавливает и УДАЛЯЕТ службу (sc create падает с 1073
        # на существующей), затем создаём заново.
        _stop_locked()
    elif _winws_running():
        # winws, запущенный вне Sakura (например из консоли/старой версии),
        # не даст драйверу корректно стартовать новую службу — чистим.
        # Драйвер WinDivert не трогаем (как в эталонной 3.3.9): его остановка
        # подвешивает драйвер в STOP_PENDING, и winws не стартует до ребута.
        logging.warning("[SERVICE] winws.exe работает без службы — завершаю перед созданием службы")
        _kill_winws()

    # если драйвер залип в STOP_PENDING — winws не стартует до перезагрузки ПК;
    # честно сообщаем, а не молча создаём мёртвую службу.
    # RUNNING-драйвер с START_TYPE=disabled зависшим НЕ считаем (см. windivert_stuck).
    if windivert_stuck():
        logging.error("[SERVICE] WinDivert залип в STOP_PENDING — winws не "
                      "запустится до перезагрузки ПК")
        return False

    # Подготовка окружения (ПЕРЕД create): наш старт обходит service.bat, поэтому
    # шаги :tcp_enable/:load_user_lists никогда не выполнялись. Без timestamps
    # стратегии с --dpi-desync-fooling=ts молча не десинкают (баг 2).
    _prepare_start_environment()

    # Ждать сеть надо ДО запуска winws (маршрут по умолчанию должен уже быть):
    # вручную на подключившемся Wi-Fi старт происходит сразу, а на логоне Wi-Fi
    # ещё ассоциируется — раньше winws в этот момент ломал ассоциацию (или
    # стартовал «в никуда»). При таймауте старт продолжается как есть
    # (не блокируем навсегда).
    _wait_for_network()

    for line in _diag_environment_lines():
        logging.info(f"[SERVICE] Состояние на старте: {line}")

    try:
        create_service(batch_path, display_version)
    except Exception as e:
        # sys.exit здесь убивал поток GUI/старта — обычное исключение ловится
        # вызывающим кодом и пишется в лог
        logging.error(f"[SERVICE] Не удалось создать службу: {e}")
        return False
    run_cmd(f'sc.exe start "{SERVICE_NAME}"')
    ok = _wait_service_running()
    if not ok:
        # Раньше тут было сухое «failed to reach RUNNING». Теперь разбираем
        # реальную причину (ошибка winws, код выхода службы, файлы, драйвер).
        logging.error("[SERVICE] winws не запустился (служба не дошла до "
                      "RUNNING).\n" + describe_start_failure())
    return ok


# ----------------------------------------------------------------------------
# МЕТКА ТЕКУЩЕЙ СТРАТЕГИИ (реестр службы). Наш create_service каждый раз
# пересоздаёт службу под выбранную стратегию; чтобы логон-восстановление после
# ребута мог понять «служба уже несёт последнюю стратегию и работает» и не
# дёргать её (баг 1: перестарт winws в момент ассоциации Wi-Fi), пишем имя
# стратегии в value реестра этой же службы. Ошибка записи не фатальна.
# ----------------------------------------------------------------------------
_STRATEGY_REG_VALUE = "SakuraStrategy"
_REG_KEY_PATH = r"SYSTEM\CurrentControlSet\Services" + "\\" + SERVICE_NAME


def _set_running_strategy(name):
    """Сохранить имя стратегии, под которой создана служба (best-effort)."""
    if winreg is None:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_KEY_PATH, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, _STRATEGY_REG_VALUE, 0, winreg.REG_SZ, name)
    except OSError as e:
        logging.warning(f"[SERVICE] Не смог записать метку стратегии в реестр: {e}")


def _get_running_strategy():
    """Имя стратегии, сохранённое при последнем create_service, или None."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_KEY_PATH) as key:
            value, _type = winreg.QueryValueEx(key, _STRATEGY_REG_VALUE)
            return str(value) if value else None
    except OSError:
        return None


def _service_running():
    """Служба SakuraFlowService в состоянии RUNNING?"""
    result = run_cmd(f'sc.exe query "{SERVICE_NAME}"', timeout=10)
    return bool(result) and bool(_RUN_RE.search(result.stdout or ""))


def _already_running(batch_path):
    """True: служба RUNNING с ТЕМ ЖЕ именем стратегии и живым winws — старт
    можно пропустить (см. docstring start_service)."""
    if not _service_running():
        return False
    if not _winws_running():
        logging.warning("[SERVICE] Служба RUNNING, а winws.exe не запущен — "
                        "пересоздаю службу")
        return False
    wanted = Path(batch_path).stem
    running = _get_running_strategy()
    if running != wanted:
        if running:
            logging.info(f"[SERVICE] Запущена другая стратегия ({running} != {wanted}) — перезапускаю")
        return False
    return True


def start_service(batch_path, display_version, force=False):
    """Старт стратегии.

    force=False (логон-восстановление, Start в трее): если служба уже RUNNING
    с той же стратегией и живым winws, НЕ пересоздаём её. Без этого после ребута
    последовательность «delayed-auto службу поднял → SakuraFlow при логоне
    остановил/удалил/создал заново» давала окно без обхода и (баг 1) дёргала
    сеть в момент ассоциации Wi-Fi.

    force=True (quick_restart из Network Tools — сменились списки/ipset/DNS,
    перезапуск после сна): безусловный старт.
    """
    with _service_lock:
        if not force and _already_running(batch_path):
            logging.info(f"[SERVICE] Стратегия «{Path(batch_path).stem}» уже "
                         "запущена (delayed-auto) — не пересоздаю службу")
            return True
        return _start_locked(batch_path, display_version)


def stop_service():
    with _service_lock:
        _stop_locked()
