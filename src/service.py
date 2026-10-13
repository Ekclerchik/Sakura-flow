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
        result = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
        # 1060 — служба не существует (уже удалена) — считаем остановленной
        if result and (result.returncode == 1060 or (result.stdout and _STOP_RE.search(result.stdout))):
            return True
        time.sleep(0.5)
    return False


def _wait_service_running(timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        result = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
        if result and (result.stdout and _RUN_RE.search(result.stdout)):
            return True
        time.sleep(0.5)
    return False


def _winws_running():
    result = run_cmd('tasklist /FI "IMAGENAME eq winws.exe"')
    return bool(result) and "winws.exe" in (result.stdout or "").lower()


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
        # Удаляем службу (она создаётся с start=auto): иначе после Stop/Exit она
        # остаётся автозапускаемой и Windows поднимет winws при следующей загрузке
        # ПК. Это же обязательно перед следующим стартом — sc create не
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
        'sc.exe', 'create', SERVICE_NAME, 'start=', 'auto',
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


def start_service(batch_path, display_version):
    with _service_lock:
        return _start_locked(batch_path, display_version)


def stop_service():
    with _service_lock:
        _stop_locked()
