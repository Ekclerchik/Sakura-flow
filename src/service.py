"""Windows service management functions for Sakura Flow."""
import subprocess
import re
import time
import logging
from pathlib import Path

try:
    from .config import SERVICE_NAME, BAT_DIR, CONSOLE_ENCODING
except ImportError:
    from src.config import SERVICE_NAME, BAT_DIR, CONSOLE_ENCODING


# sc.exe query выдаёт статус на языке ОС (RU: РАБОТАЕТ/ОСТАНОВЛЕН).
_RUN_RE = re.compile(r"\b(RUNNING|РАБОТАЕТ)\b", re.IGNORECASE)
_STOP_RE = re.compile(r"\b(STOPPED|ОСТАНОВЛЕН\w*)\b", re.IGNORECASE)

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


def _wait_service_gone(timeout=10):
    """Служба удалена окончательно (sc query → 1060). Пока она в состоянии
    'marked for deletion', sc create с тем же именем падает с 1072."""
    start = time.time()
    while time.time() - start < timeout:
        result = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
        if result and result.returncode == 1060:
            return True
        time.sleep(0.5)
    return False


def windivert_stuck():
    """True, если драйвер WinDivert завис в STOP_PENDING — winws не сможет
    стартовать до перезагрузки ПК. Останавливать его принудительно нельзя
    (гонка при остановке вешает драйвер), но знать о зависании нужно."""
    result = run_cmd('sc.exe query "WinDivert"')
    return bool(result) and "STOP_PENDING" in (result.stdout or "")


def restart_service(batch_path, display_version):
    if service_exists():
        stop_service()
        _wait_service_stopped()
        delete_service()
    return start_service(batch_path, display_version)


def run_cmd(cmd, timeout=None):
    logging.info(f"Выполнение команды: {cmd}")
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              encoding=CONSOLE_ENCODING, timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.warning(f"Команда зависла ({timeout}с): {cmd}")
        return None
    except Exception as e:
        logging.error(f"Ошибка команды: {e}")
        return None


def service_exists():
    result = run_cmd(f'sc.exe query "{SERVICE_NAME}"')
    return result and result.stdout


def get_service_display_name():
    if not service_exists():
        return None
    result = run_cmd(f'sc.exe qc "{SERVICE_NAME}"')
    if result and result.returncode == 0:
        match = re.search(r'DISPLAY_NAME\s*:\s*(.+)', result.stdout)
        if match:
            return match.group(1).strip()
    return None


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


def parse_bat_file(batch_path):
    """Достаёт из стратегии .bat путь к winws.exe и его аргументы."""
    logging.info(f"Разбор стратегии: {batch_path}")
    with open(batch_path, 'r', encoding="utf-8") as f:
        bat_content = f.read()

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
    # winws стартует с CWD=bin_dir и логируется в winws.log рядом со стратегией
    # (абсолютный путь — чтобы проверки ремонта находили его из zapret\)
    log_path = bin_dir.parent / "winws.log"
    # Служба выполняется инлайн-командой cmd.exe (редirect в winws.log сохранён),
    # БЕЗ пакетного файла. Раньше здесь создавался _zapret_service.bat, который cmd
    # держал открытым всё время работы winws → файл нельзя было удалить/перезаписать
    # до остановки службы или перезагрузки ПК. Теперь лочить нечего.
    cmd_line = f'cmd.exe /c "cd /d "{bin_dir}" && "{executable}" {args} > "{log_path}" 2>&1"'

    cmd_args = [
        'sc.exe', 'create', SERVICE_NAME, 'start=', 'auto',
        'displayname=', service_display, 'binPath=', cmd_line
    ]
    result = subprocess.run(cmd_args, capture_output=True, text=True, encoding=CONSOLE_ENCODING)
    if result.returncode != 0:
        raise RuntimeError(
            f"sc.exe create не удался ({result.returncode}): "
            f"{(result.stderr or result.stdout or '').strip()}")


def start_service(batch_path, display_version):
    if service_exists():
        stop_service()
        # без этих ожиданий sc create иногда падает с 1072/183: служба ещё
        # не остановилась или висит в 'marked for deletion' после sc delete
        _wait_service_stopped()
        delete_service()
        _wait_service_gone()

    # если драйвер завис в STOP_PENDING — winws не стартует до перезагрузки ПК;
    # честно сообщаем, а не молча создаём мёртвую службу
    if windivert_stuck():
        logging.error("[SERVICE] WinDivert завис в STOP_PENDING — winws не запустится до перезагрузки ПК")
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
        logging.error("[SERVICE] Service failed to reach RUNNING state after start")
    return ok


def stop_service():
    if service_exists():
        logging.info("Остановка SakuraFlowService и очистка процессов...")
        # таймауты: sc.exe команды могут висеть (напр. драйвер, держимый процессом)
        run_cmd(f'sc.exe stop "{SERVICE_NAME}"', timeout=30)
        run_cmd('taskkill /F /IM winws.exe /T', timeout=15)
        # WinDivert принудительно НЕ останавливаем: гонка при остановке подвешивает
        # драйвер в STOP_PENDING, после чего winws не может стартовать до ребута
        if windivert_stuck():
            logging.error("[SERVICE] WinDivert завис в STOP_PENDING — потребуется перезагрузка ПК")
    else:
        return None


def delete_service():
    if service_exists():
        run_cmd(f'sc.exe delete "{SERVICE_NAME}"')
    else:
        return None
