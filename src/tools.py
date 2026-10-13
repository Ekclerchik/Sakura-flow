import subprocess
import socket
import threading
import time
import logging
import re
import os
from pathlib import Path

# psutil/ping3 — опциональные зависимости: на «убитом» компе их может не быть,
# приложение должно ЗАПУСТИТЬСЯ в любом случае (функции сами отдадут 0/None)
try:
    import psutil
except ImportError:
    psutil = None

try:
    from ping3 import ping
except ImportError:
    ping = None

try:
    from .config import BASE_DIR, FILE_ENCODING
    from . import state
    from .state import generate_secret
except ImportError:
    from src.config import BASE_DIR, FILE_ENCODING
    from src import state
    from src.state import generate_secret

# GUI-процесс запускается без консоли. Любой дочерний консольный процесс
# (tasklist / netsh / reg / ping) без этого флага получает НОВОЕ консольное
# окно, которое мелькает на экране. Особенно заметно из 1-секундного
# трей-таймера: он зовёт is_winws_running → tasklist, пока winws выключен.
_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW

_last_io = None
LIST_PATH = BASE_DIR / "zapret" / "lists" / "list-general.txt"
EXCLUDE_LIST_PATH = BASE_DIR / "zapret" / "lists" / "list-exclude.txt"

_proxies = {}
_proxy_lock = threading.Lock()


def get_ping(host):
    try:
        if ping is not None:
            p = ping(host, unit='ms')
            if p:
                return round(p, 2)
        else:
            return _ping_shell(host)
    except Exception:
        try:
            return _ping_shell(host)
        except Exception:
            return 'Error'
    return 'Timeout'


def _ping_shell(host, timeout_ms=1500):
    """Fallback-пинг без ping3: системный ping.exe (работает везде, где есть TCP/IP)."""
    try:
        r = subprocess.run(
            f'ping -n 1 -w {timeout_ms} {host}',
            shell=True, capture_output=True, text=True, timeout=timeout_ms // 1000 + 2,
            errors="replace", creationflags=_NO_WINDOW
        )
        m = re.search(r"[=<]\s*(\d+)\s*(?:ms|мс)",
                      (r.stdout or "") + (r.stderr or ""), re.IGNORECASE)
        if m:
            return float(m.group(1))
        if "TTL" in r.stdout:
            return 1.0
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return 'Timeout'


def get_traffic_stats():
    global _last_io
    try:
        net_io = psutil.net_io_counters()
        now_io = (net_io.bytes_sent, net_io.bytes_recv)
        if _last_io is None:
            _last_io = now_io
            return 0.0, 0.0
        up = (now_io[0] - _last_io[0]) / 1024
        down = (now_io[1] - _last_io[1]) / 1024
        _last_io = now_io
        return max(0, round(up, 1)), max(0, round(down, 1))
    except:
        return 0.0, 0.0


def read_blocklist():
    try:
        if not LIST_PATH.exists():
            return ""
        return LIST_PATH.read_text(encoding=FILE_ENCODING)
    except:
        return ""


def save_blocklist(text):
    try:
        LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        LIST_PATH.write_text(text.strip(), encoding=FILE_ENCODING)
        return True
    except:
        return False


def read_ignore_list():
    try:
        if not EXCLUDE_LIST_PATH.exists():
            return ""
        return EXCLUDE_LIST_PATH.read_text(encoding=FILE_ENCODING)
    except:
        return ""


def save_ignore_list(text):
    try:
        EXCLUDE_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        EXCLUDE_LIST_PATH.write_text(text.strip(), encoding=FILE_ENCODING)
        return True
    except:
        return False


# Контрольные домены: резолвим их ИМЕННО через проверяемый DNS, а потом пингуем
# полученный IP. Обычный `ping google.com` тут бесполезен — имя резолвит
# системный DNS, а не проверяемый, поэтому про конкретный резолвер не скажет ничего.
_DNS_CHECK_HOSTS = ("google.com", "yandex.ru")

# Приоритет резолверов при прочих равных. Yandex сделан под РФ-сегмент и хуже
# отдаёт зарубежные сервисы (тот же Discord грузится дольше, чем через Google),
# поэтому он — самый низкий. Остальные равны между собой, между ними решает замер.
_DNS_PRIORITY = {"Cloudflare": 3, "Google": 3, "Quad9": 3, "Yandex": 1}


def _resolve_via_dns(host, dns_ip):
    """Резолв host через конкретный DNS (nslookup host <dns>). Возвращает IP или None."""
    raw = _nslookup([host, dns_ip])
    if not raw:
        return None
    for a in re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw):
        if a == dns_ip or a == "0.0.0.0":
            continue
        if a.startswith(("10.", "192.168.", "169.254.", "127.")):
            continue
        octets = [int(x) for x in a.split(".")]
        if 0 < octets[0] < 224 and not (octets[0] == 172 and 16 <= octets[1] <= 31):
            return a
    return None


def find_best_dns():
    """Выбирает DNS не по пингу до него самого, а по тому, резолвит ли он живые
    сайты: для каждого резолвера резолвим контрольные домены через него и пингуем
    полученные IP. Лучший — приоритетнее, затем кто резолвит/пингует больше
    сайтов, затем быстрее. Возвращает список из 1-2 IP (первичный + вторичный)."""
    dns_list = {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8",
                "Yandex": "77.88.8.8", "Quad9": "9.9.9.9"}
    results = {}
    for name, ip in dns_list.items():
        sites = {}
        for host in _DNS_CHECK_HOSTS:
            addr = _resolve_via_dns(host, ip)
            ping_ms = None
            if addr:
                p = get_ping(addr)
                if isinstance(p, (int, float)):
                    ping_ms = p
            sites[host] = (addr, ping_ms)

        resolved = sum(1 for a, _ in sites.values() if a)
        alive = sum(1 for a, p in sites.values() if a and p is not None)
        pings = [p for _, p in sites.values() if p is not None]
        avg = round(sum(pings) / len(pings), 2) if pings else None
        results[name] = (ip, sites, resolved, alive, avg)

    usable = {n: r for n, r in results.items() if r[2] > 0}
    if not usable:
        return None, "All DNS failed to resolve google.com/yandex.ru"

    def _rank(n):
        _, _, resolved, alive, avg = usable[n]
        # живой резолвер > приоритет провайдера > больше живых сайтов > быстрее
        return (1 if alive else 0, _DNS_PRIORITY.get(n, 0), alive, resolved,
                -(avg if avg is not None else 1e9))

    ordered = sorted(usable, key=_rank, reverse=True)
    names = ordered[:2]                        # первичный + вторичный (разные)
    ips = [usable[n][0] for n in names]

    parts = []
    for host, (addr, ping_ms) in usable[names[0]][1].items():
        label = host.split(".")[0]
        if not addr:
            parts.append(f"{label}\u2716")           # не резолвится
        elif ping_ms is None:
            parts.append(f"{label}:resolve")          # резолвится, но не пингуется
        else:
            parts.append(f"{label}:{ping_ms}ms")
    head = " + ".join(f"{n} [{usable[n][0]}]" for n in names)
    return ips, f"{head} ({' '.join(parts)})"


def get_active_interface():
    try:
        for name, stats in psutil.net_if_stats().items():
            if stats.isup and not name.startswith("Loopback"):
                addrs = psutil.net_if_addrs().get(name, [])
                if any(a.family == 2 and not a.address.startswith("127.") for a in addrs):
                    return name
    except:
        pass
    return None


def set_system_dns(dns_ip):
    """Ставит DNS на активный интерфейс. Принимает один IP или список
    [первичный, вторичный] — второй добавляется как резервный (index=2)."""
    iface = get_active_interface()
    if not iface:
        return False, "Interface not found"
    ips = [dns_ip] if isinstance(dns_ip, str) else [x for x in (dns_ip or []) if x]
    if not ips:
        return False, "No DNS"
    try:
        # set ... source=static address=... полностью переписывает список (сбрасывает
        # в единственную запись), поэтому вторичный добавляем уже после.
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', f'name={iface}',
                        'source=static', f'address={ips[0]}'], capture_output=True,
                       creationflags=_NO_WINDOW)
        if len(ips) > 1:
            subprocess.run(['netsh', 'interface', 'ip', 'add', 'dns', f'name={iface}',
                            f'addr={ips[1]}', 'index=2'], capture_output=True,
                           creationflags=_NO_WINDOW)
        return True, iface
    except Exception as e:
        return False, str(e)


def reset_system_dns():
    iface = get_active_interface()
    if not iface:
        return False, "Interface not found"
    try:
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', f'name={iface}', 'source=dhcp'], capture_output=True, creationflags=_NO_WINDOW)
        return True, iface
    except Exception as e:
        return False, str(e)


def _get_process_using_port(port):
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port:
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        return f"{proc.name()} (PID {conn.pid})"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return f"PID {conn.pid}"
        return None
    except Exception:
        return None


def start_mtproto_proxy(port=1443, host='127.0.0.1', secret=None):
    port = int(port)
    # Ключ — ТОЛЬКО порт: host (127.0.0.1 / 0.0.0.0 / LAN-IP) это лишь адрес
    # прослушивания, а слушатель на порту один. Из-за ключа (host, port) стоп
    # не находил запись, если host между стартом и стопом отличался (0.0.0.0
    # → 127.0.0.1) → прокси оставался жив, кнопка застревала на STOP.
    key = port
    
    with _proxy_lock:
        if key in _proxies and _proxies[key]['thread'] and _proxies[key]['thread'].is_alive():
            if _check_mtproto_traffic(port, host):
                logging.info(f"[MTPROTO] Proxy {host}:{port} already running")
                return True
            else:
                logging.info(f"[MTPROTO] Proxy {host}:{port} thread dead but key exists, cleaning up")
                try:
                    del _proxies[key]
                except:
                    pass

    logging.debug(f"[MTPROTO] Proxy {host}:{port} starting...")

    try:
        from src.proxy.config import proxy_config
        from src import tg_ws_proxy
        logging.info("[MTPROTO] Import via 'from src' worked")
    except ImportError:
        from proxy.config import proxy_config
        import tg_ws_proxy
        logging.info("[MTPROTO] Import via 'import' worked")

    dc_opt = {
        4: '149.154.167.91'
    }

    app_state = state.load_state()
    
    # Поддержка кастомных DC из настроек (DC->IP в UI)
    custom_dc = app_state.get("custom_dc_redirects", {})
    if custom_dc:
        dc_opt.update(custom_dc)
    if secret is None:
        secret = app_state.get("mtproto_secret") or generate_secret()

    for attempt in range(3):
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            test_sock.bind((host, port))
            test_sock.close()
            break
        except OSError as e:
            test_sock.close()
            if attempt < 2:
                time.sleep(0.5)
                continue
            proc_info = _get_process_using_port(port)
            if proc_info:
                reason = f"Port {port} already used by: {proc_info}"
                logging.error(f"[MTPROTO] {reason}")
                return False
            else:
                reason = f"Port {port} already in use: {e}"
                logging.error(f"[MTPROTO] {reason}")
                return False
    
    import asyncio
    stop_event = asyncio.Event()
    thread_error: list = [None]
    loop_ref: list = [None]
    
    def _run():
        loop = None
        try:
            logging.info(f"[MTPROTO] _run before config, port={port}, host={host}")
            proxy_config.port = port
            proxy_config.host = host
            proxy_config.secret = secret
            proxy_config.dc_redirects = dc_opt
            proxy_config.fake_tls_domain = ''

            logging.info(f"[MTPROTO] proxy_config set: {proxy_config.port}:{proxy_config.host}")
            
            logging.info("[MTPROTO] Creating event loop...")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop_ref[0] = loop
            logging.info("[MTPROTO] Event loop set, calling run...")
            
            try:
                loop.run_until_complete(tg_ws_proxy._run(stop_event))
                logging.info("[MTPROTO] run_until_complete returned")
            except Exception as e:
                logging.error(f"[MTPROTO] run_until_complete error: {e}", exc_info=True)
                raise
            finally:
                logging.info("[MTPROTO] Closing loop")
                loop.close()
        except Exception as e:
            thread_error[0] = str(e)
            logging.error(f"[MTPROTO] Proxy error: {e}", exc_info=True)
            import traceback
            logging.error(f"[MTPROTO] Traceback: {traceback.format_exc()}")
        finally:
            logging.info("[MTPROTO] _run finally")
            with _proxy_lock:
                if key in _proxies:
                    _proxies[key]['running'] = False
                    _proxies[key]['thread'] = None
            if loop and not loop.is_closed():
                try:
                    loop.close()
                except:
                    pass
    
    thread = threading.Thread(target=_run, daemon=True, name=f'MTPROTO-{port}')
    thread.start()
    logging.info("[MTPROTO] Thread started, waiting for server...")
    
    for _ in range(10):
        if thread_error[0]:
            reason = f"Startup error: {thread_error[0]}"
            logging.error(f"[MTPROTO] Proxy failed to start - {reason}")
            return False
        if _check_mtproto_traffic(port, host):
            break
        time.sleep(0.5)
    else:
        if thread_error[0]:
            reason = f"Startup error: {thread_error[0]}"
            logging.error(f"[MTPROTO] Proxy failed to start - {reason}")
            return False
        reason = "Port not listening after 5s"
        logging.error(f"[MTPROTO] Proxy failed to start - {reason}")
        return False
    
    with _proxy_lock:
        _proxies[key] = {
            'thread': thread,
            'stop_event': stop_event,
            'loop_ref': loop_ref,
            'port': port,
            'host': host,
            'running': True
        }
    
    logging.info(f"[MTPROTO] Proxy start: {host}:{port}")
    return True


def stop_mtproto_proxy(port, host='127.0.0.1', wait=True):
    logging.info(f"[MTPROTO] stop_mtproto_proxy called: {host}:{port}")
    
    port = int(port)
    # Ключ — ТОЛЬКО порт (см. комментарий в start_mtproto_proxy). Иначе стоп с
    # другим host, чем при старте, не находил запись и прокси оставался жив.
    key = port
    
    proxy = None
    with _proxy_lock:
        proxy = _proxies.pop(key, None)
    
    if proxy:
        try:
            stop_evt = proxy.get('stop_event')
            thread = proxy.get('thread')
            loop_ref = proxy.get('loop_ref')
            if stop_evt:
                # asyncio.Event.set() из чужого потока НЕ будит event loop: цикл
                # просыпается только по своим таймерам (stats каждые 60с), всё это
                # время порт продолжает слушать → закрывается минутами, а кнопка
                # остаётся «STOP». call_soon_threadsafe ставит set() в loop потока
                # прокси — остановка мгновенная.
                loop = (loop_ref or [None])[0]
                if loop and not loop.is_closed():
                    loop.call_soon_threadsafe(stop_evt.set)
                else:
                    stop_evt.set()
            if thread:
                thread.join(timeout=3)
        except Exception as e:
            logging.error(f"[MTPROTO] Stop error: {e}")
        
        logging.info(f"[MTPROTO] Proxy {host}:{port} stopped")
    else:
        logging.warning(f"[MTPROTO] stop: no tracked proxy on port {port} (already stopped?)")
    
    # Ждём, пока порт реально освободится: умирающий поток слушает ещё пару
    # мгновений, и без ожидания кнопка после стопа продолжала бы показывать
    # «STOP» из-за ложного «ещё слушает». На выходе из приложения ожидание не
    # нужно — процесс закрывается, ОС сама освободит сокет (wait=False).
    if wait:
        _wait_port_free(port)
    
    return True


def is_mtproto_proxy_running(port=1443, host='127.0.0.1'):
    # Факт работы определяем простукиванием порта (TCP-connect), а не записью в
    # _proxies: словарь нужен лишь для предупреждения о «мёртвом» потоке.
    # Ключ — только порт. Пробник вынесен из-под _proxy_lock: это сетевой
    # connect до 0.5с, под локом он блокировал бы старт/стоп прокси.
    port = int(port)
    with _proxy_lock:
        proxy = _proxies.get(port)
        if proxy:
            thread = proxy.get('thread')
            if (not thread or not thread.is_alive()) and proxy.get('running'):
                logging.warning(f"[MTPROTO] Proxy port {port} marked as running but thread dead")
    return _check_mtproto_traffic(port, host)


def _check_mtproto_traffic(port, host='127.0.0.1'):
    # Только прямое TCP-подключение. psutil-фолбэк по ESTABLISHED/LISTENING
    # убираем: после остановки прокси «висящий» клиентский сокет в состоянии
    # ESTABLISHED даёт ложное «работает», и кнопка STOP не отрисовывалась.
    # Проверяем И заданный host, И localhost: при host=0.0.0.0 слушатель
    # доступен на 127.0.0.1, при host=LAN-IP — на этом адресе. Раньше здесь
    # был жёстко 127.0.0.1 — при не-loopback хосте прокси работал, но кнопка
    # и старт-ожидание «не видели» его (ложное «не работает»).
    candidates = []
    if host and host not in ('0.0.0.0', '::'):
        candidates.append(host)
    if '127.0.0.1' not in candidates:
        candidates.append('127.0.0.1')
    for addr in candidates:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((addr, port))
                sock.close()
                return True
            except (ConnectionRefusedError, OSError):
                sock.close()
                continue
        except Exception as e:
            logging.warning(f"[MTPROTO] _check_mtproto_traffic({addr}:{port}) error: {e}")
            continue
    return False


def _port_busy(port):
    """True, если порт реально слушается (или занят процессом)."""
    try:
        if psutil is not None:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN':
                    return True
        return _check_mtproto_traffic(port)
    except Exception as e:
        logging.warning(f"[MTPROTO] _port_busy error: {e}")
        return _check_mtproto_traffic(port)


def _wait_port_free(port, timeout=5.0):
    """Ждём, пока порт освободится (не слушается). Возвращает True, если освободился."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _port_busy(port):
            return True
        time.sleep(0.2)
    logging.warning(f"[MTPROTO] Port {port} не освободился за {timeout}s")
    return False


def _tasklist_winws_running():
    """Проверка через tasklist — видит winws.exe даже там, где psutil молчит
    о процессах с недоступными атрибутами (AccessDenied / пустое имя / гонка
    с завершением процесса). Запускаем БЕЗ shell=True: аргументы и так списком,
    а лишний cmd.exe на каждый вызов ни к чему (замер: ~60мс → ~43мс)."""
    try:
        r = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq winws.exe'],
                           capture_output=True, text=True, errors="replace",
                           timeout=10, creationflags=_NO_WINDOW)
        return "winws.exe" in (r.stdout or "").lower()
    except Exception:
        return False


# tasklist-фолбэк — это subprocess (~43мс), а зовётся он из 1-секундного
# трей-таймера и срабатывает ВСЕГДА, когда winws не найден (т.е. пока служба
# выключена). Кэшируем его результат на _WINWS_FALLBACK_TTL сек: psutil-проверка
# (дешёвая, ~2мс) выполняется каждый раз, а тяжёлый tasklist — не чаще раза в TTL.
_WINWS_FALLBACK_TTL = 5.0
_winws_fallback = {"t": 0.0, "v": False}


def is_winws_running():
    """winws.exe запущен? Трей и логи опираются на это. psutil может тихо
    пропустить живой процесс и вернуть False (симптом «в трее сам вырубился,
    а в диспетчере есть»), поэтому при отсутствии матча перепроверяем через
    tasklist — он видал все процессы на машине. tasklist дорогой, поэтому не
    чаще раза в _WINWS_FALLBACK_TTL сек, иначе из 1-секундного таймера спамим
    subprocess'ами всё время, пока служба выключена."""
    try:
        if psutil is not None:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() == 'winws.exe':
                    return True
    except Exception:
        pass
    now = time.time()
    if now - _winws_fallback["t"] >= _WINWS_FALLBACK_TTL:
        _winws_fallback["t"] = now
        _winws_fallback["v"] = _tasklist_winws_running()
    return _winws_fallback["v"]


def is_ipv6_disabled():
    return not _is_ipv6_enabled_actual()


def real_ipv6_enabled():
    """Реальное состояние IPv6 по активным интерфейсам (не только реестр)."""
    return _is_ipv6_enabled_actual()


def _is_ipv6_enabled_actual():
    """Реальная проверка: IPv6 считается включенным, если есть хотя бы один
    активный IPv6-интерфейс, кроме loopback. Статус netsh локален:
    EN: connected/up, RU: Подключено/Активн — парсим оба варианта."""
    try:
        result = subprocess.run(
            ['netsh', 'interface', 'ipv6', 'show', 'interfaces'],
            capture_output=True, text=True, errors="replace", shell=True,
            creationflags=_NO_WINDOW
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                if re.search(r'\b(connected|up|подключ|актив)', line, re.IGNORECASE):
                    parts = line.split()
                    # пропускаем заголовки и итоги: реальная строка начинается с ID интерфейса
                    if len(parts) >= 4 and parts[0].isdigit() and int(parts[0]) > 1:
                        return True
            # если строки не распарсились, падаем на реестр
        return _ipv6_registry_enabled()
    except Exception:
        return _ipv6_registry_enabled()


def _ipv6_registry_enabled():
    """Проверка через реестр. DisabledComponents — битовая маска, а не флаг.
    Полностью отключает IPv6 только значение 0xFF (или 0x11/0x21 в связке с
    включенной политикой). Ненулевое значение само по себе НЕ означает отключение."""
    try:
        result = subprocess.run([
            'reg', 'query',
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
            '/v', 'DisabledComponents'
        ], capture_output=True, text=True, errors="replace", shell=True,
           creationflags=_NO_WINDOW)
        if 'DisabledComponents' in result.stdout:
            match = re.search(r'DisabledComponents\s+REG_DWORD\s+0x([0-9a-fA-F]+)', result.stdout)
            if match:
                value = int(match.group(1), 16)
                # 0xFF и 0x11/0x21 с политикой — фактическое отключение;
                # остальные значения (например 0x20 = prefer IPv4) IPv6 НЕ отключают
                if value == 0xFF:
                    return False
        return True
    except Exception:
        return True


def disable_ipv6():
    try:
        result = subprocess.run([
            'reg', 'add',
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
            '/v', 'DisabledComponents', '/t', 'REG_DWORD',         '/d', '255', '/f'
        ], capture_output=True, shell=True, creationflags=_NO_WINDOW)
        logging.info("[IPv6] Disabled via registry")
        return result.returncode == 0
    except Exception as e:
        logging.error(f"[IPv6] Error: {e}")
        return False


def enable_ipv6():
    try:
        # Если значения DisabledComponents нет — IPv6 уже включён, и это НЕ ошибка
        # (reg delete по отсутствующему значению возвращает код 1).
        probe = subprocess.run([
            'reg', 'query',
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
            '/v', 'DisabledComponents'
        ], capture_output=True, text=True, errors="replace", shell=True,
           creationflags=_NO_WINDOW)
        if 'DisabledComponents' not in (probe.stdout or ''):
            logging.info("[IPv6] DisabledComponents уже отсутствует (IPv6 включён)")
            return True

        result = subprocess.run([
            'reg', 'delete',
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
            '/v', 'DisabledComponents', '/f'
        ], capture_output=True, shell=True, creationflags=_NO_WINDOW)
        logging.info("[IPv6] Enabled via registry")
        return result.returncode == 0
    except Exception as e:
        logging.error(f"[IPv6] Error: {e}")
        return False


def get_ipv6_interface_names():
    """Имена интерфейсов (idx>1, кроме loopback) из netsh ipv6 show interface."""
    names = []
    try:
        result = subprocess.run(
            ['netsh', 'interface', 'ipv6', 'show', 'interface'],
            capture_output=True, text=True, errors="replace", shell=True,
            creationflags=_NO_WINDOW)
        if result.stdout:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].isdigit() and int(parts[0]) > 1:
                    names.append(" ".join(parts[4:]))
    except Exception as e:
        logging.error(f"[IPv6] interface list error: {e}")
    return names


def set_ipv6_interface(name, enabled):
    """Мгновенно вкл/выкл IPv6 на одном интерфейсе (netsh). Реестра мало —
    DisabledComponents срабатывает только после перезагрузки, а интерфейс до
    этого продолжает держать IPv6-адреса и путает проверки реального состояния."""
    try:
        r = subprocess.run(
            ['netsh', 'interface', 'ipv6', 'set', 'interface', name,
             'enabled' if enabled else 'disabled'],
            capture_output=True, text=True, errors="replace", shell=True,
            creationflags=_NO_WINDOW)
        ok = r.returncode == 0
        logging.info(f"[IPv6] Interface {name!r} {'enabled' if enabled else 'disabled'}: {ok}")
        return ok
    except Exception as e:
        logging.error(f"[IPv6] set interface {name!r} error: {e}")
        return False


def clear_discord_cache():
    import shutil
    msgs = []
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() == 'discord.exe':
                proc.terminate()
                proc.wait(timeout=5)
                msgs.append("Discord.exe closed")
                break
    except Exception as e:
        msgs.append(f"Failed to close Discord: {e}")

    cache_dir = Path(os.environ.get('APPDATA', '')) / 'discord'
    for folder in ['Cache', 'Code Cache', 'GPUCache']:
        p = cache_dir / folder
        if p.exists():
            try:
                shutil.rmtree(p)
                msgs.append(f"Deleted {folder}")
            except Exception as e:
                msgs.append(f"Failed to delete {folder}: {e}")
        else:
            msgs.append(f"{folder} not found")
    return " | ".join(msgs)


GAME_FILTER_PATH = BASE_DIR / "zapret" / "utils" / "game_filter.enabled"
IPSET_PATH = BASE_DIR / "zapret" / "lists" / "ipset-all.txt"


def get_game_filter_mode():
    if not GAME_FILTER_PATH.exists():
        return "disabled"
    mode = GAME_FILTER_PATH.read_text(encoding="utf-8").strip().lower()
    return mode if mode in ("all", "tcp", "udp") else "disabled"


def set_game_filter_mode(mode):
    if mode == "disabled":
        try:
            GAME_FILTER_PATH.unlink()
        except FileNotFoundError:
            pass
    else:
        GAME_FILTER_PATH.parent.mkdir(parents=True, exist_ok=True)
        GAME_FILTER_PATH.write_text(mode, encoding="utf-8")
    
    if get_game_filter_mode() != mode:
        logging.error(f"[GameFilter] Verification failed: expected {mode}, got {get_game_filter_mode()}")
        return False
    return True


def get_ipset_status():
    if not IPSET_PATH.exists():
        return "any"
    text = IPSET_PATH.read_text(encoding="utf-8").strip()
    if not text or text == "0.0.0.0/0":
        return "any"
    if text == "203.0.113.113/32":
        return "none"
    return "loaded"


def set_ipset_mode(mode):
    IPSET_PATH.parent.mkdir(parents=True, exist_ok=True)
    backup = IPSET_PATH.with_suffix(".txt.backup")

    if mode == "any":
        if get_ipset_status() == "loaded":
            IPSET_PATH.replace(backup)
        IPSET_PATH.write_text("0.0.0.0/0\n", encoding="utf-8")
    elif mode == "none":
        if get_ipset_status() == "loaded":
            IPSET_PATH.replace(backup)
        IPSET_PATH.write_text("203.0.113.113/32\n", encoding="utf-8")
    elif mode == "loaded":
        if backup.exists():
            backup.replace(IPSET_PATH)
        else:
            logging.error("[IPSet] No backup to restore")
            return False

    if get_ipset_status() != mode:
        logging.error(f"[IPSet] Verification failed: expected {mode}, got {get_ipset_status()}")
        return False
    return True


def _nslookup(args):
    try:
        p = subprocess.Popen(
            ["nslookup"] + args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=_NO_WINDOW,
        )
        return p.communicate(timeout=6)[0].decode("utf-8", "ignore")
    except Exception as e:
        logging.warning(f"[DNS] nslookup {' '.join(args)} failed: {e}")
        return ""


def _is_real_strategy(name):
    """Служебные .bat (Windows-служба, заготовки) стратегией не считаются."""
    low = name.lower()
    return low not in ("service.bat", "general.bat", "_zapret_service.bat")


def pick_strategy_bat(candidates, last_bat):
    """Логика выбора стратегии при запуске/старте: ручной выбор (last_bat) держится
    только если файл ещё существует и это реальная стратегия. Иначе — первая
    реальная стратегия (как в 3.3.9). Без DNS/провайдер-детекции."""
    if last_bat:
        for b in candidates:
            if b.stem == last_bat and _is_real_strategy(b.name):
                return b
    for b in candidates:
        if _is_real_strategy(b.name):
            logging.info(f"[STRATEGY] default strategy: {b.name}")
            return b
    return None