import subprocess
import socket
import threading
import time
import logging
import asyncio
import signal
import re
import os
import json
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

_last_io = None
LIST_PATH = BASE_DIR / "zapret" / "lists" / "list-general.txt"
EXCLUDE_LIST_PATH = BASE_DIR / "zapret" / "lists" / "list-exclude.txt"

def is_mtproto_enabled():
    return state.load_state().get("mtproto_enabled", False)


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
            errors="replace"
        )
        m = re.search(r"[=<](\\d+)ms", (r.stdout or "") + (r.stderr or ""))
        if m:
            return float(m.group(1))
        if "TTL" in r.stdout:
            return 1.0
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return 'Timeout'


def run_tracert(host):
    subprocess.Popen(['cmd', '/c', f'tracert {host} & pause'], creationflags=subprocess.CREATE_NEW_CONSOLE)


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


def find_best_dns():
    dns_list = {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8", "Yandex": "77.88.8.8", "Quad9": "9.9.9.9"}
    results = {}
    for name, ip in dns_list.items():
        p = get_ping(ip)
        if isinstance(p, (float, int)):
            results[name] = (ip, p)
    if not results:
        return None, "All DNS timed out"
    best_name = min(results, key=lambda k: results[k][1])
    return results[best_name][0], f"{best_name} [{results[best_name][0]}] ({results[best_name][1]}ms)"


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
    iface = get_active_interface()
    if not iface:
        return False, "Interface not found"
    try:
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', f'name={iface}', 'source=static', f'address={dns_ip}'], capture_output=True)
        return True, iface
    except Exception as e:
        return False, str(e)


def reset_system_dns():
    iface = get_active_interface()
    if not iface:
        return False, "Interface not found"
    try:
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', f'name={iface}', 'source=dhcp'], capture_output=True)
        return True, iface
    except Exception as e:
        return False, str(e)


def set_mtproto_enabled(enabled):
    state.save_state(mtproto_enabled=enabled)
    logging.info(f"[MTPROTO] Enabled: {enabled}")


def get_mtproto_enabled():
    return is_mtproto_enabled()


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


def stop_process_by_port(port):
    """Kill the process(es) listening on a given port. Returns True on success."""
    killed = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN' and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    if proc.name().lower() in ('winws.exe', 'sakuraflow.exe'):
                        continue
                    proc.terminate()
                    proc.wait(timeout=5)
                    killed.append(proc.name())
                except psutil.NoSuchProcess:
                    continue
                except psutil.AccessDenied:
                    subprocess.run(f'taskkill /F /PID {conn.pid}', shell=True, capture_output=True)
                    killed.append(f"PID {conn.pid}")
    except Exception as e:
        logging.error(f"[MTPROTO] stop_process_by_port error: {e}")
        return False
    if killed:
        logging.info(f"[MTPROTO] Stopped on port {port}: {', '.join(killed)}")
        time.sleep(0.5)
        return not _get_process_using_port(port)
    return True


def start_mtproto_proxy(port=1080, host='127.0.0.1', secret=None):
    global _proxies

    port = int(port)
    key = (host, port)
    
    with _proxy_lock:
        if key in _proxies and _proxies[key]['thread'] and _proxies[key]['thread'].is_alive():
            if _check_mtproto_traffic(port):
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
        logging.info(f"[MTPROTO] Import via 'from src' worked")
    except ImportError:
        from proxy.config import proxy_config
        import tg_ws_proxy
        logging.info(f"[MTPROTO] Import via 'import' worked")

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
            
            logging.info(f"[MTPROTO] Creating event loop...")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop_ref[0] = loop
            logging.info(f"[MTPROTO] Event loop set, calling run...")
            
            try:
                loop.run_until_complete(tg_ws_proxy._run(stop_event))
                logging.info("[MTPROTO] run_until_complete returned")
            except Exception as e:
                logging.error(f"[MTPROTO] run_until_complete error: {e}", exc_info=True)
                raise
            finally:
                logging.info(f"[MTPROTO] Closing loop")
                loop.close()
        except Exception as e:
            thread_error[0] = str(e)
            logging.error(f"[MTPROTO] Proxy error: {e}", exc_info=True)
            import traceback
            logging.error(f"[MTPROTO] Traceback: {traceback.format_exc()}")
        finally:
            logging.info(f"[MTPROTO] _run finally")
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
    logging.info(f"[MTPROTO] Thread started, waiting for server...")
    
    for _ in range(10):
        if thread_error[0]:
            reason = f"Startup error: {thread_error[0]}"
            logging.error(f"[MTPROTO] Proxy failed to start - {reason}")
            return False
        if _check_mtproto_traffic(port):
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


def stop_mtproto_proxy(port, host='127.0.0.1'):
    global _proxies
    
    logging.info(f"[MTPROTO] stop_mtproto_proxy called: {host}:{port}")
    
    port = int(port)
    key = (host, port)
    
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
    
    # Ждём, пока порт реально освободится: умирающий поток слушает ещё пару
    # мгновений, и без ожидания кнопка после стопа продолжала бы показывать
    # «STOP» из-за ложного «ещё слушает».
    _wait_port_free(port)
    
    return True


def is_mtproto_proxy_running(port=1080, host='127.0.0.1'):
    with _proxy_lock:
        port = int(port)
        key = (host, port)
        proxy = _proxies.get(key)
        
        if not proxy:
            return _check_mtproto_traffic(port)
        
        thread = proxy.get('thread')
        if not thread or not thread.is_alive():
            if proxy.get('running'):
                logging.warning(f"[MTPROTO] Proxy {host}:{port} marked as running but thread dead")
            return _check_mtproto_traffic(port)
        
        return _check_mtproto_traffic(port)


def _check_mtproto_traffic(port):
    # Только прямое TCP-подключение. psutil-фолбэк по ESTABLISHED/LISTENING
    # убираем: после остановки прокси «висящий» клиентский сокет в состоянии
    # ESTABLISHED даёт ложное «работает», и кнопка STOP не отрисовывалась.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect(('127.0.0.1', port))
            sock.close()
            return True
        except (ConnectionRefusedError, OSError):
            sock.close()
            return False
    except Exception as e:
        logging.warning(f"[MTPROTO] _check_mtproto_traffic error: {e}")
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


def is_mtproto_running():
    with _proxy_lock:
        return any(p.get('thread') and p['thread'].is_alive() for p in _proxies.values())


def _tasklist_winws_running():
    """Проверка через tasklist — видит winws.exe даже там, где psutil молчит
    о процессах с недоступными атрибутами (AccessDenied / пустое имя / гонка
    с завершением процесса)."""
    try:
        r = subprocess.run('tasklist /FI "IMAGENAME eq winws.exe"',
                           shell=True, capture_output=True, text=True, errors="replace",
                           timeout=10)
        return "winws.exe" in (r.stdout or "").lower()
    except Exception:
        return False


def is_winws_running():
    """winws.exe запущен? Трей и логи опираются на это. psutil может тихо
    пропустить живой процесс и вернуть False (симптом «в трее сам вырубился,
    а в диспетчере есть»), поэтому при отсутствии матча ВСЕГДА перепроверяем
    через tasklist — он видал все процессы на машине."""
    try:
        if psutil is not None:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() == 'winws.exe':
                    return True
    except Exception:
        pass
    return _tasklist_winws_running()


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
            capture_output=True, text=True, errors="replace", shell=True
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
        ], capture_output=True, text=True, errors="replace", shell=True)
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
        ], capture_output=True, shell=True)
        logging.info("[IPv6] Disabled via registry")
        return result.returncode == 0
    except Exception as e:
        logging.error(f"[IPv6] Error: {e}")
        return False


def enable_ipv6():
    try:
        result = subprocess.run([
            'reg', 'delete',
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
            '/v', 'DisabledComponents', '/f'
        ], capture_output=True, shell=True)
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
            capture_output=True, text=True, errors="replace", shell=True)
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
            capture_output=True, text=True, errors="replace", shell=True)
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


# Стратегии, подобранные под конкретного провайдера: ключ — код провайдера,
# кортеж — токены поиска в имени .bat и в ответах DNS (o-o.myaddr / Team Cymru).
PROVIDER_STRATEGY_TOKENS = {
    "beeline": ("beeline", "vimpel", "вымпел", "билайн"),
    "ertelecom": ("er-telecom", "ertc", "interzet", "дом.ру", "dom.ru"),
    "rostelecom": ("rostelecom", "rtk", "онлайм", "ртк"),
    "mts": ("mts", "мтс", "комстар", "mgts"),
    "megafon": ("megafon", "мегафон"),
    "yota": ("yota", "йота"),
    "ttk": ("ttk", "ттк"),
}

# AS-номера крупных РФ-операторов (Cymru отдаёт их всегда, имени может не быть)
_ASN_PROVIDERS = {
    "3216": "beeline",
    "23577": "beeline",
    "12389": "rostelecom",
    "12668": "rostelecom",
    "16345": "rostelecom",
    "41733": "ertelecom",
    "41729": "ertelecom",
    "8359": "mts",
    "31133": "megafon",
    "208722": "megafon",
    "4156": "ttk",
    "28917": "ttk",
}

_PROVIDER_CACHE_TTL = 30 * 24 * 3600


def _nslookup(args):
    try:
        p = subprocess.Popen(
            ["nslookup"] + args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=0x08000000,
        )
        return p.communicate(timeout=6)[0].decode("utf-8", "ignore")
    except Exception as e:
        logging.warning(f"[PROVIDER] nslookup {' '.join(args)} failed: {e}")
        return ""


def _public_ip_dns():
    """Публичный IP без сторонних сайтов: myip.opendns.com отдаёт наш IP как
    A-запись (DNS-only). Фолбэк — /24 из edns0-client-subnet Google TXT
    (для ASN-определения сети достаточно). Возвращает строку IP или None."""
    raw = _nslookup(["myip.opendns.com", "208.67.222.222"])
    if not raw:
        raw = _nslookup(["myip.opendns.com", "208.67.220.220"])
    addrs = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw)
    for a in addrs:
        if a in ("208.67.222.222", "208.67.220.220"):
            continue
        if a.startswith(("10.", "192.168.", "169.254.", "127.")):
            continue
        octets = [int(x) for x in a.split(".")]
        if 0 < octets[0] < 224 and not (octets[0] == 172 and 16 <= octets[1] <= 31):
            return a
    # фолбэк: сеть из Google TXT (edns0-client-subnet X.X.X.0/24)
    g = _nslookup(["-q=TXT", "o-o.myaddr.l.google.com", "8.8.8.8"])
    m = re.search(r"edns0-client-subnet\s+(\d{1,3}\.\d{1,3}\.\d{1,3})\.0/24", g)
    if m:
        return m.group(1) + ".0"
    return None


def _asn_via_cymru(public_ip):
    """ASN/название оператора по IP через DNS-версию WHOIS (Team Cymru origin.asn).
    Cymru принимает и точный IP, и /24 (последний октет .0)."""
    rev = ".".join(public_ip.split(".")[::-1])
    return _nslookup(["-q=TXT", f"{rev}.origin.asn.cymru.com", "8.8.8.8"])


def _provider_from_text(text):
    """Провайдер по токенам в тексте (имя оператора) или по ASN из Cymru."""
    low = text.lower()
    for key, tokens in PROVIDER_STRATEGY_TOKENS.items():
        if any(t in low for t in tokens):
            return key
    m = re.search(r"(?:\A|[^\d])(\d{4,6})\s*\|", low)
    if m and m.group(1) in _ASN_PROVIDERS:
        return _ASN_PROVIDERS[m.group(1)]
    return None


def detect_provider():
    """Определяет провайдера интернет БЕЗ сторонних сайтов, только по DNS:
    1) публичный IP через myip.opendns.com (или /24 через Google TXT);
    2) ASN/оператор через Team Cymru origin.asn (мэппинг по ASN + токены имени);
    3) подстраховка — TXT o-o.myaddr.l.google.com. Всё по UDP 53, winws/DPI
    это не режут. Кэш в state на 12 часов."""
    st = state.load_state()
    cached = st.get("isp_provider", "")
    ts = st.get("isp_provider_ts", 0)
    if cached and isinstance(ts, (int, float)) and time.time() - ts < _PROVIDER_CACHE_TTL:
        return cached or None

    out = ""
    public_ip = _public_ip_dns()
    if public_ip:
        out += " " + _asn_via_cymru(public_ip)
    else:
        logging.warning("[PROVIDER] public IP not resolved (OpenDNS+Google TXT)")

    provider = _provider_from_text(out)
    if not provider:
        out = " " + _nslookup(["-q=TXT", "o-o.myaddr.l.google.com", "8.8.8.8"])
        provider = _provider_from_text(out)

    logging.info(f"[PROVIDER] ip={public_ip} detected={provider or 'unknown'} "
                 f"raw={out.strip()[:200]}")
    state.save_state(isp_provider=provider, isp_provider_ts=time.time())
    return provider


def _is_real_strategy(name):
    """Служебные .bat (Windows-служба, заготовки) стратегией не считаются."""
    low = name.lower()
    return low not in ("service.bat", "general.bat", "_zapret_service.bat")


def _strategy_owner(name):
    """Какому провайдеру принадлежит стратегия судя по имени .bat (или None)."""
    low = name.lower()
    for prov, tokens in PROVIDER_STRATEGY_TOKENS.items():
        if any(t in low for t in tokens):
            return prov
    return None


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