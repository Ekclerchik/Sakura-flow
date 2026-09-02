"""Diagnose and repair local PC issues that prevent DPI-bypass (winws) from working.

The "Fix Everything" button runs a full diagnostic pass over the local machine,
fixes anything it finds, then (re)starts the DPI-bypass strategy and verifies
it actually works by pinging a few well-known targets.
"""
import subprocess
import logging
import re
import time
from pathlib import Path

try:
    from .config import BAT_DIR, SERVICE_NAME
    from . import tools, service, state
except ImportError:
    from src.config import BAT_DIR, SERVICE_NAME
    from src import tools, service, state

# Цели для проверки работоспособности обхода (HTTPS/TLS — потому что DPI режет
# по SNI/TLS-рукопожатию, а не по ICMP; zapret работает с TCP/UDP)
VERIFY_TARGETS = [
    ("https://youtube.com/", "YouTube"),
    ("https://discord.com/", "Discord"),
    ("https://google.com/", "Google"),
    ("https://www.cloudflare.com/", "Cloudflare"),
]


def _https_status(url, timeout=8):
    """Настоящая проверка DPI: TLS-рукопожатие + HTTPS GET. Возвращает
    (status_code, err_kind). 200/301/302/403/405/404 — сайт отвечает = обход живой.
    Timeout/ConnectionError — соединение виснет на рукопожатии = DPI режет.
    getaddrinfo-fail — системный DNS отравлен для домена (РКН), не вина TLS.
    Первый timeout-срыв сбрасываем в retry: после старта winws первое рукопожатие
    под DPI может занимать 2-3 сек из-за дефрагментации пакетов."""
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
    last_err = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, None
        except urllib.error.HTTPError as e:
            # 403/405/404 от самого YouTube/поля — это НОРМАЛЬНЫЙ ответ, обход работает
            return e.code, None
        except Exception as e:
            last_err = e
            if attempt == 0:
                time.sleep(1.5)
                continue
    s = str(last_err)
    if "getaddrinfo" in s:
        return None, "dns"
    return None, "tls_conn"


def _doh_resolve(name, timeout=8):
    """Разрешить имя через DoH (dns.google). Нужен, когда системный DNS отравлен
    для конкретного домена: браузер в таком случае работает по DoH и кажется,
    что «YouTube отвечает», а наш getaddrinfo — нет."""
    import json
    import urllib.request as _ur
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        req = _ur.Request(f"https://dns.google/resolve?name={name}&type=A",
                          headers={"User-Agent": "Mozilla/5.0"})
        with _ur.urlopen(req, timeout=timeout, context=ctx) as r:
            data = json.loads(r.read().decode())
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []


def _https_status_at(ip, domain, timeout=8):
    """HTTPS-проверка по IP с подстановкой SNI=domain — когда DNS отравлен и
    надо идти по IP, но TLS-сертификат/SNI требует настоящее имя."""
    import socket as _s
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    sock = _s.create_connection((ip, 443), timeout=timeout)
    tls = ctx.wrap_socket(sock, server_hostname=domain)
    tls.settimeout(timeout)
    tls.sendall(
        f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n".encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = tls.recv(4096)
        if not chunk:
            break
        buf += chunk
    tls.close()
    m = re.search(rb"HTTP/\S+\s+(\d{3})", buf)
    return int(m.group(1)) if m else None


def _tls_issuer(host, ip=None, timeout=8):
    """Проверка подлинности TLS-паспорта: издатель (Issuer) сертификата сайта при
    СПЕЦИАЛЬНОМ прохождении с полной верификацией доверенного корня. Если handshake
    прошёл — issuer настоящий (Google/GTS и т.п.). Если ловим
    CERTIFICATE_VERIFY_FAILED (и упал только проверенный вариант, а простой прошёл)
    — в системе висит MITM-корень (антивирус/прокси-твик), и zapret не сможет
    десинхронить такой сайт. Возвращает (issuer_str|None, phase) где phase:
      "ok" — верификация прошла (issuer настоящий),
      "untrusted" — подозрение на MITM (сертификат не из доверенного корня),
      None — не удалось установить TLS (DPI/timeout)."""
    import socket as _s
    import ssl as _ssl
    dest = ip or host
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = _ssl.CERT_REQUIRED
        sock = _s.create_connection((dest, 443), timeout=timeout)
        try:
            tls = ctx.wrap_socket(sock, server_hostname=host)
        except _ssl.SSLCertVerificationError:
            return None, "untrusted"
        cert = tls.getpeercert()
        tls.close()
        if not cert:
            return None, "untrusted"
        issuer = cert.get("issuer", ())
        org = ""
        for rdn in issuer:
            for oid, val in rdn:
                if oid == "organizationName":
                    org = " ".join(val) if isinstance(val, (list, tuple)) else str(val)
                    break
            if org:
                break
        if not org:
            parts = " ".join(x for rdn in issuer for _, val in rdn for x in val)
            org = parts[:60]
        return org or "неизвестный издатель", "ok"
    except Exception:
        return None, None


def verify_targets(diag):
    """HTTPS/TLS-проверка: если сайт отвечает (любой код) — обход работает
    (ICMP-ping тут обманчив: DPI блокирует SNI, а не ICMP). DNS-провал домена
    ретраится через DoH+IP+SNI — иначе «ютуб работает в браузере, а у нас нет»
    из-за отравленного системного DNS. Возвращает (reachable, total, results)."""
    from urllib.parse import urlparse
    reachable = 0
    total = 0
    results = []
    dns_fallback = []
    for url, name in VERIFY_TARGETS:
        total += 1
        host = urlparse(url).netloc
        code, err = _https_status(url)
        if code is None and err == "dns":
            # системный DNS отравлен для этого домена — пробуем DoH + IP + SNI
            for ip in _doh_resolve(host)[:2]:
                try:
                    code = _https_status_at(ip, host)
                except Exception:
                    code = None
                if code is not None:
                    err = None
                    dns_fallback.append(host)
                    break
            else:
                err = "dns (и DoH не дал IP)"
        if code is not None:
            reachable += 1
            results.append((name, code, err))
        else:
            results.append((name, None, err))
    lines = "\n".join(
        f"{name}: HTTP {code}" if code is not None else f"{name}: {err}"
        for name, code, err in results
    )
    diag.add("Проверка HTTPS (TLS-рукопожатие + GET):\n" + lines,
             reachable >= 1)
    if dns_fallback:
        diag.add(f"⚠️ Системный DNS не резолвит: {', '.join(dns_fallback)} — "
                 f"проверено через DoH. Включите DoH в браузере (он у ютуба уже "
                 f"работает именно так)")
    diag.add(f"Отвечают {reachable}/{total} сайтов", reachable >= 1)

# --- Подлинность TLS-паспорта (Issuer): ловим системный MITM-перехват ---
    # Простая проверка версии проходит с CERT_NONE; тут доводим с полной верификацией
    # доверенного корня по первым 2 отвечающим хостам. Если сертификат не прошёл
    # доверенный корень — подозрение на MITM.
    mitm_hits = []
    for url, name in VERIFY_TARGETS[:2]:
        host = urlparse(url).netloc
        try:
            issuer, phase = _tls_issuer(host)
        except Exception:
            continue
        if phase == "ok" and issuer:
            diag.add(f"TLS-сертификат {name}: издатель «{issuer}» — подлинный",
                     True)
        elif phase == "untrusted":
            mitm_hits.append(name)
    if mitm_hits:
        diag.add(f"⚠️ TLS-сертификат {', '.join(mitm_hits)} НЕ прошёл проверку "
                 f"доверенного корня — похоже на MITM-перехват (антивирусный "
                 f"прокси/твикер). zapret не сможет обойти такой сайт", False)
        diag.recommend("В системе перехватывается TLS (антивирусный/прокси-сертификат). "
                       "Отключите HTTPS/SSL-скан в антивирусе, чтобы winws мог "
                       "десинхронить сайты", needs_user=True)

    return reachable, total, results

# Процессы, которые обычно лезут в сеть и могут конфликтовать с WinDivert/WinWS.
# Сюда же другие DPI-обходы (GoodbyeDPI/ByeDPI/zapret) — их фильтры дерутся за трафик.
KNOWN_VPN_PROCESSES = [
    "openvpn", "wireguard", "windscribe", "nordvpn", "protonvpn", "surfshark",
    "expressvpn", "kerio", "hotspot", "tun2socks", "v2ray", "sing-box",
    "hiddify", "nekoray", "clash", "mihomo", "xray", "shadow", "mullvad",
    "awingu", "anydesk", "teamviewer", "radmin", "multilogin",
    "goodbyedpi", "byedpi", "zapret", "valdikss",
]

# Известные сторонние антивирусы (процессы/службы)
THIRD_PARTY_AV = [
    "kaspersky", "avp", "kis", "kes", "avast", "avg", "avira", "bitdefender",
    "norton", "mcafee", "eset", "nod32", "drweb", "360", "comodo", "malwarebytes",
    "hitmanpro", "adaware", "bullguard", "f-secure", "emsisoft", "zillya",
    "webroot", "sophos", "trend", "totalav", "ahnlab", "viguard", "panda",
    "arcabit", "gdata", "qihoo", "quickheal",
]


class Diagnosis:
    """Collects per-step results so we can log everything and report a summary."""

    def __init__(self):
        self.steps = []
        self.recommendations = []
        self.user_actions = []

    def add(self, text, ok=None):
        self.steps.append((text, ok))
        if ok is True:
            logging.info(f"[REPAIR] OK: {text}")
        elif ok is False:
            logging.warning(f"[REPAIR] BAD: {text}")
        else:
            logging.info(f"[REPAIR] {text}")

    def recommend(self, text, needs_user=False):
        self.recommendations.append(text)
        if needs_user:
            self.user_actions.append(text)

    @property
    def has_problems(self):
        return any(ok is False for _, ok in self.steps)


def _run(cmd, shell=True, timeout=None):
    """Run command, decoding output robustly across encodings (some consoles are
    UTF-8, most Russian are cp866). Returns subprocess.CompletedProcess with text."""
    try:
        proc = subprocess.run(cmd, shell=shell, capture_output=True, text=False,
                              timeout=timeout)
        out = proc.stdout
        err = proc.stderr
        if isinstance(out, bytes):
            out = _smart_decode(out)
        if isinstance(err, bytes):
            err = _smart_decode(err)
        proc.stdout = out
        proc.stderr = err
        return proc
    except subprocess.TimeoutExpired:
        logging.warning(f"[REPAIR] command timeout {timeout}s: {cmd}")
        return None
    except Exception as e:
        logging.error(f"[REPAIR] command error {cmd}: {e}")
        return None


def _smart_decode(b):
    for enc in ("utf-8", "cp866", "cp1251", "cp437"):
        try:
            s = b.decode(enc)
            if "\ufffd" in s:
                continue
            return s
        except (UnicodeDecodeError, UnicodeError):
            continue
    return b.decode("cp1251", errors="replace")


def real_ipv6_enabled():
    """Accurate IPv6 state based on actual active interfaces (not just registry)."""
    r = _run("netsh interface ipv6 show interfaces")
    if r is None or r.stdout is None:
        return tools.is_ipv6_disabled() is False
    active = 0
    for line in r.stdout.splitlines():
        # connected/up interfaces (skip loopback idx 1 and header/summary lines)
        if re.search(r"\b(connected|up)\b", line, re.IGNORECASE):
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit() and int(parts[0]) > 1:
                active += 1
    return active > 0


def check_processes(diag):
    winws = tools.is_winws_running()
    diag.add(f"Процесс WinWS запущен: {'да' if winws else 'нет'}", winws)
    return winws


def check_folder_path(diag):
    """Путь к zapret: пробелы/кириллица/длинный путь обычно работают (батники уже
    в кавычках), но при странностях это первое подозрение — просто информируем."""
    s = str(BAT_DIR)
    warns = []
    if " " in s:
        warns.append("пробел в пути")
    if any(ord(c) > 127 for c in s):
        warns.append("не-ASCII символы")
    if len(s) > 200:
        warns.append("очень длинный путь (близко к MAX_PATH)")
    if warns:
        diag.add(f"Путь к zapret: {s} — содержит {', '.join(warns)}. Обычно работает, "
                 f"но при странностях переустановите в простой путь без пробелов/кириллицы")
    else:
        diag.add(f"Путь к zapret: {s} — без пробелов/кириллицы")


def check_winws_instances(diag):
    """Дабл-старт: служба + ручная копия winws (запущенная прямо из bat) — их
    фильтры будут драться за трафик, обход «молча» не работает."""
    import psutil
    try:
        procs = [p for p in psutil.process_iter(["name", "exe"])
                 if (p.info.get("name") or "").lower() == "winws.exe"]
    except Exception:
        diag.add("winws.exe: не удалось посчитать процессы")
        return None
    count = len(procs)
    if count > 1:
        # считаем уникальные пути — если копии из РАЗНЫХ папок, это точно чужие
        # установки (отделный zapret/goodbyedpi), а не дубль одной стратегии
        exes = set()
        for p in procs:
            e = p.info.get("exe") or ""
            if e:
                exes.add(str(e).lower())
        if len(exes) > 1:
            diag.add(f"winws.exe запущен {count} копиями ИЗ РАЗНЫХ ПАПОК: "
                     f"{', '.join(sorted(exes))} — параллельные установки обходчиков "
                     f"дерутся за пакеты через WinDivert (каша и дропы)", False)
            diag.recommend("Обнаружены несколько независимых обходчиков. Оставьте ОДИН "
                           "(Sakura Flow из его папки), а остальные install'ы "
                           "(GoodbyeDPI/zapret) удалите или не запускайте", needs_user=True)
            return False
        diag.add(f"winws.exe запущен {count} копиями — вероятен ручной запуск из bat "
                 f"параллельно со службой; фильтры будут конфликтовать", False)
        diag.recommend("Оставьте только одну копию winws (от службы); завершите ручные "
                       "запуски из .bat", needs_user=True)
        return False
    if count == 1:
        diag.add("winws.exe: 1 процесс (служба) — дублей нет", True)
    else:
        diag.add("winws.exe: не запущен (нормально, пока обход выключен)")
    return count == 1


def check_dpi_conflicts(diag):
    """Проверка на установленные службы ДРУГИХ обходчиков (GoodbyeDPI, ByeDPI,
    GoodbyeDiscord, GoodbyeDPI-UI и т.п.). Даже если их процесс сейчас не виден,
    служба может стоять Автоматически и конфликтовать с нашим winws за WinDivert."""
    names = ("goodbyedpi", "goodbye", "byedpi", "gedpi", "goodbydiscord",
             "zapret", "winws", "byp4xx", "spoofdpi", "uhubctl")
    found = []
    r = _run('powershell -NoProfile -Command "Get-CimInstance Win32_Service | '
             'Select-Object -ExpandProperty Name"')
    if r and r.stdout:
        for svc in r.stdout.splitlines():
            n = svc.strip().lower()
            # не считаем конфликтом наш собственный сервис и общий драйвер WinDivert
            if (n and any(k in n for k in names)
                    and n.lower() != SERVICE_NAME.lower()
                    and n != "windivert"):
                found.append(svc.strip())
    if found:
        diag.add(f"Найдены службы ДРУГИХ обходчиков: {', '.join(found)} — они "
                 f"конкурируют за WinDivert и роняют пакеты. Оставьте один обходчик", False)
        diag.recommend(f"Отключите/удалите службы чужых обходчиков: "
                       f"{', '.join(found)} — параллельно с Sakura Flow они будут "
                       f"дропать трафик друг друга", needs_user=True)
        return True
    diag.add("Конфликтующие службы обходчиков (GoodbyeDPI/zapret и пр.) не найдены", True)
    return False


def check_windivert(diag):
    """Только информативная проверка в Фазе 1: разрядность ОС и наличие драйвера
    на диске. НЕ ругаемся на статус службы — winws регистрирует WinDivert «на лету»
    при старте и выгружает при выходе, так что «служба не установлена» при
    выключенном обходе — это НОРМА. Реальная проверка старта — в Фазе 4."""
    bin_dir = BAT_DIR / "bin"
    have_64 = (bin_dir / "WinDivert64.sys").exists()

    # разрядность ОС
    import platform
    is_64bit = platform.machine().endswith("64")
    diag.add(f"ОС: {'64-бит' if is_64bit else '32-бит'}", is_64bit)

    if not is_64bit:
        diag.add("Для работы zapret/WinDivert нужна 64-битная Windows", False)
        diag.recommend("Установите 64-битную Windows — 32-бит не поддерживается")

    if not have_64:
        diag.add("WinDivert64.sys ОТСУТСТВУЕТ в папке bin — драйвер удалён/не скопирован "
                 "(часто антивирусом)", False)
        diag.recommend("Верните WinDivert64.sys из дистрибутива в папку zapret/bin/"
                       " и добавьте её в исключения антивируса")
    else:
        diag.add("Драйвер WinDivert64.sys на месте", True)

    # целостность winws.exe: антивирус может «кастрировать» файл (0 байт / запрет чтения)
    winws_bin = bin_dir / "winws.exe"
    if winws_bin.exists():
        try:
            size = winws_bin.stat().st_size
            with open(winws_bin, "rb") as f:
                f.read(1)
            if size == 0:
                diag.add("winws.exe КАСТРИРОВАН: размер 0 байт — антивирус занулил файл", False)
                diag.recommend("Восстановите winws.exe из дистрибутива и добавьте папку zapret "
                               "в исключения антивируса", needs_user=True)
            else:
                diag.add(f"winws.exe цел: {size} байт, чтение доступно", True)
        except Exception:
            diag.add("winws.exe на месте, но НЕ читается (заблокирован антивирусом/правами)", False)
            diag.recommend("Снимите блокировку с winws.exe и добавьте папку zapret "
                           "в исключения антивируса", needs_user=True)
    else:
        diag.add("winws.exe ОТСУТСТВУЕТ в zapret/bin — обход не запустится", False)
        diag.recommend("Восстановите winws.exe из дистрибутива в папку zapret/bin/",
                       needs_user=True)

    # статус не оцениваем как проблему в фазе 1 (нормально, если обход выключен):
    r = _run('sc.exe query "WinDivert"')
    if r is None:
        return not have_64 or not is_64bit
    out = (r.stdout or "") + (r.stderr or "")
    if "RUNNING" in out:
        diag.add("Драйвер WinDivert: работает")
        return True
    if "1060" in r.stderr or "не существует" in out.lower() or \
       r.returncode == 1060 or "1060" in out:
        diag.add("Служба WinDivert не установлена — нормально, пока обход выключен; "
                 "запустится вместе с WinWS")
    else:
        diag.add(f"Служба WinDivert без аварий: {out[:80].strip() or 'не запущена'}")
    return not have_64 or not is_64bit


def check_ipv6(diag):
    enabled = real_ipv6_enabled()
    # сбрасываем кэшированное состояние в UI/state при следующей синхронизации
    state.save_state(ipv6_enabled=enabled)
    diag.add(f"IPv6 реально {'включен' if enabled else 'выключен'}", enabled)
    return enabled


def check_vpn_adapters(diag):
    r = _run("netsh interface show interface")
    found = []
    if r and r.stdout:
        low = r.stdout.lower()
        for token in ("tap", "tun", "wireguard", "openvpn", "vpn", "wf"):
            if token in low:
                found.append(token)
    found = list(dict.fromkeys(found))
    if found:
        diag.add(f"Найдены сетевые адаптеры VPN/туннеля: {', '.join(found)}", False)
    else:
        diag.add("VPN-адаптеры не обнаружены", True)
    return bool(found)


def check_vpn_processes(diag):
    import psutil
    found = []
    try:
        for proc in psutil.process_iter(["name"]):
            n = (proc.info.get("name") or "").lower()
            if any(k in n for k in KNOWN_VPN_PROCESSES):
                found.append(proc.info["name"])
    except Exception:
        pass
    found = list(dict.fromkeys(found))
    if found:
        diag.add(f"Работают VPN/прокси приложения: {', '.join(found)} (могут конфликтовать с обходом)", False)
        diag.recommend("Закройте VPN/прокси приложения перед использованием обхода, "
                       f"они перехватывают трафик: {', '.join(found)}", needs_user=True)
    else:
        diag.add("VPN/прокси приложения не запущены", True)
    return bool(found)


def check_antivirus(diag):
    """Detect third-party antivirus running — they often quarantine winws/WinDivert.
    Also detect installed-not-running AV services AND CryptoPro/MITM roots that
    re-assemble TLS at the app layer, annulling winws desync."""
    import psutil
    found = []
    try:
        for proc in psutil.process_iter(["name"]):
            n = (proc.info.get("name") or "").lower()
            if any(k in n for k in THIRD_PARTY_AV):
                found.append(proc.info["name"])
    except Exception:
        pass

    # службы СЕЙЧАС запущенные
    if not found:
        r = _run("powershell -NoProfile -Command "
                 "\"Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } | "
                 "Select-Object -ExpandProperty Name\"")
        if r and r.stdout:
            for svc in r.stdout.splitlines():
                name = svc.strip().lower()
                if name and any(k in name for k in THIRD_PARTY_AV):
                    found.append(name)

    found = list(dict.fromkeys(found))
    av_reported = False
    if found:
        diag.add(f"Работает сторонний антивирус: {', '.join(found)} — "
                 f"может блокировать WinWS/WinDivert И подменять TLS-сертификаты "
                 f"(HTTPS-сканер), что ломает обход. Добавьте папку zapret в исключения "
                 f"и отключите HTTPS-scan", False)
        diag.recommend(f"Добавьте папку обхода ({BAT_DIR}) в исключения антивируса "
                       f"({', '.join(found)}) и выключите в нём «Проверку защищённых "
                       f"соединений» (HTTPS/SSL-сканер)", needs_user=True)
        av_reported = True

    # КриптоПро и пр. MITM-сертификаты: даже если антивирус не найден, собственный
    # корень в trust store перехватывает TLS и делает winws бесполезным
    mitm_hint = _detect_mitm_roots()
    if mitm_hint:
        diag.add(f"⚠️ В системных корневых сертификатах есть MITM-корень: {mitm_hint}. "
                 f"Он перехватывает TLS (КриптоПро/антивирус/корпоративный прокси) — "
                 f"winws не сможет десинхронить сайты", False)
        diag.recommend(f"Обнаружен MITM-сертификат ({mitm_hint}). Удалите его из "
                       f"«Доверенные корневые центры сертификации» или отключите "
                       f"HTTPS-scan, иначе обход не заработает", needs_user=True)
        return True

    if not av_reported:
        diag.add("Сторонний антивирус и MITM-корни не обнаружены", True)
    return av_reported or bool(mitm_hint)


def _detect_mitm_roots():
    """Ищем в корневых хранилищах сертификаты, несущие признаки MITM-перехвата:
    имена КриптоПро, антивирусных HTTPS-сканеров и т.п. Возвращает имя или None."""
    r = _run('powershell -NoProfile -Command "Get-ChildItem Cert:\\LocalMachine\\Root | '
             'ForEach-Object { $_.Subject }"')
    if not r or not r.stdout:
        return None
    keywords = ("cryptopro", "crypto-pro", "криптопро", "avast", "avg", "kaspersky",
                "avp", "eset", "bitdefender", "nod32", "dr.web", "drweb",
                "meter 1/mht", "russian trusted", "контур", "сбис", "главупдк",
                "center", "verisign class", "geotrust public")
    for line in r.stdout.splitlines():
        low = line.lower()
        if any(k in low for k in ("cryptopro", "crypto-pro", "криптопро", "avast",
                                  "avg", "kaspersky", "eset", "nod32", "dr.web",
                                  "drweb", "bitdefender", "sectigo", "contur",
                                  "контур", "сбис", "главупдк", "ustelserv")):
            return line.strip()
        # маркер самоподписанного MITM-корня: выдал много доменов/выпущен самой системой
        if "issued to:" in low and "issued by:" in low and "serial" in low:
            return line.strip()
    return None


def check_windows_defender(diag):
    """Check Windows Defender real-time protection is actually active."""
    r = _run('powershell -NoProfile -Command "Get-MpComputerStatus | '
             'Select-Object -ExpandProperty RealTimeProtectionEnabled"')
    if r is not None and r.returncode == 0:
        val = (r.stdout or "").strip().lower()
        if val in ("true", "1"):
            diag.add("Windows Defender: защита в реальном времени ВКЛ (но не блокирует необязательно)") 
            return True
        elif val in ("false", "0"):
            diag.add("Windows Defender: защита в реальном времени ВЫКЛ", False)
            diag.recommend("Антивирус полностью выключен — включите его или убедитесь, "
                           "что системой управляет сторонний AV", needs_user=True)
            return False

    # fallback via service state
    r2 = _run('sc.exe query "WinDefend"')
    running = r2 is not None and "RUNNING" in (r2.stdout or "")
    state_txt = "работает" if running else "не работает"
    diag.add(f"Служба Windows Defender: {state_txt}")
    return running


def check_ports(diag):
    """Check configured MTProto port and common dpi ports aren't hijacked.
    Порт 1443 (наш MTProto) не считается занятым, если прокси включён и его
    слушает тот же процесс приложения — это наш собственный сервис, не чужой."""
    import psutil
    app_state = state.load_state()
    mtproto_port = app_state.get("mtproto_port", 1443)
    mtproto_enabled = bool(app_state.get("mtproto_enabled", False))
    watched = {
        mtproto_port: "MTProto proxy",
        1080: "MTProto / SOCKS",
    }
    occupied = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.status == "LISTEN":
                port = conn.laddr.port
                if port not in watched:
                    continue
                pid = conn.pid or 0
                if port == mtproto_port and mtproto_enabled and pid > 0:
                    # наш MTProto-прокси поднялся этим же приложением — это норма,
                    # пропускаем, чтобы не ругаться на собственный сервис
                    try:
                        self_exe = psutil.Process(pid).name()
                    except Exception:
                        self_exe = ""
                    if self_exe.lower() in ("python.exe", "pythonw.exe", "sakuraflow.exe"):
                        continue
                pname = "unknown"
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pass
                occupied.setdefault(port, (pname, pid))
    except Exception as e:
        logging.warning(f"[REPAIR] ports error: {e}")

    if occupied:
        for port, (pname, pid) in sorted(occupied.items()):
            label = watched.get(port, "unknown")
            diag.add(f"Порт {port} ({label}) занят: {pname} (PID {pid}) — "
                     f"может мешать старту прокси", False)
            diag.recommend(f"Порт {port} занят процессом {pname} (PID {pid}). "
                           f"Его нужно освободить/закрыть.", needs_user=True)
        return False
    diag.add(f"Порты свободны: {', '.join(str(p) for p in watched)}", True)
    return True


def check_dns(diag):
    r = _run("netsh interface ipv4 show dnsservers")
    servers = []
    if r and r.stdout:
        for line in r.stdout.splitlines():
            m = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", line)
            if m:
                ip = m.group(0)
                if ip not in servers:
                    servers.append(ip)
    if servers:
        diag.add(f"Системный DNS: {', '.join(servers)}")
    else:
        diag.add("Системный DNS не получен (авто?)")
    diag.dns_servers = servers
    return servers


def _interface_gateways():
    """Активные адаптеры с настроенным шлюзом — [ (iface, gw) ], без
    виртуальных/VPN-карт (их отсекли по токенам) и loopback."""
    skip = ("tap", "tun", "vpn", "wireguard", "wintun", "bridge", "wf-",
            "loopback", "петл", "npcap", "virtual", "hamachi")
    r = _run("netsh interface ipv4 show config")
    if not r or not r.stdout:
        return []
    out = []
    iface = None
    for line in r.stdout.splitlines():
        s = line.strip()
        low = s.lower()
        if ("интерфейса" in low and '"' in s) or low.startswith("configuration for interface"):
            m = re.search(r'"([^"]+)"', s)
            iface = m.group(1) if m else s.split(":", 1)[-1].strip()
            continue
        if iface is None:
            continue
        if any(t in iface.lower() for t in skip):
            continue
        if "основной шлюз" in low or "default gateway" in low:
            m = re.search(r"(\d{1,3}\.){3}\d{1,3}", s)
            if m:
                out.append((iface, m.group(0)))
    return out


def _ping_gateway(gw):
    """Короткий пинг шлюза. Возвращает (rtt_ms, None) или (None, reason)."""
    r = _run(f"ping -n 2 -w 1500 {gw}", timeout=10)
    if r is None or r.returncode != 0:
        return None, "timeout"
    out = (r.stdout or "") + (r.stderr or "")
    times = (re.findall(r"время\s*[=<]\s*(\d+)\s*мс", out)
             or re.findall(r"time[=<]\s*(\d+)", out, re.IGNORECASE))
    if not times:
        return None, "no-data"
    return int(times[-1]), None


def check_icmp_targets(diag):
    """ICMP-пинг до реальных целей (YouTube/Discord). HTTPS может отвечать при живом
    TCP, а потерянные ICMP — сигнал о дропах на маршруте, что влияет на тайминги
    десинка winws."""
    result = []
    ok = True
    import socket as _so
    hosts = ["youtube.com", "discord.com"]
    for h in hosts:
        try:
            ip = _so.gethostbyname(h)
        except Exception:
            ip = None
        rtt, err = _ping_gateway(h)
        if rtt is None:
            result.append(f"{h}: ICMP не отвечает ({err})")
            ok = False
        else:
            result.append(f"{h} ({ip}): {rtt} мс")
    status = ok
    diag.add(f"ICMP-пинг целей:\n" + "\n".join(result) +
             ("  — оба отвечают" if ok else
              "  — часть недоступна (могут резать ICMP/дропы на пути)"),
             status)
    return ok


def check_tcp_http(diag):
    """Отдельно: (a) TCP-коннект на 443 без TLS — доходит ли вообще пакет до сервера
    (в отличие от TLS, который может виснуть из-за SNI-резни DPI); (b) HTTP GET на :80.
    Позволяет отличить «сеть мертва/порт закрыт» от «работет только TLS-путь».
    Возвращает bool: есть хотя бы один живой путь."""
    import socket as _so
    lines = []
    alive = False
    for host, port, label in (("google.com", 443, "TCP 443 (без TLS)"),
                              ("google.com", 80, "HTTP :80"),
                              ("youtube.com", 443, "TCP 443 (без TLS)")):
        try:
            with _so.create_connection((host, port), timeout=5):
                lines.append(f"{label} {host}:{port} — достижим")
                alive = True
        except Exception as e:
            s = str(e)
            kind = "timeout" if "timed out" in s or "timed-out" in s else "refused/fail"
            lines.append(f"{label} {host}:{port} — {kind}")
    diag.add("Транспортный уровень (TCP/HTTP до обхода TLS):\n" + "\n".join(lines),
             alive)
    return alive


def check_lan(diag):
    """Качество локального звена: пинг шлюза + двойной шлюз + DNS через роутер.
    Если локальная сеть/роутер плохие — zapret физически бессилен."""
    gws = _interface_gateways()
    uniq = {}
    for iface, gw in gws:
        uniq.setdefault(gw, []).append(iface)
    if not uniq:
        diag.add("Шлюз по умолчанию не найден в конфигурации", None)
        return None

    # пингуем основной шлюз (тот, что на большем числе адаптеров)
    gw = sorted(uniq.items(), key=lambda kv: -len(kv[1]))[0][0]
    rtt, err = _ping_gateway(gw)
    if rtt is None:
        diag.add(f"[LAN_ALERT] Шлюз {gw} не отвечает на ping. Может блокировать ICMP "
                 f"(тогда всё ок) или завис под нагрузкой/проблема с кабелем", False)
        diag.recommend("Проверьте кабель/Wi-Fi и перезагрузите роутер — если физика "
                       "мертва, интернет не появится даже после починки обхода")
    elif rtt >= 50:
        diag.add(f"[LAN] Шлюз {gw} отвечает, но пинг {rtt} мс — локальное звено "
                 f"нагружено (по проводу <5 мс, по Wi-Fi <10 мс)", False)
        diag.recommend(f"Задержка до роутера {rtt} мс — проверьте кабель/эфир, "
                       "перезагрузите роутер. zapret это не лечит")
    else:
        diag.add(f"Шлюз {gw} пингуется: {rtt} мс — локальная сеть в порядке", True)

    if len(uniq) > 1:
        diag.add(f"[LAN] Несколько шлюзов: {', '.join(sorted(uniq))} — возможен "
                 f"двойной NAT/второй роутер/раздача интернета", None)
        diag.recommend("Активно несколько шлюзов (двойной NAT) — настройте подключение "
                       "провайдера к роутеру в один каскад")

    # DNS через роутер: бюджетные роутеры режут изменённые zapret'ом запросы
    if gw in getattr(diag, "dns_servers", []):
        diag.add(f"[LAN] Системный DNS совпадает со шлюзом ({gw}) — запросы идут через "
                 f"DNS-маскарад роутера", None)
        diag.recommend("Пропишите в свойствах адаптера DNS напрямую (8.8.8.8 / 77.88.8.8), "
                       "в обход роутера — бюджетные роутеры могут резать DNS при обходе")

    return len(uniq) == 1


def check_wifi(diag):
    """Сигнал Wi-Fi: при <30% desync-фрагменты winws теряются в эфире."""
    r = _run("netsh wlan show interfaces")
    if not r or not r.stdout:
        diag.add("Wi-Fi: адаптер не найден (netsh wlan молчит) — вероятно проводное")
        return None
    if not re.search(r"(SSID|СЕТЬ)\s*:\s*\S", r.stdout):
        diag.add("Wi-Fi: адаптер есть, сеть не подключена", None)
        return None
    m = re.search(r"(Signal|Сигнал|Уровень)\s*[:\-]\s*(\d+)\s*%", r.stdout)
    if not m:
        diag.add("Wi-Fi: подключён (уровень сигнала не определён)")
        return None
    sig = int(m.group(2))
    if sig < 30:
        diag.add(f"[LAN] Wi-Fi: сигнал {sig}% — пакеты (в т.ч. desync-фрагменты winws) "
                 f"будут теряться в эфире", False)
        diag.recommend("Улучшите сигнал Wi-Fi (ближе к роутеру / канал 5 ГГц / провод) — "
                       "фрагментированные пакеты winws не долетают при слабом сигнале")
        return False
    diag.add(f"Wi-Fi: сигнал {sig}% — норма", True)
    return True


def check_loopback(diag):
    """Стек loopback: если «оптимизатор»/файрвол сломали 127.0.0.1, прокси/SOCKS-режим
    winws не пропустит трафик в браузер."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(2)
        c.connect(("127.0.0.1", port))
        s.close()
        c.close()
        diag.add("Loopback 127.0.0.1: TCP-сокет биндится и коннектится — стек жив", True)
        return True
    except Exception as e:
        diag.add(f"Loopback 127.0.0.1 СЛОМАН: {e} — прокси-режим winws не заработает", False)
        diag.recommend("Сломан loopback-стек: откатите «оптимизатор»/файрвол, который его "
                       "блокирует")
        return False


def check_dns_resolution(diag):
    """Real DNS resolution through the system resolver — if this fails, nothing works."""
    import socket
    ok = False
    target = "google.com"
    try:
        socket.setdefaulttimeout(2)
        ip = socket.gethostbyname(target)
        if ip and not ip.startswith("127."):
            ok = True
            diag.add(f"DNS резолв работает: {target} -> {ip}")
        else:
            diag.add(f"DNS резолв вернул подозрительный IP: {ip}")
    except Exception as e:
        diag.add(f"DNS резолв НЕ работает: {e}", False)
    return ok


def check_system_clock(diag):
    """Skewed system clock breaks certificate validation / TLS handshakes."""
    from datetime import datetime, timezone
    try:
        import socket as _s
        import time as _t
        # quick sanity: system clock shouldn't be too far from real time
        # using ping3 result timestamps is unreliable; just warn if year is off
        now = datetime.now(timezone.utc)
        if now.year < 2020 or now.year > 2100:
            diag.add(f"Системные часы выглядят неверно: {now.isoformat()}", False)
            return False
        diag.add(f"Системные часы в норме: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    except Exception as e:
        diag.add(f"Не удалось проверить часы: {e}")
        return True


def check_service_drift(diag):
    """Verify the registered service points at the current executable and bat file."""
    r = _run(f'sc.exe qc "{SERVICE_NAME}"')
    if r is None or not r.stdout:
        diag.add("Служба обхода не зарегистрирована (будет создана)")
        return False
    diag.add("RAW sc qc SakuraFlowService:\n" + (r.stdout or r.stderr or "").strip())
    # тип запуска (проверяем и на англ., и на русской локали, до binPath — он
    # на русской локали называется «Имя_двоичного_файла» и не найдётся ниже)
    st = re.search(r"START_TYPE\s*:\s*\d+\s+([A-Z_]+)", r.stdout, re.IGNORECASE) \
        or re.search(r"Тип_запуска\s*:\s*\d+\s+([A-Z_]+)", r.stdout)
    if st:
        start_type = st.group(1).upper()
        if start_type in ("DISABLED",):
            diag.add(f"⚠️ Тип запуска службы: DISABLED — в Фазе 2 служба "
                     f"пересоздастся с AUTO, иначе winws не поднимется", False)
        else:
            diag.add(f"Тип запуска службы: {start_type} (рек. AUTO)", True)
    binpath = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", r.stdout) \
        or re.search(r"Имя_двоичного_файла\s*:\s*(.+)", r.stdout)
    if binpath:
        path_str = binpath.group(1).strip()
        diag.add(f"Служба зарегистрирована: {path_str}")
        return "_zapret_service.bat" in path_str.lower()
    diag.add("Служба зарегистрирована (binPath не разобран)")
    return True


# Фейк-паттерны winws (fake-tls/fake-quic/fake-unknown-udp), которые winws загружает
# при старте. Если антивирус/кривая распаковка их удалил — winws падает сразу,
# а в логе невнятная ошибка. Проверяем те, что реально зашиты в стратегию.
FAKE_BIN_FILES = [
    "quic_initial_www_google_com.bin",
    "quic_initial_4pda.to.bin",
    "quic_initial_dbankcloud_ru.bin",
    "tls_clienthello_www_google_com.bin",
    "tls_clienthello_4pda_to.bin",
    "tls_clienthello_max_ru.bin",
    "stun.bin",
]


def _fake_bins_referenced():
    """Какие .bin реально используются текущей стратегией (по _zapret_service.bat)."""
    bat = BAT_DIR / "_zapret_service.bat"
    if not bat.exists():
        return None
    text = bat.read_text(encoding="utf-8", errors="ignore")
    found = []
    for f in FAKE_BIN_FILES:
        if f in text:
            found.append(f)
    return found or None


def check_fake_bins(diag):
    """Фаза 1: физическое наличие фейк-паттернов winws в папке bin. Отсутствуют —
    winws упадёт сразу после старта (типично: антивирус почистил)."""
    bin_dir = BAT_DIR / "bin"
    referenced = _fake_bins_referenced()
    refs = referenced if referenced is not None else FAKE_BIN_FILES

    missing = []
    zeroed = []
    unread = []
    for name in refs:
        p = bin_dir / name
        if not p.exists():
            missing.append(name)
            continue
        try:
            size = p.stat().st_size
            with open(p, "rb") as fh:
                fh.read(1)
            if size == 0:
                zeroed.append(name)
        except Exception:
            unread.append(name)

    if missing:
        diag.add(f"{len(missing)} фейк-паттерн(а) ОТСУТСТВУЮТ: {', '.join(missing)} — "
                 f"winws упадёт сразу после старта (удалил антивирус?)", False)
        diag.recommend("Верните отсутствующие .bin из zapret/bin дистрибутива и добавьте "
                       "папку zapret в исключения антивируса", needs_user=True)
        return False
    if zeroed:
        diag.add(f"Фейк-паттерны ЗАНУЛЕНЫ (0 байт): {', '.join(zeroed)}", False)
        diag.recommend("Восстановите .bin из дистрибутива и добавьте zapret в исключения "
                       "антивируса", needs_user=True)
        return False
    if unread:
        diag.add(f"Фейк-паттерны не читаются: {', '.join(unread)}", False)
        diag.recommend("Снимите блокировку с фейк-паттернов и добавьте zapret в исключения",
                       needs_user=True)
        return False
    diag.add(f"Фейк-паттерны winws на месте: {', '.join(refs)}", True)
    return True


USER_LISTS = [
    "list-general-user.txt",
    "list-exclude-user.txt",
    "list-google.txt",
    "list-general.txt",
    "ipset-all.txt",
    "ipset-exclude.txt",
    "ipset-exclude-user.txt",
]


def _looks_like_non_utf8(b):
    """Детект «перебитых» байтов: UTF-8-цепочки некорректны ИЛИ найдена кириллица
    в Windows-1251 (последовательности 0xC0–0xFF, которые не дали валидный UTF-8)."""
    try:
        b.decode("utf-8")
        return False
    except UnicodeDecodeError:
        # есть ли кириллические/высокие байты (cp1251 диапазон) — признак ANSI-сохранения
        high = sum(1 for x in b if x >= 0x80)
        return high > 0


def check_user_list_encoding(diag):
    """Фаза 1: кастомные списки обязаны быть UTF-8 (батник делает chcp 65001).
    Если пользователь сохранил домен .рф в ANSI/1251 через блокнот — winws споткнётся
    о такую строку. Ловим некорректную кодировку без полного перебора cp1251."""
    lists_dir = BAT_DIR / "lists"
    bad = []
    checked = 0
    for name in USER_LISTS:
        p = lists_dir / name
        if not p.exists():
            continue
        checked += 1
        try:
            data = p.read_bytes()
        except Exception as e:
            logging.warning(f"[REPAIR] list read error {name}: {e}")
            continue
        if _looks_like_non_utf8(data):
            bad.append(name)
    if bad:
        diag.add(f"Списки НЕ в UTF-8 (winws может их забить/споткнуться): "
                 f"{', '.join(bad)} — кириллические домены (.рф) лучше в UTF-8", False)
        diag.recommend(f"Пересохраните {', '.join(bad)} в UTF-8 без BOM (блокнот: "
                       f"«Сохранить как» → кодировка UTF-8)", needs_user=True)
        return False
    diag.add(f"Кодировка списков валидная (UTF-8): {checked} файл(ов)", True)
    return True


def _game_filter_info():
    """Инфо: какой GameFilter сейчас в стратегии — чтобы быть уверенным, что в
    стартовую строку winws подставились реальные порты, а не `%GameFilter%` вслепую."""
    p = BAT_DIR / "utils" / "game_filter.enabled"
    mode = "disabled"
    if p.exists():
        try:
            mode = p.read_text("utf-8").strip().lower()
        except Exception:
            mode = "? (не читается)"
    tcp = {"all": "1024-65535", "tcp": "1024-65535", "udp": "12"}.get(mode, "12")
    udp = {"all": "1024-65535", "tcp": "12", "udp": "1024-65535"}.get(mode, "12")
    return mode, tcp, udp


def check_game_filter_resolved(diag):
    """Фаза 1 (инфо): GameFilter-переменные подставлены в службу корректно.
    Не ломается — parse_bat_file всегда выдаёт конкретные порты."""
    mode, tcp, udp = _game_filter_info()
    diag.add(f"GameFilter: mode={mode}, TCP={tcp}, UDP={udp} — подставлено в службу", True)
    return True


def check_hosts(diag):
    hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
    suspicious = []
    try:
        if hosts.exists():
            for line in hosts.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if re.match(r"^\d", s) and not s.lower().startswith("127.0.0.1"):
                    suspicious.append(s)
                elif "telegram" in s.lower() or "discord" in s.lower():
                    suspicious.append(s)
    except Exception as e:
        logging.error(f"[REPAIR] hosts error: {e}")
    if suspicious:
        diag.add("В hosts-файле подозрительные записи:\n" + "\n".join(suspicious), False)
    else:
        diag.add("hosts-файл чист", True)
    return bool(suspicious)


def check_winws_logs(diag):
    """Фаза 1: информативно. Редирект вывода в winws.log автоматически добавляется
    в _zapret_service.bat (service._write_bat), так что тут вердиктов нет —
    настоящая проверка дропов идёт в Фазе 4 после старта службы."""
    log = BAT_DIR / "winws.log"
    if not log.exists():
        diag.add("Лог WinWS пока отсутствует (появится после перезапуска службы — "
                 "редирект добавляется автоматически)")
        return None
    size = log.stat().st_size
    diag.add(f"Лог WinWS существует ({size} байт)")
    return None


DROP_HINTS = ("drop", "error", "fail", "loss", "deny", "reject", "fatal", "cant", "can't")


def check_winws_packet_drop(diag):
    """Фаза 4: после старта службы winws.log обязан существовать (мы сами добавляем
    редирект). Отсутствует — winws вообще не запустился. Есть — сканим хвост на
    признаки того, что драйвер отбрасывает трафик."""
    log = BAT_DIR / "winws.log"
    if not log.exists():
        diag.add("winws.log НЕ создан после старта службы — winws не запустился "
                 "или упал сразу. Проверь службу выше.", False)
        return False

    # свежесть: если файл давно не трогали — это норма (winws пишет только трафик),
# но хвост всё равно посмотрим на ошибки
    try:
        age = time.time() - log.stat().st_mtime
        if age > 600:
            diag.add(f"winws.log не обновлялся {int(age)} сек — трафика нет (не ошибка)")
    except OSError:
        diag.add("winws.log не удалось проверить по времени")
        return None

    try:
        tail = log.read_text(encoding="utf-8", errors="ignore").splitlines()[-300:]
    except Exception as e:
        logging.warning(f"[REPAIR] winws.log read error: {e}")
        diag.add("winws.log не читается")
        return None

    hits = []
    for line in tail:
        low = line.lower()
        if any(k in low for k in DROP_HINTS):
            hits.append(line.strip())
    if not hits:
        diag.add("winws.log свежий, признаков дропов/ошибок нет", True)
        return True

    diag.add("[DANGER] В хвосте winws.log признаки проблем с трафиком (драйвер "
             "отбрасывает/ругается):\n" + "\n".join(hits[-8:]), False)
    diag.recommend("WinWS/драйвер отбрасывает пакеты или пишет ошибки — конфликт "
                   "фильтров/стратегии. Проверь лог WinWS.")
    return False


SCHANNEL_BASE = (r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders"
                 r"\SCHANNEL\Protocols")


def check_mtu(diag):
    """Аномальный MTU интерфейса. 1500 — норма. <1280 (зажатый WireGuard/PPPoE) —
    winws-desync фрагментирует TLS-хендшейки и пакеты режутся уже на DPI."""
    r = _run("netsh interface ipv4 show subinterfaces")
    if not r or not r.stdout:
        diag.add("MTU: не удалось получить subinterfaces", None)
        return None
    infos, alerts = [], []
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*(\d{3,10})\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$", line)
        if not m:
            continue
        mtu = int(m.group(1))
        name = m.group(5).strip()
        # 0xFFFFFFFF — «бесконечный» MTU loopback'а, не интерфейс
        if mtu >= 0xFFFFFFFF or mtu == 0:
            continue
        info = f"{name}: MTU {mtu}"
        if mtu < 1280 or mtu > 1500:
            alerts.append(info)
        else:
            infos.append(info)
    if infos:
        diag.add("MTU интерфейсов: " + "; ".join(infos), True)
    if alerts:
        diag.add("[MTU_ALERT] Аномальный MTU: " + "; ".join(alerts) +
                 ". При <1280 (зажатый WireGuard/PPPoE) winws-desync фрагментирует "
                 "TLS-хендшейки и пакеты режутся на DPI.", False)
        diag.recommend("Аномальный MTU у адаптера. Для обхода лучше 1500: VPN/WireGuard "
                       "не должны резать MTU ниже 1280.", needs_user=True)
        return False
    if not infos and not alerts:
        diag.add("MTU: активных IPv4-интерфейсов не нашлось", None)
        return True
    return True


def check_schannel(diag):
    """Проверка «оптимизаторов»: если в Schannel вырублен TLS 1.2 или TLS 1.3 —
    HTTPS в системе сломан НЕЗАВИСИМО от обхода (winws не сможет модифицировать SNI,
    а наши HTTPS-тесты будут врать «не работает»). TLS 1.0/1.1 — норм и по умолчанию выкл."""
    disabled, looked = [], False
    for ver in ("TLS 1.2", "TLS 1.3"):
        for side in ("Client", "Server"):
            r = _run(f'reg query "{SCHANNEL_BASE}\\{ver}\\{side}"')
            if not r or r.returncode != 0:
                continue
            out = (r.stdout or "") + (r.stderr or "")
            if "REG_DWORD" not in out:
                continue
            looked = True
            enabled = re.search(r"\bEnabled\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
            bydefault = re.search(r"DisabledByDefault\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
            off = (enabled and int(enabled.group(1), 16) == 0) or \
                  (bydefault and int(bydefault.group(1), 16) == 1)
            if off and side == "Client":
                disabled.append(ver)
    if disabled:
        diag.add("ОС: ВЫРУБЛЕН TLS " + ", ".join(dict.fromkeys(disabled)) +
                 " в Schannel — HTTPS мёртв, обход бессилен, пока это не вернуть", False)
        diag.recommend("Включите TLS 1.2/1.3 в " + SCHANNEL_BASE +
                       " или откатите «оптимизатор», их вырубивший", needs_user=True)
        return False
    if looked:
        diag.add("ОС: TLS 1.2/1.3 в Schannel не вырублены", True)
    else:
        diag.add("ОС: SCHANNEL\\Protocols не переопределена — TLS по умолчанию включён", True)
    return True


def stop_conflicts():
    """Kill leftover winws and stop the (stale) service so a rebuild is clean.
    Дополнительно принудительно завершаем зависшие winws ИЗ ДРУГИХ ПАПОК (чужие
    установки обходчиков): они не остановятся через нашу службу и будут воровать
    пакеты у заново созданного winws."""
    try:
        service.stop_service()
        service.delete_service()
    except Exception as e:
        logging.warning(f"[REPAIR] cleanup error: {e}")
    _kill_foreign_winws()
    _stop_windivert()


def _kill_foreign_winws():
    """Завершить winws, exe которых лежит НЕ в нашей папке zapret (зависшие чужие
    обходчики из сторонних установок). Нашу копию трогаем только через службу."""
    import psutil
    our_dir = str((BAT_DIR / "bin").resolve()).lower()
    killed = 0
    try:
        for p in psutil.process_iter(["name", "exe"]):
            n = (p.info.get("name") or "").lower()
            if n != "winws.exe":
                continue
            e = p.info.get("exe") or ""
            if not e:
                continue
            if str(Path(e).parent.resolve()).lower() != our_dir:
                try:
                    p.kill()
                    killed += 1
                    logging.info(f"[REPAIR] killed foreign winws: {e}")
                except Exception:
                    pass
    except Exception as e:
        logging.warning(f"[REPAIR] foreign winws scan error: {e}")
    if killed:
        logging.info(f"[REPAIR] killed {killed} foreign winws instance(s)")
    return killed


def _stop_windivert():
    """Принудительный сброс драйвера WinDivert с таймаутом. Обычный sc stop может
    вечно висеть на драйвере, который держится процессом. Если не остановился —
    пробуем удалить службу драйвера; при следующем старте winws пересоздаст её."""
    r = _run('sc.exe stop "WinDivert"', timeout=8)
    if r is not None:
        for _ in range(10):
            time.sleep(1)
            q = _run('sc.exe query "WinDivert"', timeout=5)
            if q is None:
                break
            out = (q.stdout or "") + (q.stderr or "")
            if "STOPPED" in out or "1060" in out:
                logging.info("[REPAIR] WinDivert cleanly stopped")
                return
    # не успокоился / stop завис — принудительно сносим (пересоздастся при старте)
    logging.warning("[REPAIR] WinDivert не остановился за отведённое время — "
                    "принудительное удаление (пересоздастся при старте winws)")
    _run('sc.exe delete "WinDivert"', timeout=5)


def _backup_dns():
    """Backup manually-configured (static) DNS servers per interface BEFORE resetting
    the network stack. `netsh int ip reset` wipes static DNS back to DHCP.
    Parses both English and Russian netsh output."""
    import re as _re
    backup = {}
    r = _run("netsh interface ipv4 show dnsservers")
    if not r or not r.stdout:
        return backup
    iface = None
    in_static = False
    for line in r.stdout.splitlines():
        s = line.strip()
        low = s.lower()
        if not s:
            continue
        # заголовок интерфейса: "Interface ..." / "интерфейса ..."
        if low.startswith("interface") or "интерфейса" in low and '"' in s:
            m = _re.search(r'"([^"]+)"', s)
            iface = m.group(1) if m else s.split(":")[-1].strip()
            in_static = False
            continue
        if not iface:
            continue
        # российская/английская секция статики
        if ("static" in low and "dns" in low) or ("настроен" in low and "dns" in low):
            in_static = True
            # IP может быть в той же строке, что и заголовок секции
            m = _re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", s)
            if m:
                backup.setdefault(iface, []).append(m.group(0))
            continue
        elif "dns" in low and ("dhcp" in low or "автомат" in low or "нет" in low):
            in_static = False
        elif in_static and _re.match(r"^\d", s):
            ip = _re.match(r"([0-9]{1,3}\.){3}[0-9]{1,3}", s).group(0)
            backup.setdefault(iface, []).append(ip)
    return backup


def _restore_dns(backup):
    """Re-apply manually-configured DNS servers after network stack reset."""
    if not backup:
        return 0
    restored = 0
    for iface_desc, servers in backup.items():
        if not servers:
            continue
        name = iface_desc.split(":")[-1].strip().strip('"')
        if not name:
            continue
        # применять только первый DNS как static, остальные — add
        first, *rest = servers
        _run(f'netsh interface ipv4 set dns name="{name}" source=static address={first}')
        for index, extra in enumerate(rest, start=2):
            _run(f'netsh interface ipv4 add dns name="{name}" address={extra} index={index}')
        restored += 1
        logging.info(f"[REPAIR] DNS restored on {name}: {', '.join(servers)}")
    return restored


def _backup_ip_config():
    """Бэкап СТАТИЧЕСКИХ (не DHCP) IPv4-адресов. `netsh int ip reset` стирает
    их на всех адаптерах — без этого бэкапа юзер со статикой от провайдера
    останется без интернета после автопочинки."""
    r = _run("netsh interface ipv4 show config")
    if not r or not r.stdout:
        return {}
    backup = {}
    iface = None
    static = False
    ip = prefix = gw = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        # заголовок интерфейса: 'Настройка интерфейса "Ethernet"' / 'Configuration for interface'
        if ("интерфейса" in low and '"' in s) or low.startswith("configuration for interface"):
            if iface and static and ip:
                backup[iface] = {"ip": ip, "prefix": prefix, "gateway": gw}
            m = re.search(r'"([^"]+)"', s)
            iface = m.group(1) if m else s.split(":", 1)[-1].strip()
            static = False
            ip = prefix = gw = None
            # loopback не бывает «статикой провайдера» — не трогаем
            if iface and ("loopback" in iface.lower() or "петл" in iface.lower()):
                iface = None
            continue
        if iface is None:
            continue
        if "dhcp включен" in low or "dhcp enabled" in low:
            static = ("нет" in low or "no" in low)
            continue
        if "ip-адрес" in low or "ip address" in low:
            m = re.search(r"(\d{1,3}\.){3}\d{1,3}", s)
            ip = m.group(0) if m else None
            continue
        if "префикс подсети" in low or "subnet prefix" in low:
            m = re.search(r"/\d{1,2}", s)
            if m:
                prefix = int(m.group(0)[1:])
            continue
        if "основной шлюз" in low or "default gateway" in low:
            m = re.search(r"(\d{1,3}\.){3}\d{1,3}", s)
            gw = m.group(0) if m else None
            continue
    if iface and static and ip:
        backup[iface] = {"ip": ip, "prefix": prefix, "gateway": gw}
    return backup


def _restore_ip_config(backup):
    """Вернуть статические IP/маску/шлюз после полного сброса сети."""
    if not backup:
        return 0
    import ipaddress
    restored = 0
    for name, cfg in backup.items():
        ip = cfg.get("ip")
        prefix = cfg.get("prefix")
        if not ip:
            continue
        mask = None
        if prefix:
            try:
                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
            except Exception:
                mask = None
        if not mask:
            continue
        cmd = f'netsh interface ipv4 set address name="{name}" source=static ' \
              f'address={ip} mask={mask}'
        if cfg.get("gateway"):
            cmd += f" gateway={cfg['gateway']}"
        _run(cmd)
        restored += 1
        logging.info(f"[REPAIR] Static IP restored on {name}: {ip}/{prefix}")
    return restored


_PROXY_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def check_system_proxy(diag):
    """Инфо-проверка системного прокси в Фазе 1: задан ли, и если да — жив ли порт
    (застрявший от закрытого Nekobox/v2ray/Clash убивает работу winws)."""
    import winreg
    import socket as _s
    enabled = 0
    server = ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_REG_KEY) as k:
            try:
                enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
            except OSError:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(k, "ProxyServer")
            except OSError:
                server = ""
    except OSError as e:
        logging.warning(f"[REPAIR] proxy status read error: {e}")
        diag.add("Статус системного прокси: прочитать реестр не удалось", False)
        return

    if not enabled or not server:
        diag.add("Системный прокси Windows: не задан", True)
        return

    parts = re.split(r"[; ]", server)
    host = port = None
    for p in parts:
        if not p or "=" in p:
            continue
        if ":" in p:
            host, port = p.rsplit(":", 1)
            break
    if not host or not port.isdigit():
        diag.add(f"Системный прокси: {server} (формат не разобран)", None)
        return
    port = int(port)
    alive = False
    try:
        with _s.create_connection((host, port), timeout=2):
            alive = True
    except Exception:
        alive = False
    if alive:
        diag.add(f"Системный прокси: {server} — порт живой (рабочий)", True)
    else:
        diag.add(f"⚠️ Системный прокси: {server} — порт НЕ отвечает. Это может быть "
                 f"застрявший после закрытия Nekobox/v2ray/Clash и блокировать winws "
                 f"(чинится в Фазе 2)", False)


def _reset_stale_proxy(ask=None, log=None):
    """Чинит «застрявший» системный прокси. Прокси-клиенты (Nekobox/v2ray/Clash)
    при закрытии нередко оставляют включённым системный прокси Windows, и трафик
    летит на мёртвый локальный адрес, блокируя winws. Сбрасываем ТОЛЬКО если включён
    и указывает на МЕРТВЫЙ порт; живой рабочий прокси не трогаем."""
    import winreg
    import socket as _s
    changed = False
    enabled = 0
    server = ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_REG_KEY) as k:
            try:
                enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
            except OSError:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(k, "ProxyServer")
            except OSError:
                server = ""
    except OSError as e:
        logging.warning(f"[REPAIR] proxy reg read error: {e}")
        return changed

    if not enabled:
        if log:
            log("Системный прокси Windows не задан — ничего сбрасывать")
        return changed

    # ProxyServer может быть "host:port", "http=host:port;https=host:port", "host=port"
    parts = re.split(r"[; ]", server)
    host = port = None
    for p in parts:
        if not p or "=" in p:
            continue
        if ":" in p:
            host, port = p.rsplit(":", 1)
            break
    if not host or not port:
        if log:
            log(f"Прокси включён, но формат ProxyServer не распознан: {server!r}")
        return changed

    port = int(port) if port.isdigit() else None
    alive = False
    if host and port:
        try:
            with _s.create_connection((host, port), timeout=2):
                alive = True
        except Exception:
            alive = False

    if alive:
        if log:
            log(f"Системный прокси активен ({host}:{port}) — рабочий, не трогаю")
        return changed

    # мёртвый прокси — застрял от закрытого клиента
    if ask and not ask(f"Обнаружен «застрявший» системный прокси {host}:{port} — "
                       f"адрес не отвечает (обычно ломает winws после закрытия "
                       f"Nekobox/v2ray/Clash). Сбросить его?\n\nВыполню: отключу "
                       f"ProxyEnable, удалю ProxyServer/ProxyOverride и netsh winhttp "
                       f"reset proxy."):
        if log:
            log(f"Прокси {host}:{port} не отвечает (застрявший) — пропущено, юзер отказался")
        return changed

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_REG_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(k, "ProxyServer")
            except OSError:
                pass
            try:
                winreg.DeleteValue(k, "ProxyOverride")
            except OSError:
                pass
        changed = True
    except OSError as e:
        logging.warning(f"[REPAIR] proxy reg write error: {e}")
    _run("netsh winhttp reset proxy")
    if log and changed:
        log(f"Системный прокси сброшен: был {server} (застрявший), ProxyOverride удалён. "
            f"Браузеры/система пойдут напрямую")
    return changed


def _flush_dns(ask=None, log=None):
    """Лечение сетевого стека.

    По умолчанию — МЯГКИЙ сброс: flushdns + чистка ARP + nbtstat. Это безопасно и
    лечит залипшие кэши после кривых VPN.

    ПОЛНЫЙ `netsh int ip reset` — только с явного согласия пользователя: эта команда
    стирает статические IP/DNS на ВСЕХ адаптерах. Перед ним делаем полный бэкап
    статики (IP+DNS) и восстанавливаем."""
    _run("ipconfig /flushdns")
    _run("netsh interface ipv4 delete arpcache")
    _run("nbtstat -R")
    _run("nbtstat -RR")
    if log:
        log("Сброс сети: мягкий (flushdns + arpcache + nbtstat) — статика не тронута")

    backup = {}
    try:
        backup = _backup_dns()
        logging.info(f"[REPAIR] Backed up DNS for {len(backup)} interface(s)")
    except Exception as e:
        logging.warning(f"[REPAIR] DNS backup failed: {e}")

    if ask and ask("⚠️ Дополнительно выполнить ПОЛНЫЙ сброс сети "
                   "(netsh int ip reset)?\n\nОн стирает статические IP/DNS на всех "
                   "адаптерах (интернет может отвалиться, если адрес ручной от "
                   "провайдера). Нужен только если стек реально сломан — например "
                   "после кривого VPN. Бэкап статики сделаем и восстановим.") is True:
        if log:
            log("Составление бэкапа статических IP/DNS перед полным сбросом...")
        ip_backup = _backup_ip_config()
        _run("netsh int ip reset")
        _run("ipconfig /registerdns")
        n_ip = _restore_ip_config(ip_backup)
        n_dns = _restore_dns(backup) if backup else 0
        logging.info(f"[REPAIR] Full reset done; restored {n_ip} static IP, {n_dns} DNS")
        if log:
            log(f"Полный сброс выполнен; восстановлено IP: {n_ip}, DNS: {n_dns}", True)
        return "full"

    _run("ipconfig /registerdns")
    return "soft"


def start_strategy():
    """(Re)create and start the currently selected strategy. Returns True if up."""
    app_state = state.load_state()
    last_bat = app_state.get("last_bat")
    candidates = [f for f in BAT_DIR.glob("*.bat")
                  if f.name.lower() not in ("service.bat", "general.bat")]
    bat_path = None
    for b in candidates:
        if b.stem == last_bat:
            bat_path = b
            break
    if bat_path is None and candidates:
        bat_path = candidates[0]
    if bat_path is None:
        return False
    ok = service.restart_service(bat_path, bat_path.stem)
    state.save_state(last_bat=bat_path.stem, stopped=not ok)
    return ok


def check_service_after_start(diag):
    """Phase 4: after trying to start SakuraFlowService — did it actually go RUNNING?
    If START_FAILED — THAT is when we dig into WinDivert (created? error?) and the
    winws log. Earlier (phase 1) WinDivert absence is normal."""
    r = _run(f'sc.exe query "{SERVICE_NAME}"')
    if r is None:
        diag.add("Не удалось опросить службу обхода", False)
        return False
    out = str(r.stdout or "") + str(r.stderr or "")
    if "RUNNING" in out:
        diag.add("Служба обхода SakuraFlowService: RUNNING", True)
        return True
    if "START_PENDING" in out:
        # даём время добраться до RUNNING
        for _ in range(6):
            time.sleep(1)
            r = _run(f'sc.exe query "{SERVICE_NAME}"')
            out = str(r.stdout or "") + str(r.stderr or "")
            if "RUNNING" in out:
                diag.add("Служба обхода SakuraFlowService: RUNNING", True)
                return True
            if "STOPPED" in out or "FAILED" in out:
                break

    m = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", out)
    state_txt = m.group(1) if m else "неизвестно"
    diag.add(f"Служба обхода НЕ запустилась (STATE {state_txt})", False)

    # --- теперь уже имеет смысл смотреть WinDivert ---
    rd = _run('sc.exe query "WinDivert"')
    dout = str(rd.stdout or "") + str(rd.stderr or "") if rd else ""
    if "RUNNING" in dout:
        diag.add("WinDivert при этом успел стартовать — падение где-то в winws")
    elif "1060" in dout or "не установлен" in dout.lower():
        diag.add("WinDivert так и не создался при старте службы — драйвер не подхватился. "
                 "Причины: нет подписи (обновите Windows) / блокировка антивирусом / "
                 "WinDivert64.sys удалён", False)
        diag.recommend("WinDivert не стартует вместе со службой: добавьте папку zapret "
                       "в исключения антивируса, обновите Windows (нужна цифровая подпись "
                       "драйвера)", needs_user=True)
    else:
        err_code = "?"
        em = re.search(r"\(([0-9A-Fx]+)\)", dout)
        if em:
            err_code = em.group(1)
        diag.add(f"WinDivert не запустился (код {err_code}). Возможна блокировка "
                 f"драйвера или нет цифровой подписи")

    # и свежий лог winws
    log = BAT_DIR / "winws.log"
    if log.exists():
        try:
            tail = "\n".join(log.read_text(encoding="utf-8", errors="ignore")
                             .splitlines()[-15:])
            diag.add("Хвост winws.log:\n" + (tail or "(пусто)"))
        except Exception as e:
            logging.warning(f"[REPAIR] winws.log read error: {e}")
    return False


def diagnose_and_repair(on_log=None, on_confirm=None):
    """Full fix-everything pass. `on_log` is a callable(str) for live UI output.
    `on_confirm(question) -> bool` is called when the user must decide something
    (e.g. kill a process holding a port). Returning False skips that step."""
    def log(text, ok=None):
        mark = {True: "✅", False: "❌", None: "ℹ️"}[ok]
        if on_log:
            on_log(f"{mark} {text}")
    def ask(question):
        if on_confirm:
            return on_confirm(question) is True
        return False

    def raw_dump():
        """Сырой вывод системных команд — пугает, но инфополезно."""
        log("─" * 46)
        log("RAW SYSINFO (raw output — по нему диагностировал):")
        for cmd, label in (
            ('sc.exe query "WinDivert"', "WinDivert service"),
            ('sc.exe query "SakuraFlowService"', "SakuraFlowService"),
            ("netsh interface ipv4 show dnsservers", "DNS servers"),
            ("netsh interface ipv4 show config", "IPv4 config"),
            ("netsh interface ipv4 show subinterfaces", "Subinterface MTU"),
            ("netsh interface ipv6 show interfaces", "IPv6 interfaces"),
            ("ipconfig /all", "IP config full"),
        ):
            r = _run(cmd)
            body = ""
            if r:
                body = (r.stdout or "").strip() or (r.stderr or "").strip() or "(empty)"
            log(f"\n[{label}]  $ {cmd}\n{body}")

    def flush_steps():
        """Вывести в UI накопленный чек-лист проверок (diag.add попадал только
        в файловый лог и diag.steps — без этого юзер не видел результатов)."""
        if not diag.steps:
            return
        log("")
        log("📋 ЧЕК-ЛИСТ ДИАГНОСТИКИ:")
        for text, ok in diag.steps:
            log(text, ok)
        diag.steps.clear()

    log("🔧 Запускаю диагностику системы...")

    diag = Diagnosis()

    check_folder_path(diag)
    winws = check_processes(diag)
    check_winws_instances(diag)
    check_dpi_conflicts(diag)
    windivert = check_windivert(diag)

    # --- локальные проблемы, мешающие обходу ---
    check_ipv6(diag)
    check_vpn_adapters(diag)
    check_vpn_processes(diag)
    check_antivirus(diag)
    check_windows_defender(diag)
    check_ports(diag)
    check_dns(diag)
    check_system_proxy(diag)
    check_lan(diag)
    check_wifi(diag)
    check_dns_resolution(diag)
    check_system_clock(diag)
    check_loopback(diag)
    check_mtu(diag)
    check_icmp_targets(diag)
    check_tcp_http(diag)
    check_schannel(diag)
    check_fake_bins(diag)
    check_user_list_encoding(diag)
    check_game_filter_resolved(diag)
    check_hosts(diag)
    check_service_drift(diag)
    check_winws_logs(diag)

    flush_steps()
    raw_dump()

    log("")
    log("🧹 Очистка застрявших процессов и службы...")
    stop_conflicts()
    _flush_dns(ask=ask, log=log)
    _reset_stale_proxy(ask=ask, log=log)

    log("🔄 Пересоздание службы обхода...")
    if not start_strategy():
        log("Не удалось запустить стратегию обхода", False)
    else:
        log("Служба обхода запущена", True)

    # --- WinDivert и служба: оцениваем ТОЛЬКО после попытки старта ---
    check_service_after_start(diag)
    check_winws_instances(diag)
    check_winws_packet_drop(diag)
    flush_steps()

    # --- действия, требующие согласия пользователя ---
    asked = []
    for action in list(diag.user_actions):
        # диалоги привязываем ТОЛЬКО к закрытию процесса на занятом порту;
        # остальные рекомендации с needs_user печатаются в «РЕКОМЕНДАЦИИ» в конце
        if "Порт" in action and "занят" in action:
            port = None
            m = re.search(r"Порт (\d+) занят", action)
            if m:
                port = int(m.group(1))
            if port and ask(f"Закрыть процесс, занимающий порт {port}?\n\n{action}"):
                if tools.stop_process_by_port(port):
                    log(f"Процесс на порту {port} остановлен", True)
                    asked.append(action)

    time.sleep(2)
    log("")
    log("📡 Проверка работы (HTTPS: YouTube/Discord/Google/Cloudflare)...")
    reached, total, vresults = verify_targets(diag)

    # YouTube-подсказки: QUIC (UDP 443) — только когда TLS к ютубу реально виснет;
    # отравленный DNS — это отдельная история (DoH/прямой DNS)
    yt_res = next((r for r in vresults if r[0] == "YouTube"), None)
    if yt_res and yt_res[1] is None:
        if yt_res[2] and "dns" in yt_res[2]:
            diag.recommend("YouTube не резолвится через системный DNS (фильтр/травля). "
                           "Включите DoH в браузере или пропишите DNS 8.8.8.8 напрямую")
        else:
            diag.recommend("YouTube не отвечает: если UDP-порт 443 (QUIC) не "
                           "обрабатывается стратегией — отключите QUIC в браузере "
                           "(chrome://flags/#enable-quic)")
    elif not yt_res and reached == 0:
        diag.recommend("Ни одна цель не отвечает — проверьте статус службы и лог WinWS")

    if not winws:
        log("WinWS не был запущен — теперь пересоздан", True)
    elif diag.has_problems:
        pass

    log("")
    if reached > 0:
        log("✅ Обход работает! Цели отвечают.", True)
    else:
        log("⚠️ Обход запущен, но цели не отвечают. Проверь: VPN выше и лог WinWS.", False)

    if diag.recommendations:
        log("")
        log("📋 РЕКОМЕНДАЦИИ:")
        for rec in diag.recommendations:
            log(f"  • {rec}")

    return {"diag": diag, "reachable": reached, "total": total}
