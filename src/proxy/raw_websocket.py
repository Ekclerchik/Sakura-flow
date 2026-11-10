import os
import ssl
import base64
import struct
import asyncio
import socket as _socket

from typing import List, Optional, Tuple
from .config import proxy_config


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = ssl.create_default_context()

# Предел на размер одного WS-фрейма. Длину фрейма диктует удалённая сторона, и
# без проверки `readexactly(length)` может попросить гигабайты (ОЗУ процесса
# мгновенно уходит в OOM). Легальные MTProto-сообщения мельче 1 МБ; 8 МБ — с
# большим запасом.
MAX_FRAME_SIZE = 8 * 1024 * 1024

# После записи фрейма не копим больше этого в буфере транспорта: иначе при
# медленном аплинке (отдача файла) буфер растёт без ограничений и «утекает»
# память. Это же лечит и общий рост при долгой сессии.
WRITE_BUFFER_HIGH_WATER = 256 * 1024


def _abort_writer(writer) -> None:
    """Мгновенно освободить транспорт, не ожидая корректного TLS-shutdown.

    Нужно на всех путях ошибки/отмены connect(): иначе недоделанный
    ssl-транспорт (сокет + буферы) живёт до сборщика мусора. При частых
    переподключениях Telegram это и есть наблюдаемая «утечка» памяти и
    сокетов в CLOSE_WAIT.
    """
    if writer is None:
        return
    transport = None
    try:
        transport = writer.transport
    except Exception:
        transport = None
    try:
        if transport is not None:
            transport.abort()
        else:
            writer.close()
    except Exception:
        pass


class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: dict = None, location: str = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    """XOR-маска без по-байтового питоновского цикла.

    Раньше: result[i] ^= mask[i & 3] — 131072 итераций интерпретатора на
    каждый 64KB-чанк аплинка (x2 с bytes(result)). Теперь: данные и
    периодическая маска переводятся в big-int, XOR выполняется одним
    машинным действием в CPython. Корректность: little-endian XOR big-int
    == потактовый XOR байтов."""
    if not data:
        return data
    n = len(data)
    m = (mask * ((n >> 2) + 1))[:n]
    return (int.from_bytes(data, 'little')
            ^ int.from_bytes(m, 'little')).to_bytes(n, 'little')


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed')

    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0) -> 'RawWebSocket':
        # writer остаётся в этой переменной, пока владение не передано объекту
        # RawWebSocket. Любой выход (ошибка, таймаут, отмена) обязан закрыть
        # транспорт — см. except ниже.
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=_ssl_ctx,
                                        server_hostname=domain),
                timeout=min(timeout, 10))

            set_sock_opts(writer.transport, proxy_config.buffer_size)

            ws_key = base64.b64encode(os.urandom(16)).decode()

            req = (
                f'GET /apiws HTTP/1.1\r\n'
                f'Host: {domain}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Protocol: binary\r\n'
                f'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                f'AppleWebKit/537.36 (KHTML, like Gecko) '
                f'Chrome/131.0.0.0 Safari/537.36\r\n'
                f'\r\n'
            )
            writer.write(req.encode())
            await writer.drain()

            response_lines: list[str] = []
            while True:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())

            if not response_lines:
                raise WsHandshakeError(0, 'empty response')

            first_line = response_lines[0]
            parts = first_line.split(' ', 2)
            try:
                status_code = int(parts[1]) if len(parts) >= 2 else 0
            except ValueError:
                status_code = 0

            if status_code == 101:
                ws = RawWebSocket(reader, writer)
                writer = None  # владение транспортом перешло к RawWebSocket
                return ws

            headers: dict[str, str] = {}
            for hl in response_lines[1:]:
                if ':' in hl:
                    k, v = hl.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            raise WsHandshakeError(status_code, first_line, headers,
                                   location=headers.get('location'))
        except BaseException:
            _abort_writer(writer)
            raise

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        length = len(data)
        if length < 1500:
            # Мелкий фрейм дешевле одной аллокацией; большие чанки не копируем
            # ещё раз в конкатенацию header+payload — asyncio-транспорт
            # принимает несколько write() без дополнительных копий данных.
            self.writer.write(self._build_frame(self.OP_BINARY, data, mask=True))
        else:
            fb = 0x80 | self.OP_BINARY
            mask_key = os.urandom(4)
            if length < 126:
                self.writer.write(_st_BB4s.pack(fb, 0x80 | length, mask_key))
            elif length < 65536:
                self.writer.write(_st_BBH4s.pack(fb, 0x80 | 126, length, mask_key))
            else:
                self.writer.write(_st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key))
            self.writer.write(_xor_mask(data, mask_key))
        # Без этого буфер транспорта рос бы неограниченно при отдаче данных от
        # клиента (аплинк медленнее, чем читает tcp_to_ws) — главный источник
        # роста ОЗУ во время загрузок.
        await self._drain_if_needed()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            self.writer.write(
                self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def drain(self):
        await self.writer.drain()

    async def _drain_if_needed(self):
        try:
            pending = self.writer.transport.get_write_buffer_size()
        except (AttributeError, NotImplementedError):
            await self.writer.drain()
            return
        if pending >= WRITE_BUFFER_HIGH_WATER:
            await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (0x1, 0x2):
                return payload
            continue
        return None

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(
                self._build_frame(self.OP_CLOSE, b'', mask=True))
            await asyncio.wait_for(self.writer.drain(), timeout=1.0)
        except BaseException:
            pass
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
        except BaseException:
            pass
        finally:
            # Гарантированно отпускаем транспорт: если TLS-shutdown не
            # завершился за 2с, сокет и буферы не должны ждать GC.
            _abort_writer(self.writer)

    def abort(self):
        """Закрыть без ожидания (пул, отмена, ошибки)."""
        self._closed = True
        _abort_writer(self.writer)

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes]:
        hdr = await self.reader.readexactly(2)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if length > MAX_FRAME_SIZE:
            raise ConnectionError(
                f"WebSocket frame too large: {length} bytes")
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key)
        payload = await self.reader.readexactly(length)
        return opcode, payload