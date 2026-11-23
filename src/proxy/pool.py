import asyncio
import logging
import random
import time

from collections import deque
from urllib.parse import urlencode
from typing import Dict, List, Optional, Tuple

from .raw_websocket import RawWebSocket
from .stats import stats
from .config import proxy_config
from .utils import DC_DEFAULT_IPS

log = logging.getLogger('tg-mtproto-proxy')


class _CfWorkerPool:
    WS_POOL_MAX_AGE = 100.0
    WS_POOL_CHECK_INTERVAL = 5.0
    PER_DC_LIMIT = 1
    REFILL_BACKOFF_INITIAL = 1.0
    REFILL_BACKOFF_MAX = 3600.0

    def __init__(self):
        self._idle: Dict[int, deque] = {}
        self._refilling: Dict[int, asyncio.Task] = {}
        self._rotating: Dict[int, asyncio.Task] = {}
        self._refill_failures: Dict[int, int] = {}
        self._refill_after: Dict[int, float] = {}

    async def get(self, dc: int, fallback_dst: str,
                  worker_domains: List[str]
                  ) -> Optional[Tuple[RawWebSocket, str]]:
        if proxy_config.pool_size <= 0 or not worker_domains:
            return None
        now = time.monotonic()

        bucket = self._idle.get(dc)
        if bucket is None:
            bucket = deque()
            self._idle[dc] = bucket
        while bucket:
            ws, created, worker_domain = bucket.popleft()
            age = now - created
            if self._is_stale(ws, created, now):
                asyncio.create_task(self._quiet_close(ws))
                continue
            stats.cf_pool_hits += 1
            log.debug(
                "CF worker pool hit DC%d via %s (age=%.1fs, left=%d)",
                dc, worker_domain, age, len(bucket))
            self._schedule_refill(dc, fallback_dst, worker_domains)
            return ws, worker_domain

        stats.cf_pool_misses += 1
        self._schedule_refill(dc, fallback_dst, worker_domains)
        return None

    def _is_stale(self, ws, created, now):
        return (now - created >= self.WS_POOL_MAX_AGE or ws._closed
                or ws.writer.transport.is_closing() or ws.reader.at_eof()
                or ws.reader.exception() is not None)

    def _schedule_refill(self, dc, fallback_dst, worker_domains):
        if proxy_config.pool_size <= 0 or not worker_domains:
            return
        self._schedule_rotation(dc, fallback_dst, worker_domains)
        if (dc in self._refilling
                or time.monotonic() < self._refill_after.get(dc, 0)):
            return
        self._refilling[dc] = asyncio.create_task(self._refill(
            dc, fallback_dst, list(worker_domains)))

    async def _refill(self, dc, fallback_dst, worker_domains):
        try:
            bucket = self._idle.setdefault(dc, deque())
            target_size = min(proxy_config.pool_size, self.PER_DC_LIMIT)
            needed = target_size - len(bucket)
            if needed <= 0:
                return
            connected = 0
            for _ in range(needed):
                result = await self._connect_one(
                    worker_domains, fallback_dst, dc)
                if self._refilling.get(dc) is not asyncio.current_task():
                    if result is not None:
                        await self._quiet_close(result[0])
                    return
                if result is None:
                    break
                ws, worker_domain = result
                bucket.append((ws, time.monotonic(), worker_domain))
                connected += 1
            if connected:
                self._refill_failures.pop(dc, None)
                self._refill_after.pop(dc, None)
            else:
                failures = self._refill_failures.get(dc, 0) + 1
                self._refill_failures[dc] = failures
                delay = min(
                    self.REFILL_BACKOFF_INITIAL
                    * (2 ** min(failures - 1, 12)),
                    self.REFILL_BACKOFF_MAX,
                )
                self._refill_after[dc] = time.monotonic() + delay
                log.info("CF worker pool refill failed for DC%d, retry in %.0fs",
                         dc, delay)
            log.debug("CF worker pool refilled DC%d: %d ready",
                      dc, len(bucket))
        finally:
            if self._refilling.get(dc) is asyncio.current_task():
                self._refilling.pop(dc, None)

    def _schedule_rotation(self, dc, fallback_dst, worker_domains):
        if dc in self._rotating:
            return
        self._rotating[dc] = asyncio.create_task(
            self._rotate(dc, fallback_dst, list(worker_domains)))

    async def _rotate(self, dc, fallback_dst, worker_domains):
        try:
            while proxy_config.pool_size > 0:
                bucket = self._idle.setdefault(dc, deque())
                now = time.monotonic()
                expired = []
                ready = deque()
                while bucket:
                    ws, created, worker_domain = bucket.popleft()
                    if self._is_stale(ws, created, now):
                        expired.append(ws)
                    else:
                        ready.append((ws, created, worker_domain))
                bucket.extend(ready)

                if expired:
                    for ws in expired:
                        asyncio.create_task(self._quiet_close(ws))
                    log.debug("CF worker pool rotated DC%d: %d stale, %d ready",
                              dc, len(expired), len(bucket))

                if len(bucket) < min(proxy_config.pool_size, self.PER_DC_LIMIT):
                    self._schedule_refill(dc, fallback_dst, worker_domains)

                wake_at = now + self.WS_POOL_CHECK_INTERVAL
                if bucket:
                    wake_at = min(wake_at, min(
                        created + self.WS_POOL_MAX_AGE for _, created, _ in bucket))
                if dc not in self._refilling and self._refill_after.get(dc, 0) > now:
                    wake_at = min(wake_at, self._refill_after[dc])
                await asyncio.sleep(max(0, wake_at - time.monotonic()))
        finally:
            if self._rotating.get(dc) is asyncio.current_task():
                self._rotating.pop(dc, None)

    async def _connect_one(self, worker_domains, fallback_dst, dc):
        query = urlencode({
            'dst': fallback_dst,
            'dc': str(dc),
        })
        path = f'/apiws?{query}'
        for worker_domain in self.available_domains(worker_domains):
            try:
                ws = await RawWebSocket.connect(
                    worker_domain, worker_domain, timeout=8, path=path,
                    secure=False)
                return ws, worker_domain
            except Exception as exc:
                log.debug("CF worker pool connect DC%d via %s for %s failed: %r",
                          dc, worker_domain, fallback_dst, exc)
        return None

    def available_domains(self, worker_domains: List[str]) -> List[str]:
        domains = list(dict.fromkeys(worker_domains))
        random.shuffle(domains)
        return domains

    async def _quiet_close(self, ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        cf_fallbacks = {
            dc: ip for dc, ip in DC_DEFAULT_IPS.items()
            if dc not in proxy_config.dc_redirects
        }

        if (proxy_config.pool_size <= 0 or not cf_fallbacks
                or not proxy_config.cfproxy_worker_domains):
            return

        worker_domains = list(proxy_config.cfproxy_worker_domains)
        for dc, fallback_dst in cf_fallbacks.items():
            self._schedule_refill(dc, fallback_dst, worker_domains)

        log.info("CF worker pool warmup started for %d DC(s)", len(cf_fallbacks))

    def reset(self):
        loop = asyncio.get_running_loop()
        for task in list(self._rotating.values()) + list(self._refilling.values()):
            if not task.done() and task.get_loop() is loop:
                task.cancel()
        for bucket in self._idle.values():
            for ws, _, _ in bucket:
                try:
                    ws.writer.close()
                except Exception as exc:
                    log.debug("CF worker pool close failed: %r", exc)
        self._idle.clear()
        self._refilling.clear()
        self._rotating.clear()
        self._refill_failures.clear()
        self._refill_after.clear()

    async def close(self):
        tasks = list(self._rotating.values()) + list(self._refilling.values())
        self.reset()
        await asyncio.gather(*tasks, return_exceptions=True)


cf_worker_pool = _CfWorkerPool()
