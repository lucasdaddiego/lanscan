"""Per-device TCP connect port scan — no root required.

A connect scan: a port is reported open only when the TCP handshake completes;
refused or timed-out ports count as closed/filtered. Scoped to a curated set of
common LAN / IoT / media / dev / admin ports so it stays fast and readable (it
runs every refresh) instead of sweeping all 65535 — a full sweep is slow and, at
high concurrency, trips the flood-protection on routers and cheap IoT, which
corrupts the results and can briefly knock the device offline.
"""
from __future__ import annotations

import asyncio
import errno
import resource
from collections.abc import Callable

COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 515, 548, 554,
    587, 631, 993, 995, 1433, 1883, 2375, 3000, 3306, 3389, 5000, 5173, 5432,
    5672, 5900, 6379, 7000, 8000, 8008, 8009, 8080, 8081, 8086, 8096, 8123,
    8443, 8883, 8888, 9000, 9090, 9100, 9200, 11211, 27017, 32400, 49152, 62078,
)

# Short names for display/export (numbers stay primary; names are a hint).
PORT_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 515: "lpd", 548: "afp", 554: "rtsp", 587: "smtp",
    631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1883: "mqtt",
    2375: "docker", 3000: "dev-http", 3306: "mysql", 3389: "rdp", 5000: "upnp",
    5173: "vite", 5432: "postgres", 5672: "amqp", 5900: "vnc", 6379: "redis",
    7000: "airplay", 8000: "http-alt", 8008: "cast", 8009: "cast",
    8080: "http-alt", 8081: "http-alt", 8086: "influxdb", 8096: "jellyfin",
    8123: "home-assistant", 8443: "https-alt", 8883: "mqtts", 8888: "http-alt",
    9000: "http-alt", 9090: "prometheus", 9100: "printer", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 32400: "plex", 49152: "upnp",
    62078: "iphone",
}


async def _is_open(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> bool:
    """True only if the TCP connection is accepted. Refused/timeout = not open."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


async def open_ports(ip: str, timeout: float, sem: asyncio.Semaphore,
                     ports: tuple[int, ...] = COMMON_PORTS) -> list[int]:
    """Return the sorted list of open TCP ports on `ip` (probed concurrently)."""
    results = await asyncio.gather(*(_is_open(ip, p, timeout, sem) for p in ports))
    return [p for p, ok in zip(ports, results) if ok]


# --- On-demand full sweep of a single host (deliberately gentle) -------------
# Low concurrency on purpose: a high-rate sweep trips routers'/IoT flood
# protection (false negatives + a temporary lockout). This trades speed for
# safety — robust hosts finish in seconds; hosts that *drop* closed ports
# (routers, cheap IoT) can take many minutes. Cancellable from the UI.
_LOCAL_ERRNOS = {errno.EADDRNOTAVAIL, errno.EMFILE, errno.ENFILE,
                 errno.ENOBUFS, errno.ECONNABORTED}
FULL_TIMEOUT = 1.5
FULL_CONCURRENCY = 128


def raise_fd_limit(target: int = 4096) -> int:
    """Nudge the open-file soft limit up so the worker pool has descriptors."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = target if hard == resource.RLIM_INFINITY else min(target, hard)
    if soft < want:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            soft = want
        except (ValueError, OSError):
            pass
    return soft


async def _check_one(ip: str, port: int, timeout: float) -> bool:
    """One connect probe; retries source-side resource exhaustion (not 'closed')."""
    for attempt in range(3):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError):
            return False
        except OSError as exc:
            if exc.errno in _LOCAL_ERRNOS and attempt < 2:
                await asyncio.sleep(0.25 * (attempt + 1))
                continue
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    return False


async def full_scan(ip: str, *, timeout: float = FULL_TIMEOUT,
                    concurrency: int = FULL_CONCURRENCY,
                    progress: Callable[[int, int], None] | None = None) -> list[int]:
    """Gentle full TCP sweep (1–65535) of one host via a small worker pool.

    Pool size is the connection-rate ceiling, kept low so we don't look like a
    SYN flood. Cancellation propagates cleanly via CancelledError.
    """
    queue: asyncio.Queue[int] = asyncio.Queue()
    for port in range(1, 65536):
        queue.put_nowait(port)
    total = queue.qsize()
    found: list[int] = []
    done = 0

    async def worker() -> None:
        nonlocal done
        while True:
            try:
                port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if await _check_one(ip, port, timeout):
                found.append(port)
            done += 1
            if progress and done % 250 == 0:
                progress(done, total)

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    if progress:
        progress(total, total)
    found.sort()
    return found
