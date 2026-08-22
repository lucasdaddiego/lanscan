"""Per-device TCP connect port scan — no root required.

A connect scan: a port is reported open only when the TCP handshake completes;
refused or timed-out ports count as closed/filtered. Scoped to a curated set of
common LAN / IoT / media / dev / admin ports so it stays fast and readable (it
runs every refresh) instead of sweeping all 65535 — a full sweep is slow and, at
high concurrency, trips the flood-protection on routers and cheap IoT, which
corrupts the results and can briefly knock the device offline.
"""
import asyncio
import contextlib
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

# Service name -> coarse category. One table drives the TUI's colour grouping
# and what "connect" does, so a port can't be web-coloured but shell-launched.
PORT_CATEGORY: dict[str, str] = {
    "http": "web", "https": "web", "http-alt": "web", "https-alt": "web",
    "dev-http": "web", "vite": "web", "prometheus": "web",
    "ssh": "shell", "telnet": "shell", "rdp": "shell", "vnc": "shell",
    "ftp": "file", "smb": "file", "afp": "file", "lpd": "file", "ipp": "file",
    "printer": "file", "nfs": "file",
    "airplay": "media", "cast": "media", "rtsp": "media", "plex": "media",
    "jellyfin": "media",
    "mysql": "data", "postgres": "data", "redis": "data", "mongodb": "data",
    "mssql": "data", "influxdb": "data", "elasticsearch": "data",
    "memcached": "data", "amqp": "data",
    "mqtt": "iot", "mqtts": "iot", "upnp": "iot", "home-assistant": "iot",
    "iphone": "iot",
    "smtp": "mail", "imap": "mail", "imaps": "mail", "pop3": "mail",
    "pop3s": "mail",
    "docker": "infra", "msrpc": "infra", "netbios": "infra", "ldap": "infra",
    "dns": "infra",
}

# Ports that serve a browser UI over plain HTTP, in banner-probe preference
# order (the generic web ports first, app-specific ones after), and over TLS.
HTTP_PORTS: tuple[int, ...] = (
    80, 8080, 8000, 8008, 8081, 8888, 5000, 9000, 8123, 8096, 32400,
    3000, 5173, 8086, 9090, 49152,
)
HTTPS_PORTS: tuple[int, ...] = (443, 8443)


# Source-side resource exhaustion: the probe is retried, not reported closed.
_LOCAL_ERRNOS = {errno.EADDRNOTAVAIL, errno.EMFILE, errno.ENFILE,
                 errno.ENOBUFS, errno.ECONNABORTED}


async def _check_one(ip: str, port: int, timeout: float) -> bool:
    """True only if the TCP connection is accepted (refused/timeout = not open);
    retries source-side resource exhaustion (EMFILE & co.) rather than
    misreporting it as 'closed'."""
    for attempt in range(3):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
        except OSError as exc:  # includes TimeoutError / ConnectionRefusedError
            if exc.errno in _LOCAL_ERRNOS and attempt < 2:
                await asyncio.sleep(0.25 * (attempt + 1))
                continue
            return False
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return True
    return False  # pragma: no cover - loop always returns by the final attempt


async def open_ports(ip: str, timeout: float, sem: asyncio.Semaphore,
                     ports: tuple[int, ...] = COMMON_PORTS) -> list[int]:
    """Open TCP ports on `ip` among `ports` (probed concurrently, bounded by `sem`),
    in the order given."""
    async def _probe(port: int) -> bool:
        async with sem:
            return await _check_one(ip, port, timeout)

    results = await asyncio.gather(*(_probe(p) for p in ports))
    return [p for p, ok in zip(ports, results, strict=True) if ok]


# --- On-demand full sweep of a single host (deliberately gentle) -------------
# Low concurrency on purpose: a high-rate sweep trips routers'/IoT flood
# protection (false negatives + a temporary lockout). This trades speed for
# safety — robust hosts finish in seconds; hosts that *drop* closed ports
# (routers, cheap IoT) can take many minutes. Cancellable from the UI.
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


async def full_scan(ip: str, *, timeout: float = FULL_TIMEOUT,
                    concurrency: int = FULL_CONCURRENCY,
                    progress: Callable[[int, int], None] | None = None) -> list[int]:
    """Gentle full TCP sweep (1–65535) of one host via a small worker pool.

    Pool size is the connection-rate ceiling, kept low so we don't look like a
    SYN flood. Cancellation propagates cleanly via CancelledError.
    """
    total = 65535
    pending = iter(range(1, total + 1))  # shared: next() can't yield, so no lock needed
    found: list[int] = []
    done = 0

    async def worker() -> None:
        nonlocal done
        for port in pending:
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
