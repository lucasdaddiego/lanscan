"""HTTP-banner identification — name a device from its web server.

For a device with an open web port we do one cheap HTTP GET and read the `Server`
header and the page `<title>`. Routers, NAS boxes, cameras, printers and IoT admin
panels routinely identify themselves there even when mDNS and reverse-DNS don't.
Best-effort throughout: any failure yields no banner rather than breaking the scan.
No root, no extra dependencies.
"""
from __future__ import annotations

import asyncio
import re
import ssl

# Web ports we'll speak HTTP(S) to, in preference order (plain HTTP first).
_WEB_PORTS: tuple[int, ...] = (
    80, 8080, 8000, 8008, 8081, 8888, 5000, 9000, 8123, 8096, 32400, 443, 8443,
)
_HTTPS_PORTS = {443, 8443}

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_TLS_CTX: ssl.SSLContext | None = None


def _tls_context() -> ssl.SSLContext:
    """A permissive TLS context — LAN devices almost always present self-signed
    certs, so we connect without verifying (we only want the banner, not trust)."""
    global _TLS_CTX
    if _TLS_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False          # must precede verify_mode = CERT_NONE
        ctx.verify_mode = ssl.CERT_NONE
        _TLS_CTX = ctx
    return _TLS_CTX


async def fetch(host: str, port: int, path: str = "/", *, tls: bool = False,
                timeout: float = 2.0, max_bytes: int = 65536):
    """One HTTP/1.0 GET. Returns (status, headers, body) or None on any failure."""
    ctx = _tls_context() if tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
               "User-Agent: lanscan\r\nConnection: close\r\nAccept: */*\r\n\r\n")
        writer.write(req.encode("latin-1", "replace"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return _split_response(raw)


def _split_response(raw: bytes):
    """(status, headers, body) from a raw HTTP response, or None if unparseable."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines[0].startswith(b"HTTP/"):
        return None
    parts = lines[0].split(None, 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, val = line.partition(b":")
        if sep:
            headers[key.decode("latin-1").strip().lower()] = val.decode("latin-1").strip()
    return status, headers, body


def _title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    text = " ".join(m.group(1).decode("utf-8", "replace").split())  # collapse whitespace
    return text or None


async def identify(ip: str, open_ports: list[int], *, timeout: float = 2.0):
    """Best HTTP banner for a device as ``(server, title)`` (each str | None).

    Probes the single most-preferred open web port; no web port -> (None, None).
    """
    port = next((p for p in _WEB_PORTS if p in open_ports), None)
    if port is None:
        return None, None
    res = await fetch(ip, port, tls=port in _HTTPS_PORTS, timeout=timeout)
    if res is None:
        return None, None
    _status, headers, body = res
    return headers.get("server") or None, _title(body)
