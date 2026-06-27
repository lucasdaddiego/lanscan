"""SSDP / UPnP discovery — find devices that announce themselves over UPnP.

A one-shot M-SEARCH burst per scan: multicast the discovery request to the SSDP
group, collect the unicast 200-OK replies, and read each device's `SERVER` string
plus (best-effort) its friendlyName / manufacturer / model from the `LOCATION`
description XML. Smart TVs, media renderers, routers, NAS boxes and a lot of IoT
kit show up here. Best-effort throughout — any failure yields no UPnP data rather
than breaking the scan. No root, no extra dependencies.
"""
from __future__ import annotations

import asyncio
import re
import socket
from urllib.parse import urlparse

from . import banners

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _parse_headers(data: bytes) -> dict[str, str]:
    """SSDP reply -> lower-cased header dict (status line and body ignored)."""
    headers: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
        key, sep, val = line.partition(":")
        if sep:
            headers[key.strip().lower()] = val.strip()
    return headers


class _Collector(asyncio.DatagramProtocol):
    """Accumulates one header set per responding IP, preferring a reply that
    carries a LOCATION (so we can later fetch its description)."""

    def __init__(self) -> None:
        self.responses: dict[str, dict[str, str]] = {}

    def datagram_received(self, data: bytes, addr) -> None:
        ip = addr[0]
        headers = _parse_headers(data)
        prev = self.responses.get(ip)
        if prev is None or ("location" in headers and "location" not in prev):
            self.responses[ip] = headers


_TAG_CACHE: dict[str, re.Pattern[bytes]] = {}


def _xml_tag(xml: bytes, tag: str) -> str | None:
    """First value of a (namespace-free) XML tag, whitespace-collapsed."""
    pat = _TAG_CACHE.get(tag)
    if pat is None:
        pat = re.compile(rf"<{tag}>(.*?)</{tag}>".encode(), re.IGNORECASE | re.DOTALL)
        _TAG_CACHE[tag] = pat
    m = pat.search(xml)
    if not m:
        return None
    text = " ".join(m.group(1).decode("utf-8", "replace").split())
    return text or None


async def _enrich(info: dict, *, timeout: float) -> None:
    """Fetch the device description at LOCATION and fill in name / model."""
    loc = info.get("location")
    if not loc:
        return
    parsed = urlparse(loc)
    if not parsed.hostname:
        return
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    res = await banners.fetch(parsed.hostname, port, path,
                              tls=parsed.scheme == "https", timeout=timeout)
    if res is None:
        return
    _status, _headers, body = res
    info["name"] = _xml_tag(body, "friendlyName")
    manuf = _xml_tag(body, "manufacturer")
    model = _xml_tag(body, "modelName")
    info["model"] = " ".join(p for p in (manuf, model) if p) or None


async def probe(timeout: float = 2.0, *, fetch_details: bool = True) -> dict[str, dict]:
    """Run an M-SEARCH and return ``{ip: {server, location, name, model}}``."""
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _Collector, local_addr=("0.0.0.0", 0), family=socket.AF_INET)
    except OSError:
        return {}
    try:
        transport.sendto(_MSEARCH, (_SSDP_ADDR, _SSDP_PORT))
        await asyncio.sleep(timeout)
    finally:
        transport.close()

    result: dict[str, dict] = {
        ip: {"server": h.get("server"), "location": h.get("location"),
             "name": None, "model": None}
        for ip, h in proto.responses.items()
    }
    if fetch_details and result:
        await asyncio.gather(
            *(_enrich(info, timeout=timeout) for info in result.values()),
            return_exceptions=True)
    return result
