"""SSDP / UPnP discovery — find devices that announce themselves over UPnP.

One M-SEARCH burst per scan: multicast the discovery request to the SSDP group
out of *every* scanned interface (a multicast send otherwise leaves only via the
default route, so Ethernet-side devices would be missed while Wi-Fi holds the
default), sent twice to ride out UDP loss, then collect the unicast 200-OK
replies and read each device's `SERVER` string plus (best-effort) its
friendlyName / manufacturer / model from the `LOCATION` description XML. Smart
TVs, media renderers, routers, NAS boxes and a lot of IoT kit show up here.
Best-effort throughout — any failure yields no UPnP data rather than breaking
the scan. No root, no extra dependencies.
"""
import asyncio
import re
import socket
from collections.abc import Iterable
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


def _tag_re(tag: str) -> re.Pattern[bytes]:
    return re.compile(rf"<{tag}>(.*?)</{tag}>".encode(), re.IGNORECASE | re.DOTALL)


# The three description-XML tags we read (namespace-free, case-insensitive).
_TAGS = {t: _tag_re(t) for t in ("friendlyName", "manufacturer", "modelName")}


def _xml_tag(xml: bytes, tag: str) -> str | None:
    """First value of a description-XML tag, whitespace-collapsed."""
    m = _TAGS[tag].search(xml)
    if not m:
        return None
    text = " ".join(m.group(1).decode("utf-8", "replace").split())
    return text or None


async def _enrich(ip: str, info: dict, *, timeout: float) -> None:
    """Fetch the device description at LOCATION and fill in name / model.

    ``ip`` is the host that actually sent the reply, and we only follow a
    LOCATION whose host is that same literal address. A reply is unauthenticated
    UDP from anyone on the LAN, so an unchecked LOCATION would let a rogue
    responder both point us at an arbitrary host/port of its choosing and claim
    another device's identity by citing that device's description URL.
    """
    loc = info.get("location")
    if not loc:
        return
    parsed = urlparse(loc)
    if parsed.hostname != ip:       # missing, a name, or someone else's address
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


def _multicast_socket(local_ip: str | None) -> socket.socket:
    """A UDP socket whose multicast egress is pinned to `local_ip` — replies come
    back unicast to that address — or left to the default route when None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        if local_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(local_ip))
        sock.bind((local_ip or "0.0.0.0", 0))
    except OSError:
        sock.close()
        raise
    return sock


async def _open_transports(loop: asyncio.AbstractEventLoop, collector: _Collector,
                           local_ips: Iterable[str]) -> list[asyncio.DatagramTransport]:
    """One transport per interface address (all feeding `collector`); if none of
    those can be opened, a single default-route transport as a last resort."""
    transports: list[asyncio.DatagramTransport] = []
    candidates: list[str | None] = list(local_ips) or [None]
    while candidates:
        local_ip = candidates.pop(0)
        try:
            sock = _multicast_socket(local_ip)
            transport, _ = await loop.create_datagram_endpoint(lambda: collector, sock=sock)
        except OSError:
            if not candidates and not transports and local_ip is not None:
                candidates.append(None)  # every pinned socket failed: try unpinned
            continue
        transports.append(transport)
    return transports


async def probe(local_ips: Iterable[str] = (), *, timeout: float = 2.0,
                fetch_details: bool = True) -> dict[str, dict]:
    """M-SEARCH out of each `local_ips` interface (or the default route when none
    are given) and return ``{ip: {server, location, name, model}}``.

    `timeout` is the whole reply window: the request goes out at t=0 and again at
    t=timeout/4 (UDP loss), and with MX: 1 every reply is due within a second of
    the request it answers.
    """
    loop = asyncio.get_running_loop()
    collector = _Collector()
    transports = await _open_transports(loop, collector, local_ips)
    if not transports:
        return {}
    try:
        for wait in (timeout * 0.25, timeout * 0.75):
            for transport in transports:
                transport.sendto(_MSEARCH, (_SSDP_ADDR, _SSDP_PORT))
            await asyncio.sleep(wait)
    finally:
        for transport in transports:
            transport.close()

    result: dict[str, dict] = {
        ip: {"server": h.get("server"), "location": h.get("location"),
             "name": None, "model": None}
        for ip, h in collector.responses.items()
    }
    if fetch_details and result:
        await asyncio.gather(
            *(_enrich(ip, info, timeout=timeout) for ip, info in result.items()),
            return_exceptions=True)
    return result
