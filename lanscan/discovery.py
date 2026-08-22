"""mDNS / Bonjour discovery via zeroconf.

Browses the network for advertised services and maps them back to IPs, turning
`192.168.0.41` into e.g. "Living Room  (AirPlay, AirPlay-Audio)". Runs in the
background and is read by the scan engine through `snapshot()`. Best-effort: any
failure here degrades to no mDNS data rather than breaking the scan.
"""
import asyncio
import contextlib
import logging
import re

from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

logging.getLogger("zeroconf").setLevel(logging.ERROR)

# Friendly labels for common service types (keyed without the .local. suffix).
_LABELS: dict[str, str] = {
    "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay-Audio", "_airport._tcp": "AirPort",
    "_companion-link._tcp": "Apple", "_rdlink._tcp": "Apple", "_sleep-proxy._udp": "Apple",
    "_homekit._tcp": "HomeKit", "_hap._tcp": "HomeKit", "_matter._tcp": "Matter",
    "_matterc._udp": "Matter", "_googlecast._tcp": "Chromecast", "_googlezone._tcp": "Google",
    "_spotify-connect._tcp": "Spotify", "_sonos._tcp": "Sonos", "_ipp._tcp": "Printer",
    "_ipps._tcp": "Printer", "_printer._tcp": "Printer", "_pdl-datastream._tcp": "Printer",
    "_scanner._tcp": "Scanner", "_uscan._tcp": "Scanner", "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP", "_smb._tcp": "SMB", "_afpovertcp._tcp": "AFP",
    "_nfs._tcp": "NFS", "_http._tcp": "HTTP", "_https._tcp": "HTTPS",
    "_device-info._tcp": "device-info", "_workstation._tcp": "Workstation",
    "_amzn-wplay._tcp": "Amazon", "_hue._tcp": "Hue", "_miio._udp": "Xiaomi",
    "_rfb._tcp": "Screen-Share", "_daap._tcp": "iTunes", "_touch-able._tcp": "Apple-Remote",
}

# Everything we can label is browsed from the start by a single browser (one
# query schedule for all types), so there's no meta-type enumeration to wait on.
_TYPES = [f"{t}.local." for t in _LABELS]


def _friendly_from_txt(info: AsyncServiceInfo) -> str | None:
    """A human-set device name from the service's TXT record, if present
    (e.g. Chromecast advertises its room name under `fn`)."""
    props = info.properties or {}
    for key in (b"fn", b"n", b"FriendlyName", b"friendlyName", b"name"):
        val = props.get(key)
        if val:
            try:
                s = val.decode("utf-8", "replace").strip()
            except Exception:  # odd TXT value type — skip it
                continue
            if s:
                return s
    return None


_UUIDISH = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _best_name(instances: set[str]) -> str | None:
    if not instances:
        return None

    def rank(s: str) -> tuple:
        human = " " in s or "'" in s or "’" in s
        return (bool(_UUIDISH.match(s)), 0 if human else 1, len(s))

    # UUID-shaped names rank last; among the rest prefer human-looking, then short.
    return min(instances, key=rank)


class MdnsDiscovery:
    def __init__(self) -> None:
        self._azc: AsyncZeroconf | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._by_ip: dict[str, dict] = {}
        self._by_name: dict[str, dict] = {}  # instance -> {ips, label, instance}

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._azc = AsyncZeroconf()
        self._browser = AsyncServiceBrowser(self._azc.zeroconf, _TYPES,
                                            handlers=[self._on_service])

    def _on_service(self, zeroconf, service_type, name, state_change, **_) -> None:
        if not self._loop:
            return
        if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
            asyncio.run_coroutine_threadsafe(self._resolve(service_type, name), self._loop)
        elif state_change is ServiceStateChange.Removed:
            self._loop.call_soon_threadsafe(self._forget, name)

    async def _resolve(self, service_type: str, name: str) -> None:
        try:
            key = service_type.removesuffix(".local.").removesuffix(".")
            label = _LABELS.get(key, key)  # we only browse labelled types
            info = AsyncServiceInfo(service_type, name)
            if not await info.async_request(self._azc.zeroconf, 2500):
                return
            instance = name.removesuffix("." + service_type).removesuffix(".").strip()
            friendly = _friendly_from_txt(info)
            added = friendly if friendly else (
                instance if (instance and label != "device-info") else None)
            ips = [a for a in info.parsed_addresses() if ":" not in a]  # IPv4 only
            # An Updated event re-resolves an instance we may already know: drop the
            # previous record first (rebuilding every IP it used to claim) so an
            # address it has since left doesn't keep this name forever.
            self._forget(name)
            # remember this instance's contribution so a Removed event can undo it
            self._by_name[name] = {"ips": set(ips), "label": label, "instance": added}
            for addr in ips:
                entry = self._by_ip.setdefault(
                    addr, {"name": None, "services": set(), "instances": set()})
                entry["services"].add(label)
                if added:
                    entry["instances"].add(added)
                entry["name"] = _best_name(entry["instances"])
        except Exception:  # never let discovery crash a scan
            return

    def _forget(self, name: str) -> None:
        """Drop a departed service instance, then rebuild each affected IP from
        the records that remain — so a name still backed by a sibling service
        type (Apple/Sonos/Chromecast advertise one name under several types) is
        kept, and a stale name can't bleed onto whatever later reuses the IP."""
        rec = self._by_name.pop(name, None)
        if not rec:
            return
        for ip in rec["ips"]:
            services: set[str] = set()
            instances: set[str] = set()
            for other in self._by_name.values():
                if ip in other["ips"]:
                    services.add(other["label"])
                    if other["instance"]:
                        instances.add(other["instance"])
            if services or instances:
                self._by_ip[ip] = {"name": _best_name(instances),
                                   "services": services, "instances": instances}
            else:
                self._by_ip.pop(ip, None)

    def snapshot(self) -> dict[str, dict]:
        return {ip: {"name": v["name"], "services": set(v["services"])}
                for ip, v in self._by_ip.items()}

    async def stop(self) -> None:
        if self._browser:
            with contextlib.suppress(Exception):
                await self._browser.async_cancel()
        if self._azc:
            with contextlib.suppress(Exception):
                await self._azc.async_close()
