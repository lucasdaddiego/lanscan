"""Core data models for the LAN scanner."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Interface:
    """A local network interface we can scan from."""

    device: str  # BSD name, e.g. "en0"
    port: str  # friendly hardware port, e.g. "Wi-Fi"
    kind: str  # "wifi" | "ethernet"
    ipv4: str  # our address on it, e.g. "192.168.0.10"
    prefix: int  # network prefix length, e.g. 24
    cidr: str  # network, e.g. "192.168.0.0/24"
    mac: str | None = None

    @property
    def label(self) -> str:
        return f"{self.port} ({self.device})"


@dataclass(slots=True)
class Device:
    """A device discovered on the LAN."""

    ip: str
    interface: str = ""  # device name it was seen on, e.g. "en0"
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None  # reverse DNS
    mdns_name: str | None = None  # friendly Bonjour name
    upnp_name: str | None = None  # UPnP/SSDP friendlyName
    upnp_model: str | None = None  # UPnP manufacturer / model
    http_server: str | None = None  # HTTP Server header from an open web port
    http_title: str | None = None  # <title> of the device's web UI
    services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    is_self: bool = False
    is_gateway: bool = False
    randomized_mac: bool = False
    via: str = ""  # how liveness was detected: icmp | tcp | arp
    first_seen: float = 0.0
    last_seen: float = 0.0
    ever_seen: bool = False  # seen in a previous run (from persisted history)

    @property
    def name(self) -> str:
        """Best human-facing name for the device."""
        if self.mdns_name:
            return self.mdns_name
        if self.upnp_name:
            return self.upnp_name
        if self.hostname:
            # strip trailing dot / .local. noise but keep it readable
            return self.hostname.rstrip(".")
        if self.http_title:
            return self.http_title
        return ""

    @property
    def tags(self) -> list[str]:
        t: list[str] = []
        if self.is_gateway:
            t.append("router")
        if self.is_self:
            t.append("self")
        return t

    def ip_sort_key(self) -> tuple[int, ...]:
        try:
            return tuple(int(o) for o in self.ip.split("."))
        except ValueError:
            return (999,)

    def as_dict(self) -> dict:
        """Plain dict for JSON export."""
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "name": self.name, "hostname": self.hostname, "mdns_name": self.mdns_name,
            "upnp_name": self.upnp_name, "upnp_model": self.upnp_model,
            "http_server": self.http_server, "http_title": self.http_title,
            "services": self.services, "open_ports": self.open_ports,
            "interface": self.interface, "via": self.via,
            "tags": self.tags, "randomized_mac": self.randomized_mac,
            "ever_seen": self.ever_seen,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }
