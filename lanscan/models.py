"""Core data models for the LAN scanner."""
import unicodedata
from dataclasses import asdict, dataclass, field

# Unicode general categories that must never reach a terminal: Cc (the C0 and
# C1 controls, U+0000-U+001F and U+007F-U+009F) and Cf (format characters: the
# bidi overrides, zero-width joiners/spaces, the BOM, ...). Replaced rather than
# dropped, so a hostile name still shows *that* something was there.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf"})
SANITIZE_MARK = "\u00b7"  # "·"


def sanitize(text: str) -> str:
    """Neutralise a device-supplied string before it is rendered or exported.

    Every control (Cc, including the C1 range) and format (Cf) character becomes
    ``·``. Rich/Textual strip only a handful of C0 codes, so an mDNS instance
    name, a UPnP friendlyName, an HTTP ``<title>``/``Server`` or a PTR record
    could otherwise carry an ESC/CSI sequence (or a right-to-left override)
    straight into the detail pane and the JSON export. Applied once, at each
    ingestion point, and again over every string field of ``Device.as_dict``.
    """
    return "".join(SANITIZE_MARK if unicodedata.category(c) in _UNSAFE_CATEGORIES else c
                   for c in text)


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
    remembered_name: str | None = None  # last name history stored, when nameless now
    services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    is_self: bool = False
    is_gateway: bool = False
    randomized_mac: bool = False
    via: str = ""  # how liveness was detected: icmp | arp | self
    first_seen: float = 0.0
    last_seen: float = 0.0
    ever_seen: bool = False  # seen in a previous run (from persisted history)

    @property
    def live_name(self) -> str:
        """Best name learnt from the device itself this run ("" if none)."""
        if self.mdns_name:
            return self.mdns_name
        if self.upnp_name:
            return self.upnp_name
        if self.hostname:
            # strip trailing dot / .local. noise but keep it readable
            return self.hostname.rstrip(".")
        return self.http_title or ""

    @property
    def name(self) -> str:
        """Best human-facing name: what it says now, else what history remembers."""
        return self.live_name or self.remembered_name or ""

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

    def as_dict(self) -> dict[str, object]:
        """Plain dict for JSON export: every field plus the derived name / tags.

        String fields are sanitized again here, so the export stays clean even
        for a name that reached the record by another route (e.g. history)."""
        data = asdict(self) | {"name": self.name, "tags": self.tags}
        return {k: sanitize(v) if isinstance(v, str) else v for k, v in data.items()}
