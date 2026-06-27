"""Live Textual TUI for the LAN scanner — master/detail split.

Left: a compact device list. Right: a detail pane with the full picture for the
selected device (identity, network, every open port, all services, activity).
The list refreshes on an interval, runs mDNS in the background, re-discovers
interfaces each cycle, and keeps the selection pinned to the same device (by IP)
across refreshes.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from rich.align import Align
from rich.columns import Columns
from rich.console import Group
from rich.table import Table as RTable
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import DataTable, Footer, Header, Label, OptionList, Static
from textual.widgets.option_list import Option

from . import history, launch, net, ports
from .engine import scan
from .models import Device

_KIND_CYCLE = {None: "wifi", "wifi": "ethernet", "ethernet": None}

# Compact master columns; everything wide lives in the detail pane.
_COLUMNS = (
    ("", 2),       # status dot
    ("IP", 16),    # always shown
    ("Name", 22),  # friendly name (+ role), blank when unknown
)

# 24-bit palette (Tokyo-Night-ish). Theme $vars resolve in Textual CSS but NOT
# inside raw rich style strings, so every renderable below uses concrete hex —
# which Ghostty (and any truecolor terminal) reproduces exactly.
C = {
    "blue": "#7aa2f7", "cyan": "#7dcfff", "green": "#9ece6a", "yellow": "#e0af68",
    "orange": "#ff9e64", "purple": "#bb9af7", "red": "#f7768e", "teal": "#73daca",
    "fg": "#c0caf5", "muted": "#7c83ad", "faint": "#565f89", "bg": "#1a1b26",
}
PAL = {
    "ip": C["cyan"], "ip_new": f"bold {C['cyan']}", "new": f"bold {C['green']}",
    "router": C["yellow"], "self": C["cyan"], "ok": C["green"], "svc": C["purple"],
    "warn": C["yellow"], "muted": C["faint"], "label": C["muted"],
    "head": f"bold {C['fg']}", "accent": C["blue"],
}

# A Textual theme so borders, scrollbars, the row cursor and panels all share the
# palette above (CSS uses $primary / $surface / $panel / $accent, etc.).
THEME = Theme(
    name="lanscan", dark=True,
    background=C["bg"], surface="#24283b", panel="#1f2335",
    primary=C["blue"], secondary=C["purple"], accent=C["cyan"],
    success=C["green"], warning=C["yellow"], error=C["red"], foreground=C["fg"],
)


def _badge(text: str, color: str) -> Text:
    """A solid pill: dark text on a colour block."""
    return Text(f" {text} ", style=f"bold {C['bg']} on {color}")


# Port/service → category → colour, so a glance at the ports list groups them.
_CAT_COLOR = {
    "web": C["blue"], "shell": C["green"], "file": C["yellow"],
    "media": C["purple"], "data": C["orange"], "iot": C["cyan"],
    "mail": C["red"], "infra": C["muted"],
}
_SVC_CAT = {
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


def _port_color(name: str | None) -> str:
    return _CAT_COLOR.get(_SVC_CAT.get((name or "").lower(), ""), C["faint"])


# mDNS service labels are free-form friendly names, so match by keyword.
_SVC_KEYWORDS = (
    ("airplay", "media"), ("airtunes", "media"), ("cast", "media"),
    ("chromecast", "media"), ("spotify", "media"), ("dlna", "media"),
    ("roku", "media"), ("sonos", "media"), ("print", "file"), ("ipp", "file"),
    ("smb", "file"), ("afp", "file"), ("nfs", "file"), ("file", "file"),
    ("time capsule", "file"), ("ssh", "shell"), ("sftp", "shell"),
    ("remote", "shell"), ("homekit", "iot"), ("home", "iot"), ("matter", "iot"),
    ("thread", "iot"), ("mqtt", "iot"), ("companion", "iot"), ("http", "web"),
    ("web", "web"),
)


def _svc_color(label: str) -> str:
    t = label.lower()
    for key, cat in _SVC_KEYWORDS:
        if key in t:
            return _CAT_COLOR[cat]
    return C["purple"]


_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
DASH = "—"
_VIA = {"icmp": "ICMP ping", "tcp": "TCP probe", "arp": "ARP", "self": "this host"}


def _kv() -> RTable:
    """Borderless two-column grid: dim right-justified label / folding value."""
    t = RTable.grid(padding=(0, 2))
    t.add_column(justify="right", style=PAL["label"], no_wrap=True, width=9)
    t.add_column(overflow="fold")
    return t


def _val(s: str | None) -> Text:
    return Text(s) if s else Text(DASH, style="dim")


class DeviceTable(DataTable):
    """The master list. Re-points Enter at the app's connect action (instead of
    DataTable's hidden `select_cursor`) so the Footer advertises "Connect ▸"."""

    BINDINGS = [Binding("enter", "app.connect", "Connect", show=True)]


class PortPicker(ModalScreen):
    """Pick one of a device's open ports → connect to it (browser / terminal).

    Dismisses with (port, service) on selection, or None on cancel.
    """

    CSS = """
    PortPicker { align: center middle; background: $background 55%; }
    #picker {
        width: 56; height: auto; max-height: 80%;
        background: $surface; border: round $primary; padding: 1 2;
    }
    #picker-title { text-style: bold; width: 1fr; }
    #picker OptionList { height: auto; max-height: 14; background: $surface; }
    #picker-hint { color: $text-muted; padding-top: 1; }
    """
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, ip: str, entries: list[tuple[int, str | None]]) -> None:
        super().__init__()
        self._ip = ip
        self._entries = entries

    def compose(self) -> ComposeResult:
        opts = []
        for port, service in self._entries:
            col = _port_color(service)
            line = Text()
            line.append("▪ ", style=col)
            line.append(f"{port:>5}  ", style=f"bold {col}")
            line.append(f"{service or '?':<13}", style="" if service else "dim")
            line.append(f"→ {launch.describe(self._ip, port, service)}", style="dim")
            opts.append(Option(line, id=str(port)))
        with Vertical(id="picker"):
            yield Label(f"Connect to {self._ip}", id="picker-title")
            yield OptionList(*opts)
            yield Label("enter ▸ connect    esc ▸ cancel", id="picker-hint")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        port = int(event.option.id)
        service = next((s for p, s in self._entries if p == port), None)
        self.dismiss((port, service))

    def action_cancel(self) -> None:
        self.dismiss(None)


class LanScanApp(App):
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen { layers: base; }
    #status { height: 1; padding: 0 1; color: $text-muted; background: $panel; }
    #body { height: 1fr; }
    #devices {
        width: 48;
        min-width: 28;
        max-width: 45%;
        height: 1fr;
        border-right: vkey $primary-darken-2;
    }
    #detail-wrap {
        width: 1fr;
        min-width: 24;
        height: 1fr;
        overflow-x: hidden;
        padding: 1 2;
    }
    #detail { width: 1fr; height: auto; }
    """
    BINDINGS = [
        ("enter", "connect", "Connect"),
        ("r", "rescan", "Rescan"),
        ("e", "export", "Export"),
        ("o", "toggle_ports", "Ports"),
        ("f", "full_scan", "Full-scan"),
        ("J", "scroll_detail_down", "Detail ▼"),
        ("K", "scroll_detail_up", "Detail ▲"),
        ("p", "toggle_pause", "Pause"),
        ("a", "cycle_kind", "Scope"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, args) -> None:
        super().__init__()
        self.args = args
        self._kind = args.kind  # None | "wifi" | "ethernet"
        self._ports = not args.no_ports
        self._full_ports: dict[str, list[int]] = {}  # IP -> last full-scan result
        self._fullscan = None          # (ip, done, total) while a full scan runs
        self._fullscan_worker = None
        self._selected_ip: str | None = None
        self._mdns = None
        self._history: dict[str, dict] | None = None  # persisted across runs (None = off)
        self._ifaces: list = []
        self._devices: list[Device] = []
        self._first_seen: dict[str, float] = {}
        self._known: set[str] = set()
        self._new: set[str] = set()
        self._scanning = False
        self._paused = False
        self._progress = (0, 0)
        self._last_scan = 0.0
        self._scanned_once = False
        self._spin = 0  # braille-spinner frame, ticked while scanning
        self._detail_sig: tuple | None = None  # skip redundant detail re-renders

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, icon=" ")  # drop Textual's default ⭘ (spotty font coverage)
        yield Static("starting…", id="status")
        with Horizontal(id="body"):
            table = DeviceTable(id="devices", zebra_stripes=True, cursor_type="row")
            for label, width in _COLUMNS:
                table.add_column(label, width=width)
            yield table
            with VerticalScroll(id="detail-wrap"):
                yield Static(id="detail")
        yield Footer(compact=True)

    async def on_mount(self) -> None:
        self.title = "lanscan"
        self.register_theme(THEME)
        self.theme = "lanscan"
        ports.raise_fd_limit()
        if not self.args.no_history:
            self._history = history.load()
        if not self.args.no_mdns:
            try:
                from .discovery import MdnsDiscovery
                self._mdns = MdnsDiscovery()
                await self._mdns.start()
            except Exception:  # noqa: BLE001 - mDNS is optional
                self._mdns = None
        self.set_interval(self.args.interval, self._trigger_scan)
        self.set_timer(1.2, self._trigger_scan)  # first scan after brief mDNS warmup
        self.set_interval(0.1, self._tick_spin)  # animate the scan spinner
        self._update_status()
        self._refresh_detail()  # show the "Scanning…" placeholder up front

    def _tick_spin(self) -> None:
        """Advance the spinner only while there's activity to show — and only
        repaint the detail pane during the very first scan, when it holds the
        full-screen placeholder (later repaints could wipe a text selection)."""
        if not (self._scanning or self._fullscan or not self._scanned_once):
            return
        self._spin = (self._spin + 1) % len(_SPINNER)
        self._update_status()
        if not self._scanned_once:
            self._refresh_detail(force=True)

    async def on_unmount(self) -> None:
        if self._mdns is not None:
            await self._mdns.stop()
        if self._history is not None:
            history.save(self._history)

    # ---- scanning -------------------------------------------------------
    def _trigger_scan(self) -> None:
        if self._scanning or self._paused:
            return
        self._scanning = True
        self._run_scan()

    @work(exclusive=True, group="scan")
    async def _run_scan(self) -> None:
        try:
            self._ifaces = net.discover_interfaces(
                only_device=self.args.interface, only_kind=self._kind)
            self._update_status()
            devices = await scan(
                self._ifaces, resolve=not self.args.no_resolve, mdns=self._mdns,
                ssdp_enabled=not self.args.no_ssdp, scan_ports=self._ports,
                http_id=not self.args.no_http, timeout=self.args.timeout,
                progress=self._on_progress)
            self._apply(devices)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a scan error must not kill the TUI
            self.notify(f"Scan failed: {exc}", severity="error")
        finally:
            self._scanning = False
            self._progress = (0, 0)
            self._last_scan = time.time()
            self._scanned_once = True
            self._update_status()

    def _on_progress(self, done: int, total: int) -> None:
        self._progress = (done, total)
        if done == total or done % 24 == 0:  # throttle UI churn
            self._update_status()

    def _apply(self, devices: list[Device]) -> None:
        current = {d.ip for d in devices}
        if self._history is not None:
            # Persisted history owns first_seen/ever_seen and survives restarts.
            history.merge(self._history, devices)
            history.save(self._history)
        else:
            for d in devices:
                if d.ip in self._first_seen:
                    d.first_seen = self._first_seen[d.ip]
                else:
                    self._first_seen[d.ip] = d.first_seen
        self._new = (current - self._known) if self._scanned_once else set()
        self._known |= current
        for d in devices:  # keep any on-demand full-scan results across refreshes
            if d.ip in self._full_ports:
                d.open_ports = sorted(set(d.open_ports) | set(self._full_ports[d.ip]))
        self._devices = devices
        self._refresh_table()

    # ---- master list ----------------------------------------------------
    def _refresh_table(self) -> None:
        try:
            table = self.query_one("#devices", DataTable)
        except Exception:  # noqa: BLE001 - not mounted / tearing down
            return
        prev_ip = self._selected_ip  # survives clear()
        table.clear()

        present = {d.ip for d in self._devices}
        target_row = 0
        for idx, d in enumerate(self._devices):
            is_new = d.ip in self._new
            if is_new:
                dot = Text("●", style=PAL["new"])
            elif d.is_gateway:
                dot = Text("◆", style=PAL["router"])
            elif d.is_self:
                dot = Text("◆", style=PAL["self"])
            else:
                dot = Text("·", style="dim")

            ip = Text(d.ip, overflow="ellipsis", no_wrap=True,
                      style=PAL["ip_new"] if is_new else "")

            nm = Text(overflow="ellipsis", no_wrap=True)
            if d.name:
                nm.append(d.name)
            role = "router" if d.is_gateway else "self" if d.is_self else ""
            if role:
                if d.name:
                    nm.append("  ")
                nm.append(f"({role})", style="dim")

            table.add_row(dot, ip, nm, key=d.ip)
            if d.ip == prev_ip:
                target_row = idx

        if self._devices:
            if prev_ip not in present:
                target_row = 0
            table.move_cursor(row=target_row)
            self._selected_ip = self._devices[target_row].ip
        else:
            self._selected_ip = None
        self._refresh_detail()  # idempotent; covers the no-op move_cursor case

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return  # empty-table / stale highlight — keep current selection
        self._selected_ip = event.row_key.value
        self._refresh_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # A click on the already-highlighted row → connect. (Enter is handled by
        # DeviceTable's `app.connect` binding so the Footer can advertise it.)
        if event.row_key is not None and event.row_key.value is not None:
            self._selected_ip = event.row_key.value
        self.action_connect()

    # ---- connect (launch a tool against an open port) -------------------
    def action_connect(self) -> None:
        dev = self._selected_device()
        if dev is None:
            return
        if not dev.open_ports:
            self.notify("No open ports — press f to full-scan this device.",
                        severity="warning")
            return
        entries = [(p, ports.PORT_NAMES.get(p)) for p in dev.open_ports]
        self.push_screen(PortPicker(dev.ip, entries),
                         lambda res, ip=dev.ip: self._launch_port(ip, res))

    def _launch_port(self, ip: str, result) -> None:
        if not result:
            return
        port, service = result
        ok, msg = launch.launch(ip, port, service)
        self.notify(msg, title=f"Connect {ip}:{port}",
                    severity="information" if ok else "error")

    # ---- detail pane ----------------------------------------------------
    def _device_by_ip(self, ip: str | None) -> Device | None:
        if ip is None:
            return None
        return next((d for d in self._devices if d.ip == ip), None)

    def _selected_device(self) -> Device | None:
        return self._device_by_ip(self._selected_ip)

    def _detail_signature(self, dev: Device | None) -> tuple:
        """Everything the detail pane actually displays, so we can skip a redundant
        re-render (which would otherwise wipe an in-progress mouse text selection)."""
        if dev is None:
            return ("placeholder", self._scanned_once, bool(self._devices), self._kind)
        fs = self._fullscan if (self._fullscan and self._fullscan[0] == dev.ip) else None
        return (
            dev.ip, dev.name, dev.mdns_name, dev.hostname, dev.vendor, dev.mac,
            dev.randomized_mac, dev.interface, dev.via, dev.is_gateway, dev.is_self,
            dev.upnp_name, dev.upnp_model, dev.http_server, dev.http_title,
            tuple(dev.open_ports), tuple(dev.services),
            dev.ip in self._new, dev.ip in self._full_ports,
            dev.ever_seen, int(dev.first_seen), int(dev.last_seen), fs,
        )

    def _refresh_detail(self, *, force: bool = False) -> None:
        try:
            pane = self.query_one("#detail", Static)
        except Exception:  # noqa: BLE001 - not mounted yet
            return
        dev = self._selected_device()
        sig = self._detail_signature(dev)
        if sig == self._detail_sig and not force:
            return  # unchanged → leave the rendered pane (and any text selection) alone
        self._detail_sig = sig
        pane.update(self._detail_renderable(dev))

    def _placeholder(self):
        scope = {None: "All", "wifi": "Wi-Fi", "ethernet": "Ethernet"}[self._kind]
        if not self._scanned_once:
            glyph, gcol = _SPINNER[self._spin], C["cyan"]
            title, sub = "Scanning your network…", f"discovering devices on {scope}"
        elif not self._devices:
            glyph, gcol = "○", C["faint"]
            title, sub = "No devices found", "press a to widen scope · r to rescan"
        else:
            glyph, gcol = "←", C["blue"]
            title, sub = "Select a device", "pick a row on the left"
        body = Group(
            Text(""),
            Text(glyph, style=f"bold {gcol}", justify="center"),
            Text(""),
            Text(title, style=f"bold {C['fg']}", justify="center"),
            Text(sub, style=PAL["muted"], justify="center"),
        )
        return Align.center(body, vertical="middle")

    def _detail_renderable(self, dev: Device | None):
        if dev is None:
            return self._placeholder()

        is_new = dev.ip in self._new
        blocks = []

        title = Text()
        title.append("● " if is_new else "· ", style=PAL["new"] if is_new else "dim")
        title.append(dev.ip, style=PAL["ip_new"] if is_new else f"bold {C['fg']}")
        for tag in dev.tags:
            title.append("  ")
            if tag == "router":
                title.append_text(_badge("ROUTER", C["yellow"]))
            elif tag == "self":
                title.append_text(_badge("THIS MAC", C["cyan"]))
        blocks.append(title)

        def section(name, body, *, suffix=""):
            head = Text()
            head.append("▌ ", style=PAL["accent"])
            head.append(name, style=PAL["head"])
            if suffix:
                head.append(f"  · {suffix}", style="dim")
            return Group(head, body)

        # IDENTITY
        ident = _kv()
        ident.add_row("Name", _val(dev.name))
        if dev.mdns_name:
            ident.add_row("mDNS", Text(dev.mdns_name))
        if dev.upnp_name:
            ident.add_row("UPnP", Text(dev.upnp_name))
        if dev.hostname:
            ident.add_row("Host", Text(dev.hostname.rstrip(".")))
        if dev.http_title:
            ident.add_row("Web", Text(dev.http_title))
        if dev.vendor:
            ven = Text(dev.vendor)
        elif dev.randomized_mac:
            ven = Text("private MAC", style=PAL["warn"])
        else:
            ven = Text("unknown", style="dim")
        ident.add_row("Vendor", ven)
        if dev.upnp_model:
            ident.add_row("Model", Text(dev.upnp_model, style="dim"))
        if dev.http_server:
            ident.add_row("Server", Text(dev.http_server, style="dim"))
        blocks.append(section("IDENTITY", ident))

        # NETWORK
        netg = _kv()
        netg.add_row("IP", Text(dev.ip, style="cyan"))
        if dev.mac:
            mac = Text(dev.mac)
            if dev.randomized_mac:
                mac.append("  ")
                mac.append_text(_badge("randomized", C["yellow"]))
        else:
            mac = Text(DASH, style="dim")
        netg.add_row("MAC", mac)
        netg.add_row("Iface", _val(dev.interface))
        netg.add_row("Via", Text(_VIA.get(dev.via, dev.via or DASH),
                                 style="" if dev.via in _VIA else "dim"))
        if dev.is_gateway:
            netg.add_row("Role", Text("gateway / router", style=PAL["warn"]))
        elif dev.is_self:
            netg.add_row("Role", Text("this Mac", style="cyan"))
        blocks.append(section("NETWORK", netg))

        # PORTS (omit unless there are any, or a full-scan of this host is running).
        # The count lives in the section header ("PORTS · 4 open"); the rows below
        # are just the ports. Enter on a port (or the row) connects to it.
        scanning_here = bool(self._fullscan) and self._fullscan[0] == dev.ip
        full_done = dev.ip in self._full_ports
        if dev.open_ports or scanning_here or full_done:
            n = len(dev.open_ports)
            if scanning_here:
                _, fdone, ftotal = self._fullscan
                pct = 100 * fdone // ftotal if ftotal else 0
                suffix = f"{n} open · scanning {pct}%" if n else f"scanning {pct}%"
            elif full_done:
                suffix = f"{n} open · full"
            else:
                suffix = f"{n} open"
            pt = _kv()
            if dev.open_ports:
                for p in dev.open_ports:
                    name = ports.PORT_NAMES.get(p)
                    col = _port_color(name)
                    num = Text("▪ ", style=col)
                    num.append(f"{p:>5}", style=f"bold {col}")
                    pt.add_row(num, Text(name or "?", style="" if name else "dim"))
            elif scanning_here:
                pt.add_row("", Text("no open ports yet", style="dim"))
            else:
                pt.add_row("", Text("no open ports", style="dim"))
            blocks.append(section("PORTS", pt, suffix=suffix))

        # SERVICES
        if dev.services:
            chips = Columns([_badge(s, _svc_color(s)) for s in dev.services],
                            padding=(0, 1), expand=False)
            blocks.append(section("SERVICES", chips))

        # ACTIVITY
        act = _kv()

        def ts(v):
            return time.strftime("%H:%M:%S", time.localtime(v)) if v else DASH
        # Persisted history can put first-seen days ago, so show the date when it's old.
        if dev.first_seen and time.time() - dev.first_seen >= 86400:
            first_txt = time.strftime("%b %d %H:%M", time.localtime(dev.first_seen))
        else:
            first_txt = ts(dev.first_seen)
        act.add_row("First", Text(first_txt))
        act.add_row("Last", Text(ts(dev.last_seen)))
        if dev.last_seen:
            age = max(0, int(time.time() - dev.last_seen))
            rel = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            act.add_row("Seen", Text(rel, style="dim"))
        if dev.ever_seen:
            act.add_row("History", Text("returning device", style="dim"))
        if is_new:
            act.add_row("New", Text("yes", style=PAL["ok"]))
        blocks.append(section("ACTIVITY", act))

        spaced = []
        for i, b in enumerate(blocks):
            if i:
                spaced.append(Text(""))
            spaced.append(b)
        return Group(*spaced)

    # ---- status ---------------------------------------------------------
    def _update_status(self) -> None:
        try:
            status = self.query_one("#status", Static)
        except Exception:  # noqa: BLE001 - not mounted yet
            return
        scope = {None: "All", "wifi": "Wi-Fi", "ethernet": "Ethernet"}[self._kind]
        parts = [f"{i.label} {i.cidr}"
                 + ("" if net.sweepable(i.cidr) else " (too large to sweep)")
                 for i in self._ifaces]
        nets = "  ".join(parts) or "no active interface"
        spin = _SPINNER[self._spin]

        line = Text(no_wrap=True, overflow="ellipsis")
        line.append_text(_badge(scope, C["blue"]))
        line.append(f" {nets}", style=PAL["muted"])
        line.append("    ")
        if self._scanning:
            done, total = self._progress
            if total and done >= total:
                msg = "scanning ports…" if self._ports else "identifying…"
            elif total:
                msg = f"scanning {done}/{total}…"
            else:
                msg = "scanning…"
            line.append(f"{spin} {msg}", style=C["cyan"])
        elif self._paused:
            line.append("paused ", style=C["yellow"])
            line.append("(p to resume)", style=PAL["muted"])
        else:
            when = (time.strftime("%H:%M:%S", time.localtime(self._last_scan))
                    if self._last_scan else "—")
            n = len(self._devices)
            line.append("● ", style=C["green"])
            line.append(f"{n} device{'s' if n != 1 else ''}", style=C["fg"])
            line.append(f" · last {when} · auto {self.args.interval:g}s", style=PAL["muted"])
        if self._new:
            line.append(f"  · {len(self._new)} new", style=C["green"])
        if not self._ports:
            line.append("  · ports off", style=PAL["muted"])
        if self._fullscan:
            fip, fdone, ftotal = self._fullscan
            pct = 100 * fdone // ftotal if ftotal else 0
            line.append(f"  · {spin} full-scan {fip} {pct}%", style=C["yellow"])
        status.update(line)

        ndev = len(self._devices)
        self.sub_title = f"{ndev} device{'s' if ndev != 1 else ''} · {scope}"

    # ---- actions --------------------------------------------------------
    def action_rescan(self) -> None:
        self._trigger_scan()

    def action_scroll_detail_down(self) -> None:
        self.query_one("#detail-wrap", VerticalScroll).scroll_relative(y=5, animate=False)

    def action_scroll_detail_up(self) -> None:
        self.query_one("#detail-wrap", VerticalScroll).scroll_relative(y=-5, animate=False)

    def action_export(self) -> None:
        if not self._devices:
            self.notify("Nothing to export yet — wait for a scan.", severity="warning")
            return
        path = Path.cwd() / f"lanscan-{time.strftime('%Y%m%d-%H%M%S')}.json"
        try:
            path.write_text(json.dumps([d.as_dict() for d in self._devices], indent=2))
        except OSError as exc:
            self.notify(f"Export failed: {exc}", title="Export", severity="error")
            return
        n = len(self._devices)
        self.notify(f"{n} device{'s' if n != 1 else ''} → {path}", title="Exported")

    def action_toggle_ports(self) -> None:
        self._ports = not self._ports
        if self._ports:
            self.notify("Port scan on — rescanning.")
            self._trigger_scan()
        else:
            # Reflect "off" instantly instead of waiting on a network sweep: drop the
            # ports we already have (keeping any on-demand full-scan results).
            self.notify("Port scan off.")
            for d in self._devices:
                if d.ip not in self._full_ports:
                    d.open_ports = []
            self._update_status()
            self._refresh_detail(force=True)

    def action_full_scan(self) -> None:
        if self._fullscan is not None:  # one already running -> second press cancels
            if self._fullscan_worker is not None:
                self._fullscan_worker.cancel()
            return
        dev = self._selected_device()
        if dev is None:
            self.notify("Select a device row first.", severity="warning")
            return
        self._fullscan_worker = self._run_full_scan(dev.ip)

    @work(exclusive=True, group="fullscan")
    async def _run_full_scan(self, ip: str) -> None:
        self._fullscan = (ip, 0, 65535)
        self.notify(f"Full-scanning {ip} — gentle, can take a while. Press f to cancel.",
                    title="Full scan")
        self._update_status()
        self._refresh_table()  # mark the scanning row (also refreshes the detail)

        def prog(done: int, total: int) -> None:
            self._fullscan = (ip, done, total)
            self._update_status()
            if self._selected_ip == ip:  # advance the in-pane % live
                self._refresh_detail()

        try:
            found = await ports.full_scan(ip, progress=prog)
        except asyncio.CancelledError:
            self.notify(f"Full scan of {ip} cancelled.", severity="warning")
            raise
        except Exception as exc:  # noqa: BLE001 - best-effort; never crash the TUI
            self.notify(f"Full scan of {ip} failed: {exc}", title="Full scan",
                        severity="error")
            return
        finally:
            self._fullscan = None
            self._fullscan_worker = None
            self._update_status()
            self._refresh_table()  # clear the "scanning…" marker on every exit path

        self._full_ports[ip] = found
        for d in self._devices:
            if d.ip == ip:
                d.open_ports = sorted(set(d.open_ports) | set(found))
        self._refresh_table()
        shown = ", ".join(map(str, found[:15])) + (" …" if len(found) > 15 else "")
        self.notify(f"{ip}: {len(found)} open ports — {shown or 'none'}",
                    title="Full scan done")

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self._update_status()

    def action_cycle_kind(self) -> None:
        self._kind = _KIND_CYCLE[self._kind]
        self._known.clear()  # filter changed; don't flag everything as "new"
        self._scanned_once = False
        self._devices = []   # drop stale rows/selection so the placeholder shows now
        self._selected_ip = None
        self._new = set()
        self._refresh_table()
        self._update_status()
        self._trigger_scan()


def run_tui(args) -> int:
    LanScanApp(args).run()
    return 0
