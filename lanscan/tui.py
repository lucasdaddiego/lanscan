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
from textual.widgets import DataTable, Footer, Header, Label, OptionList, Static
from textual.widgets.option_list import Option

from . import launch, net, ports
from .engine import scan
from .models import Device

_KIND_CYCLE = {None: "wifi", "wifi": "ethernet", "ethernet": None}

# Compact master columns; everything wide lives in the detail pane.
_COLUMNS = (
    ("", 2),       # status dot
    ("IP", 16),    # always shown
    ("Name", 22),  # friendly name (+ role), blank when unknown
)

# Theme $vars resolve in Textual CSS, NOT inside raw rich style strings — so
# every rich renderable below uses concrete colour names from here.
PAL = {
    "ip": "cyan", "ip_new": "bold cyan", "new": "bold green",
    "router": "yellow", "self": "cyan", "ok": "green", "svc": "magenta",
    "warn": "yellow", "muted": "grey50", "label": "grey50", "head": "bold white",
}
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
            line = Text()
            line.append(f"{port:>5}  ", style="green")
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
        ports.raise_fd_limit()
        if not self.args.no_mdns:
            try:
                from .discovery import MdnsDiscovery
                self._mdns = MdnsDiscovery()
                await self._mdns.start()
            except Exception:  # noqa: BLE001 - mDNS is optional
                self._mdns = None
        self.set_interval(self.args.interval, self._trigger_scan)
        self.set_timer(1.2, self._trigger_scan)  # first scan after brief mDNS warmup
        self._update_status()
        self._refresh_detail()  # show the "Scanning…" placeholder up front

    async def on_unmount(self) -> None:
        if self._mdns is not None:
            await self._mdns.stop()

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
                scan_ports=self._ports, timeout=self.args.timeout,
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
            tuple(dev.open_ports), tuple(dev.services),
            dev.ip in self._new, dev.ip in self._full_ports, fs, int(dev.last_seen),
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
            glyph, title, sub = "◐", "Scanning your network…", f"discovering devices on {scope}"
        elif not self._devices:
            glyph, title, sub = "○", "No devices found", "press a to widen scope · r to rescan"
        else:
            glyph, title, sub = "←", "Select a device", "pick a row on the left"
        body = Group(
            Text(""),
            Text(glyph, style="bold cyan", justify="center"),
            Text(""),
            Text(title, style="bold", justify="center"),
            Text(sub, style="grey50", justify="center"),
        )
        return Align.center(body, vertical="middle")

    def _detail_renderable(self, dev: Device | None):
        if dev is None:
            return self._placeholder()

        is_new = dev.ip in self._new
        blocks = []

        title = Text()
        title.append("● " if is_new else "· ", style=PAL["new"] if is_new else "dim")
        title.append(dev.ip, style=PAL["ip_new"] if is_new else "bold")
        for tag in dev.tags:
            title.append("  ")
            if tag == "router":
                title.append(" ROUTER ", style="reverse yellow")
            elif tag == "self":
                title.append(" THIS MAC ", style="reverse cyan")
        blocks.append(title)

        def section(name, body, *, suffix=""):
            head = Text(name, style=PAL["head"])
            if suffix:
                head.append(f"  · {suffix}", style="dim")
            return Group(head, body)

        # IDENTITY
        ident = _kv()
        ident.add_row("Name", _val(dev.name))
        if dev.mdns_name:
            ident.add_row("mDNS", Text(dev.mdns_name))
        if dev.hostname:
            ident.add_row("Host", Text(dev.hostname.rstrip(".")))
        if dev.vendor:
            ven = Text(dev.vendor)
        elif dev.randomized_mac:
            ven = Text("private MAC", style=PAL["warn"])
        else:
            ven = Text("unknown", style="dim")
        ident.add_row("Vendor", ven)
        blocks.append(section("IDENTITY", ident))

        # NETWORK
        netg = _kv()
        netg.add_row("IP", Text(dev.ip, style="cyan"))
        if dev.mac:
            mac = Text(dev.mac)
            if dev.randomized_mac:
                mac.append("  ")
                mac.append(" randomized ", style="reverse yellow")
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
                    pt.add_row(Text(f"{p:>5}", style="green"),
                               Text(name or "?", style="" if name else "dim"))
            elif scanning_here:
                pt.add_row("", Text("no open ports yet", style="dim"))
            else:
                pt.add_row("", Text("no open ports", style="dim"))
            blocks.append(section("PORTS", pt, suffix=suffix))

        # SERVICES
        if dev.services:
            chips = Columns([Text(f" {s} ", style="reverse magenta") for s in dev.services],
                            padding=(0, 1), expand=False)
            blocks.append(section("SERVICES", chips))

        # ACTIVITY
        act = _kv()

        def ts(v):
            return time.strftime("%H:%M:%S", time.localtime(v)) if v else DASH
        act.add_row("First", Text(ts(dev.first_seen)))
        act.add_row("Last", Text(ts(dev.last_seen)))
        if dev.last_seen:
            age = max(0, int(time.time() - dev.last_seen))
            rel = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            act.add_row("Seen", Text(rel, style="dim"))
        if is_new:
            act.add_row("New", Text("yes", style="green"))
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
        left = f"[{scope}] {nets}"
        if self._scanning:
            done, total = self._progress
            if total and done >= total:
                state = "scanning ports…" if self._ports else "identifying…"
            elif total:
                state = f"scanning {done}/{total}…"
            else:
                state = "scanning…"
        elif self._paused:
            state = "paused (p to resume)"
        else:
            when = time.strftime("%H:%M:%S", time.localtime(self._last_scan)) if self._last_scan else "—"
            n = len(self._devices)
            state = f"{n} device{'s' if n != 1 else ''} · last {when} · auto {self.args.interval:g}s"
        extra = f" · {len(self._new)} new" if self._new else ""
        if not self._ports:
            extra += " · ports off"
        if self._fullscan:
            fip, fdone, ftotal = self._fullscan
            extra += f" · full-scan {fip} {100 * fdone // ftotal if ftotal else 0}%"
        status.update(f"{left}    {state}{extra}")

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
