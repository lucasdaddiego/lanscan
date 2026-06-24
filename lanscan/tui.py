"""Live Textual TUI for the LAN scanner.

A table that refreshes on an interval, runs mDNS continuously in the background,
re-discovers interfaces every cycle (so a plugged-in Ethernet adapter appears on
its own), and highlights devices that are new since the last sweep.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Header, Static

from . import net, ports
from .engine import scan
from .models import Device

_KIND_CYCLE = {None: "wifi", "wifi": "ethernet", "ethernet": None}
_COLUMNS = ("", "IP", "Name", "Vendor", "MAC", "Ports", "Services", "If", "Via")


class LanScanApp(App):
    CSS = """
    Screen { layers: base; }
    #status { height: 1; padding: 0 1; color: $text-muted; background: $panel; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        ("r", "rescan", "Rescan"),
        ("e", "export", "Export"),
        ("o", "toggle_ports", "Ports on/off"),
        ("f", "full_scan", "Full-scan device"),
        ("p", "toggle_pause", "Pause/Resume"),
        ("a", "cycle_kind", "Wi-Fi/Eth/All"),
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

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("starting…", id="status")
        table = DataTable(id="devices", zebra_stripes=True, cursor_type="row")
        table.add_columns(*_COLUMNS)
        yield table
        yield Footer()

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

    # ---- rendering ------------------------------------------------------
    def _refresh_table(self) -> None:
        table = self.query_one("#devices", DataTable)
        table.clear()
        for d in self._devices:
            is_new = d.ip in self._new
            marker = Text("●", style="bold green") if is_new else Text(" ")
            ip = Text(d.ip, style="bold cyan" if is_new else "cyan")
            name = Text(d.name or "—", style="" if d.name else "dim")
            if d.tags:
                name.append(f"  ({', '.join(d.tags)})", style="dim")
            if d.vendor:
                vendor = Text(d.vendor)
            elif d.randomized_mac:
                vendor = Text("private MAC", style="yellow")
            else:
                vendor = Text("?", style="dim")
            svcs = ", ".join(d.services[:4])
            if len(d.services) > 4:
                svcs += f" +{len(d.services) - 4}"
            if d.open_ports:
                shown = ", ".join(str(p) for p in d.open_ports[:8])
                if len(d.open_ports) > 8:
                    shown += f" +{len(d.open_ports) - 8}"
                ports_cell = Text(shown, style="green")
            else:
                ports_cell = Text("—", style="dim")
            table.add_row(marker, ip, name, vendor,
                          Text(d.mac or "—", style="dim" if not d.mac else ""),
                          ports_cell, Text(svcs),
                          Text(d.interface, style="dim"), Text(d.via, style="dim"))

    def _update_status(self) -> None:
        try:
            status = self.query_one("#status", Static)
        except Exception:  # noqa: BLE001 - not mounted yet
            return
        scope = {None: "All", "wifi": "Wi-Fi", "ethernet": "Ethernet"}[self._kind]
        nets = "  ".join(f"{i.label} {i.cidr}" for i in self._ifaces) or "no active interface"
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
            state = f"{len(self._devices)} devices · last {when} · auto {self.args.interval:g}s"
        extra = f" · {len(self._new)} new" if self._new else ""
        if not self._ports:
            extra += " · ports off"
        if self._fullscan:
            fip, fdone, ftotal = self._fullscan
            extra += f" · full-scan {fip} {100 * fdone // ftotal}%"
        status.update(f"{left}    {state}{extra}")

    # ---- actions --------------------------------------------------------
    def action_rescan(self) -> None:
        self._trigger_scan()

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
        self.notify(f"{len(self._devices)} devices → {path}", title="Exported")

    def action_toggle_ports(self) -> None:
        self._ports = not self._ports
        self.notify(f"Port scan {'on' if self._ports else 'off'}.")
        self._trigger_scan()

    def _selected_device(self) -> Device | None:
        table = self.query_one("#devices", DataTable)
        row = table.cursor_row
        if row is None or not (0 <= row < len(self._devices)):
            return None
        return self._devices[row]

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

        def prog(done: int, total: int) -> None:
            self._fullscan = (ip, done, total)
            self._update_status()

        try:
            found = await ports.full_scan(ip, progress=prog)
        except asyncio.CancelledError:
            self.notify(f"Full scan of {ip} cancelled.", severity="warning")
            raise
        finally:
            self._fullscan = None
            self._fullscan_worker = None
            self._update_status()

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
        self._trigger_scan()


def run_tui(args) -> int:
    LanScanApp(args).run()
    return 0
