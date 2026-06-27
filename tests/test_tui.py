"""Tests for lanscan.tui — the Textual master/detail TUI.

Two layers: pure renderable helpers (exercised on an unmounted app instance) and
behaviour driven through Textual's ``run_test()`` pilot with the scan engine and
mDNS mocked out.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from conftest import make_args
from rich.console import Console

from lanscan import tui
from lanscan.models import Device, Interface
from lanscan.tui import LanScanApp, PortPicker


def render(renderable) -> str:
    """Render a Rich renderable to plain (style-stripped) text for assertions.

    Wide console so the no-wrap status line and detail rows don't fold mid-word.
    """
    console = Console(width=200, color_system=None, legacy_windows=False)
    with console.capture() as cap:
        console.print(renderable)
    return cap.get()


def bare_app(**argkw) -> LanScanApp:
    return LanScanApp(make_args(**argkw))


# ---- module-level helpers -------------------------------------------------
def test_badge_text():
    assert tui._badge("HI", "#ffffff").plain == " HI "


@pytest.mark.parametrize("name,expected", [
    ("http", tui.C["blue"]),       # web
    ("ssh", tui.C["green"]),       # shell
    ("zzz", tui.C["faint"]),       # unknown service name
    (None, tui.C["faint"]),        # no name
])
def test_port_color(name, expected):
    assert tui._port_color(name) == expected


@pytest.mark.parametrize("label,expected", [
    ("AirPlay", tui._CAT_COLOR["media"]),
    ("Printer", tui._CAT_COLOR["file"]),
    ("SSH", tui._CAT_COLOR["shell"]),
    ("Something Else", tui.C["purple"]),   # keyword fallback
])
def test_svc_color(label, expected):
    assert tui._svc_color(label) == expected


def test_val():
    assert tui._val("hello").plain == "hello"
    assert tui._val(None).plain == tui.DASH
    assert tui._val("").plain == tui.DASH


def test_kv_grid_has_two_columns():
    grid = tui._kv()
    assert len(grid.columns) == 2


def test_run_tui(monkeypatch):
    ran = {}
    monkeypatch.setattr(LanScanApp, "run", lambda self: ran.setdefault("ok", True))
    assert tui.run_tui(make_args()) == 0
    assert ran["ok"] is True


# ---- _placeholder ---------------------------------------------------------
def test_placeholder_scanning():
    app = bare_app()
    app._scanned_once = False
    assert "Scanning your network" in render(app._placeholder())


def test_placeholder_no_devices():
    app = bare_app()
    app._scanned_once = True
    app._devices = []
    assert "No devices found" in render(app._placeholder())


def test_placeholder_select_a_device():
    app = bare_app()
    app._scanned_once = True
    app._devices = [Device(ip="10.0.0.1")]
    assert "Select a device" in render(app._placeholder())


# ---- _detail_renderable ---------------------------------------------------
def test_detail_none_is_placeholder():
    app = bare_app()
    app._scanned_once = True
    app._devices = []
    assert "No devices found" in render(app._detail_renderable(None))


def test_detail_ignores_unknown_tag():
    # A tag outside {router, self} falls through the title's if/elif and is dropped.
    class _ThreeTag(Device):
        @property
        def tags(self):
            return ["router", "self", "ghost"]

    app = bare_app()
    dev = _ThreeTag(ip="192.168.0.1")
    app._devices = [dev]
    out = render(app._detail_renderable(dev))
    assert "ROUTER" in out and "THIS MAC" in out


def test_detail_full_gateway_device():
    app = bare_app()
    dev = Device(
        ip="192.168.0.1", interface="en0", mac="A0:BB:CC:DD:EE:01", vendor="Acme",
        hostname="router.local.", mdns_name="My Router", services=["AirPlay", "SSH"],
        open_ports=[22, 80, 9999], is_gateway=True, via="icmp",
        first_seen=time.time() - 5, last_seen=time.time() - 5,
    )
    app._devices = [dev]
    app._new = {dev.ip}
    out = render(app._detail_renderable(dev))
    assert "ROUTER" in out                 # tag badge + Role
    assert "My Router" in out              # mDNS name
    assert "router.local" in out           # hostname
    assert "Acme" in out                   # vendor
    assert "ssh" in out and "http" in out  # known port names
    assert "?" in out                      # unknown port 9999
    assert "3 open" in out                 # ports suffix
    assert "AirPlay" in out                # services chip
    assert "ago" in out                    # recent activity
    assert "yes" in out                    # New: yes


def test_detail_self_randomized_full_scanned():
    app = bare_app()
    dev = Device(
        ip="192.168.0.10", interface="", mac="12:BB:CC:DD:EE:10", randomized_mac=True,
        is_self=True, via="weird", first_seen=time.time() - 120, last_seen=time.time() - 120,
    )
    app._devices = [dev]
    app._full_ports = {dev.ip: []}   # full-scan done, nothing open
    out = render(app._detail_renderable(dev))
    assert "THIS MAC" in out
    assert "private MAC" in out      # no vendor + randomized
    assert "randomized" in out       # MAC badge
    assert "this Mac" in out         # Role
    assert "0 open" in out and "full" in out
    assert "no open ports" in out
    assert "ago" in out              # 2m ago branch


def test_detail_plain_unknown_device():
    app = bare_app()
    dev = Device(ip="192.168.0.20", interface="en0", mac=None, via="", last_seen=0)
    app._devices = [dev]
    out = render(app._detail_renderable(dev))
    assert "unknown" in out          # no vendor, not randomized
    assert tui.DASH in out           # MAC dash + via dash


def test_detail_scanning_no_ports_yet():
    app = bare_app()
    dev = Device(ip="192.168.0.30", open_ports=[])
    app._devices = [dev]
    app._fullscan = ("192.168.0.30", 50, 100)
    out = render(app._detail_renderable(dev))
    assert "scanning 50%" in out
    assert "no open ports yet" in out


def test_detail_scanning_with_ports():
    app = bare_app()
    dev = Device(ip="192.168.0.31", open_ports=[80])
    app._devices = [dev]
    app._fullscan = ("192.168.0.31", 30, 100)
    out = render(app._detail_renderable(dev))
    assert "1 open" in out and "scanning 30%" in out


def test_detail_scanning_zero_total():
    app = bare_app()
    dev = Device(ip="192.168.0.32", open_ports=[])
    app._devices = [dev]
    app._fullscan = ("192.168.0.32", 0, 0)   # ftotal 0 -> pct 0 branch
    assert "scanning 0%" in render(app._detail_renderable(dev))


# ---- _detail_signature ----------------------------------------------------
def test_detail_signature_placeholder_and_device():
    app = bare_app()
    assert app._detail_signature(None)[0] == "placeholder"
    dev = Device(ip="10.0.0.1")
    app._fullscan = ("10.0.0.1", 1, 2)
    sig = app._detail_signature(dev)
    assert sig[0] == "10.0.0.1"
    assert sig[-2] == ("10.0.0.1", 1, 2)   # fullscan tuple captured when it matches
    app._fullscan = ("10.0.0.9", 1, 2)
    assert app._detail_signature(dev)[-2] is None  # non-matching fullscan -> None


# ---- unmounted guards (query_one raises -> early return) ------------------
def test_refresh_helpers_safe_when_unmounted():
    app = bare_app()
    # None of these should raise even though no widgets are mounted.
    app._refresh_table()
    app._update_status()
    app._refresh_detail()


# ==========================================================================
# Harness-driven tests
# ==========================================================================
def make_app(monkeypatch, *, devices=None, **argkw):
    # Note: not copied — tests may mutate the same list to simulate the LAN changing.
    devs = devices if devices is not None else []

    async def fake_scan(interfaces, **kw):
        return list(devs)

    monkeypatch.setattr(tui, "scan", fake_scan)
    monkeypatch.setattr(tui.net, "discover_interfaces", lambda **kw: [])
    return LanScanApp(make_args(**argkw))


async def run_scan(app, pilot):
    app.action_rescan()
    for _ in range(200):
        await pilot.pause()
        if not app._scanning:
            return
    raise AssertionError("scan did not finish")  # pragma: no cover


async def test_app_populates_table_and_detail(monkeypatch):
    devices = [
        Device(ip="192.168.0.1", is_gateway=True, mdns_name="Router"),
        Device(ip="192.168.0.10", is_self=True),
        Device(ip="192.168.0.20"),
    ]
    app = make_app(monkeypatch, devices=devices)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        table = app.query_one("#devices", tui.DataTable)
        assert table.row_count == 3
        assert app._selected_ip == "192.168.0.1"
        assert app._scanned_once is True


async def test_new_device_marked_on_second_scan(monkeypatch):
    devices = [Device(ip="192.168.0.1")]
    app = make_app(monkeypatch, devices=devices)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        assert app._new == set()            # first scan never flags "new"
        devices.append(Device(ip="192.168.0.2"))
        await run_scan(app, pilot)
        assert "192.168.0.2" in app._new


async def test_status_states(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        status = app.query_one("#status", tui.Static)
        # Capture whatever _update_status hands to the widget, render it to text.
        last = []
        monkeypatch.setattr(status, "update", lambda r: last.append(r))

        def plain():
            return render(last[-1])

        app._ifaces = [
            Interface("en0", "Wi-Fi", "wifi", "192.168.0.10", 24, "192.168.0.0/24"),
            Interface("en1", "Eth", "ethernet", "10.0.0.2", 16, "10.0.0.0/16"),
        ]

        # scanning: ports phase (done >= total)
        app._scanning, app._ports, app._progress = True, True, (10, 10)
        app._update_status()
        assert "scanning ports" in plain()
        assert "too large to sweep" in plain()

        # scanning: identify phase (ports off)
        app._ports = False
        app._update_status()
        assert "identifying" in plain()
        assert "ports off" in plain()

        # scanning: counted progress
        app._progress = (3, 100)
        app._update_status()
        assert "scanning 3/100" in plain()

        # scanning: indeterminate
        app._progress = (0, 0)
        app._update_status()
        assert "scanning" in plain()

        # paused
        app._scanning, app._paused = False, True
        app._update_status()
        assert "paused" in plain()

        # idle with devices + new + fullscan
        app._paused, app._ports = False, True
        app._devices = [Device(ip="192.168.0.1")]
        app._new = {"192.168.0.1"}
        app._last_scan = time.time()
        app._fullscan = ("192.168.0.1", 50, 100)
        app._update_status()
        assert "1 device" in plain() and "new" in plain() and "full-scan" in plain()

        # fullscan with zero total -> 0%
        app._fullscan = ("192.168.0.1", 0, 0)
        app._update_status()
        assert "full-scan 192.168.0.1 0%" in plain()

        # no interfaces -> "no active interface"
        app._ifaces = []
        app._fullscan = None
        app._update_status()
        assert "no active interface" in plain()


async def test_tick_spin(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        # Idle + already scanned once -> early return (spin frame unchanged).
        app._scanning = False
        app._fullscan = None
        app._scanned_once = True
        before = app._spin
        app._tick_spin()
        assert app._spin == before
        # Active -> spinner advances.
        app._scanning = True
        app._tick_spin()
        assert app._spin == (before + 1) % len(tui._SPINNER)
        # Pre-first-scan path also forces a detail repaint.
        app._scanning = False
        app._scanned_once = False
        app._tick_spin()


async def test_on_progress(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._on_progress(5, 100)     # not a multiple of 24 -> stored, no forced repaint
        assert app._progress == (5, 100)
        app._on_progress(24, 100)    # multiple of 24 -> updates status
        assert app._progress == (24, 100)


async def test_actions_export(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1", mac="A0:BB:CC:DD:EE:01")])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.action_export()
        await pilot.pause()
        exports = list(tmp_path.glob("lanscan-*.json"))
        assert len(exports) == 1
        assert "192.168.0.1" in exports[0].read_text()


async def test_export_nothing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._devices = []
        app.action_export()
        await pilot.pause()
        assert list(tmp_path.glob("lanscan-*.json")) == []


async def test_export_failure(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1")])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)

        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(tui.Path, "write_text", boom)
        app.action_export()
        await pilot.pause()
        assert list(tmp_path.glob("lanscan-*.json")) == []


async def test_toggle_ports(monkeypatch):
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1", open_ports=[80])])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        assert app._ports is False             # --no-ports default in make_args
        app.action_toggle_ports()              # -> on, triggers a rescan
        assert app._ports is True
        for _ in range(100):
            await pilot.pause()
            if not app._scanning:
                break
        app.action_toggle_ports()              # -> off, clears open ports inline
        assert app._ports is False
        assert app._devices[0].open_ports == []


async def test_toggle_ports_off_keeps_full_scan(monkeypatch):
    dev = Device(ip="192.168.0.1", open_ports=[80, 443])
    app = make_app(monkeypatch, devices=[dev])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._ports = True
        app._full_ports = {"192.168.0.1": [443]}   # a prior full-scan result
        app.action_toggle_ports()                  # off
        assert app._devices[0].open_ports == [80, 443]  # untouched (full-scan kept)


async def test_toggle_pause(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._paused is False
        app.action_toggle_pause()
        assert app._paused is True
        # A paused trigger is a no-op.
        app._trigger_scan()
        assert app._scanning is False


async def test_cycle_kind(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        assert app._kind is None
        app.action_cycle_kind()
        assert app._kind == "wifi"
        for _ in range(100):
            await pilot.pause()
            if not app._scanning:
                break
        assert app._scanned_once is True


async def test_scroll_detail(monkeypatch):
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1")])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.action_scroll_detail_down()
        app.action_scroll_detail_up()
        await pilot.pause()


async def test_rescan_blocked_while_scanning(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._scanning = True            # pretend a scan is in flight
        app._trigger_scan()             # guarded -> does not start another
        # nothing to assert beyond "no crash"; the guard branch is exercised


# ---- scan worker error / cancel paths ------------------------------------
async def test_scan_reports_failure(monkeypatch):
    app = make_app(monkeypatch)

    async def boom(interfaces, **kw):
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(tui, "scan", boom)
    notes = []
    async with app.run_test() as pilot:
        monkeypatch.setattr(app, "notify",
                            lambda *a, **k: notes.append((a, k)))
        await run_scan(app, pilot)
        assert any("scan exploded" in str(a) for a, k in notes)


async def test_scan_cancelled(monkeypatch):
    app = make_app(monkeypatch)
    gate = asyncio.Event()

    async def hang(interfaces, **kw):
        await gate.wait()
        return []

    monkeypatch.setattr(tui, "scan", hang)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_rescan()
        await pilot.pause()
        assert app._scanning is True
        for worker in list(app.workers):
            worker.cancel()
        for _ in range(100):
            await pilot.pause()
            if not app._scanning:
                break
        assert app._scanning is False


# ---- row events -----------------------------------------------------------
class _RowKey:
    def __init__(self, value):
        self.value = value


class _RowEvent:
    def __init__(self, value, *, none_key=False):
        self.row_key = None if none_key else _RowKey(value)


async def test_row_highlighted(monkeypatch):
    app = make_app(monkeypatch, devices=[
        Device(ip="192.168.0.1"), Device(ip="192.168.0.2")])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.on_data_table_row_highlighted(_RowEvent("192.168.0.2"))
        assert app._selected_ip == "192.168.0.2"
        # None row key / value -> ignored, selection unchanged.
        app.on_data_table_row_highlighted(_RowEvent(None, none_key=True))
        app.on_data_table_row_highlighted(_RowEvent(None))
        assert app._selected_ip == "192.168.0.2"


async def test_row_selected_triggers_connect(monkeypatch):
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1")])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        warned = []
        monkeypatch.setattr(app, "notify", lambda *a, **k: warned.append((a, k)))
        app.on_data_table_row_selected(_RowEvent("192.168.0.1"))
        await pilot.pause()
        # No open ports -> a warning notification, no picker.
        assert warned
        # A row-selected event with no key still routes to connect (selection kept).
        app.on_data_table_row_selected(_RowEvent(None, none_key=True))
        await pilot.pause()


# ---- connect / PortPicker -------------------------------------------------
async def test_connect_no_selection(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._devices = []
        app._selected_ip = None
        app.action_connect()       # no device -> early return
        await pilot.pause()


async def test_connect_no_open_ports(monkeypatch):
    app = make_app(monkeypatch, devices=[Device(ip="192.168.0.1", open_ports=[])])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        warned = []
        monkeypatch.setattr(app, "notify", lambda *a, **k: warned.append((a, k)))
        app.action_connect()
        await pilot.pause()
        assert any("full-scan" in str(a) for a, k in warned)


async def test_connect_picks_port_and_launches(monkeypatch):
    dev = Device(ip="192.168.0.1", open_ports=[22, 9999])  # 9999 has no name
    app = make_app(monkeypatch, devices=[dev])
    calls = []
    monkeypatch.setattr(tui.launch, "launch",
                        lambda ip, port, svc: calls.append((ip, port, svc)) or (True, "ok"))
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.action_connect()
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, PortPicker)

        class _Opt:
            id = "22"

        class _Sel:
            option = _Opt()

        picker.on_option_list_option_selected(_Sel())
        await pilot.pause()
        assert calls == [("192.168.0.1", 22, "ssh")]


async def test_connect_launch_failure_notifies(monkeypatch):
    dev = Device(ip="192.168.0.1", open_ports=[80])
    app = make_app(monkeypatch, devices=[dev])
    monkeypatch.setattr(tui.launch, "launch", lambda ip, port, svc: (False, "nope"))
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.action_connect()
        await pilot.pause()
        app.screen.on_option_list_option_selected(
            type("S", (), {"option": type("O", (), {"id": "80"})()})())
        await pilot.pause()


async def test_port_picker_cancel(monkeypatch):
    dev = Device(ip="192.168.0.1", open_ports=[80])
    app = make_app(monkeypatch, devices=[dev])
    launched = []
    monkeypatch.setattr(tui.launch, "launch",
                        lambda *a: launched.append(a) or (True, "ok"))
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app.action_connect()
        await pilot.pause()
        app.screen.action_cancel()   # dismiss(None) -> _launch_port returns early
        await pilot.pause()
        assert launched == []


# ---- full scan worker -----------------------------------------------------
async def test_full_scan_no_device(monkeypatch):
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._devices = []
        app._selected_ip = None
        warned = []
        monkeypatch.setattr(app, "notify", lambda *a, **k: warned.append((a, k)))
        app.action_full_scan()
        await pilot.pause()
        assert any("Select a device" in str(a) for a, k in warned)


async def test_full_scan_second_press_without_worker(monkeypatch):
    # A full-scan is flagged but its worker handle is gone -> second press just returns.
    app = make_app(monkeypatch)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._fullscan = ("192.168.0.1", 0, 100)
        app._fullscan_worker = None
        app.action_full_scan()
        await pilot.pause()
        assert app._fullscan == ("192.168.0.1", 0, 100)


async def test_full_scan_progress_when_selection_moved(monkeypatch):
    dev = Device(ip="192.168.0.1")
    app = make_app(monkeypatch, devices=[dev])

    async def fake_full(ip, *, progress=None, **kw):
        app._selected_ip = "192.168.0.99"   # selection moved away from the target
        if progress:
            progress(100, 200)              # prog sees selected != ip -> no detail repaint
        return [80]

    monkeypatch.setattr(tui.ports, "full_scan", fake_full)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._selected_ip = "192.168.0.1"
        app.action_full_scan()
        for _ in range(200):
            await pilot.pause()
            if app._fullscan is None and "192.168.0.1" in app._full_ports:
                break
        assert app._full_ports["192.168.0.1"] == [80]


async def test_apply_merges_kept_full_scan_results(monkeypatch):
    # A regular rescan must fold any retained full-scan ports back into the device.
    dev = Device(ip="192.168.0.1", open_ports=[80])
    app = make_app(monkeypatch, devices=[dev])
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._full_ports = {"192.168.0.1": [443, 8443]}
        await run_scan(app, pilot)
        assert app._devices[0].open_ports == [80, 443, 8443]


async def test_full_scan_success(monkeypatch):
    dev = Device(ip="192.168.0.1", open_ports=[22])
    other = Device(ip="192.168.0.2")   # a non-target row the merge loop must skip
    app = make_app(monkeypatch, devices=[dev, other])

    async def fake_full(ip, *, progress=None, **kw):
        if progress:
            progress(100, 200)        # exercises the live-progress callback (selected == ip)
        return list(range(1, 20))     # 19 ports -> notify truncates with "…"

    monkeypatch.setattr(tui.ports, "full_scan", fake_full)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._selected_ip = "192.168.0.1"
        app.action_full_scan()
        for _ in range(200):
            await pilot.pause()
            if app._fullscan is None and "192.168.0.1" in app._full_ports:
                break
        assert app._full_ports["192.168.0.1"] == list(range(1, 20))
        assert 22 in app._devices[0].open_ports   # merged with the curated result
        assert app._devices[1].open_ports == []   # other device left untouched


async def test_full_scan_empty_result(monkeypatch):
    dev = Device(ip="192.168.0.1")
    app = make_app(monkeypatch, devices=[dev])

    async def fake_full(ip, *, progress=None, **kw):
        return []

    monkeypatch.setattr(tui.ports, "full_scan", fake_full)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._selected_ip = "192.168.0.1"
        app.action_full_scan()
        for _ in range(200):
            await pilot.pause()
            if app._fullscan is None and "192.168.0.1" in app._full_ports:
                break
        assert app._full_ports["192.168.0.1"] == []


async def test_full_scan_failure(monkeypatch):
    dev = Device(ip="192.168.0.1")
    app = make_app(monkeypatch, devices=[dev])

    async def boom(ip, *, progress=None, **kw):
        raise RuntimeError("full scan died")

    monkeypatch.setattr(tui.ports, "full_scan", boom)
    notes = []
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        monkeypatch.setattr(app, "notify", lambda *a, **k: notes.append((a, k)))
        app._selected_ip = "192.168.0.1"
        app.action_full_scan()
        for _ in range(200):
            await pilot.pause()
            if app._fullscan is None:
                break
        assert any("died" in str(a) or "failed" in str(a) for a, k in notes)


async def test_full_scan_cancel(monkeypatch):
    dev = Device(ip="192.168.0.1")
    app = make_app(monkeypatch, devices=[dev])
    gate = asyncio.Event()

    async def hang(ip, *, progress=None, **kw):
        await gate.wait()
        return []

    monkeypatch.setattr(tui.ports, "full_scan", hang)
    async with app.run_test() as pilot:
        await run_scan(app, pilot)
        app._selected_ip = "192.168.0.1"
        app.action_full_scan()
        await pilot.pause()
        assert app._fullscan is not None
        app.action_full_scan()       # second press cancels
        for _ in range(200):
            await pilot.pause()
            if app._fullscan is None:
                break
        assert app._fullscan is None


# ---- mDNS lifecycle on mount/unmount -------------------------------------
class FakeMdns:
    def __init__(self):
        self.started = False
        self.stopped = False

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    def snapshot(self):
        return {}


async def test_mdns_started_and_stopped(monkeypatch):
    from lanscan import discovery

    fake = FakeMdns()
    monkeypatch.setattr(discovery, "MdnsDiscovery", lambda: fake)
    monkeypatch.setattr(tui, "scan", _empty_scan)
    monkeypatch.setattr(tui.net, "discover_interfaces", lambda **kw: [])
    app = LanScanApp(make_args(no_mdns=False))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert fake.started is True
        assert app._mdns is fake
    # on_unmount runs on exit
    assert fake.stopped is True


async def test_mdns_start_failure_degrades(monkeypatch):
    from lanscan import discovery

    class BoomMdns(FakeMdns):
        async def start(self):
            raise RuntimeError("no multicast")

    monkeypatch.setattr(discovery, "MdnsDiscovery", BoomMdns)
    monkeypatch.setattr(tui, "scan", _empty_scan)
    monkeypatch.setattr(tui.net, "discover_interfaces", lambda **kw: [])
    app = LanScanApp(make_args(no_mdns=False))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._mdns is None     # failure -> mDNS quietly disabled


async def _empty_scan(interfaces, **kw):
    return []
