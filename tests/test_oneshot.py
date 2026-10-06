"""Tests for lanscan.oneshot — the headless `--once [--json]` mode."""
import io
import json

import pytest
from conftest import make_args

from lanscan import __version__, oneshot
from lanscan.models import Device, Interface


def _iface() -> Interface:
    return Interface(device="en0", port="Wi-Fi", kind="wifi", ipv4="192.168.0.10",
                     prefix=24, cidr="192.168.0.0/24", mac="A0:BB:CC:DD:EE:F0")


def _devices() -> list[Device]:
    return [
        Device(ip="192.168.0.1", mac="A0:BB:CC:DD:EE:F1", vendor="Acme", mdns_name="Router",
               open_ports=[22, 80, 443], is_gateway=True),
        Device(ip="192.168.0.2", mac="12:BB:CC:DD:EE:F2", randomized_mac=True,
               http_title="A very long web title that will not fit the column"),
        Device(ip="192.168.0.10", mac="A0:BB:CC:DD:EE:F0", is_self=True),
        Device(ip="192.168.0.11", hostname="tv\x1b[2J.local"),  # unsanitized by a fake
    ]


class FakeMdns:
    instances: list[FakeMdns] = []

    def __init__(self, *, fail=False):
        self.fail = fail
        self.started = self.stopped = False
        FakeMdns.instances.append(self)

    async def start(self):
        if self.fail:
            raise OSError("no multicast")
        self.started = True

    async def stop(self):
        self.stopped = True


@pytest.fixture
def mocks(monkeypatch):
    """Everything that touches the OS/network/disk, recorded for assertions."""
    calls = {"scan": [], "saved": [], "preload": 0}
    monkeypatch.setattr(oneshot.net, "discover_interfaces", lambda **kw: [_iface()])

    async def fake_preload():
        calls["preload"] += 1

    monkeypatch.setattr(oneshot.vendors, "preload", fake_preload)

    async def fake_scan(ifaces, **kw):
        calls["scan"].append(kw)
        return _devices()

    monkeypatch.setattr(oneshot, "scan", fake_scan)
    monkeypatch.setattr(oneshot.history, "load", lambda: {"A0:BB:CC:DD:EE:F1": {
        "first_seen": 5.0, "last_seen": 6.0, "name": "Old"}})
    monkeypatch.setattr(oneshot.history, "save", lambda records: calls["saved"].append(records))
    monkeypatch.setattr(oneshot, "MDNS_WARMUP", 0)
    FakeMdns.instances.clear()
    monkeypatch.setattr("lanscan.discovery.MdnsDiscovery", FakeMdns)
    return calls


def _run(args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    rc = oneshot.run_once(args, out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def test_table_output(mocks):
    rc, out, err = _run(make_args(once=True, json=False, no_history=False))
    assert rc == 0 and err == ""
    lines = out.splitlines()
    assert lines[0].split() == ["IP", "MAC", "VENDOR", "NAME", "PORTS"]
    assert lines[1].startswith("192.168.0.1 ") and "Acme" in lines[1]
    assert "Router (router)" in lines[1] and lines[1].endswith("22,80,443")
    assert "private MAC" in lines[2] and "A very long web title that wi…" in lines[2]
    assert "(self)" in lines[3] and "?" in lines[3]
    assert lines[1].endswith("22,80,443")
    # flags are forwarded to the engine (make_args defaults: mdns/ports/ssdp/http off)
    kw = mocks["scan"][0]
    assert kw["mdns"] is None and kw["scan_ports"] is False and kw["ssdp_enabled"] is False
    assert kw["http_id"] is False and kw["resolve"] is True and kw["timeout"] == 1.0
    assert mocks["preload"] == 1
    # history: merged and saved (make_args defaults to --no-history; off here)
    assert len(mocks["saved"]) == 1 and "A0:BB:CC:DD:EE:F1" in mocks["saved"][0]


def test_json_output_is_versioned_timestamped_and_sanitized(mocks):
    rc, out, err = _run(make_args(once=True, json=True, no_history=True))
    assert rc == 0 and err == ""
    doc = json.loads(out)
    assert doc["version"] == __version__
    assert len(doc["ts"]) == 20 and doc["ts"].endswith("Z") and doc["ts"][10] == "T"
    assert doc["interfaces"][0]["device"] == "en0"
    by_ip = {d["ip"]: d for d in doc["devices"]}
    assert by_ip["192.168.0.1"]["tags"] == ["router"]
    assert by_ip["192.168.0.1"]["ever_seen"] is False      # --no-history: nothing remembered
    assert by_ip["192.168.0.11"]["hostname"] == "tv·[2J.local"   # export is sanitized
    assert mocks["saved"] == []                             # and nothing written


def test_history_is_merged_into_the_output(mocks):
    rc, out, _ = _run(make_args(once=True, json=True, no_history=False))
    assert rc == 0
    router = next(d for d in json.loads(out)["devices"] if d["ip"] == "192.168.0.1")
    assert router["ever_seen"] is True and router["first_seen"] == 5.0


def test_mdns_is_started_warmed_up_and_stopped(mocks):
    rc, _, _ = _run(make_args(once=True, json=False, no_mdns=False))
    assert rc == 0
    (md,) = FakeMdns.instances
    assert md.started and md.stopped
    assert mocks["scan"][0]["mdns"] is md


def test_mdns_failure_degrades_to_no_mdns(mocks, monkeypatch):
    monkeypatch.setattr("lanscan.discovery.MdnsDiscovery", lambda: FakeMdns(fail=True))
    rc, _, _ = _run(make_args(once=True, json=False, no_mdns=False))
    assert rc == 0
    assert mocks["scan"][0]["mdns"] is None


def test_mdns_is_stopped_when_the_scan_fails(mocks, monkeypatch):
    async def boom(ifaces, **kw):
        raise RuntimeError("sweep exploded")

    monkeypatch.setattr(oneshot, "scan", boom)
    rc, out, err = _run(make_args(once=True, json=False, no_mdns=False))
    assert rc == 1 and out == ""
    assert "lanscan: scan failed: sweep exploded" in err
    assert FakeMdns.instances[0].stopped


def test_no_interface_exits_3(mocks, monkeypatch):
    monkeypatch.setattr(oneshot.net, "discover_interfaces", lambda **kw: [])
    rc, out, err = _run(make_args(once=True, json=True))
    assert rc == 3 and out == ""
    assert "no active Wi-Fi/Ethernet interface" in err
    assert mocks["scan"] == []


def test_cell_pads_and_truncates():
    assert oneshot._cell("ab", 4) == "ab  "
    assert oneshot._cell("abcdef", 4) == "abc…"
