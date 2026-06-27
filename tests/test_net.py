"""Tests for lanscan.net — interface discovery and subnet math.

All of macOS's `networksetup` / `route` / `ifconfig` shell-outs and `ifaddr`'s
adapter enumeration are mocked, so this runs anywhere.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from lanscan import net
from lanscan.models import Interface


def _run_returns(text):
    return lambda *a, **k: SimpleNamespace(stdout=text)


def _run_raises(exc):
    def _raise(*a, **k):
        raise exc
    return _raise


# ---- pure helpers ---------------------------------------------------------
@pytest.mark.parametrize("port,kind", [
    ("Wi-Fi", "wifi"),
    ("AirPort", "wifi"),
    ("Ethernet", "ethernet"),
    ("Thunderbolt Ethernet", "ethernet"),
    ("USB 10/100/1000 LAN", "ethernet"),
    ("Thunderbolt Bridge", None),
    ("Bluetooth PAN", None),
])
def test_classify(port, kind):
    assert net._classify(port) == kind


@pytest.mark.parametrize("device,virtual", [
    ("en0", False), ("bridge100", True), ("vmenet0", True), ("utun3", True),
    ("awdl0", True), ("llw0", True), ("anpi0", True), ("ap1", True), ("lo0", False),
])
def test_is_virtual_name(device, virtual):
    assert net._is_virtual_name(device) is virtual


@pytest.mark.parametrize("cidr,ok", [
    ("192.168.0.0/24", True),     # 256 addrs
    ("10.0.0.0/22", True),        # 1024 addrs (the boundary)
    ("10.0.0.0/16", False),       # too large
    ("not-a-cidr", False),        # ValueError
])
def test_sweepable(cidr, ok):
    assert net.sweepable(cidr) is ok


def test_broadcast_set_skips_bad_cidr():
    ifaces = [
        Interface("en0", "Wi-Fi", "wifi", "192.168.0.10", 24, "192.168.0.0/24"),
        Interface("en1", "Eth", "ethernet", "10.0.0.2", 24, "garbage"),
    ]
    assert net.broadcast_set(ifaces) == {"192.168.0.255"}


def test_hosts_for_skips_too_large_and_dedupes():
    ifaces = [
        Interface("en0", "Wi-Fi", "wifi", "192.168.0.10", 30, "192.168.0.0/30"),
        Interface("en1", "Eth", "ethernet", "192.168.0.20", 30, "192.168.0.0/30"),
        Interface("en2", "Big", "ethernet", "10.0.0.1", 8, "10.0.0.0/8"),
    ]
    hosts = net.hosts_for(ifaces)
    # /30 -> two usable hosts; the /8 is skipped entirely (not sweepable).
    assert hosts == {"192.168.0.1": "en0", "192.168.0.2": "en0"}


# ---- subprocess-backed parsers -------------------------------------------
_NETWORKSETUP = """\
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Thunderbolt Bridge
Device: bridge0

Hardware Port: Ethernet
Device:

Hardware Port: USB 10/100 LAN
Device: en5
Device: orphan
"""


def test_hardware_ports_parsing(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run", _run_returns(_NETWORKSETUP))
    ports = net._hardware_ports()
    assert ports == {"en0": ("Wi-Fi", "wifi"), "en5": ("USB 10/100 LAN", "ethernet")}


def test_hardware_ports_error(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run", _run_raises(OSError("boom")))
    assert net._hardware_ports() == {}


def test_default_gateway_match(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run",
                        _run_returns("   gateway: 192.168.0.1\n"))
    assert net.default_gateway() == "192.168.0.1"


def test_default_gateway_no_match(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run", _run_returns("no gateway here"))
    assert net.default_gateway() is None


def test_default_gateway_error(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run",
                        _run_raises(net.subprocess.SubprocessError()))
    assert net.default_gateway() is None


_IFCONFIG = """\
\tstray indented line before any header
en0: flags=8863<UP> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255
bridge100: flags=8863<UP> mtu 1500
\tmember: en1
\tinet 192.168.97.1 netmask 0xffffff00 broadcast 192.168.97.255
bridge101: flags=8863<UP> mtu 1500
\tinet 10.9.9.9 netmask zzzz broadcast 10.9.9.255
bridge102: flags=8863<UP> mtu 1500
\tinet 10.8.8.8
"""


def test_ifconfig_facts_parsing(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run", _run_returns(_IFCONFIG))
    members, virtual_subnets, macs = net._ifconfig_facts()
    assert members == {"en1"}
    assert macs == {"en0": "aa:bb:cc:dd:ee:ff"}
    # Only the cleanly-parsed virtual interface contributes a subnet; the bad-hex
    # netmask (ValueError) and the netmask-less inet (IndexError) are swallowed.
    assert virtual_subnets == {"192.168.97.0/24"}


def test_ifconfig_facts_error(monkeypatch):
    monkeypatch.setattr(net.subprocess, "run", _run_raises(OSError()))
    assert net._ifconfig_facts() == (set(), set(), {})


# ---- discover_interfaces (the orchestrator) -------------------------------
class _FakeIP:
    def __init__(self, ip, prefix, is_ipv4=True):
        self.ip = ip
        self.network_prefix = prefix
        self.is_IPv4 = is_ipv4


class _FakeAdapter:
    def __init__(self, name, ips):
        self.name = name
        self.ips = ips


@pytest.fixture
def fake_discovery(monkeypatch):
    ports = {
        "en0": ("Wi-Fi", "wifi"),
        "en3": ("Ethernet", "ethernet"),
        "bridge0": ("Weird", "ethernet"),   # virtual-named yet listed -> skipped
        "en1": ("Thunderbolt", "ethernet"),  # bridge member -> skipped
    }
    members = {"en1"}
    virtual_subnets = {"192.168.97.0/24"}
    monkeypatch.setattr(net, "_hardware_ports", lambda: ports)
    monkeypatch.setattr(net, "_ifconfig_facts",
                        lambda: (members, virtual_subnets, {"en0": "aa:bb:cc:dd:ee:ff"}))

    adapters = [
        _FakeAdapter("lo0", []),                       # not in ports -> skip
        _FakeAdapter("en1", [_FakeIP("192.168.1.5", 24)]),   # member -> skip
        _FakeAdapter("bridge0", [_FakeIP("192.168.2.5", 24)]),  # virtual -> skip
        _FakeAdapter("en0", [
            _FakeIP(("fe80::1",), 64, is_ipv4=False),   # not IPv4 -> skip
            _FakeIP(("x",), 24, is_ipv4=True),          # addr not str -> skip
            _FakeIP("169.254.1.1", 16),                 # link-local -> skip
            _FakeIP("192.168.0.10", 99),                # bad prefix (ValueError) -> skip
            _FakeIP("8.8.8.8", 24),                     # public -> skip
            _FakeIP("192.168.97.5", 24),                # virtual subnet -> skip
            _FakeIP("192.168.0.10", 24),                # keeper
        ]),
        _FakeAdapter("en3", [_FakeIP("10.0.0.2", 24)]),  # keeper (ethernet)
    ]
    monkeypatch.setattr(net.ifaddr, "get_adapters", lambda: adapters)
    return ports


def test_discover_interfaces_all(fake_discovery):
    ifaces = net.discover_interfaces()
    # Wi-Fi sorts first; only the two keepers survive every exclusion rule.
    assert [(i.device, i.kind, i.ipv4, i.cidr) for i in ifaces] == [
        ("en0", "wifi", "192.168.0.10", "192.168.0.0/24"),
        ("en3", "ethernet", "10.0.0.2", "10.0.0.0/24"),
    ]
    assert ifaces[0].mac == "aa:bb:cc:dd:ee:ff"  # merged from ifconfig
    assert ifaces[1].mac is None


def test_discover_interfaces_only_device(fake_discovery):
    ifaces = net.discover_interfaces(only_device="en0")
    assert [i.device for i in ifaces] == ["en0"]


def test_discover_interfaces_only_kind(fake_discovery):
    ifaces = net.discover_interfaces(only_kind="wifi")
    assert [i.device for i in ifaces] == ["en0"]
