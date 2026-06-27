"""Tests for lanscan.engine — the async liveness sweep + ARP/DNS/vendor merge.

The OS shell-outs (ping, arp) and all sockets are mocked, so the orchestration
logic is exercised without touching the network.
"""
from __future__ import annotations

import asyncio

import pytest

from lanscan import engine
from lanscan.models import Interface


class FakeWriter:
    def __init__(self, wait_exc=None):
        self.closed = False
        self._wait_exc = wait_exc

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self._wait_exc:
            raise self._wait_exc


class FakeProc:
    """Stand-in for an asyncio subprocess; `hang` makes the first wait() block."""
    def __init__(self, rc=0):
        self.rc = rc
        self.killed = False

    async def wait(self):
        return self.rc

    def kill(self):
        self.killed = True


def _exec_returning(proc):
    async def _exec(*args, **kw):
        return proc
    return _exec


# ---- _ping ----------------------------------------------------------------
@pytest.mark.parametrize("rc,alive", [(0, True), (1, False)])
async def test_ping_return_code(monkeypatch, rc, alive):
    monkeypatch.setattr(engine.asyncio, "create_subprocess_exec",
                        _exec_returning(FakeProc(rc=rc)))
    ip, ok = await engine._ping("10.0.0.9", 0.1, asyncio.Semaphore(2))
    assert ip == "10.0.0.9"
    assert ok is alive


async def test_ping_spawn_oserror(monkeypatch):
    async def _boom(*a, **k):
        raise OSError("no ping binary")

    monkeypatch.setattr(engine.asyncio, "create_subprocess_exec", _boom)
    assert await engine._ping("10.0.0.9", 0.1, asyncio.Semaphore(2)) == ("10.0.0.9", False)


async def test_ping_timeout_kills_proc(monkeypatch):
    proc = FakeProc(rc=0)
    monkeypatch.setattr(engine.asyncio, "create_subprocess_exec", _exec_returning(proc))

    async def fake_wait_for(awaitable, timeout):
        if asyncio.iscoroutine(awaitable):
            awaitable.close()  # avoid "coroutine never awaited"
        raise asyncio.TimeoutError

    monkeypatch.setattr(engine.asyncio, "wait_for", fake_wait_for)
    ip, ok = await engine._ping("10.0.0.9", 0.1, asyncio.Semaphore(2))
    assert (ip, ok) == ("10.0.0.9", False)
    assert proc.killed is True


# ---- _port_up -------------------------------------------------------------
async def test_port_up_true(monkeypatch):
    monkeypatch.setattr("asyncio.open_connection",
                        lambda h, p: _coro((object(), FakeWriter())))
    assert await engine._port_up("10.0.0.9", 80, 0.1) is True


async def test_port_up_wait_closed_oserror(monkeypatch):
    monkeypatch.setattr("asyncio.open_connection",
                        lambda h, p: _coro((object(), FakeWriter(wait_exc=OSError()))))
    assert await engine._port_up("10.0.0.9", 80, 0.1) is True


async def test_port_up_refused_counts_as_up(monkeypatch):
    monkeypatch.setattr("asyncio.open_connection",
                        lambda h, p: _raise_coro(ConnectionRefusedError()))
    assert await engine._port_up("10.0.0.9", 80, 0.1) is True


@pytest.mark.parametrize("exc", [asyncio.TimeoutError(), OSError()])
async def test_port_up_down(monkeypatch, exc):
    monkeypatch.setattr("asyncio.open_connection", lambda h, p: _raise_coro(exc))
    assert await engine._port_up("10.0.0.9", 80, 0.1) is False


async def _coro(value):
    return value


async def _raise_coro(exc):
    raise exc


# ---- _tcp_alive -----------------------------------------------------------
async def test_tcp_alive_any_port_up(monkeypatch):
    async def fake_port_up(ip, port, timeout):
        return port == engine._TCP_PORTS[-1]  # only the last probe answers

    monkeypatch.setattr(engine, "_port_up", fake_port_up)
    assert await engine._tcp_alive("10.0.0.9", 0.1, asyncio.Semaphore(4)) == ("10.0.0.9", True)


async def test_tcp_alive_all_down(monkeypatch):
    async def fake_port_up(ip, port, timeout):
        return False

    monkeypatch.setattr(engine, "_port_up", fake_port_up)
    assert await engine._tcp_alive("10.0.0.9", 0.1, asyncio.Semaphore(4)) == ("10.0.0.9", False)


# ---- _reverse_dns ---------------------------------------------------------
async def test_reverse_dns_success(monkeypatch):
    monkeypatch.setattr(engine.socket, "gethostbyaddr",
                        lambda ip: ("host.local", [], [ip]))
    assert await engine._reverse_dns("10.0.0.9", asyncio.Semaphore(4)) == ("10.0.0.9", "host.local")


async def test_reverse_dns_failure(monkeypatch):
    def _boom(ip):
        raise OSError("no PTR")

    monkeypatch.setattr(engine.socket, "gethostbyaddr", _boom)
    assert await engine._reverse_dns("10.0.0.9", asyncio.Semaphore(4)) == ("10.0.0.9", None)


# ---- read_arp -------------------------------------------------------------
_ARP_OUT = """\
? (192.168.0.1) at a:b:c:d:e:f on en0 ifscope [ethernet]
? (192.168.0.2) at (incomplete) on en0 ifscope [ethernet]
? (10.0.0.99) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 01:00:5e:00:00:fb on en0 ifscope [ethernet]
this line does not match the arp pattern at all
? (192.168.0.5) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.0.9) at 33:33:00:00:00:01 on en0 ifscope [ethernet]
? (192.168.0.7) at 1:2:3 on en0 ifscope [ethernet]
"""


def test_read_arp_filters(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(engine, "_is_linux", lambda: False)
    targets = {f"192.168.0.{n}": "en0" for n in (1, 2, 5, 7, 9)}
    targets["224.0.0.251"] = "en0"
    monkeypatch.setattr(engine.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(stdout=_ARP_OUT))
    table = engine.read_arp(targets)
    assert table == {
        "192.168.0.1": ("a:b:c:d:e:f", "en0"),
        # "1:2:3" fails normalisation -> not classed as broadcast -> kept verbatim.
        "192.168.0.7": ("1:2:3", "en0"),
    }


# Linux `ip neigh show` rows: "ip dev <dev> lladdr <mac> <state>".
_NEIGH_OUT = """\
192.168.0.1 dev eth0 lladdr a:b:c:d:e:f REACHABLE
192.168.0.2 dev eth0  INCOMPLETE
10.0.0.99 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
224.0.0.251 dev eth0 lladdr 01:00:5e:00:00:fb PERMANENT
fe80::1 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE
192.168.0.5 dev eth0 lladdr ff:ff:ff:ff:ff:ff PERMANENT
"""


def test_read_arp_linux(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(engine, "_is_linux", lambda: True)
    targets = {f"192.168.0.{n}": "eth0" for n in (1, 2, 5)}
    targets["224.0.0.251"] = "eth0"
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout=_NEIGH_OUT)

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    table = engine.read_arp(targets)
    assert captured["cmd"] == ["ip", "neigh", "show"]
    # .2 has no lladdr (INCOMPLETE), .251 is multicast, .5 is broadcast, 10.0.0.99
    # isn't a target, fe80:: doesn't match the IPv4 pattern -> only .1 survives.
    assert table == {"192.168.0.1": ("a:b:c:d:e:f", "eth0")}


def test_read_arp_error(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no arp")

    monkeypatch.setattr(engine.subprocess, "run", _boom)
    assert engine.read_arp({"x": "en0"}) == {}


@pytest.mark.parametrize("linux,flag", [(True, "-W"), (False, "-t")])
def test_ping_argv(monkeypatch, linux, flag):
    monkeypatch.setattr(engine, "_is_linux", lambda: linux)
    assert engine._ping_argv("10.0.0.9", 2.5) == ["ping", "-c", "1", flag, "2", "10.0.0.9"]


def test_is_linux_reads_platform(monkeypatch):
    monkeypatch.setattr(engine.sys, "platform", "linux2")
    assert engine._is_linux() is True
    monkeypatch.setattr(engine.sys, "platform", "darwin")
    assert engine._is_linux() is False


# ---- _is_host -------------------------------------------------------------
@pytest.mark.parametrize("ip,broadcasts,ok", [
    ("192.168.0.5", set(), True),
    ("224.0.0.1", set(), False),          # multicast
    ("0.0.0.0", set(), False),            # unspecified
    ("192.168.0.255", {"192.168.0.255"}, False),  # known broadcast
    ("255.255.255.255", set(), False),    # all-ones broadcast
    ("not-an-ip", set(), False),          # unparseable
])
def test_is_host(ip, broadcasts, ok):
    assert engine._is_host(ip, broadcasts) is ok


# ---- scan (the orchestrator) ---------------------------------------------
def _iface(mac="a0:bb:cc:dd:ee:f0"):
    return Interface("en0", "Wi-Fi", "wifi", "192.168.0.10", 24,
                     "192.168.0.0/24", mac=mac)


class FakeMdns:
    def snapshot(self):
        return {"192.168.0.1": {"name": "Router", "services": {"HTTP", "SSH"}}}


def _install_scan_mocks(monkeypatch, *, targets, alive_icmp, arp_seq, tcp_alive,
                        gateway="192.168.0.1", broadcasts=(), ssdp_snap=None,
                        http_map=None):
    monkeypatch.setattr(engine.net, "hosts_for", lambda ifaces: dict(targets))
    monkeypatch.setattr(engine.net, "default_gateway", lambda: gateway)
    monkeypatch.setattr(engine.net, "broadcast_set", lambda ifaces: set(broadcasts))

    async def fake_ssdp_probe(timeout=2.0, **kw):
        return dict(ssdp_snap or {})

    monkeypatch.setattr(engine.ssdp, "probe", fake_ssdp_probe)

    async def fake_identify(ip, open_ports, **kw):
        return (http_map or {}).get(ip, (None, None))

    monkeypatch.setattr(engine.banners, "identify", fake_identify)

    async def fake_ping(ip, timeout, sem):
        return (ip, ip in alive_icmp)

    monkeypatch.setattr(engine, "_ping", fake_ping)

    state = {"n": 0}

    def fake_read_arp(tg):
        idx = min(state["n"], len(arp_seq) - 1)
        state["n"] += 1
        return dict(arp_seq[idx])

    monkeypatch.setattr(engine, "read_arp", fake_read_arp)

    async def fake_tcp(ip, timeout, sem):
        return (ip, ip in tcp_alive)

    monkeypatch.setattr(engine, "_tcp_alive", fake_tcp)

    async def fake_rdns(ip, sem):
        return (ip, f"host-{ip}")

    monkeypatch.setattr(engine, "_reverse_dns", fake_rdns)

    async def fake_open_ports(ip, timeout, sem):
        return [80]

    monkeypatch.setattr(engine.ports, "open_ports", fake_open_ports)
    monkeypatch.setattr(engine.vendors, "lookup", lambda mac: "Vend" if mac else None)


async def test_scan_empty_interfaces():
    assert await engine.scan([]) == []


async def test_scan_full(monkeypatch):
    targets = {f"192.168.0.{n}": "en0" for n in (10, 1, 2, 3)}
    arp_first = {
        "192.168.0.1": ("a0:bb:cc:dd:ee:f1", "en0"),
        "192.168.0.2": ("12:bb:cc:dd:ee:f2", "en0"),  # locally-administered -> randomized
    }
    arp_after_tcp = dict(arp_first, **{"192.168.0.3": ("a0:bb:cc:dd:ee:f3", "en0")})
    ssdp_snap = {
        "192.168.0.1": {"name": "My Router", "model": "Acme RT-1",
                        "server": "Linux UPnP/1.0"},
        "192.168.0.2": {"name": None, "model": None, "server": "Roku UPnP/1.0"},
    }
    http_map = {
        "192.168.0.1": ("nginx", "Router Admin"),
        "192.168.0.3": (None, "Cam"),
    }
    _install_scan_mocks(
        monkeypatch,
        targets=targets,
        alive_icmp={"192.168.0.1"},
        arp_seq=[arp_first, arp_after_tcp],
        tcp_alive={"192.168.0.3"},
        broadcasts={"192.168.0.255"},
        ssdp_snap=ssdp_snap,
        http_map=http_map,
    )
    progress = []
    devices = await engine.scan(
        [_iface()], resolve=True, mdns=FakeMdns(), scan_ports=True, timeout=0.1,
        progress=lambda d, t: progress.append((d, t)))

    by_ip = {d.ip: d for d in devices}
    assert [d.ip for d in devices] == ["192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.10"]

    router = by_ip["192.168.0.1"]
    assert router.via == "icmp"
    assert router.is_gateway is True
    assert router.mac == "A0:BB:CC:DD:EE:F1"
    assert router.randomized_mac is False
    assert router.vendor == "Vend"
    assert router.hostname == "host-192.168.0.1"
    assert router.mdns_name == "Router"
    assert router.services == ["HTTP", "SSH"]
    assert router.open_ports == [80]
    assert router.upnp_name == "My Router"
    assert router.upnp_model == "Acme RT-1"
    assert router.http_server == "nginx"
    assert router.http_title == "Router Admin"

    assert by_ip["192.168.0.2"].via == "arp"
    assert by_ip["192.168.0.2"].randomized_mac is True
    assert by_ip["192.168.0.2"].upnp_name is None
    assert by_ip["192.168.0.2"].upnp_model == "Roku UPnP/1.0"   # SERVER fallback
    assert by_ip["192.168.0.3"].via == "tcp"
    assert by_ip["192.168.0.3"].http_server is None
    assert by_ip["192.168.0.3"].http_title == "Cam"

    me = by_ip["192.168.0.10"]
    assert me.is_self is True
    assert me.via == "self"
    assert me.mac == "A0:BB:CC:DD:EE:F0"      # filled from the interface, not ARP
    assert me.interface == "en0"

    assert (0, 3) in progress and (3, 3) in progress  # 3 swept (self excluded)


async def test_scan_flags_off_and_no_tcp_hit(monkeypatch):
    # self=.1, sweep=[.2]; .2 is ICMP-silent, ARP-absent, TCP-down -> dropped.
    _install_scan_mocks(
        monkeypatch,
        targets={"192.168.0.1": "en0", "192.168.0.2": "en0"},
        alive_icmp=set(),
        arp_seq=[{}],
        tcp_alive=set(),
        gateway=None,
    )
    devices = await engine.scan([_iface()], resolve=False, mdns=None,
                                ssdp_enabled=False, scan_ports=False, http_id=False,
                                timeout=0.1, progress=None)
    assert [d.ip for d in devices] == ["192.168.0.10"]
    me = devices[0]
    assert me.hostname is None        # resolve off
    assert me.services == []          # mdns off
    assert me.open_ports == []        # ports off
    assert me.upnp_name is None       # ssdp off
    assert me.http_server is None     # http banner off


async def test_scan_skips_tcp_when_nothing_missing(monkeypatch):
    # The only swept host answers ICMP, so `missing` is empty and the whole
    # TCP-fallback block is skipped.
    _install_scan_mocks(
        monkeypatch,
        targets={"192.168.0.2": "en0"},
        alive_icmp={"192.168.0.2"},
        arp_seq=[{"192.168.0.2": ("a0:bb:cc:dd:ee:f2", "en0")}],
        tcp_alive=set(),
    )
    devices = await engine.scan([_iface()], resolve=False, mdns=None,
                                scan_ports=False, timeout=0.1)
    assert {d.ip for d in devices} == {"192.168.0.2", "192.168.0.10"}
