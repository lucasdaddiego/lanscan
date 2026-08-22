"""Tests for lanscan.engine — the async liveness sweep + ARP/DNS/vendor merge.

The OS shell-outs (ping, arp) and all sockets are mocked, so the orchestration
logic is exercised without touching the network.
"""
import asyncio

import pytest

from lanscan import engine
from lanscan.models import Interface


class FakeProc:
    """Stand-in for an asyncio subprocess; `hang` makes the first wait() block."""
    def __init__(self, rc=0, hang=False):
        self.rc = rc
        self.killed = False
        self._hang = hang

    async def wait(self):
        if self._hang:
            self._hang = False
            await asyncio.sleep(3600)
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
        raise TimeoutError

    monkeypatch.setattr(engine.asyncio, "wait_for", fake_wait_for)
    ip, ok = await engine._ping("10.0.0.9", 0.1, asyncio.Semaphore(2))
    assert (ip, ok) == ("10.0.0.9", False)
    assert proc.killed is True


async def test_ping_cancel_kills_proc(monkeypatch):
    proc = FakeProc(hang=True)
    monkeypatch.setattr(engine.asyncio, "create_subprocess_exec", _exec_returning(proc))
    task = asyncio.create_task(engine._ping("10.0.0.9", 30.0, asyncio.Semaphore(2)))
    await asyncio.sleep(0.02)          # let it reach the proc.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert proc.killed is True         # child killed, not left running


async def test_ping_cancel_tolerates_already_exited_proc(monkeypatch):
    class GoneProc(FakeProc):
        def kill(self):
            raise ProcessLookupError  # exited between the cancel and the kill

    proc = GoneProc(hang=True)
    monkeypatch.setattr(engine.asyncio, "create_subprocess_exec", _exec_returning(proc))
    task = asyncio.create_task(engine._ping("10.0.0.9", 30.0, asyncio.Semaphore(2)))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task                     # ProcessLookupError must not mask the cancel


# ---- ICMP socket sweep ----------------------------------------------------
def _words_sum(pkt: bytes) -> int:
    total = sum(int.from_bytes(pkt[i:i + 2], "big") for i in range(0, len(pkt), 2))
    total = (total >> 16) + (total & 0xFFFF)
    return (total + (total >> 16)) & 0xFFFF


def test_checksum_known_vectors():
    assert engine._checksum(b"") == 0xFFFF
    assert engine._checksum(b"\x00\x01") == 0xFFFE
    assert engine._checksum(b"\xff\xff\x00\x02") == 0xFFFD   # folds the carry back in
    assert engine._checksum(b"\x01") == 0xFEFF               # odd length is zero-padded


def test_echo_request_is_well_formed():
    pkt = engine._echo_request(0x1_0007)   # seq is masked to 16 bits
    assert len(pkt) == 8 + len(engine._ECHO_PAYLOAD)
    assert pkt[0] == engine._ICMP_ECHO_REQUEST and pkt[1] == 0
    assert int.from_bytes(pkt[6:8], "big") == 7
    assert _words_sum(pkt) == 0xFFFF       # a valid checksum sums to all-ones


@pytest.mark.parametrize("data,alive", [
    (b"\x45" + b"\0" * 19 + b"\x00\x00\x00\x00", True),     # macOS: IP header + reply
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", True),             # Linux: bare reply
    (b"\x45" + b"\0" * 19 + b"\x08\x00", False),             # an echo *request*
    (b"\x45" + b"\0" * 19, False),                            # header only, no ICMP
    (b"", False),                                              # empty datagram
])
def test_echo_collector_parses_both_framings(data, alive):
    proto = engine._EchoCollector()
    proto.datagram_received(data, ("10.0.0.9", 0))
    assert ("10.0.0.9" in proto.alive) is alive


class FakeSock:
    def __init__(self):
        self.blocking = None
        self.closed = False

    def setblocking(self, flag):
        self.blocking = flag

    def close(self):
        self.closed = True


def test_icmp_socket_refused(monkeypatch):
    def _boom(*a, **k):
        raise PermissionError("ping_group_range")

    monkeypatch.setattr(engine.socket, "socket", _boom)
    assert engine._icmp_socket() is None


def test_icmp_socket_is_non_blocking(monkeypatch):
    sock = FakeSock()
    monkeypatch.setattr(engine.socket, "socket", lambda *a, **k: sock)
    assert engine._icmp_socket() is sock
    assert sock.blocking is False


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


def _patch_icmp_endpoint(monkeypatch, *, replies=(), exc=None):
    """Fake the datagram endpoint; `replies` are pre-loaded into the collector."""
    loop = asyncio.get_running_loop()
    transport = FakeTransport()
    sock = FakeSock()
    monkeypatch.setattr(engine, "_icmp_socket", lambda: sock)

    async def fake_cde(factory, **kw):
        if exc:
            raise exc
        proto = factory()
        proto.alive.update(replies)
        return transport, proto

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_cde)
    return transport, sock


async def test_icmp_sweep_no_socket(monkeypatch):
    monkeypatch.setattr(engine, "_icmp_socket", lambda: None)
    assert await engine._icmp_sweep(["10.0.0.1"], 0.01, None) is None


async def test_icmp_sweep_endpoint_error_closes_socket(monkeypatch):
    _, sock = _patch_icmp_endpoint(monkeypatch, exc=OSError("no"))
    assert await engine._icmp_sweep(["10.0.0.1"], 0.01, None) is None
    assert sock.closed is True


async def test_icmp_sweep_sends_every_target_and_filters_replies(monkeypatch):
    targets = [f"10.0.0.{n}" for n in range(1, 70)]   # > one send batch
    transport, _ = _patch_icmp_endpoint(
        monkeypatch, replies={"10.0.0.5", "10.0.0.9", "192.168.9.9"})  # last one foreign
    progress = []
    alive = await engine._icmp_sweep(targets, 0.05, lambda d, t: progress.append((d, t)))
    assert alive == {"10.0.0.5", "10.0.0.9"}
    assert [addr for _, addr in transport.sent] == [(ip, 0) for ip in targets]
    assert transport.closed is True
    assert progress and progress[-1][1] == len(targets)
    assert all(0 <= d <= t for d, t in progress)


async def test_icmp_sweep_ends_early_when_everyone_answered(monkeypatch):
    _patch_icmp_endpoint(monkeypatch, replies={"10.0.0.1", "10.0.0.2"})
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    assert await engine._icmp_sweep(["10.0.0.1", "10.0.0.2"], 5.0, None) == {"10.0.0.1", "10.0.0.2"}
    assert loop.time() - t0 < 1.0        # did not wait out the 5s window


async def test_icmp_sweep_waits_out_the_window_without_progress(monkeypatch):
    _patch_icmp_endpoint(monkeypatch, replies=set())
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    assert await engine._icmp_sweep(["10.0.0.1"], 0.05, None) == set()
    assert loop.time() - t0 >= 0.04          # several 0.1s-capped sleeps, no callback


async def test_ping_sweep_collects_and_reports(monkeypatch):
    async def fake_ping(ip, timeout, sem):
        return ip, ip.endswith(".1")

    monkeypatch.setattr(engine, "_ping", fake_ping)
    progress = []
    alive = await engine._ping_sweep(["10.0.0.1", "10.0.0.2"], 0.1, 4,
                                     lambda d, t: progress.append((d, t)))
    assert alive == {"10.0.0.1"}
    assert progress == [(1, 2), (2, 2)]


# ---- _reverse_dns ---------------------------------------------------------
async def test_reverse_dns_success(monkeypatch):
    monkeypatch.setattr(engine.socket, "gethostbyaddr",
                        lambda ip: ("host.local", [], [ip]))
    assert await engine._reverse_dns("10.0.0.9", 1.0) == ("10.0.0.9", "host.local")


async def test_reverse_dns_failure(monkeypatch):
    def _boom(ip):
        raise OSError("no PTR")

    monkeypatch.setattr(engine.socket, "gethostbyaddr", _boom)
    assert await engine._reverse_dns("10.0.0.9", 1.0) == ("10.0.0.9", None)


def test_rdns_pool_is_a_singleton(monkeypatch):
    monkeypatch.setattr(engine, "_RDNS_POOL", None)
    pool = engine._rdns_pool()
    try:
        assert engine._rdns_pool() is pool
        assert pool._max_workers == engine._RDNS_WORKERS
    finally:
        pool.shutdown(wait=False)


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
    monkeypatch.setattr(engine, "is_linux", lambda: False)
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
    monkeypatch.setattr(engine, "is_linux", lambda: True)
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
    monkeypatch.setattr(engine, "is_linux", lambda: linux)
    assert engine._ping_argv("10.0.0.9", 2.5) == ["ping", "-c", "1", flag, "2", "10.0.0.9"]



# ---- scan (the orchestrator) ---------------------------------------------
def _iface(mac="a0:bb:cc:dd:ee:f0"):
    return Interface("en0", "Wi-Fi", "wifi", "192.168.0.10", 24,
                     "192.168.0.0/24", mac=mac)


class FakeMdns:
    def snapshot(self):
        return {"192.168.0.1": {"name": "Router", "services": {"HTTP", "SSH"}}}


def _install_scan_mocks(monkeypatch, *, targets, alive_icmp, arp, gateway="192.168.0.1",
                        ssdp_snap=None, http_map=None, icmp_socket=False):
    """Mock every collaborator of scan(). `alive_icmp` answers via the `ping`
    fallback by default; with icmp_socket=True the socket sweep returns it."""
    monkeypatch.setattr(engine.net, "hosts_for", lambda ifaces: dict(targets))
    monkeypatch.setattr(engine.net, "default_gateway", lambda: gateway)

    async def fake_ssdp_probe(local_ips=(), **kw):
        return dict(ssdp_snap or {})

    monkeypatch.setattr(engine.ssdp, "probe", fake_ssdp_probe)

    async def fake_identify(ip, open_ports, **kw):
        return (http_map or {}).get(ip, (None, None))

    monkeypatch.setattr(engine.banners, "identify", fake_identify)

    async def fake_icmp_sweep(sweep, timeout, progress):
        return set(alive_icmp) if icmp_socket else None

    monkeypatch.setattr(engine, "_icmp_sweep", fake_icmp_sweep)

    async def fake_ping(ip, timeout, sem):
        return (ip, ip in alive_icmp)

    monkeypatch.setattr(engine, "_ping", fake_ping)
    monkeypatch.setattr(engine, "read_arp", lambda tg: dict(arp))

    async def fake_rdns(ip, timeout):
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
    arp = {
        "192.168.0.1": ("a0:bb:cc:dd:ee:f1", "en0"),
        "192.168.0.2": ("12:bb:cc:dd:ee:f2", "en0"),  # locally-administered -> randomized
        "192.168.0.3": ("a0:bb:cc:dd:ee:f3", "en0"),  # ICMP-silent, ARP only
    }
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
        arp=arp,
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
    assert by_ip["192.168.0.3"].via == "arp"
    assert by_ip["192.168.0.3"].http_server is None
    assert by_ip["192.168.0.3"].http_title == "Cam"

    me = by_ip["192.168.0.10"]
    assert me.is_self is True
    assert me.via == "self"
    assert me.mac == "A0:BB:CC:DD:EE:F0"      # filled from the interface, not ARP
    assert me.interface == "en0"

    assert (0, 3) in progress and (3, 3) in progress  # 3 swept (self excluded)


async def test_scan_flags_off_and_silent_host_dropped(monkeypatch):
    # self=.1, sweep=[.2]; .2 is ICMP-silent and ARP-absent -> not on the link.
    _install_scan_mocks(
        monkeypatch,
        targets={"192.168.0.1": "en0", "192.168.0.2": "en0"},
        alive_icmp=set(),
        arp={},
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


async def test_scan_cancel_stops_the_ping_sweep(monkeypatch):
    # Quitting the TUI mid-sweep cancels scan(); as_completed does not cancel the
    # tasks it consumes, so without explicit ownership the whole sweep keeps running.
    started = []

    async def slow_ping(ip, timeout, sem):
        started.append(ip)
        await asyncio.sleep(30)
        return ip, False

    _install_scan_mocks(
        monkeypatch,
        targets={f"192.168.0.{n}": "en0" for n in (1, 2, 3, 4, 5)},
        alive_icmp=set(), arp={},
    )
    monkeypatch.setattr(engine, "_ping", slow_ping)   # after the mocks, which set it too
    task = asyncio.create_task(engine.scan(
        [_iface()], resolve=False, mdns=None, ssdp_enabled=False,
        scan_ports=False, http_id=False, timeout=0.1))
    for _ in range(100):
        if len(started) == 5:
            break
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert [t for t in asyncio.all_tasks() if t.get_coro().__name__ == "slow_ping"] == []


async def test_scan_uses_icmp_socket_sweep_when_available(monkeypatch):
    # The socket sweep answers, so the `ping` fallback must not run at all.
    _install_scan_mocks(
        monkeypatch,
        targets={"192.168.0.2": "en0", "192.168.0.3": "en0"},
        alive_icmp={"192.168.0.2"},
        arp={"192.168.0.2": ("a0:bb:cc:dd:ee:f2", "en0")},
        icmp_socket=True,
    )

    async def must_not_ping(*a, **k):
        raise AssertionError("ping fallback ran despite a working ICMP socket")

    monkeypatch.setattr(engine, "_ping", must_not_ping)
    progress = []
    devices = await engine.scan([_iface()], resolve=False, mdns=None, ssdp_enabled=False,
                                scan_ports=False, http_id=False, timeout=0.1,
                                progress=lambda d, t: progress.append((d, t)))
    assert {d.ip: d.via for d in devices} == {"192.168.0.2": "icmp", "192.168.0.10": "self"}
    assert progress[0] == (0, 2) and progress[-1] == (2, 2)
