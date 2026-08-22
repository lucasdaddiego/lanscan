"""Tests for lanscan.discovery — mDNS/Bonjour browsing via zeroconf.

zeroconf's AsyncZeroconf / AsyncServiceBrowser / AsyncServiceInfo and the event
loop are all faked, so nothing touches the network or spawns real browsers.
"""
import pytest

from lanscan import discovery
from lanscan.discovery import MdnsDiscovery, ServiceStateChange


# ---- _friendly_from_txt ---------------------------------------------------
class _Info:
    def __init__(self, *, ok=True, properties=None, addresses=()):
        self._ok = ok
        self.properties = properties
        self._addresses = list(addresses)

    async def async_request(self, zc, timeout):
        return self._ok

    def parsed_addresses(self):
        return self._addresses


def test_friendly_from_txt_none_properties():
    assert discovery._friendly_from_txt(_Info(properties=None)) is None


def test_friendly_from_txt_reads_fn():
    assert discovery._friendly_from_txt(_Info(properties={b"fn": b"Living Room"})) == "Living Room"


def test_friendly_from_txt_skips_bad_then_finds_good():
    # b"fn" is an int -> .decode raises -> skipped; b"name" wins.
    info = _Info(properties={b"fn": 123, b"name": b"Bob"})
    assert discovery._friendly_from_txt(info) == "Bob"


def test_friendly_from_txt_blank_value_ignored():
    assert discovery._friendly_from_txt(_Info(properties={b"fn": b"   "})) is None


# ---- _best_name -----------------------------------------------------------
def test_best_name_empty():
    assert discovery._best_name(set()) is None


def test_best_name_prefers_human_readable():
    assert discovery._best_name({"Living Room", "abcdef"}) == "Living Room"


def test_best_name_uuid_ranks_last():
    uuid = "12345678-1234-1234-1234-123456789abc"
    assert discovery._best_name({uuid, "Box"}) == "Box"


def test_best_name_shortest_among_equal():
    assert discovery._best_name({"abcd", "ab"}) == "ab"


# ---- fakes for the zeroconf objects --------------------------------------
class FakeAZC:
    def __init__(self):
        self.zeroconf = object()
        self.closed = False

    async def async_close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, zc, service_type, handlers=None):
        self.service_type = service_type
        self.cancelled = False

    async def async_cancel(self):
        self.cancelled = True


@pytest.fixture
def patched_zeroconf(monkeypatch):
    monkeypatch.setattr(discovery, "AsyncZeroconf", FakeAZC)
    monkeypatch.setattr(discovery, "AsyncServiceBrowser", FakeBrowser)


# ---- start / stop ---------------------------------------------------------
async def test_start_registers_one_browser_for_every_labelled_type(patched_zeroconf):
    md = MdnsDiscovery()
    await md.start()
    assert isinstance(md._azc, FakeAZC)
    assert md._browser.service_type == discovery._TYPES
    assert set(md._browser.service_type) == {f"{t}.local." for t in discovery._LABELS}


async def test_stop_cancels_and_closes(patched_zeroconf):
    md = MdnsDiscovery()
    await md.start()
    azc = md._azc
    await md.stop()
    assert azc.closed is True
    assert md._browser.cancelled is True


async def test_stop_without_start_is_noop():
    md = MdnsDiscovery()
    await md.stop()  # no browsers, no azc -> must not raise
    assert md._azc is None


async def test_stop_suppresses_errors():
    class BoomBrowser:
        async def async_cancel(self):
            raise RuntimeError("cancel failed")

    class BoomAZC:
        async def async_close(self):
            raise RuntimeError("close failed")

    md = MdnsDiscovery()
    md._browser = BoomBrowser()
    md._azc = BoomAZC()
    await md.stop()  # both errors swallowed by contextlib.suppress


# ---- _on_service ----------------------------------------------------------
class FakeLoop:
    def __init__(self):
        self.coros = []

    def call_soon_threadsafe(self, fn, *args):
        fn(*args)  # run inline so the effect is observable synchronously


def test_on_service_no_loop_returns():
    md = MdnsDiscovery()
    # _loop is None -> early return, nothing scheduled / raised.
    md._on_service(None, "_airplay._tcp.local.", "x", ServiceStateChange.Added)


@pytest.mark.parametrize("change", [ServiceStateChange.Added, ServiceStateChange.Updated])
def test_on_service_schedules_resolve(monkeypatch, change):
    captured = []

    def cap(coro, loop):
        captured.append(coro)
        coro.close()  # we are only checking it was scheduled

    monkeypatch.setattr(discovery.asyncio, "run_coroutine_threadsafe", cap)
    md = MdnsDiscovery()
    md._loop = FakeLoop()
    md._on_service(None, "_airplay._tcp.local.", "TV._airplay._tcp.local.", change)
    assert len(captured) == 1


def test_on_service_removed_calls_forget():
    md = MdnsDiscovery()
    md._loop = FakeLoop()
    forgotten = []
    md._forget = lambda name: forgotten.append(name)
    md._on_service(None, "_airplay._tcp.local.", "TV", ServiceStateChange.Removed)
    assert forgotten == ["TV"]


def test_on_service_ignores_unknown_state():
    # A state change that is neither Added/Updated nor Removed is simply dropped.
    md = MdnsDiscovery()
    md._loop = FakeLoop()
    md._on_service(None, "_airplay._tcp.local.", "TV", "some-future-state")


# ---- _resolve -------------------------------------------------------------
def _info_factory(info):
    return lambda service_type, name: info


async def test_resolve_unlabelled_type_falls_back_to_its_key(monkeypatch):
    # Never browsed in practice, but a stray type must not crash the resolver.
    info = _Info(properties={}, addresses=["192.168.0.9"])
    monkeypatch.setattr(discovery, "AsyncServiceInfo", _info_factory(info))
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_obscure._tcp.local.", "X._obscure._tcp.local.")
    assert md.snapshot() == {"192.168.0.9": {"name": "X", "services": {"_obscure._tcp"}}}


async def test_resolve_request_false(monkeypatch):
    monkeypatch.setattr(discovery, "AsyncServiceInfo", _info_factory(_Info(ok=False)))
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_airplay._tcp.local.", "TV._airplay._tcp.local.")
    assert md.snapshot() == {}


async def test_resolve_with_friendly_name(monkeypatch):
    info = _Info(properties={b"fn": b"Living Room"},
                 addresses=["192.168.0.5", "fe80::1"])  # IPv6 dropped
    monkeypatch.setattr(discovery, "AsyncServiceInfo", _info_factory(info))
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_airplay._tcp.local.", "TV._airplay._tcp.local.")
    snap = md.snapshot()
    assert snap == {"192.168.0.5": {"name": "Living Room", "services": {"AirPlay"}}}


async def test_resolve_uses_instance_when_no_txt(monkeypatch):
    info = _Info(properties={}, addresses=["192.168.0.6"])
    monkeypatch.setattr(discovery, "AsyncServiceInfo", _info_factory(info))
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_airplay._tcp.local.", "AppleTV._airplay._tcp.local.")
    assert md.snapshot()["192.168.0.6"]["name"] == "AppleTV"


async def test_resolve_device_info_suppresses_instance(monkeypatch):
    info = _Info(properties={}, addresses=["192.168.0.7"])
    monkeypatch.setattr(discovery, "AsyncServiceInfo", _info_factory(info))
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_device-info._tcp.local.", "Box._device-info._tcp.local.")
    snap = md.snapshot()
    assert snap["192.168.0.7"] == {"name": None, "services": {"device-info"}}


async def test_resolve_again_releases_departed_ip(monkeypatch):
    # The speaker takes a new DHCP lease, so an Updated event re-resolves the same
    # instance at a different address. The address it left must be released — a
    # sibling service type still advertising there keeps it, a bare move doesn't.
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    sonos, raop = "Kitchen._sonos._tcp.local.", "Kitchen._raop._tcp.local."
    monkeypatch.setattr(discovery, "AsyncServiceInfo",
                        _info_factory(_Info(properties={}, addresses=["192.168.0.41"])))
    await md._resolve("_sonos._tcp.local.", sonos)
    await md._resolve("_raop._tcp.local.", raop)
    assert md.snapshot()["192.168.0.41"]["services"] == {"Sonos", "AirPlay-Audio"}

    monkeypatch.setattr(discovery, "AsyncServiceInfo",
                        _info_factory(_Info(properties={}, addresses=["192.168.0.55"])))
    await md._resolve("_sonos._tcp.local.", sonos)
    assert md.snapshot() == {
        "192.168.0.41": {"name": "Kitchen", "services": {"AirPlay-Audio"}},  # raop only
        "192.168.0.55": {"name": "Kitchen", "services": {"Sonos"}},
    }
    md._forget(raop)
    assert set(md.snapshot()) == {"192.168.0.55"}   # nothing left claiming .41


async def test_resolve_swallows_exceptions(monkeypatch):
    def boom(service_type, name):
        raise RuntimeError("zeroconf blew up")

    monkeypatch.setattr(discovery, "AsyncServiceInfo", boom)
    md = MdnsDiscovery()
    md._azc = FakeAZC()
    await md._resolve("_airplay._tcp.local.", "TV._airplay._tcp.local.")  # no raise
    assert md.snapshot() == {}


# ---- _forget --------------------------------------------------------------
def test_forget_unknown_name_is_noop():
    md = MdnsDiscovery()
    md._forget("nope")  # nothing recorded -> early return
    assert md.snapshot() == {}


def test_forget_rebuilds_from_remaining_records():
    md = MdnsDiscovery()
    ip = "192.168.0.5"
    md._by_name = {
        "a": {"ips": {ip}, "label": "AirPlay", "instance": "Speaker"},
        "b": {"ips": {ip}, "label": "Sonos", "instance": "Speaker"},
        "c": {"ips": {ip}, "label": "HTTP", "instance": None},  # no instance
        "d": {"ips": {"192.168.0.99"}, "label": "SSH", "instance": "Other"},  # other IP
    }
    md._by_ip = {ip: {"name": "Speaker", "services": {"AirPlay", "Sonos", "HTTP"},
                      "instances": {"Speaker"}}}

    md._forget("a")
    # Rebuilt from b + c: services shrink, name still backed by b's instance.
    assert md._by_ip[ip]["services"] == {"Sonos", "HTTP"}
    assert md._by_ip[ip]["name"] == "Speaker"

    md._forget("b")
    md._forget("c")
    # Last record gone -> the IP is dropped entirely.
    assert ip not in md._by_ip
    assert md.snapshot() == {}
