"""Tests for lanscan.ssdp — SSDP/UPnP discovery.

The UDP datagram endpoint and the description-XML fetch are both mocked.
"""
import asyncio

import pytest

from lanscan import ssdp


# ---- _parse_headers -------------------------------------------------------
def test_parse_headers():
    data = (b"HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0\r\n"
            b"GarbageLineNoColon\r\nLOCATION: http://x/d.xml\r\n\r\n")
    assert ssdp._parse_headers(data) == {
        "server": "Linux UPnP/1.0", "location": "http://x/d.xml"}


# ---- _Collector -----------------------------------------------------------
def test_collector_prefers_a_reply_with_location():
    c = ssdp._Collector()
    addr = ("192.168.1.1", 1900)
    # 1) first reply (no LOCATION) is stored
    c.datagram_received(b"HTTP/1.1 200 OK\r\nSERVER: A\r\n\r\n", addr)
    assert c.responses["192.168.1.1"]["server"] == "A"
    # 2) a reply WITH location replaces the one without
    c.datagram_received(
        b"HTTP/1.1 200 OK\r\nSERVER: B\r\nLOCATION: http://x/d.xml\r\n\r\n", addr)
    assert c.responses["192.168.1.1"]["location"] == "http://x/d.xml"
    # 3) a later reply WITHOUT location does not clobber the located one
    c.datagram_received(b"HTTP/1.1 200 OK\r\nSERVER: C\r\n\r\n", addr)
    assert c.responses["192.168.1.1"]["server"] == "B"
    # 4) another located reply also leaves the first-seen location in place
    c.datagram_received(
        b"HTTP/1.1 200 OK\r\nSERVER: D\r\nLOCATION: http://y/\r\n\r\n", addr)
    assert c.responses["192.168.1.1"]["location"] == "http://x/d.xml"


# ---- _xml_tag -------------------------------------------------------------
def test_xml_tag():
    xml = b"<friendlyName>\n  Living   Room \n</friendlyName>"
    assert ssdp._xml_tag(xml, "friendlyName") == "Living Room"   # whitespace collapsed
    assert ssdp._xml_tag(xml, "manufacturer") is None            # absent
    assert ssdp._xml_tag(b"<modelName></modelName>", "modelName") is None  # empty
    # second lookup of the same tag exercises the compiled-pattern cache
    assert ssdp._xml_tag(b"<friendlyName>X</friendlyName>", "friendlyName") == "X"


# ---- _enrich --------------------------------------------------------------
async def test_enrich_no_location():
    info = {"location": None}
    await ssdp._enrich("192.168.1.1", info, timeout=0)
    assert "name" not in info


async def test_enrich_bad_url():
    info = {"location": "no-scheme-no-host"}
    await ssdp._enrich("192.168.1.1", info, timeout=0)
    assert "name" not in info


async def test_enrich_refuses_a_location_pointing_at_another_host(monkeypatch):
    """An SSDP reply is unauthenticated UDP: a rogue responder must not be able
    to aim our GET at a host it doesn't own (here a loopback-only admin UI)."""
    async def must_not_run(*a, **k):
        raise AssertionError("fetch must not be called for a foreign LOCATION")

    monkeypatch.setattr(ssdp.banners, "fetch", must_not_run)
    info = {"location": "http://127.0.0.1:8080/admin/reboot?confirm=1"}
    await ssdp._enrich("192.168.0.66", info, timeout=1.0)
    assert "name" not in info


async def test_enrich_refuses_a_hostname_that_is_not_the_responder_literal(monkeypatch):
    """Same check catches the identity-spoof shape: citing the router's own
    description URL so the rogue host inherits the router's name."""
    async def must_not_run(*a, **k):
        raise AssertionError("fetch must not be called for a foreign LOCATION")

    monkeypatch.setattr(ssdp.banners, "fetch", must_not_run)
    for loc in ("http://192.168.0.1/desc.xml",      # a neighbour's address
                "http://router.local/desc.xml"):    # a name, not the literal
        info = {"location": loc}
        await ssdp._enrich("192.168.0.66", info, timeout=1.0)
        assert "name" not in info


async def test_enrich_fetch_fails(monkeypatch):
    async def fake_fetch(*a, **k):
        return None

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "http://192.168.1.1:8060/dd.xml"}
    await ssdp._enrich("192.168.1.1", info, timeout=0)
    assert "name" not in info


async def test_enrich_success_https_with_query(monkeypatch):
    cap = {}

    async def fake_fetch(host, port, path="/", **kw):
        cap.update(host=host, port=port, path=path, tls=kw.get("tls"))
        return 200, {}, (b"<friendlyName>My TV</friendlyName>"
                         b"<manufacturer>Acme</manufacturer><modelName>X1</modelName>")

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "https://192.168.1.2:8443/desc.xml?v=1"}
    await ssdp._enrich("192.168.1.2", info, timeout=1.0)
    assert info["name"] == "My TV"
    assert info["model"] == "Acme X1"
    assert cap == {"host": "192.168.1.2", "port": 8443, "path": "/desc.xml?v=1", "tls": True}


async def test_enrich_default_http_port_empty_path(monkeypatch):
    cap = {}

    async def fake_fetch(host, port, path="/", **kw):
        cap.update(port=port, path=path, tls=kw.get("tls"))
        return 200, {}, b"<modelName>OnlyModel</modelName>"

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "http://192.168.1.3"}   # no port, no path
    await ssdp._enrich("192.168.1.3", info, timeout=0)
    assert cap["port"] == 80 and cap["path"] == "/" and cap["tls"] is False
    assert info["name"] is None                 # no friendlyName
    assert info["model"] == "OnlyModel"         # manufacturer absent


async def test_enrich_name_only_model_none(monkeypatch):
    async def fake_fetch(*a, **k):
        return 200, {}, b"<friendlyName>Bare</friendlyName>"

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "http://192.168.1.4:80/d.xml"}
    await ssdp._enrich("192.168.1.4", info, timeout=0)
    assert info["name"] == "Bare"
    assert info["model"] is None                # neither manufacturer nor model


# ---- probe ----------------------------------------------------------------
class FakeTransport:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


class FakeSock:
    def __init__(self, local_ip=None):
        self.local_ip = local_ip
        self.closed = False

    def close(self):
        self.closed = True


def _patch_endpoint(monkeypatch, responses=None, *, exc=None, fail_ips=()):
    """Fake the sockets + datagram endpoints. Returns the list of transports
    opened (one per local IP that didn't fail); each records what it sent."""
    loop = asyncio.get_running_loop()
    transports = []

    def fake_socket(local_ip):
        if local_ip in fail_ips:
            raise OSError(f"cannot bind {local_ip}")
        return FakeSock(local_ip)

    async def fake_cde(factory, **kw):
        if exc:
            raise exc
        proto = factory()
        if responses is not None:
            proto.responses = responses
        transport = FakeTransport()
        transport.local_ip = kw["sock"].local_ip
        transports.append(transport)
        return transport, proto

    monkeypatch.setattr(ssdp, "_multicast_socket", fake_socket)
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_cde)
    return transports


async def test_probe_endpoint_error(monkeypatch):
    _patch_endpoint(monkeypatch, exc=OSError("no multicast"))
    assert await ssdp.probe(timeout=0) == {}


async def test_probe_no_responses(monkeypatch):
    transports = _patch_endpoint(monkeypatch, responses={})
    assert await ssdp.probe(timeout=0) == {}
    (transport,) = transports                  # no local IPs -> one unpinned socket
    assert transport.local_ip is None
    assert transport.closed is True
    assert len(transport.sent) == 2            # the M-SEARCH goes out twice


async def test_probe_sends_from_every_interface(monkeypatch):
    transports = _patch_endpoint(monkeypatch, responses={})
    await ssdp.probe(["192.168.0.10", "10.0.0.2"], timeout=0)
    assert [t.local_ip for t in transports] == ["192.168.0.10", "10.0.0.2"]
    assert all(len(t.sent) == 2 and t.closed for t in transports)


async def test_probe_skips_an_interface_that_cannot_bind(monkeypatch):
    transports = _patch_endpoint(monkeypatch, responses={}, fail_ips={"10.0.0.2"})
    await ssdp.probe(["192.168.0.10", "10.0.0.2"], timeout=0)
    assert [t.local_ip for t in transports] == ["192.168.0.10"]


async def test_probe_falls_back_to_default_route_when_no_interface_binds(monkeypatch):
    transports = _patch_endpoint(monkeypatch, responses={}, fail_ips={"192.168.0.10"})
    await ssdp.probe(["192.168.0.10"], timeout=0)
    assert [t.local_ip for t in transports] == [None]


def test_multicast_socket_pins_egress_and_closes_on_error(monkeypatch):
    calls = []

    class Sock:
        def __init__(self, *a):
            self.closed = False

        def setblocking(self, flag):
            calls.append(("blocking", flag))

        def setsockopt(self, level, opt, val):
            calls.append(("opt", level, opt, val))

        def bind(self, addr):
            calls.append(("bind", addr))
            if addr[0] == "10.9.9.9":
                raise OSError("bad bind")

        def close(self):
            self.closed = True

    monkeypatch.setattr(ssdp.socket, "socket", Sock)
    sock = ssdp._multicast_socket("192.168.0.10")
    assert sock.closed is False
    assert ("opt", ssdp.socket.IPPROTO_IP, ssdp.socket.IP_MULTICAST_IF,
            ssdp.socket.inet_aton("192.168.0.10")) in calls
    assert ("bind", ("192.168.0.10", 0)) in calls

    calls.clear()
    sock = ssdp._multicast_socket(None)
    assert ("bind", ("0.0.0.0", 0)) in calls and not any(c[0] == "opt" for c in calls)

    with pytest.raises(OSError):
        ssdp._multicast_socket("10.9.9.9")


async def test_probe_collects_and_enriches(monkeypatch):
    responses = {
        "192.168.1.1": {"server": "Linux UPnP/1.0",
                        "location": "http://192.168.1.1:80/desc.xml"},
        "192.168.1.50": {"server": "Roku UPnP/1.0"},   # no LOCATION -> not enriched
    }
    _patch_endpoint(monkeypatch, responses=responses)

    async def fake_fetch(host, port, path="/", **kw):
        return 200, {}, (b"<friendlyName>Living Room TV</friendlyName>"
                         b"<manufacturer>Acme</manufacturer><modelName>X9</modelName>")

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    result = await ssdp.probe(timeout=0)
    assert result["192.168.1.1"]["name"] == "Living Room TV"
    assert result["192.168.1.1"]["model"] == "Acme X9"
    assert result["192.168.1.50"]["server"] == "Roku UPnP/1.0"
    assert result["192.168.1.50"]["name"] is None


async def test_probe_does_not_attribute_a_foreign_location_to_the_responder(monkeypatch):
    """End to end: the rogue host stays anonymous and only the honest device,
    whose LOCATION points back at itself, gets enriched."""
    responses = {
        "192.168.0.66": {"server": "rogue/1.0",           # claims the router's URL
                         "location": "http://192.168.0.1:80/desc.xml"},
        "192.168.0.1": {"server": "Linux UPnP/1.0",
                        "location": "http://192.168.0.1:80/desc.xml"},
    }
    _patch_endpoint(monkeypatch, responses=responses)
    fetched = []

    async def fake_fetch(host, port, path="/", **kw):
        fetched.append(host)
        return 200, {}, b"<friendlyName>Corporate Router</friendlyName>"

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    result = await ssdp.probe(timeout=0)
    assert result["192.168.0.66"]["name"] is None        # not the router
    assert result["192.168.0.1"]["name"] == "Corporate Router"
    assert fetched == ["192.168.0.1"]                    # exactly one GET, to itself


async def test_probe_without_details(monkeypatch):
    responses = {"192.168.1.1": {"server": "x", "location": "http://192.168.1.1/d.xml"}}
    _patch_endpoint(monkeypatch, responses=responses)

    async def must_not_run(*a, **k):
        raise AssertionError("fetch should not be called when fetch_details=False")

    monkeypatch.setattr(ssdp.banners, "fetch", must_not_run)
    result = await ssdp.probe(timeout=0, fetch_details=False)
    assert result["192.168.1.1"] == {
        "server": "x", "location": "http://192.168.1.1/d.xml", "name": None, "model": None}
