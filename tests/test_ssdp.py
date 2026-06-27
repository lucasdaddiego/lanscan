"""Tests for lanscan.ssdp — SSDP/UPnP discovery.

The UDP datagram endpoint and the description-XML fetch are both mocked.
"""
from __future__ import annotations

import asyncio

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
    await ssdp._enrich(info, timeout=0)
    assert "name" not in info


async def test_enrich_bad_url():
    info = {"location": "no-scheme-no-host"}
    await ssdp._enrich(info, timeout=0)
    assert "name" not in info


async def test_enrich_fetch_fails(monkeypatch):
    async def fake_fetch(*a, **k):
        return None

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "http://192.168.1.1:8060/dd.xml"}
    await ssdp._enrich(info, timeout=0)
    assert "name" not in info


async def test_enrich_success_https_with_query(monkeypatch):
    cap = {}

    async def fake_fetch(host, port, path="/", **kw):
        cap.update(host=host, port=port, path=path, tls=kw.get("tls"))
        return 200, {}, (b"<friendlyName>My TV</friendlyName>"
                         b"<manufacturer>Acme</manufacturer><modelName>X1</modelName>")

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "https://192.168.1.2:8443/desc.xml?v=1"}
    await ssdp._enrich(info, timeout=1.0)
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
    await ssdp._enrich(info, timeout=0)
    assert cap["port"] == 80 and cap["path"] == "/" and cap["tls"] is False
    assert info["name"] is None                 # no friendlyName
    assert info["model"] == "OnlyModel"         # manufacturer absent


async def test_enrich_name_only_model_none(monkeypatch):
    async def fake_fetch(*a, **k):
        return 200, {}, b"<friendlyName>Bare</friendlyName>"

    monkeypatch.setattr(ssdp.banners, "fetch", fake_fetch)
    info = {"location": "http://192.168.1.4:80/d.xml"}
    await ssdp._enrich(info, timeout=0)
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


def _patch_endpoint(monkeypatch, responses=None, *, exc=None):
    loop = asyncio.get_running_loop()
    transport = FakeTransport()

    async def fake_cde(factory, **kw):
        if exc:
            raise exc
        proto = factory()
        if responses is not None:
            proto.responses = responses
        return transport, proto

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_cde)
    return transport


async def test_probe_endpoint_error(monkeypatch):
    _patch_endpoint(monkeypatch, exc=OSError("no multicast"))
    assert await ssdp.probe(timeout=0) == {}


async def test_probe_no_responses(monkeypatch):
    transport = _patch_endpoint(monkeypatch, responses={})
    assert await ssdp.probe(timeout=0) == {}
    assert transport.closed is True
    assert transport.sent  # the M-SEARCH was actually transmitted


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


async def test_probe_without_details(monkeypatch):
    responses = {"192.168.1.1": {"server": "x", "location": "http://192.168.1.1/d.xml"}}
    _patch_endpoint(monkeypatch, responses=responses)

    async def must_not_run(*a, **k):
        raise AssertionError("fetch should not be called when fetch_details=False")

    monkeypatch.setattr(ssdp.banners, "fetch", must_not_run)
    result = await ssdp.probe(timeout=0, fetch_details=False)
    assert result["192.168.1.1"] == {
        "server": "x", "location": "http://192.168.1.1/d.xml", "name": None, "model": None}
