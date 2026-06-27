"""Tests for lanscan.banners — HTTP-banner identification.

All sockets are mocked via asyncio.open_connection; nothing hits the network.
"""
from __future__ import annotations

import asyncio
import ssl

import pytest

from lanscan import banners


class FakeReader:
    def __init__(self, data=b"", read_exc=None):
        self._data = data
        self._exc = read_exc

    async def read(self, n):
        if self._exc:
            raise self._exc
        return self._data[:n]


class FakeWriter:
    def __init__(self, *, drain_exc=None, wait_exc=None):
        self.drain_exc = drain_exc
        self.wait_exc = wait_exc
        self.written = b""
        self.closed = False

    def write(self, b):
        self.written += b

    async def drain(self):
        if self.drain_exc:
            raise self.drain_exc

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self.wait_exc:
            raise self.wait_exc


def _patch_conn(monkeypatch, reader=None, writer=None, exc=None, capture=None):
    async def conn(host, port, ssl=None):
        if capture is not None:
            capture["host"], capture["port"], capture["ssl"] = host, port, ssl
        if exc:
            raise exc
        return reader, writer

    monkeypatch.setattr("asyncio.open_connection", conn)


_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.21\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<html><head><title>Router Admin</title></head></html>"
)


# ---- _tls_context ---------------------------------------------------------
def test_tls_context_permissive_and_cached():
    a = banners._tls_context()
    b = banners._tls_context()
    assert a is b                              # cached
    assert a.check_hostname is False
    assert a.verify_mode == ssl.CERT_NONE


# ---- _split_response ------------------------------------------------------
def test_split_response_ok():
    status, headers, body = banners._split_response(_RESPONSE)
    assert status == 200
    assert headers["server"] == "nginx/1.21"
    assert headers["content-type"] == "text/html"
    assert b"<title>Router Admin" in body


def test_split_response_not_http():
    assert banners._split_response(b"garbage here\r\n\r\nbody") is None


def test_split_response_bad_status():
    assert banners._split_response(b"HTTP/1.1 notnum OK\r\n\r\n") is None


def test_split_response_missing_status():
    assert banners._split_response(b"HTTP/1.1\r\n\r\n") is None


def test_split_response_skips_colonless_header_lines():
    raw = b"HTTP/1.0 204 No Content\r\nX-Garbage-No-Colon\r\nServer: x\r\n\r\n"
    status, headers, _ = banners._split_response(raw)
    assert status == 204
    assert headers == {"server": "x"}


# ---- _title ---------------------------------------------------------------
@pytest.mark.parametrize("body,expected", [
    (b"<title>Hello</title>", "Hello"),
    (b"<TITLE>\n  My   Device \n</TITLE>", "My Device"),   # collapsed whitespace
    (b"<html>no title here</html>", None),
    (b"<title></title>", None),                            # empty
])
def test_title(body, expected):
    assert banners._title(body) == expected


# ---- fetch ----------------------------------------------------------------
async def test_fetch_ok(monkeypatch):
    writer = FakeWriter()
    _patch_conn(monkeypatch, reader=FakeReader(_RESPONSE), writer=writer)
    status, headers, body = await banners.fetch("1.2.3.4", 80)
    assert status == 200
    assert headers["server"] == "nginx/1.21"
    assert writer.closed is True
    assert b"GET / HTTP/1.0" in writer.written


async def test_fetch_connect_error(monkeypatch):
    _patch_conn(monkeypatch, exc=OSError("refused"))
    assert await banners.fetch("1.2.3.4", 80) is None


async def test_fetch_connect_timeout(monkeypatch):
    _patch_conn(monkeypatch, exc=asyncio.TimeoutError())
    assert await banners.fetch("1.2.3.4", 80) is None


async def test_fetch_drain_error(monkeypatch):
    _patch_conn(monkeypatch, reader=FakeReader(_RESPONSE),
                writer=FakeWriter(drain_exc=OSError("broken pipe")))
    assert await banners.fetch("1.2.3.4", 80) is None


async def test_fetch_read_error(monkeypatch):
    _patch_conn(monkeypatch, reader=FakeReader(read_exc=OSError("reset")),
                writer=FakeWriter())
    assert await banners.fetch("1.2.3.4", 80) is None


async def test_fetch_wait_closed_error_suppressed(monkeypatch):
    _patch_conn(monkeypatch, reader=FakeReader(_RESPONSE),
                writer=FakeWriter(wait_exc=OSError("reset")))
    res = await banners.fetch("1.2.3.4", 80)
    assert res[0] == 200       # the close-time error is swallowed


async def test_fetch_tls_passes_context(monkeypatch):
    cap = {}
    _patch_conn(monkeypatch, reader=FakeReader(_RESPONSE), writer=FakeWriter(), capture=cap)
    await banners.fetch("1.2.3.4", 443, tls=True)
    assert cap["ssl"] is banners._tls_context()


async def test_fetch_no_tls_passes_none(monkeypatch):
    cap = {}
    _patch_conn(monkeypatch, reader=FakeReader(_RESPONSE), writer=FakeWriter(), capture=cap)
    await banners.fetch("1.2.3.4", 80)
    assert cap["ssl"] is None


# ---- identify -------------------------------------------------------------
async def test_identify_no_web_port():
    assert await banners.identify("1.2.3.4", [22, 445]) == (None, None)


async def test_identify_success(monkeypatch):
    async def fake_fetch(ip, port, **kw):
        assert port == 80
        return 200, {"server": "lighttpd"}, b"<title>My NAS</title>"

    monkeypatch.setattr(banners, "fetch", fake_fetch)
    assert await banners.identify("1.2.3.4", [22, 80]) == ("lighttpd", "My NAS")


async def test_identify_fetch_fails(monkeypatch):
    async def fake_fetch(ip, port, **kw):
        return None

    monkeypatch.setattr(banners, "fetch", fake_fetch)
    assert await banners.identify("1.2.3.4", [8080]) == (None, None)


async def test_identify_server_header_absent(monkeypatch):
    async def fake_fetch(ip, port, **kw):
        return 200, {}, b"<title>Cam</title>"

    monkeypatch.setattr(banners, "fetch", fake_fetch)
    assert await banners.identify("1.2.3.4", [443]) == (None, "Cam")
