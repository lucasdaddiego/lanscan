"""Tests for lanscan.ports — the per-device TCP connect scans.

`asyncio.open_connection` is mocked throughout, so no real sockets are opened.
"""
import asyncio
import errno

import pytest

from lanscan import ports


class FakeWriter:
    def __init__(self, wait_exc=None):
        self.closed = False
        self._wait_exc = wait_exc

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self._wait_exc:
            raise self._wait_exc


def _sem():
    return asyncio.Semaphore(8)


def test_port_tables_are_consistent():
    # Every named port has a category, and every web port has a name.
    assert set(ports.PORT_NAMES.values()) <= set(ports.PORT_CATEGORY)
    web = (*ports.HTTP_PORTS, *ports.HTTPS_PORTS)
    assert set(web) <= set(ports.PORT_NAMES)
    assert len(set(web)) == len(web)                       # no duplicates
    assert set(ports.PORT_NAMES) <= set(ports.COMMON_PORTS)  # names only for scanned ports


async def test_open_ports_bounded_by_semaphore(monkeypatch):
    sem = asyncio.Semaphore(2)
    peak = {"now": 0, "max": 0}

    async def fake_check(ip, port, timeout):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        await asyncio.sleep(0)
        peak["now"] -= 1
        return True

    monkeypatch.setattr(ports, "_check_one", fake_check)
    assert await ports.open_ports("1.2.3.4", 0.1, sem, ports=(1, 2, 3, 4, 5)) == [1, 2, 3, 4, 5]
    assert peak["max"] <= 2


async def _no_sleep(*a, **k):
    """Drop-in for asyncio.sleep so retry backoff is instant in tests."""
    return None


# ---- open_ports -----------------------------------------------------------
async def test_open_ports_returns_sorted_open(monkeypatch):
    async def fake_check(ip, port, timeout):
        return port in {22, 443}

    monkeypatch.setattr(ports, "_check_one", fake_check)
    res = await ports.open_ports("1.2.3.4", 0.1, _sem(), ports=(80, 443, 22))
    assert res == [443, 22]  # order follows the input tuple, filtered to open


# ---- raise_fd_limit -------------------------------------------------------
def test_raise_fd_limit_bumps_soft(monkeypatch):
    calls = {}
    monkeypatch.setattr(ports.resource, "getrlimit", lambda res: (1024, 8192))
    monkeypatch.setattr(ports.resource, "setrlimit",
                        lambda res, lim: calls.setdefault("lim", lim))
    assert ports.raise_fd_limit(4096) == 4096
    assert calls["lim"] == (4096, 8192)


def test_raise_fd_limit_infinite_hard(monkeypatch):
    monkeypatch.setattr(ports.resource, "getrlimit",
                        lambda res: (1024, ports.resource.RLIM_INFINITY))
    monkeypatch.setattr(ports.resource, "setrlimit", lambda res, lim: None)
    assert ports.raise_fd_limit(4096) == 4096


def test_raise_fd_limit_already_high(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(ports.resource, "getrlimit", lambda res: (8192, 8192))

    def _set(res, lim):
        called["n"] += 1

    monkeypatch.setattr(ports.resource, "setrlimit", _set)
    assert ports.raise_fd_limit(4096) == 8192
    assert called["n"] == 0  # already above target -> no change attempted


def test_raise_fd_limit_setrlimit_fails(monkeypatch):
    monkeypatch.setattr(ports.resource, "getrlimit", lambda res: (1024, 8192))

    def _boom(res, lim):
        raise OSError("not permitted")

    monkeypatch.setattr(ports.resource, "setrlimit", _boom)
    assert ports.raise_fd_limit(4096) == 1024  # unchanged on failure


# ---- _check_one (with retry on local resource exhaustion) -----------------
def _seq_conn(behaviors):
    """open_connection that yields a different behavior per call."""
    state = {"i": 0}

    async def _conn(host, port, **kw):
        b = behaviors[state["i"]]
        state["i"] += 1
        if isinstance(b, BaseException):
            raise b
        return (object(), b)

    return _conn, state


async def test_check_one_success(monkeypatch):
    conn, state = _seq_conn([FakeWriter()])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is True
    assert state["i"] == 1


async def test_check_one_success_wait_closed_oserror(monkeypatch):
    # A reset while closing the probe socket is swallowed; the port is still open.
    conn, _ = _seq_conn([FakeWriter(wait_exc=OSError("reset"))])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is True


@pytest.mark.parametrize("exc", [ConnectionRefusedError(), TimeoutError()])
async def test_check_one_refused_or_timeout(monkeypatch, exc):
    conn, _ = _seq_conn([exc])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is False


async def test_check_one_non_retryable_oserror(monkeypatch):
    conn, state = _seq_conn([OSError(errno.EPERM, "nope")])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is False
    assert state["i"] == 1  # not retried


async def test_check_one_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _no_sleep)
    conn, state = _seq_conn([OSError(errno.EMFILE, "too many"), FakeWriter()])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is True
    assert state["i"] == 2  # retried once, then connected


async def test_check_one_retries_exhausted(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _no_sleep)
    conn, state = _seq_conn([OSError(errno.EMFILE, "too many") for _ in range(3)])
    monkeypatch.setattr("asyncio.open_connection", conn)
    assert await ports._check_one("1.2.3.4", 80, 0.1) is False
    assert state["i"] == 3  # three attempts, all resource-exhausted


# ---- full_scan ------------------------------------------------------------
async def test_full_scan_with_progress(monkeypatch):
    open_set = {22, 80, 443}

    async def fake_check(ip, port, timeout):
        return port in open_set

    monkeypatch.setattr(ports, "_check_one", fake_check)
    seen = []
    found = await ports.full_scan("1.2.3.4", timeout=0.01, concurrency=64,
                                  progress=lambda d, t: seen.append((d, t)))
    assert found == [22, 80, 443]
    assert seen[-1] == (65535, 65535)  # final progress pulse
    assert len(seen) > 1               # periodic pulses fired too


async def test_full_scan_without_progress(monkeypatch):
    async def fake_check(ip, port, timeout):
        return port == 8080

    monkeypatch.setattr(ports, "_check_one", fake_check)
    found = await ports.full_scan("1.2.3.4", timeout=0.01, concurrency=32)
    assert found == [8080]
