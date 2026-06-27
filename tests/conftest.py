"""Shared fixtures and helpers for the lanscan test suite.

Everything the package shells out to (ping/arp/ifconfig/networksetup/route, the
network, mDNS) is mocked, so the suite runs hermetically on any platform — no
root, no LAN, no macOS required.
"""
from __future__ import annotations

import argparse

import pytest


def make_args(**over) -> argparse.Namespace:
    """A parsed-args namespace with test-friendly defaults (mDNS/ports off)."""
    ns = argparse.Namespace(
        interface=None,
        kind=None,
        no_resolve=False,
        no_mdns=True,
        no_ports=True,
        timeout=1.0,
        interval=30.0,
        update_vendors=False,
    )
    for key, value in over.items():
        setattr(ns, key, value)
    return ns


@pytest.fixture
def args():
    return make_args()


@pytest.fixture
def manuf_cache(tmp_path, monkeypatch):
    """Point the vendors module's manuf cache at a writable temp file and clear
    its lru_cache, so tests never touch the real user cache dir."""
    from lanscan import vendors

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    path = cache_dir / "manuf"
    monkeypatch.setattr(vendors, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(vendors, "_MANUF_PATH", path)
    vendors._tables.cache_clear()
    yield path
    vendors._tables.cache_clear()
