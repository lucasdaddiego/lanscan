"""Tests for lanscan.vendors — MAC normalisation and OUI -> vendor lookup."""
from __future__ import annotations

import urllib.error

import pytest

from lanscan import vendors

# A tiny manuf file exercising the /24, /28 and /36 prefix tables plus the
# comment / blank / short-line skips.
_MANUF = "\n".join([
    "# a comment line",
    "",
    "00:1A:2B\tAcme24",
    "00:1A:2B:30:00:00/28\tAcme28",
    "00:1A:2B:30:40:00/36\tAcme36",
    "no-tab-here",          # < 2 fields -> skipped
    "FF:FF:FF\tBroadcastVendor",
]) + "\n"


@pytest.mark.parametrize("raw,expected", [
    (None, None),
    ("", None),
    ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"),
    ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
    ("c:ef:15:3f:e4:0", "0C:EF:15:3F:E4:00"),        # macOS zero-stripped octets
    ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),       # dash separator
    ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),            # bare 12 hex
    ("001a.2b3c.4d5e", "00:1A:2B:3C:4D:5E"),          # Cisco dotted
    ("1:2:3", None),                                  # wrong octet count
    ("zz:bb:cc:dd:ee:ff", None),                      # non-hex octet
    ("123:45:67:89:ab:cd", None),                     # octet too long
    ("aabbcc", None),                                 # bare but wrong length
])
def test_normalize_mac(raw, expected):
    assert vendors.normalize_mac(raw) == expected


def test_is_locally_administered():
    assert vendors.is_locally_administered("02:00:00:00:00:00") is True
    assert vendors.is_locally_administered("00:11:22:33:44:55") is False
    # Non-hex first octet -> ValueError swallowed -> False.
    assert vendors.is_locally_administered("ZZ:00:00:00:00:00") is False


def test_tables_empty_without_file(manuf_cache):
    # manuf_cache points at a path that does not exist yet.
    assert not manuf_cache.exists()
    assert vendors._tables() == ({}, {}, {})


def test_tables_parses_prefix_lengths(manuf_cache):
    manuf_cache.write_text(_MANUF)
    vendors._tables.cache_clear()
    o24, o28, o36 = vendors._tables()
    assert o24["001A2B"] == "Acme24"
    assert o24["FFFFFF"] == "BroadcastVendor"
    assert o28["001A2B3"] == "Acme28"
    assert o36["001A2B304"] == "Acme36"


def test_lookup_none_and_randomized(manuf_cache):
    assert vendors.lookup(None) is None
    # Locally-administered -> reported as randomized by the caller, not guessed.
    assert vendors.lookup("02:1A:2B:00:00:00") is None


def test_lookup_prefers_longest_prefix(manuf_cache):
    manuf_cache.write_text(_MANUF)
    vendors._tables.cache_clear()
    # /36 sub-allocation wins over its /28 and /24 parents.
    assert vendors.lookup("00:1A:2B:30:4F:FF") == "Acme36"
    # /28 wins over /24 when no /36 match.
    assert vendors.lookup("00:1A:2B:31:00:00") == "Acme28"
    # /24 when neither longer prefix matches.
    assert vendors.lookup("00:1A:2B:99:99:99") == "Acme24"


def test_lookup_builtin_fallback(manuf_cache):
    # No manuf file -> tables empty -> built-in map answers for known kit.
    assert vendors.lookup("B8:27:EB:11:22:33") == "Raspberry Pi"


def test_lookup_unknown_returns_none(manuf_cache):
    assert vendors.lookup("12:34:56:78:9A:BC") is None


class _FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_update_manuf_success(manuf_cache, monkeypatch):
    monkeypatch.setattr(vendors.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(_MANUF.encode()))
    ok, msg = vendors.update_manuf()
    assert ok is True
    assert manuf_cache.exists()
    # update_manuf counts raw non-comment, non-blank lines (5 here, incl. the
    # malformed "no-tab-here" line which the parser itself later skips).
    assert "5 vendor prefixes" in msg
    # Cache was cleared, so a subsequent lookup reflects the freshly written file.
    assert vendors.lookup("00:1A:2B:99:99:99") == "Acme24"


def test_update_manuf_failure(manuf_cache, monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(vendors.urllib.request, "urlopen", boom)
    ok, msg = vendors.update_manuf()
    assert ok is False
    assert "URLError" in msg
    assert not manuf_cache.exists()
