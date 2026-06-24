"""MAC normalisation and OUI -> vendor lookup.

Lookup order: cached Wireshark `manuf` database (fetched on demand via
`--update-vendors`) -> small built-in map of common vendors -> Unknown.
Locally-administered addresses (randomised privacy MACs) are reported as such
rather than guessed, since their OUI is meaningless.
"""
from __future__ import annotations

import os
import re
import urllib.request
from functools import lru_cache
from pathlib import Path

from platformdirs import user_cache_dir

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
_CACHE_DIR = Path(user_cache_dir("lanscan"))
_MANUF_PATH = _CACHE_DIR / "manuf"

# Small, high-confidence fallback so common kit is labelled even before the full
# IEEE database is fetched. Keyed by the 24-bit OUI (upper, colon-separated).
_BUILTIN: dict[str, str] = {
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "00:1A:11": "Google",
    "F4:F5:E8": "Google",
    "18:B4:30": "Nest Labs",
    "FC:65:DE": "Amazon",
    "44:65:0D": "Amazon",
    "68:37:E9": "Amazon",
    "00:0E:58": "Sonos",
    "B8:E9:37": "Sonos",
    "94:9F:3E": "Sonos",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "B0:7F:B9": "Netgear",
    "00:1D:D8": "Microsoft",
}

_NON_HEX = re.compile(r"[^0-9a-fA-F]")
_HEXSET = frozenset("0123456789abcdefABCDEF")


def normalize_mac(raw: str | None) -> str | None:
    """'c:ef:15:3f:e4:0' -> '0C:EF:15:3F:E4:00'. None for incomplete/invalid.

    macOS `arp` prints octets without leading zeros, so we must zero-pad each
    octet individually — stripping separators and counting nibbles would mangle
    any MAC containing a single-digit octet.
    """
    if not raw:
        return None
    raw = raw.strip()
    for sep in (":", "-"):
        if sep in raw:
            parts = raw.split(sep)
            if len(parts) == 6 and all(1 <= len(p) <= 2 and all(c in _HEXSET for c in p)
                                       for p in parts):
                return ":".join(p.rjust(2, "0") for p in parts).upper()
            return None
    hexs = _NON_HEX.sub("", raw)  # bare 12-hex or dotted xxxx.xxxx.xxxx
    if len(hexs) == 12:
        return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).upper()
    return None


def is_locally_administered(mac: str) -> bool:
    """True for randomised / privacy MACs (the 0x02 bit of the first octet)."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


@lru_cache(maxsize=1)
def _tables() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Parse the cached manuf file into (oui24, oui28, oui36) hex-prefix maps.

    Longer-prefix tables (MA-M /28, MA-S /36 sub-allocations) are consulted
    before the /24 table so a sub-allocated block wins over its parent.
    """
    o24: dict[str, str] = {}
    o28: dict[str, str] = {}
    o36: dict[str, str] = {}
    if not _MANUF_PATH.exists():
        return o24, o28, o36
    for line in _MANUF_PATH.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix, name = parts[0].strip(), parts[1].strip()
        mask = 24
        if "/" in prefix:
            prefix, _, m = prefix.partition("/")
            mask = int(m)
        nibbles = _NON_HEX.sub("", prefix).upper()
        if mask >= 36:
            o36[nibbles[:9]] = name
        elif mask >= 28:
            o28[nibbles[:7]] = name
        else:
            o24[nibbles[:6]] = name
    return o24, o28, o36


def lookup(mac: str | None) -> str | None:
    """Vendor name for a (normalised) MAC, or None if unknown/randomised."""
    if not mac:
        return None
    if is_locally_administered(mac):
        return None  # caller flags this as a private/randomised MAC
    hexs = _NON_HEX.sub("", mac).upper()
    o24, o28, o36 = _tables()
    if (v := o36.get(hexs[:9])):
        return v
    if (v := o28.get(hexs[:7])):
        return v
    if (v := o24.get(hexs[:6])):
        return v
    return _BUILTIN.get(mac[:8].upper())


def update_manuf() -> tuple[bool, str]:
    """Download the Wireshark manuf database to the cache. Outward network call;
    only invoked via the explicit --update-vendors flag."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _MANUF_PATH.with_suffix(".tmp")
    try:
        req = urllib.request.Request(MANUF_URL, headers={"User-Agent": "lanscan"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        tmp.write_bytes(data)
        os.replace(tmp, _MANUF_PATH)
    except Exception as exc:  # noqa: BLE001 - report any fetch/IO failure to the user
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        _tables.cache_clear()
    n = sum(1 for line in _MANUF_PATH.read_text(errors="replace").splitlines()
            if line and not line.startswith("#"))
    return True, f"{n:,} vendor prefixes cached at {_MANUF_PATH}"
