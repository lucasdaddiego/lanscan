"""Headless one-shot scan — `lanscan --once [--json]`.

Runs what the TUI's scan worker runs (interface discovery, vendor preload, an
optional mDNS warm-up, `engine.scan`, the history merge) exactly once, prints
the device list and exits. Exit codes follow the sibling scanners: 0 ok,
1 runtime error, 3 no interface to scan (a usage error is argparse's 2).
"""
import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, TextIO

from rich.cells import cell_len

from . import __version__, history, net, vendors
from .engine import scan
from .models import Device, Interface

if TYPE_CHECKING:  # imported lazily at runtime so --no-mdns never loads zeroconf
    from .discovery import MdnsDiscovery

EXIT_OK, EXIT_ERROR, EXIT_NO_SOURCE = 0, 1, 3
# Seconds the mDNS browser runs before the sweep, as before the TUI's first scan.
MDNS_WARMUP = 1.2


async def _gather(args: argparse.Namespace) -> tuple[list[Interface], list[Device]]:
    ifaces = net.discover_interfaces(only_device=args.interface, only_kind=args.kind)
    if not ifaces:
        return [], []
    mdns: MdnsDiscovery | None = None
    if not args.no_mdns:
        from .discovery import MdnsDiscovery
        try:
            mdns = MdnsDiscovery()
            await mdns.start()
        except Exception:  # mDNS is optional, as in the TUI
            mdns = None
    try:
        await vendors.preload()
        if mdns is not None:
            await asyncio.sleep(MDNS_WARMUP)
        devices = await scan(
            ifaces, resolve=not args.no_resolve, mdns=mdns,
            ssdp_enabled=not args.no_ssdp, scan_ports=not args.no_ports,
            http_id=not args.no_http, timeout=args.timeout)
    finally:
        if mdns is not None:
            await mdns.stop()
    # History owns first_seen / ever_seen / remembered_name; --no-history keeps
    # the file untouched (every device then simply reads as new).
    records = {} if args.no_history else history.load()
    records = history.merge(records, devices)
    if not args.no_history:
        history.save(records)
    return ifaces, devices


def _cell(text: str, width: int) -> str:
    """Pad / truncate to `width` terminal columns (ellipsis when cut). Counts
    cells, not characters: a CJK name is two columns per character, and a wide
    character that would straddle the cut is dropped."""
    if cell_len(text) > width:
        # The text is wider than `width`, so this stops before running off its end.
        cut = used = 0
        while used + cell_len(text[cut]) <= width - 1:
            used += cell_len(text[cut])
            cut += 1
        text = text[:cut] + "…"
    return text + " " * (width - cell_len(text))


def _print_table(devices: list[Device], out: TextIO) -> None:
    print(f"{_cell('IP', 16)} {_cell('MAC', 18)} {_cell('VENDOR', 20)} "
          f"{_cell('NAME', 30)} PORTS", file=out)
    for d in devices:
        vendor = d.vendor or ("private MAC" if d.randomized_mac else "?")
        name = d.name
        if d.tags:
            name = f"{name} ({', '.join(d.tags)})" if name else f"({', '.join(d.tags)})"
        ports = ",".join(map(str, d.open_ports))
        print(f"{_cell(d.ip, 16)} {_cell(d.mac or '', 18)} {_cell(vendor, 20)} "
              f"{_cell(name, 30)} {ports}".rstrip(), file=out)


def document(ifaces: list[Interface], devices: list[Device]) -> dict[str, object]:
    """The JSON document `--once --json` prints and the TUI's `e` export writes:
    ``version``, ``ts`` (UTC, ISO-8601), ``interfaces`` and ``devices``."""
    return {
        "version": __version__,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "interfaces": [asdict(i) for i in ifaces],
        "devices": [d.as_dict() for d in devices],
    }


def _print_json(ifaces: list[Interface], devices: list[Device], out: TextIO) -> None:
    json.dump(document(ifaces, devices), out, indent=2)
    out.write("\n")


def run_once(args: argparse.Namespace, out: TextIO = sys.stdout,
             err: TextIO = sys.stderr) -> int:
    """Scan once and print the devices; returns the process exit code."""
    try:
        ifaces, devices = asyncio.run(_gather(args))
    except Exception as exc:  # a scan error is a runtime failure, not a crash
        print(f"lanscan: scan failed: {exc}", file=err)
        return EXIT_ERROR
    if not ifaces:
        print("lanscan: no active Wi-Fi/Ethernet interface to scan", file=err)
        return EXIT_NO_SOURCE
    if args.json:
        _print_json(ifaces, devices, out)
    else:
        _print_table(devices, out)
    return EXIT_OK
