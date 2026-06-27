"""Command-line entry point for lanscan.

Launches the live TUI. `--update-vendors` downloads the IEEE/Wireshark vendor DB
and exits. Export of the current device list is done from inside the TUI (press
`e`).
"""
from __future__ import annotations

import argparse
import sys

from . import vendors


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lanscan",
        description="Discover devices on your local LAN (Wi-Fi + Ethernet) — live TUI.",
    )
    p.add_argument("--interface", metavar="DEV",
                   help="restrict to one interface device, e.g. en0")
    p.add_argument("--kind", choices=("wifi", "ethernet"),
                   help="restrict to Wi-Fi or Ethernet interfaces only")
    p.add_argument("--no-resolve", action="store_true",
                   help="skip reverse-DNS hostname lookups")
    p.add_argument("--no-mdns", action="store_true",
                   help="skip mDNS/Bonjour device identification")
    p.add_argument("--no-ports", action="store_true",
                   help="skip the per-device open-port scan")
    p.add_argument("--no-ssdp", action="store_true",
                   help="skip SSDP/UPnP device identification")
    p.add_argument("--no-http", action="store_true",
                   help="skip HTTP-banner device identification")
    p.add_argument("--no-history", action="store_true",
                   help="don't persist device history across runs")
    p.add_argument("--timeout", type=float, default=1.0, metavar="SECS",
                   help="per-host probe timeout (default: 1.0)")
    p.add_argument("--interval", type=float, default=30.0, metavar="SECS",
                   help="auto-rescan interval (default: 30)")
    p.add_argument("--update-vendors", action="store_true",
                   help="download the Wireshark MAC vendor database, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.update_vendors:
        print("Downloading Wireshark MAC vendor database…")
        ok, msg = vendors.update_manuf()
        print(msg if ok else f"Failed: {msg}", file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1

    from .tui import run_tui
    return run_tui(args)


if __name__ == "__main__":
    raise SystemExit(main())
