"""Command-line entry point for lanscan.

Launches the live TUI by default. `--once` scans a single time and prints the
device list (a text table, or a JSON document with `--json`) for scripts and
cron; `--update-vendors` downloads the IEEE/Wireshark vendor DB and exits. The
TUI can also export its current list (press `e`).
"""
import argparse
import sys

from . import __version__, vendors


def _number(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}") from None


def _positive(text: str) -> float:
    value = _number(text)
    if not value > 0:  # also rejects nan
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _non_negative(text: str) -> float:
    value = _number(text)
    if not value >= 0:  # also rejects nan
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


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
                   help="skip the per-device open-port scan (also disables HTTP-banner "
                        "identification, which needs a known-open web port)")
    p.add_argument("--no-ssdp", action="store_true",
                   help="skip SSDP/UPnP device identification")
    p.add_argument("--no-http", action="store_true",
                   help="skip HTTP-banner device identification")
    p.add_argument("--no-history", action="store_true",
                   help="don't persist device history across runs")
    p.add_argument("--timeout", type=_non_negative, default=1.0, metavar="SECS",
                   help="per-host probe timeout (default: 1.0)")
    p.add_argument("--interval", type=_positive, default=30.0, metavar="SECS",
                   help="auto-rescan interval (default: 30)")
    p.add_argument("--update-vendors", action="store_true",
                   help="download the Wireshark MAC vendor database, then exit")
    p.add_argument("--once", action="store_true",
                   help="scan once, print the device list and exit (no TUI); "
                        "exit 3 when there is no interface to scan")
    p.add_argument("--json", action="store_true",
                   help="with --once: print a JSON document (version, ts, interfaces, "
                        "devices) instead of a table")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.json and not args.once:
        parser.error("--json requires --once")  # exits 2

    if args.update_vendors:
        print("Downloading Wireshark MAC vendor database…")
        ok, msg = vendors.update_manuf()
        print(msg if ok else f"Failed: {msg}", file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1

    if args.once:
        from .oneshot import run_once
        return run_once(args)

    from .tui import run_tui
    return run_tui(args)


if __name__ == "__main__":
    raise SystemExit(main())
