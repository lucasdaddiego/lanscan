"""Tests for lanscan.__main__ (CLI entry point) and the package __init__."""
from __future__ import annotations

import lanscan
from lanscan import __main__ as main_mod


def test_version_is_a_string():
    assert isinstance(lanscan.__version__, str)
    assert lanscan.__version__


def test_parser_defaults():
    args = main_mod._build_parser().parse_args([])
    assert args.interface is None
    assert args.kind is None
    assert args.timeout == 1.0
    assert args.interval == 30.0
    assert not any([args.no_resolve, args.no_mdns, args.no_ports, args.update_vendors])


def test_parser_all_flags():
    args = main_mod._build_parser().parse_args([
        "--interface", "en0", "--kind", "wifi", "--no-resolve", "--no-mdns",
        "--no-ports", "--timeout", "2.5", "--interval", "5", "--update-vendors",
    ])
    assert args.interface == "en0"
    assert args.kind == "wifi"
    assert args.no_resolve and args.no_mdns and args.no_ports and args.update_vendors
    assert args.timeout == 2.5
    assert args.interval == 5.0


def test_main_update_vendors_success(monkeypatch, capsys):
    monkeypatch.setattr(main_mod.vendors, "update_manuf", lambda: (True, "12 cached"))
    rc = main_mod.main(["--update-vendors"])
    assert rc == 0
    out = capsys.readouterr()
    assert "Downloading" in out.out
    assert "12 cached" in out.out


def test_main_update_vendors_failure(monkeypatch, capsys):
    monkeypatch.setattr(main_mod.vendors, "update_manuf", lambda: (False, "URLError: x"))
    rc = main_mod.main(["--update-vendors"])
    assert rc == 1
    err = capsys.readouterr()
    assert "Failed: URLError: x" in err.err


def test_main_launches_tui(monkeypatch):
    captured = {}

    def fake_run_tui(args):
        captured["args"] = args
        return 0

    # main does `from .tui import run_tui`, which binds the patched attribute.
    monkeypatch.setattr("lanscan.tui.run_tui", fake_run_tui)
    rc = main_mod.main(["--interface", "en1", "--no-mdns"])
    assert rc == 0
    assert captured["args"].interface == "en1"
    assert captured["args"].no_mdns is True
