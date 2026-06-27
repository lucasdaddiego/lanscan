"""Tests for lanscan.launch — deciding how to connect to an open port."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lanscan import launch

IP = "1.2.3.4"


@pytest.mark.parametrize("port,service,expected", [
    # HTTPS — by port (default + non-default) and by service prefix.
    (443, None, ("open", "https://1.2.3.4", "browser (HTTPS)")),
    (8443, None, ("open", "https://1.2.3.4:8443", "browser (HTTPS)")),
    (9999, "https-alt", ("open", "https://1.2.3.4:9999", "browser (HTTPS)")),
    # HTTP — by port (default + non-default) and by service membership.
    (80, None, ("open", "http://1.2.3.4", "browser")),
    (8080, None, ("open", "http://1.2.3.4:8080", "browser")),
    (9999, "jellyfin", ("open", "http://1.2.3.4:9999", "browser")),
    # Shell-oriented.
    (22, None, ("terminal", "ssh 1.2.3.4", "ssh")),
    (9999, "ssh", ("terminal", "ssh 1.2.3.4", "ssh")),
    (23, None, ("terminal", "telnet 1.2.3.4 23", "telnet")),
    (9999, "telnet", ("terminal", "telnet 1.2.3.4 9999", "telnet")),
    # File / screen / media — URL schemes.
    (21, None, ("open", "ftp://1.2.3.4", "Finder (FTP)")),
    (9999, "ftp", ("open", "ftp://1.2.3.4:9999", "Finder (FTP)")),
    (445, None, ("open", "smb://1.2.3.4", "Finder (SMB)")),
    (9999, "smb", ("open", "smb://1.2.3.4", "Finder (SMB)")),
    (548, None, ("open", "afp://1.2.3.4", "Finder (AFP)")),
    (9999, "afp", ("open", "afp://1.2.3.4", "Finder (AFP)")),
    (5900, None, ("open", "vnc://1.2.3.4", "Screen Sharing (VNC)")),
    (9999, "vnc", ("open", "vnc://1.2.3.4", "Screen Sharing (VNC)")),
    (554, None, ("open", "rtsp://1.2.3.4", "media player (RTSP)")),
    (9999, "rtsp", ("open", "rtsp://1.2.3.4:9999", "media player (RTSP)")),
    # Unknown -> netcat probe.
    (9999, None, ("terminal", "nc -v 1.2.3.4 9999", "nc probe")),
    (9999, "weird", ("terminal", "nc -v 1.2.3.4 9999", "nc probe")),
])
def test_plan(port, service, expected):
    assert launch.plan(IP, port, service) == expected


def test_describe_is_plan_label():
    assert launch.describe(IP, 443, None) == "browser (HTTPS)"


def test_launch_open(monkeypatch):
    spawned = []
    monkeypatch.setattr(launch, "_spawn", lambda argv: spawned.append(argv))
    ok, msg = launch.launch(IP, 80, None)
    assert ok is True
    assert spawned == [["open", "http://1.2.3.4"]]
    assert msg == "browser → http://1.2.3.4"


def test_launch_terminal(monkeypatch):
    # Force the terminal choice so the message is deterministic.
    monkeypatch.setattr(launch.os, "environ", {"TERM_PROGRAM": "Apple_Terminal"})
    spawned = []
    monkeypatch.setattr(launch, "_spawn", lambda argv: spawned.append(argv))
    ok, msg = launch.launch(IP, 22, "ssh")
    assert ok is True
    assert spawned and spawned[0][0] == "osascript"
    assert msg == "ssh → ssh 1.2.3.4  · Terminal"


def test_launch_failure(monkeypatch):
    def boom(argv):
        raise RuntimeError("nope")

    monkeypatch.setattr(launch, "_spawn", boom)
    ok, msg = launch.launch(IP, 80, None)
    assert ok is False
    assert "couldn't launch" in msg


def test_spawn_uses_popen(monkeypatch):
    popen = MagicMock()
    monkeypatch.setattr(launch.subprocess, "Popen", popen)
    launch._spawn(["open", "x"])
    args, kwargs = popen.call_args
    assert args[0] == ["open", "x"]
    assert kwargs["stdout"] == launch.subprocess.DEVNULL
    assert kwargs["stderr"] == launch.subprocess.DEVNULL


def test_have(monkeypatch):
    monkeypatch.setattr(launch.os.path, "isdir",
                        lambda p: p == "/Applications/Ghostty.app")
    assert launch._have("Ghostty") is True
    assert launch._have("iTerm") is False
    assert launch._have("iTerm", "Ghostty") is True


@pytest.mark.parametrize("environ,expected", [
    ({"TERM_PROGRAM": "ghostty"}, "ghostty"),
    ({"TERM_PROGRAM": "xterm", "GHOSTTY_BIN_DIR": "/x"}, "ghostty"),
    ({"TERM_PROGRAM": "iTerm.app"}, "iterm"),
    ({"TERM_PROGRAM": "Apple_Terminal"}, "terminal"),
])
def test_pick_terminal_from_env(monkeypatch, environ, expected):
    monkeypatch.setattr(launch.os, "environ", environ)
    assert launch._pick_terminal() == expected


@pytest.mark.parametrize("installed,expected", [
    ("Ghostty", "ghostty"),
    ("iTerm", "iterm"),
    (None, "terminal"),
])
def test_pick_terminal_fallback_to_installed(monkeypatch, installed, expected):
    monkeypatch.setattr(launch.os, "environ", {})  # no TERM_PROGRAM, no GHOSTTY_*
    monkeypatch.setattr(launch, "_have", lambda *names: installed in names)
    assert launch._pick_terminal() == expected


def test_terminal_argv_ghostty(monkeypatch):
    monkeypatch.setattr(launch.os, "environ",
                        {"TERM_PROGRAM": "ghostty", "SHELL": "/bin/zsh"})
    argv, name = launch._terminal_argv("ssh 1.2.3.4")
    assert name == "Ghostty"
    assert argv[:5] == ["open", "-nb", launch._GHOSTTY_BUNDLE_ID, "--args", "-e"]
    inner = argv[-1]
    assert inner.startswith("ssh 1.2.3.4; exec ")
    assert "/bin/zsh" in inner and inner.endswith("-il")


def test_terminal_argv_ghostty_default_shell(monkeypatch):
    # No $SHELL -> falls back to /bin/zsh.
    monkeypatch.setattr(launch.os, "environ", {"TERM_PROGRAM": "ghostty"})
    argv, _ = launch._terminal_argv("nc -v 1.2.3.4 9")
    assert "/bin/zsh" in argv[-1]


def test_terminal_argv_iterm(monkeypatch):
    monkeypatch.setattr(launch.os, "environ", {"TERM_PROGRAM": "iTerm.app"})
    argv, name = launch._terminal_argv("ssh 1.2.3.4")
    assert name == "iTerm"
    assert argv[0] == "osascript"
    assert 'tell application "iTerm"' in argv[2]


def test_terminal_argv_terminal(monkeypatch):
    monkeypatch.setattr(launch.os, "environ", {"TERM_PROGRAM": "Apple_Terminal"})
    argv, name = launch._terminal_argv("ssh 1.2.3.4")
    assert name == "Terminal"
    assert argv[0] == "osascript"
    assert 'tell application "Terminal"' in argv[2]


def test_terminal_script_escapes_quotes_and_backslashes():
    script = launch._terminal_script('say "hi" C:\\x', "terminal")
    # Backslash doubled, double-quotes backslash-escaped.
    assert 'say \\"hi\\" C:\\\\x' in script
    assert 'do script' in script


def test_terminal_script_iterm_variant():
    script = launch._terminal_script("ssh host", "iterm")
    assert "create window with default profile" in script
