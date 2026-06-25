"""Open a connection to a device's open port using the right local tool.

Web ports open in the default browser; file-sharing / screen-sharing / media
ports open via their macOS URL scheme (`open smb://…` etc.); shell-oriented and
unknown ports open a new Terminal/iTerm window running the relevant CLI so the
user can interact. Everything is best-effort and never raises into the TUI.
"""
from __future__ import annotations

import os
import subprocess

# Ports whose service is plain HTTP (browser, no TLS). Anything web-ish but not
# in the HTTPS set lands here.
_HTTP_PORTS = {80, 3000, 5000, 5173, 8000, 8008, 8080, 8081, 8086, 8096, 8123,
               8888, 9000, 9090, 32400}
_HTTP_SVC = {"http", "http-alt", "dev-http", "vite", "cast", "jellyfin", "plex",
             "home-assistant", "influxdb", "prometheus", "upnp"}
_HTTPS_PORTS = {443, 8443}
# Default port per URL scheme, so e.g. :80 drops the redundant suffix.
_SCHEME_DEFAULT = {"http": 80, "https": 443, "ftp": 21, "smb": 445, "afp": 548,
                   "vnc": 5900, "rtsp": 554}


def plan(ip: str, port: int, service: str | None) -> tuple[str, str, str]:
    """Decide how to connect. Returns (kind, target, label):

      kind == "open"     → run `open <target>` (target is a URL/scheme)
      kind == "terminal" → run <target> in a fresh terminal window
    """
    s = (service or "").lower()

    def url(scheme: str) -> str:
        host = ip if port == _SCHEME_DEFAULT.get(scheme) else f"{ip}:{port}"
        return f"{scheme}://{host}"

    if port in _HTTPS_PORTS or s.startswith("https"):
        return ("open", url("https"), "browser (HTTPS)")
    if port in _HTTP_PORTS or s in _HTTP_SVC:
        return ("open", url("http"), "browser")
    if port == 22 or s == "ssh":
        return ("terminal", f"ssh {ip}", "ssh")
    if port == 23 or s == "telnet":
        return ("terminal", f"telnet {ip} {port}", "telnet")
    if port == 21 or s == "ftp":
        return ("open", url("ftp"), "Finder (FTP)")
    if port == 445 or s == "smb":
        return ("open", f"smb://{ip}", "Finder (SMB)")
    if port == 548 or s == "afp":
        return ("open", f"afp://{ip}", "Finder (AFP)")
    if port == 5900 or s == "vnc":
        return ("open", f"vnc://{ip}", "Screen Sharing (VNC)")
    if port == 554 or s == "rtsp":
        return ("open", url("rtsp"), "media player (RTSP)")
    # Unknown / non-URL service: a verbose netcat probe the user can interact with.
    return ("terminal", f"nc -v {ip} {port}", "nc probe")


def describe(ip: str, port: int, service: str | None) -> str:
    """Short label for what launching this port will do (for the picker)."""
    return plan(ip, port, service)[2]


def launch(ip: str, port: int, service: str | None) -> tuple[bool, str]:
    """Best-effort launch of a connection. Returns (ok, human message)."""
    kind, target, label = plan(ip, port, service)
    try:
        if kind == "open":
            _spawn(["open", target])
        else:
            _spawn(["osascript", "-e", _terminal_script(target)])
        return True, f"{label} → {target}"
    except Exception as exc:  # noqa: BLE001 - never raise into the TUI
        return False, f"couldn't launch: {exc}"


def _spawn(argv: list[str]) -> None:
    subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _terminal_script(command: str) -> str:
    """AppleScript that opens a new Terminal/iTerm window running `command`.

    Prefers iTerm when installed (a strong signal it's the user's terminal).
    `command` is escaped for a double-quoted AppleScript string (backslash first,
    then quote) so a path/arg with a quote can't break out of the literal.
    """
    safe = command.replace("\\", "\\\\").replace('"', '\\"')
    if os.path.isdir("/Applications/iTerm.app"):
        return (
            'tell application "iTerm"\n'
            "  activate\n"
            "  set w to (create window with default profile)\n"
            f'  tell current session of w to write text "{safe}"\n'
            "end tell"
        )
    return (
        'tell application "Terminal"\n'
        "  activate\n"
        f'  do script "{safe}"\n'
        "end tell"
    )
