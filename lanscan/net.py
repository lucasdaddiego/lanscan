"""Interface discovery and subnet math (macOS + Linux).

Enumerates the Wi-Fi and Ethernet ports that currently have an IPv4 address, so
the scanner targets real LAN segments and ignores VM/Docker bridges and other
virtual interfaces. Re-running this each scan cycle is what gives us Ethernet
hotplug: a dongle that gets an address simply shows up next round.

macOS reads `networksetup`/`ifconfig`/`route`; Linux reads `ip` and
`/proc/net/wireless`. The orchestrator (`discover_interfaces`) is shared — only
the three data sources (ports, interface facts, gateway) dispatch per platform.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys

import ifaddr

from .models import Interface


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


# Hardware-port name -> our coarse "kind". We classify by the friendly port name
# reported by `networksetup`, which cleanly separates Wi-Fi/Ethernet from the
# Thunderbolt *Bridge* and any virtual interfaces (which never appear here).
_WIFI_HINTS = ("wi-fi", "airport", "wireless")
_ETH_HINTS = ("ethernet", "thunderbolt", "lan", "usb 10")


def _classify(port: str) -> str | None:
    p = port.lower()
    if "bridge" in p:  # Thunderbolt Bridge etc. — skip
        return None
    if any(h in p for h in _WIFI_HINTS):
        return "wifi"
    if any(h in p for h in _ETH_HINTS):
        return "ethernet"
    return None


def _hardware_ports() -> dict[str, tuple[str, str]]:
    """device -> (friendly port name, kind). Re-read each scan so a newly
    plugged-in adapter (a brand-new port) is picked up, not just new addresses."""
    return _hardware_ports_linux() if _is_linux() else _hardware_ports_macos()


def _hardware_ports_macos() -> dict[str, tuple[str, str]]:
    try:
        out = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    ports: dict[str, tuple[str, str]] = {}
    port = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            device = line.split(":", 1)[1].strip()
            kind = _classify(port)
            if device and kind:
                ports[device] = (port, kind)
            port = None
    return ports


def _read_text(path: str) -> str:
    """Best-effort read of a /proc or /sys file; empty string if unreadable."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _wireless_devices_linux() -> set[str]:
    """Wi-Fi device names, from the kernel's `/proc/net/wireless` table (whose
    data rows are `<dev>: ...`). Devices not listed here are treated as wired."""
    devices: set[str] = set()
    for line in _read_text("/proc/net/wireless").splitlines():
        name, sep, _ = line.partition(":")
        if sep:
            devices.add(name.strip())
    return devices


def _parse_ip_link(out: str) -> list[tuple[str, str | None, str | None, bool]]:
    """Parse `ip -o link show` into (device, mac, master, is_ether) rows.

    `ip -o` joins each record onto one line (folding embedded newlines to `\\`),
    so one physical/virtual link is one line. We pull the device name (dropping a
    `@parent` VLAN/veth suffix), its `link/ether` MAC, its enslaving `master`,
    and whether it's an Ethernet-class link (loopback/tunnels are not)."""
    rows: list[tuple[str, str | None, str | None, bool]] = []
    for line in out.splitlines():
        parts = line.replace("\\", " ").split()
        if len(parts) < 2 or not parts[0].rstrip(":").isdigit():
            continue
        device = parts[1].rstrip(":").split("@", 1)[0]
        mac = master = None
        is_ether = False
        for i, tok in enumerate(parts):
            if tok == "link/ether":
                is_ether = True
                if i + 1 < len(parts):
                    mac = parts[i + 1]
            elif tok == "master" and i + 1 < len(parts):
                master = parts[i + 1]
        rows.append((device, mac, master, is_ether))
    return rows


def _ip_link_rows() -> list[tuple[str, str | None, str | None, bool]]:
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return _parse_ip_link(out)


def _hardware_ports_linux() -> dict[str, tuple[str, str]]:
    """device -> ("Wi-Fi"/"Ethernet", kind) for every real Ethernet-class link.

    Bridge members are *not* dropped here (the orchestrator excludes them via the
    `members` set, matching the macOS path), so a bonded NIC is still classified."""
    wireless = _wireless_devices_linux()
    ports: dict[str, tuple[str, str]] = {}
    for device, _mac, _master, is_ether in _ip_link_rows():
        if not is_ether or _is_virtual_name(device):
            continue
        if device in wireless:
            ports[device] = ("Wi-Fi", "wifi")
        else:
            ports[device] = ("Ethernet", "ethernet")
    return ports


def default_gateway() -> str | None:
    return _default_gateway_linux() if _is_linux() else _default_gateway_macos()


def _default_gateway_macos() -> str | None:
    try:
        out = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"gateway:\s*([0-9.]+)", out)
    return m.group(1) if m else None


def _default_gateway_linux() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"default via\s+([0-9.]+)", out)
    return m.group(1) if m else None


# Virtual / non-LAN interface name prefixes. macOS: VM bridges, vmnet, VPN
# tunnels, AWDL (OrbStack/Docker/VMware live behind these). Linux: docker/veth/
# libvirt/VM/VPN/CNI interfaces, including the dash-named bridges (br-…, cni-…).
_VIRTUAL_RE = re.compile(
    r"^(?:bridge|vmenet|vmnet|feth|utun|awdl|llw|gif|stf|anpi|ap)\d"      # macOS
    r"|^(?:docker|veth|virbr|vnet|tap|tun|wg|tailscale|zt|nordlynx)"      # Linux
    r"|^(?:br|cni|cali|flannel|kube)-"                                    # Linux dash
)


def _is_virtual_name(device: str) -> bool:
    return bool(_VIRTUAL_RE.match(device))


def _ifconfig_facts() -> tuple[set[str], set[str], dict[str, str]]:
    """(bridge members, virtual-owned subnets, device->MAC) — used to exclude
    virtual networks. macOS reads `ifconfig`; Linux reads `ip`."""
    return _ifconfig_facts_linux() if _is_linux() else _ifconfig_facts_macos()


def _ifconfig_facts_macos() -> tuple[set[str], set[str], dict[str, str]]:
    """Parse `ifconfig` once for the things we need to exclude virtual networks:

    - bridge member devices (e.g. vmenet0, Thunderbolt en1/en2) — these belong to
      a bridge, not the LAN;
    - subnets owned by a virtual interface (OrbStack's bridge100/101/102 nets) —
      so we never sweep a container/VM network even if an enX joined one;
    - device -> MAC.
    """
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return set(), set(), {}
    members: set[str] = set()
    virtual_subnets: set[str] = set()
    macs: dict[str, str] = {}
    current = None
    for line in out.splitlines():
        if line and not line[0].isspace():
            current = line.split(":", 1)[0]
            continue
        if not current:
            continue
        s = line.strip()
        if s.startswith("member:"):
            members.add(s.split()[1])
        elif s.startswith("ether "):
            macs[current] = s.split()[1]
        elif s.startswith("inet ") and _is_virtual_name(current):
            parts = s.split()
            try:
                prefix = bin(int(parts[3], 16)).count("1")  # netmask 0xfffffe00 -> /23
                virtual_subnets.add(str(ipaddress.ip_network(
                    f"{parts[1]}/{prefix}", strict=False)))
            except (ValueError, IndexError):
                pass
    return members, virtual_subnets, macs


def _ifconfig_facts_linux() -> tuple[set[str], set[str], dict[str, str]]:
    """Linux equivalent of `_ifconfig_facts_macos`, from `ip`:

    - members: links enslaved to a bridge/bond (`ip -o link` `master <dev>`);
    - virtual subnets: nets owned by a virtual-named interface (docker0, virbr0,
      …), parsed from `ip -o addr show`, so a container/VM net is never swept;
    - device -> MAC, from each link's `link/ether`.
    """
    members: set[str] = set()
    macs: dict[str, str] = {}
    for device, mac, master, _is_ether in _ip_link_rows():
        if mac:
            macs[device] = mac
        if master:
            members.add(device)
    virtual_subnets: set[str] = set()
    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return members, virtual_subnets, macs
    for line in out.splitlines():
        parts = line.split()
        # "<idx>: <dev> inet <addr>/<prefix> ..." — only virtual-named devices.
        if len(parts) < 4 or parts[2] != "inet" or not _is_virtual_name(parts[1]):
            continue
        try:
            virtual_subnets.add(str(ipaddress.ip_network(parts[3], strict=False)))
        except ValueError:
            pass
    return members, virtual_subnets, macs


def discover_interfaces(only_device: str | None = None,
                        only_kind: str | None = None) -> list[Interface]:
    """Active Wi-Fi/Ethernet interfaces with an IPv4 address.

    only_device: restrict to a single BSD device name (e.g. "en0").
    only_kind:   "wifi" | "ethernet" to restrict by class.
    """
    ports = _hardware_ports()
    members, virtual_subnets, macs = _ifconfig_facts()
    found: list[Interface] = []
    for adapter in ifaddr.get_adapters():
        device = adapter.name
        if device not in ports:
            continue
        if device in members or _is_virtual_name(device):
            continue  # bridge member / virtual interface (OrbStack, VPN, …)
        port, kind = ports[device]
        if only_device and device != only_device:
            continue
        if only_kind and kind != only_kind:
            continue
        for ip in adapter.ips:
            if not ip.is_IPv4:
                continue
            addr = ip.ip
            if not isinstance(addr, str) or addr.startswith("169.254."):
                continue  # skip link-local
            try:
                net = ipaddress.ip_network(f"{addr}/{ip.network_prefix}", strict=False)
            except ValueError:
                continue
            if not net.is_private:  # LANs are RFC1918
                continue
            if str(net) in virtual_subnets:
                continue  # OrbStack/VM bridge-owned subnet — never sweep it
            found.append(Interface(
                device=device, port=port, kind=kind, ipv4=addr,
                prefix=ip.network_prefix, cidr=str(net), mac=macs.get(device),
            ))
    found.sort(key=lambda i: (i.kind != "wifi", i.device))  # Wi-Fi first
    return found


def broadcast_set(interfaces: list[Interface]) -> set[str]:
    """Subnet broadcast addresses for the given interfaces (to exclude from results)."""
    out: set[str] = set()
    for iface in interfaces:
        try:
            out.add(str(ipaddress.ip_network(iface.cidr).broadcast_address))
        except ValueError:
            pass
    return out


# Subnets larger than this (a /22 = 1024 addresses) are skipped: actively
# sweeping a /16+ would explode the scan, and such links are rare on a home LAN.
MAX_SWEEP_ADDRESSES = 1024


def sweepable(cidr: str) -> bool:
    """True if the subnet is small enough to actively sweep."""
    try:
        return ipaddress.ip_network(cidr).num_addresses <= MAX_SWEEP_ADDRESSES
    except ValueError:
        return False


def hosts_for(interfaces: list[Interface]) -> dict[str, str]:
    """Map every scannable host IP -> the device whose subnet owns it.

    Subnets larger than a /22 are skipped (see ``sweepable``) so a huge netmask
    can't explode the sweep. Self addresses are kept (marked later, not pinged).
    """
    targets: dict[str, str] = {}
    for iface in interfaces:
        if not sweepable(iface.cidr):
            continue
        for host in ipaddress.ip_network(iface.cidr).hosts():
            targets.setdefault(str(host), iface.device)
    return targets
