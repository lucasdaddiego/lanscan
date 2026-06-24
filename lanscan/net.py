"""Interface discovery and subnet math (macOS).

Enumerates the Wi-Fi and Ethernet ports that currently have an IPv4 address, so
the scanner targets real LAN segments and ignores VM/Docker bridges and other
virtual interfaces. Re-running this each scan cycle is what gives us Ethernet
hotplug: a dongle that gets an address simply shows up next round.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess

import ifaddr

from .models import Interface

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


def default_gateway() -> str | None:
    try:
        out = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"gateway:\s*([0-9.]+)", out)
    return m.group(1) if m else None


# Virtual / non-LAN interface name prefixes (VM bridges, vmnet, VPN tunnels,
# AWDL, etc.). OrbStack/Docker/VMware networking lives behind these.
_VIRTUAL_RE = re.compile(r"^(bridge|vmenet|vmnet|feth|utun|awdl|llw|gif|stf|anpi|ap)\d")


def _is_virtual_name(device: str) -> bool:
    return bool(_VIRTUAL_RE.match(device))


def _ifconfig_facts() -> tuple[set[str], set[str], dict[str, str]]:
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


def hosts_for(interfaces: list[Interface]) -> dict[str, str]:
    """Map every scannable host IP -> the device whose subnet owns it.

    Caps each subnet at /22 (1022 hosts) so a misconfigured huge netmask can't
    explode the sweep. Self addresses are kept (marked later, not pinged).
    """
    targets: dict[str, str] = {}
    for iface in interfaces:
        net = ipaddress.ip_network(iface.cidr)
        if net.num_addresses > 1024:
            continue
        for host in net.hosts():
            targets.setdefault(str(host), iface.device)
    return targets
