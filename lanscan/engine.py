"""Async LAN scan engine — no root required.

Strategy: a concurrent ICMP ping sweep forces the OS to ARP-resolve every host
that answers at layer 2 (which every reachable IPv4 host must), so reading the
ARP table afterwards yields the device list with MACs. A light TCP-connect probe
mops up the rare hosts that ignore ICMP. Reverse DNS, vendor and mDNS data are
merged on top.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable

from . import banners, net, ports, ssdp, vendors
from .models import Device, Interface

# macOS/BSD `arp -a -n` rows: "? (ip) at mac on dev ...".
_ARP_LINE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\) at (?P<mac>[0-9a-fA-F:]+|\(incomplete\)) on (?P<dev>\S+)"
)
# Linux `ip neigh show` rows: "ip dev <dev> lladdr <mac> <state>". Rows without an
# lladdr (INCOMPLETE/FAILED) simply don't match and are skipped.
_NEIGH_LINE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+(?P<dev>\S+)\s+lladdr\s+(?P<mac>[0-9a-fA-F:]+)"
)
_TCP_PORTS = (80, 443, 22, 445, 7)
ProgressCB = Callable[[int, int], None]


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _ping_argv(ip: str, timeout: float) -> list[str]:
    """Single-probe ping argv. The per-probe timeout flag differs: BSD/macOS `-t`
    is a wait in seconds, but Linux `-t` is the IP TTL — there the wait is `-W`."""
    secs = str(max(1, int(timeout)))
    flag = "-W" if _is_linux() else "-t"
    return ["ping", "-c", "1", flag, secs, ip]


async def _ping(ip: str, timeout: float, sem: asyncio.Semaphore) -> tuple[str, bool]:
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                *_ping_argv(ip, timeout),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            return ip, False
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=timeout + 1.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ip, False
        return ip, rc == 0


async def _port_up(ip: str, port: int, timeout: float) -> bool:
    """True if the host answers on this port (accepted *or* actively refused)."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except ConnectionRefusedError:
        return True  # refused still proves the host is up
    except (asyncio.TimeoutError, OSError):
        return False  # filtered / unreachable / down


async def _tcp_alive(ip: str, timeout: float, sem: asyncio.Semaphore) -> tuple[str, bool]:
    """Race all probe ports at once; a host is up as soon as any answers. Bounds
    each host to ~`timeout` regardless of port count."""
    async with sem:
        tasks = [asyncio.create_task(_port_up(ip, p, timeout)) for p in _TCP_PORTS]
        try:
            for fut in asyncio.as_completed(tasks):
                if await fut:
                    return ip, True
            return ip, False
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def _reverse_dns(ip: str, sem: asyncio.Semaphore) -> tuple[str, str | None]:
    loop = asyncio.get_running_loop()
    async with sem:
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=2.0)
            return ip, res[0]
        except (asyncio.TimeoutError, OSError):
            return ip, None


def read_arp(targets: dict[str, str]) -> dict[str, tuple[str, str]]:
    """ip -> (raw_mac, device) from the neighbour/ARP table, limited to hosts we
    actually swept (so stale / off-subnet cache entries don't surface as devices),
    and skipping incomplete rows and broadcast/multicast groups.

    macOS reads BSD `arp -a -n`; Linux reads `ip neigh show` (modern net-tools-free
    equivalent). Both feed the same row filter."""
    if _is_linux():
        cmd, pattern = ["ip", "neigh", "show"], _NEIGH_LINE
    else:
        cmd, pattern = ["arp", "-a", "-n"], _ARP_LINE
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table: dict[str, tuple[str, str]] = {}
    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        mac, ip, dev = m["mac"], m["ip"], m["dev"]
        if mac == "(incomplete)" or ip not in targets:
            continue
        # macOS prints octets without leading zeros, so normalise before matching.
        norm = vendors.normalize_mac(mac)
        if norm and (norm == "FF:FF:FF:FF:FF:FF" or norm.startswith(("01:00:5E", "33:33"))):
            continue  # broadcast / multicast group, not a device
        table[ip] = (mac, dev)
    return table


def _is_host(ip: str, broadcasts: set[str]) -> bool:
    """Exclude multicast, broadcast and unspecified addresses from results."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not addr.is_multicast and not addr.is_unspecified \
        and ip not in broadcasts and ip != "255.255.255.255"


async def scan(
    interfaces: list[Interface],
    *,
    resolve: bool = True,
    mdns=None,
    ssdp_enabled: bool = True,
    scan_ports: bool = True,
    http_id: bool = True,
    progress: ProgressCB | None = None,
    timeout: float = 1.0,
    concurrency: int = 128,
) -> list[Device]:
    """Scan the given interfaces' subnets and return discovered devices."""
    if not interfaces:
        return []

    targets = net.hosts_for(interfaces)  # ip -> device
    self_ips = {i.ipv4: i for i in interfaces}
    gateway = net.default_gateway()
    now = time.time()

    # 1. ICMP sweep (also populates ARP for ICMP-silent hosts that answer ARP).
    ping_sem = asyncio.Semaphore(concurrency)
    sweep = [ip for ip in targets if ip not in self_ips]
    alive_icmp: set[str] = set()
    total, done = len(sweep), 0
    if progress:
        progress(0, total)
    for coro in asyncio.as_completed([_ping(ip, timeout, ping_sem) for ip in sweep]):
        ip, ok = await coro
        if ok:
            alive_icmp.add(ip)
        done += 1
        if progress:
            progress(done, total)

    arp = read_arp(targets)

    # 2. TCP fallback only for hosts still unaccounted for (no echo, no ARP).
    missing = [ip for ip in sweep if ip not in alive_icmp and ip not in arp]
    alive_tcp: set[str] = set()
    if missing:
        tcp_sem = asyncio.Semaphore(min(concurrency, 256))
        for ip, ok in await asyncio.gather(*(_tcp_alive(ip, timeout, tcp_sem) for ip in missing)):
            if ok:
                alive_tcp.add(ip)
        if alive_tcp:
            arp = read_arp(targets)  # re-read for freshly resolved MACs

    # 3. Assemble devices: anything alive or with a complete ARP entry, plus self.
    broadcasts = net.broadcast_set(interfaces)
    discovered = {ip for ip in (set(alive_icmp) | set(alive_tcp) | set(arp) | set(self_ips))
                  if _is_host(ip, broadcasts)}
    devices: list[Device] = []
    for ip in discovered:
        raw_mac, dev = arp.get(ip, (None, targets.get(ip, "")))
        iface_self = self_ips.get(ip)
        if iface_self and not raw_mac:
            raw_mac, dev = iface_self.mac, iface_self.device
        mac = vendors.normalize_mac(raw_mac)
        randomized = bool(mac and vendors.is_locally_administered(mac))
        via = "icmp" if ip in alive_icmp else "tcp" if ip in alive_tcp else "arp"
        devices.append(Device(
            ip=ip,
            interface=dev or targets.get(ip, ""),
            mac=mac,
            vendor=vendors.lookup(mac),
            randomized_mac=randomized,
            is_self=iface_self is not None,
            is_gateway=(ip == gateway),
            via="self" if iface_self else via,
            first_seen=now,
            last_seen=now,
        ))

    # 4. Reverse DNS (parallel, bounded).
    if resolve:
        rdns_sem = asyncio.Semaphore(64)
        results = dict(await asyncio.gather(
            *(_reverse_dns(d.ip, rdns_sem) for d in devices)))
        for d in devices:
            d.hostname = results.get(d.ip)

    # 5. Merge mDNS / Bonjour identity.
    if mdns is not None:
        snap = mdns.snapshot()
        for d in devices:
            hit = snap.get(d.ip)
            if hit:
                d.mdns_name = hit.get("name") or d.mdns_name
                d.services = sorted(hit.get("services", set()))

    # 5b + 6 + 7. SSDP/UPnP identity and the port + HTTP-banner phase are
    # independent (they touch disjoint Device fields), so run them concurrently:
    # the SSDP M-SEARCH's ~2s reply window overlaps the port scan instead of being
    # tacked on after it. asyncio.gather cancels both if the scan is cancelled.
    async def _ssdp_phase() -> None:
        if not ssdp_enabled:
            return
        upnp = await ssdp.probe()
        for d in devices:
            info = upnp.get(d.ip)
            if info:
                d.upnp_name = info.get("name")
                d.upnp_model = info.get("model") or info.get("server")

    async def _ports_phase() -> None:
        if scan_ports:
            psem = asyncio.Semaphore(512)

            async def _fill(dev: Device) -> None:
                dev.open_ports = await ports.open_ports(dev.ip, timeout, psem)

            await asyncio.gather(*(_fill(d) for d in devices))
        if http_id:
            bsem = asyncio.Semaphore(64)

            async def _banner(dev: Device) -> None:
                async with bsem:
                    dev.http_server, dev.http_title = await banners.identify(
                        dev.ip, dev.open_ports)

            await asyncio.gather(*(_banner(d) for d in devices))

    await asyncio.gather(_ssdp_phase(), _ports_phase())

    devices.sort(key=Device.ip_sort_key)
    return devices
