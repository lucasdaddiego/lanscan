"""Async LAN scan engine — no root required.

Strategy: an ICMP echo sweep forces the OS to ARP-resolve every host that
answers at layer 2 (which every reachable IPv4 host must), so reading the ARP
table afterwards yields the device list with MACs — ICMP-silent hosts included.
Reverse DNS, vendor, mDNS, SSDP and HTTP-banner data are merged on top.

The sweep sends every echo from one unprivileged ICMP datagram socket (macOS
always allows one; Linux when `net.ipv4.ping_group_range` covers our group) and
falls back to spawning `ping` per host where that socket isn't available.
"""
import asyncio
import contextlib
import os
import re
import socket
import struct
import subprocess
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from . import banners, net, ports, ssdp, vendors
from ._platform import is_linux
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
ProgressCB = Callable[[int, int], None]


# ---- ICMP echo sweep over one datagram socket -------------------------------
_ICMP_ECHO_REQUEST, _ICMP_ECHO_REPLY = 8, 0
_ICMP_ID = os.getpid() & 0xFFFF
_ECHO_PAYLOAD = b"lanscan!"
_SEND_BATCH = 32  # echoes per burst before yielding, so the NIC queue isn't flooded


def _checksum(data: bytes) -> int:
    """RFC 1071 one's-complement sum. macOS doesn't fill it in for us (a wrong
    checksum is silently dropped); Linux overwrites whatever we send."""
    if len(data) % 2:
        data += b"\0"
    total = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_request(seq: int) -> bytes:
    head = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, _ICMP_ID, seq & 0xFFFF)
    csum = _checksum(head + _ECHO_PAYLOAD)
    return struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, csum, _ICMP_ID, seq & 0xFFFF) \
        + _ECHO_PAYLOAD


class _EchoCollector(asyncio.DatagramProtocol):
    """Records the source address of every echo reply that reaches the socket."""

    def __init__(self) -> None:
        self.alive: set[str] = set()

    def datagram_received(self, data: bytes, addr) -> None:
        # macOS/BSD hands us the IP header too (first nibble = version 4); Linux
        # ping sockets strip it. Either way the ICMP type byte follows.
        if data and data[0] >> 4 == 4:
            data = data[(data[0] & 0x0F) * 4:]
        if data and data[0] == _ICMP_ECHO_REPLY:
            self.alive.add(addr[0])


def _icmp_socket() -> socket.socket | None:
    """An unprivileged ICMP datagram socket, or None where the OS refuses one."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return None
    sock.setblocking(False)
    return sock


async def _icmp_sweep(targets: list[str], timeout: float,
                      progress: ProgressCB | None) -> set[str] | None:
    """Echo every target from one socket; return who answered within `timeout`.

    None when the socket isn't available, so the caller can fall back to `ping`.
    Progress is reported against the clock (the replies that never come are only
    known once it runs out) and the wait ends early if every target answered.
    """
    sock = _icmp_socket()
    if sock is None:
        return None
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(_EchoCollector, sock=sock)
    except OSError:
        sock.close()
        return None
    total, wanted = len(targets), set(targets)
    try:
        for seq, ip in enumerate(targets):
            transport.sendto(_echo_request(seq), (ip, 0))
            if seq % _SEND_BATCH == _SEND_BATCH - 1:
                await asyncio.sleep(0.005)
        deadline = loop.time() + timeout
        while True:
            left = deadline - loop.time()
            if left <= 0 or len(proto.alive & wanted) == total:
                break
            await asyncio.sleep(min(0.1, left))
            if progress:
                elapsed = min(timeout, timeout - (deadline - loop.time()))
                progress(int(total * elapsed / timeout), total)
    finally:
        transport.close()
    return proto.alive & wanted


# ---- `ping` fallback (one child process per host) ---------------------------
def _ping_argv(ip: str, timeout: float) -> list[str]:
    """Single-probe ping argv. The per-probe timeout flag differs: BSD/macOS `-t`
    is a wait in seconds, but Linux `-t` is the IP TTL — there the wait is `-W`."""
    secs = str(max(1, int(timeout)))
    flag = "-W" if is_linux() else "-t"
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
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return ip, False
        except asyncio.CancelledError:
            # The sweep was abandoned (TUI quit): don't leave the child behind.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise
        return ip, rc == 0


async def _ping_sweep(targets: list[str], timeout: float, concurrency: int,
                      progress: ProgressCB | None) -> set[str]:
    """Spawn `ping` per target, `concurrency` at a time; return who answered."""
    sem = asyncio.Semaphore(concurrency)
    alive: set[str] = set()
    total, done = len(targets), 0
    # Own the tasks explicitly: as_completed does not cancel what it started, so
    # a cancelled scan would otherwise leave the whole sweep — and its ping
    # children — running behind it.
    pings = [asyncio.create_task(_ping(ip, timeout, sem)) for ip in targets]
    try:
        for coro in asyncio.as_completed(pings):
            ip, ok = await coro
            if ok:
                alive.add(ip)
            done += 1
            if progress:
                progress(done, total)
    finally:
        for t in pings:
            t.cancel()
        await asyncio.gather(*pings, return_exceptions=True)
    return alive


# ---- reverse DNS --------------------------------------------------------------
_RDNS_WORKERS = 64
_RDNS_POOL: ThreadPoolExecutor | None = None


def _rdns_pool() -> ThreadPoolExecutor:
    """A pool sized for the lookup fan-out. The loop's default executor has only
    min(32, cpus + 4) threads, so on a wide LAN lookups would queue behind each
    other and time out before they even started."""
    global _RDNS_POOL
    if _RDNS_POOL is None:
        _RDNS_POOL = ThreadPoolExecutor(max_workers=_RDNS_WORKERS,
                                        thread_name_prefix="lanscan-rdns")
    return _RDNS_POOL


async def _reverse_dns(ip: str, timeout: float) -> tuple[str, str | None]:
    loop = asyncio.get_running_loop()
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(_rdns_pool(), socket.gethostbyaddr, ip), timeout=timeout)
        return ip, res[0]
    except OSError:  # includes TimeoutError; herror/gaierror are OSErrors too
        return ip, None


# ---- neighbour table ----------------------------------------------------------
def read_arp(targets: dict[str, str]) -> dict[str, tuple[str, str]]:
    """ip -> (raw_mac, device) from the neighbour/ARP table, limited to hosts we
    actually swept (so stale / off-subnet cache entries don't surface as devices),
    and skipping incomplete rows and broadcast/multicast groups.

    macOS reads BSD `arp -a -n`; Linux reads `ip neigh show` (modern net-tools-free
    equivalent). Both feed the same row filter."""
    if is_linux():
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


# ---- orchestration ------------------------------------------------------------
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

    # 1. ICMP sweep. Its real job is forcing ARP resolution for every address:
    # a host that drops ICMP still answers ARP (it must, to be reachable at all),
    # so the neighbour table read right after is the authoritative device list.
    sweep = [ip for ip in targets if ip not in self_ips]
    if progress:
        progress(0, len(sweep))
    alive = await _icmp_sweep(sweep, timeout, progress)
    if alive is None:
        alive = await _ping_sweep(sweep, timeout, concurrency, progress)
    if progress:
        progress(len(sweep), len(sweep))
    arp = read_arp(targets)

    # 2. Assemble devices: anything that echoed or has a complete ARP entry, plus
    # self. Every candidate is a swept host address or one of ours.
    devices: list[Device] = []
    for ip in alive | arp.keys() | self_ips.keys():
        raw_mac, dev = arp.get(ip, (None, targets.get(ip, "")))
        iface_self = self_ips.get(ip)
        if iface_self and not raw_mac:
            raw_mac, dev = iface_self.mac, iface_self.device
        mac = vendors.normalize_mac(raw_mac)
        randomized = bool(mac and vendors.is_locally_administered(mac))
        devices.append(Device(
            ip=ip,
            interface=dev,
            mac=mac,
            vendor=vendors.lookup(mac),
            randomized_mac=randomized,
            is_self=iface_self is not None,
            is_gateway=(ip == gateway),
            via="self" if iface_self else "icmp" if ip in alive else "arp",
            first_seen=now,
            last_seen=now,
        ))

    # 3. Reverse DNS (parallel, bounded to the pool width so each lookup's clock
    # starts when it actually runs).
    if resolve:
        rdns_sem = asyncio.Semaphore(_RDNS_WORKERS)

        async def _lookup(ip: str) -> tuple[str, str | None]:
            async with rdns_sem:
                return await _reverse_dns(ip, timeout + 1.0)

        results = dict(await asyncio.gather(*(_lookup(d.ip) for d in devices)))
        for d in devices:
            d.hostname = results.get(d.ip)

    # 4. Merge mDNS / Bonjour identity.
    if mdns is not None:
        snap = mdns.snapshot()
        for d in devices:
            hit = snap.get(d.ip)
            if hit:
                d.mdns_name = hit.get("name") or d.mdns_name
                d.services = sorted(hit.get("services", set()))

    # 5 + 6. SSDP/UPnP identity and the port + HTTP-banner phase are independent
    # (they touch disjoint Device fields), so run them concurrently: the SSDP
    # M-SEARCH's reply window overlaps the port scan instead of being tacked on
    # after it. asyncio.gather cancels both if the scan is cancelled.
    async def _ssdp_phase() -> None:
        if not ssdp_enabled:
            return
        upnp = await ssdp.probe([i.ipv4 for i in interfaces])
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
