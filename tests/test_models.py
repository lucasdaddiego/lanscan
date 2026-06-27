"""Tests for lanscan.models — pure dataclasses and their derived properties."""
from __future__ import annotations

from lanscan.models import Device, Interface


def test_interface_label():
    iface = Interface(device="en0", port="Wi-Fi", kind="wifi",
                      ipv4="192.168.0.10", prefix=24, cidr="192.168.0.0/24")
    assert iface.label == "Wi-Fi (en0)"
    assert iface.mac is None


def test_device_name_prefers_mdns():
    d = Device(ip="10.0.0.1", mdns_name="Living Room", hostname="host.local.")
    assert d.name == "Living Room"


def test_device_name_falls_back_to_hostname_stripping_dot():
    d = Device(ip="10.0.0.1", hostname="printer.local.")
    assert d.name == "printer.local"


def test_device_name_empty_when_unknown():
    assert Device(ip="10.0.0.1").name == ""


def test_device_tags_router_and_self():
    assert Device(ip="10.0.0.1", is_gateway=True).tags == ["router"]
    assert Device(ip="10.0.0.1", is_self=True).tags == ["self"]
    assert Device(ip="10.0.0.1", is_gateway=True, is_self=True).tags == ["router", "self"]
    assert Device(ip="10.0.0.1").tags == []


def test_ip_sort_key_valid():
    assert Device(ip="192.168.0.10").ip_sort_key() == (192, 168, 0, 10)


def test_ip_sort_key_invalid_sorts_last():
    assert Device(ip="not-an-ip").ip_sort_key() == (999,)


def test_devices_sort_by_ip():
    devices = [Device(ip="192.168.0.20"), Device(ip="192.168.0.3"),
               Device(ip="192.168.0.10")]
    devices.sort(key=Device.ip_sort_key)
    assert [d.ip for d in devices] == ["192.168.0.3", "192.168.0.10", "192.168.0.20"]


def test_as_dict_round_trips_fields():
    d = Device(
        ip="10.0.0.5", interface="en0", mac="AA:BB:CC:DD:EE:FF", vendor="Acme",
        hostname="box.local.", mdns_name="Box", services=["SSH"], open_ports=[22, 80],
        is_self=True, is_gateway=False, randomized_mac=True, via="icmp",
        first_seen=1.0, last_seen=2.0,
    )
    out = d.as_dict()
    assert out == {
        "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme",
        "name": "Box", "hostname": "box.local.", "mdns_name": "Box",
        "services": ["SSH"], "open_ports": [22, 80], "interface": "en0",
        "via": "icmp", "tags": ["self"], "randomized_mac": True,
        "first_seen": 1.0, "last_seen": 2.0,
    }
