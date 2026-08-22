"""Tests for lanscan.models — pure dataclasses and their derived properties."""
import pytest

from lanscan.models import Device, Interface


def test_interface_label():
    iface = Interface(device="en0", port="Wi-Fi", kind="wifi",
                      ipv4="192.168.0.10", prefix=24, cidr="192.168.0.0/24")
    assert iface.label == "Wi-Fi (en0)"
    assert iface.mac is None


@pytest.mark.parametrize("kwargs,expected", [
    # mDNS wins over everything.
    ({"mdns_name": "Living Room", "upnp_name": "x", "hostname": "h.local.", "http_title": "t"},
     "Living Room"),
    # UPnP friendlyName next.
    ({"upnp_name": "Samsung TV", "hostname": "h.local.", "http_title": "t"}, "Samsung TV"),
    # Reverse-DNS hostname (trailing dot stripped) next.
    ({"hostname": "printer.local.", "http_title": "t"}, "printer.local"),
    # HTTP <title> for otherwise-unknown kit.
    ({"http_title": "My NAS", "remembered_name": "old"}, "My NAS"),
    # The name history last stored is the final fallback.
    ({"remembered_name": "Kettle"}, "Kettle"),
    # Nothing known.
    ({}, ""),
])
def test_device_name_priority(kwargs, expected):
    assert Device(ip="10.0.0.1", **kwargs).name == expected


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
        hostname="box.local.", mdns_name="Box", upnp_name="Box UPnP",
        upnp_model="AcmeCorp NAS-9000", http_server="nginx", http_title="Box Admin",
        services=["SSH"], open_ports=[22, 80], is_self=True, is_gateway=False,
        randomized_mac=True, via="icmp", ever_seen=True, first_seen=1.0, last_seen=2.0,
    )
    out = d.as_dict()
    assert out == {
        "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme",
        "name": "Box", "hostname": "box.local.", "mdns_name": "Box",
        "upnp_name": "Box UPnP", "upnp_model": "AcmeCorp NAS-9000",
        "http_server": "nginx", "http_title": "Box Admin", "remembered_name": None,
        "services": ["SSH"], "open_ports": [22, 80], "interface": "en0",
        "via": "icmp", "tags": ["self"], "randomized_mac": True, "is_self": True,
        "is_gateway": False, "ever_seen": True, "first_seen": 1.0, "last_seen": 2.0,
    }
