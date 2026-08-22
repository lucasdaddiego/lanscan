"""Tests for lanscan._platform."""
from lanscan import _platform


def test_is_linux_reads_platform(monkeypatch):
    monkeypatch.setattr(_platform.sys, "platform", "linux2")
    assert _platform.is_linux() is True
    monkeypatch.setattr(_platform.sys, "platform", "darwin")
    assert _platform.is_linux() is False
