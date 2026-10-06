"""Tests for lanscan.history — persistent device history."""
import json
import os
import stat

import pytest

from lanscan import history
from lanscan.models import Device


@pytest.fixture
def hist_path(tmp_path, monkeypatch):
    """Point the history store at a temp dir."""
    data_dir = tmp_path / "data"
    path = data_dir / "history.json"
    monkeypatch.setattr(history, "_DATA_DIR", data_dir)
    monkeypatch.setattr(history, "_HISTORY_PATH", path)
    return path


# ---- _key -----------------------------------------------------------------
def test_key_prefers_mac():
    assert history._key(Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")) == "AA:BB:CC:DD:EE:FF"


def test_key_falls_back_to_ip():
    assert history._key(Device(ip="10.0.0.1")) == "ip:10.0.0.1"


# ---- load -----------------------------------------------------------------
def test_load_missing_file(hist_path):
    assert history.load() == {}


def test_load_corrupt_json(hist_path):
    hist_path.parent.mkdir(parents=True)
    hist_path.write_text("{not valid json")
    assert history.load() == {}


def test_load_non_dict_json(hist_path):
    hist_path.parent.mkdir(parents=True)
    hist_path.write_text("[1, 2, 3]")
    assert history.load() == {}


def test_load_valid(hist_path):
    hist_path.parent.mkdir(parents=True)
    hist_path.write_text(json.dumps({"AA:BB": {"first_seen": 1.0}}))
    assert history.load() == {"AA:BB": {"first_seen": 1.0}}


# ---- save -----------------------------------------------------------------
def test_save_round_trips(hist_path):
    history.save({"AA:BB": {"first_seen": 1.0, "last_seen": 2.0}})
    assert json.loads(hist_path.read_text()) == {"AA:BB": {"first_seen": 1.0, "last_seen": 2.0}}


def test_save_is_private_to_the_user(hist_path):
    old = os.umask(0o000)                            # a permissive umask must not leak
    try:
        history.save({"AA:BB": {}})
    finally:
        os.umask(old)
    assert stat.S_IMODE(hist_path.stat().st_mode) == 0o600


def test_save_tightens_a_leftover_tmp_file(hist_path):
    hist_path.parent.mkdir(parents=True)
    leftover = hist_path.with_suffix(".tmp")
    leftover.write_text("{}")
    leftover.chmod(0o644)                            # O_CREAT's mode won't apply here
    history.save({"AA:BB": {}})
    assert stat.S_IMODE(hist_path.stat().st_mode) == 0o600
    assert not leftover.exists()


def test_save_swallows_errors(hist_path, monkeypatch):
    # Make the data dir a regular file so mkdir() raises -> swallowed.
    hist_path.parent.write_text("i am a file, not a dir")
    history.save({"x": {}})  # must not raise


# ---- merge ----------------------------------------------------------------
def test_merge_new_device():
    records = {}
    dev = Device(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF", mdns_name="Box")
    out = history.merge(records, [dev], now=100.0)
    assert out["AA:BB:CC:DD:EE:FF"] == {"first_seen": 100.0, "last_seen": 100.0, "name": "Box"}
    assert dev.first_seen == 100.0
    assert dev.ever_seen is False


def test_merge_returning_device():
    records = {"AA:BB:CC:DD:EE:FF": {"first_seen": 50.0, "last_seen": 60.0, "name": "Old"}}
    dev = Device(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF", mdns_name="Box")
    history.merge(records, [dev], now=100.0)
    rec = records["AA:BB:CC:DD:EE:FF"]
    assert rec["first_seen"] == 50.0       # preserved
    assert rec["last_seen"] == 100.0       # bumped
    assert rec["name"] == "Box"            # refreshed from the live name
    assert dev.first_seen == 50.0          # device inherits stored first_seen
    assert dev.ever_seen is True
    assert dev.remembered_name is None     # it has a live name; nothing to remember


def test_merge_returning_nameless_device_gets_its_last_known_name():
    records = {"AA:BB:CC:DD:EE:FF": {"first_seen": 50.0, "last_seen": 60.0, "name": "Kettle"}}
    dev = Device(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF")   # no name this run
    history.merge(records, [dev], now=100.0)
    assert dev.remembered_name == "Kettle"
    assert dev.name == "Kettle"                            # surfaces as the display name
    assert records["AA:BB:CC:DD:EE:FF"]["name"] == "Kettle"  # stored name kept


def test_merge_sanitizes_a_remembered_name_from_disk():
    # history.json predates the sanitizer (or was edited): the stored name must
    # not carry an escape into the detail pane via `remembered_name`.
    records = {"AA:BB:CC:DD:EE:FF": {"first_seen": 1.0, "last_seen": 2.0, "name": "K\x1b[2J"}}
    dev = Device(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF")
    history.merge(records, [dev], now=100.0)
    assert dev.remembered_name == "K\u00b7[2J"


def test_merge_returning_unnamed_keeps_stored_name_and_missing_first_seen():
    # Record lacks first_seen and the device has no name -> defaults + no overwrite.
    records = {"ip:10.0.0.9": {"last_seen": 10.0}}
    dev = Device(ip="10.0.0.9")  # no mac, no name
    history.merge(records, [dev], now=200.0)
    rec = records["ip:10.0.0.9"]
    assert "name" not in rec               # device has no name -> stored name untouched
    assert dev.first_seen == 200.0         # missing first_seen -> falls back to now
    assert dev.ever_seen is True


def test_merge_defaults_now_to_wall_clock(monkeypatch):
    monkeypatch.setattr(history.time, "time", lambda: 777.0)
    records = {}
    dev = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
    history.merge(records, [dev])
    assert dev.first_seen == 777.0


# ---- _prune ---------------------------------------------------------------
def test_merge_prunes_to_cap(monkeypatch):
    monkeypatch.setattr(history, "MAX_RECORDS", 2)
    records = {
        "old": {"last_seen": 1.0},
        "mid": {"last_seen": 2.0},
    }
    # Add a third (newest) device; the oldest ("old") should be pruned.
    dev = Device(ip="10.0.0.3", mac="NEW")
    out = history.merge(records, [dev], now=99.0)
    assert set(out) == {"mid", "NEW"}      # kept the 2 most-recently-seen
    assert "old" not in out


def test_prune_under_cap_is_identity():
    records = {"a": {"last_seen": 1.0}}
    assert history._prune(records) is records
