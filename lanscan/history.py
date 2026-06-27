"""Persistent device history across runs.

Remembers every device the scanner has ever seen — keyed by MAC, falling back to
IP — so the TUI can show a true "first seen" that survives restarts and tell a
device that is brand-new to the network from one that's merely new this session.
Stored as JSON under the user data dir: best-effort, atomic, and capped so it
can't grow without bound.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from platformdirs import user_data_dir

from .models import Device

_DATA_DIR = Path(user_data_dir("lanscan"))
_HISTORY_PATH = _DATA_DIR / "history.json"
MAX_RECORDS = 4096  # oldest-seen records beyond this are pruned


def _key(device: Device) -> str:
    """Stable identity: normalised MAC when known, else the IP."""
    return device.mac or f"ip:{device.ip}"


def load() -> dict[str, dict]:
    """The stored history map, or {} if missing / unreadable / corrupt."""
    try:
        raw = _HISTORY_PATH.read_text()
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save(records: dict[str, dict]) -> None:
    """Atomically write the history map. Best-effort — never raises."""
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _HISTORY_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(records))
        os.replace(tmp, _HISTORY_PATH)
    except OSError:
        pass


def merge(records: dict[str, dict], devices: list[Device],
          now: float | None = None) -> dict[str, dict]:
    """Fold the current scan into history; stamp each device's first_seen / ever_seen.

    A device unseen in any prior run gets ``ever_seen = False`` and ``first_seen =
    now``; a returning one inherits its stored ``first_seen`` and ``ever_seen =
    True``. Returns the updated, pruned records (ready to ``save``).
    """
    now = time.time() if now is None else now
    for d in devices:
        key = _key(d)
        rec = records.get(key)
        if rec is None:
            records[key] = {"first_seen": now, "last_seen": now,
                            "name": d.name or None, "count": 1}
            d.first_seen = now
            d.ever_seen = False
        else:
            rec["last_seen"] = now
            rec["count"] = rec.get("count", 0) + 1
            if d.name:
                rec["name"] = d.name
            d.first_seen = rec.get("first_seen", now)
            d.ever_seen = True
    return _prune(records)


def _prune(records: dict[str, dict]) -> dict[str, dict]:
    """Keep only the most-recently-seen MAX_RECORDS entries."""
    if len(records) <= MAX_RECORDS:
        return records
    keep = sorted(records.items(), key=lambda kv: kv[1].get("last_seen", 0),
                  reverse=True)[:MAX_RECORDS]
    return dict(keep)
