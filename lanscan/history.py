"""Persistent device history across runs.

Remembers every device the scanner has ever seen — keyed by MAC, falling back to
IP — so the TUI can show a true "first seen" that survives restarts, tell a
device that is brand-new to the network from one that's merely new this session,
and keep labelling a device by its last known name when it's nameless this run
(sleepy IoT that only advertises now and then). Stored as JSON under the user
data dir: best-effort, atomic, and capped so it can't grow without bound.
"""
import json
import os
import time
from pathlib import Path

from platformdirs import user_data_dir

from .models import Device, sanitize

_DATA_DIR = Path(user_data_dir("lanscan"))
_HISTORY_PATH = _DATA_DIR / "history.json"
MAX_RECORDS = 4096  # oldest-seen records beyond this are pruned

# One stored device: {"first_seen": float, "last_seen": float, "name": str | None}.
# Typed loosely on purpose: the file is user-writable, so every read of a field
# goes through a check (`_num`) instead of trusting the shape.
Record = dict[str, object]


def _num(value: object, default: float) -> float:
    """A stored timestamp, or `default` when the file holds anything else there."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return default
    return float(value)


def _key(device: Device) -> str:
    """Stable identity: normalised MAC when known, else the IP."""
    return device.mac or f"ip:{device.ip}"


def load() -> dict[str, Record]:
    """The stored history map, or {} if missing / unreadable / corrupt. An entry
    that is not an object is dropped, so one bad record can't fail every scan."""
    try:
        raw = _HISTORY_PATH.read_text()
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict)}


def save(records: dict[str, Record]) -> None:
    """Atomically write the history map, readable by this user only — it holds
    MAC addresses and device names. Best-effort: never raises."""
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _HISTORY_PATH.with_suffix(".tmp")
        # Create 0600 regardless of the umask; O_CREAT's mode only applies to a
        # brand-new file, so a leftover tmp is tightened explicitly too.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(records))
        os.chmod(tmp, 0o600)
        os.replace(tmp, _HISTORY_PATH)
    except OSError:
        pass


def merge(records: dict[str, Record], devices: list[Device],
          now: float | None = None) -> dict[str, Record]:
    """Fold the current scan into history; stamp each device's first_seen / ever_seen.

    A device unseen in any prior run gets ``ever_seen = False`` and ``first_seen =
    now``; a returning one inherits its stored ``first_seen`` and ``ever_seen =
    True``, and — if it has no name this run — its last stored name as
    ``remembered_name``. Returns the updated, pruned records (ready to ``save``).
    """
    now = time.time() if now is None else now
    for d in devices:
        key = _key(d)
        rec = records.get(key)
        if rec is None:
            records[key] = {"first_seen": now, "last_seen": now, "name": d.live_name or None}
            d.first_seen = now
            d.ever_seen = False
        else:
            rec["last_seen"] = now
            if d.live_name:
                rec["name"] = d.live_name
            elif rec.get("name"):
                # Stored by an older run (possibly before names were sanitized).
                d.remembered_name = sanitize(str(rec["name"]))
            # A non-numeric first_seen (a hand-edited file) restarts the clock
            # rather than reaching the TUI's time arithmetic.
            d.first_seen = rec["first_seen"] = _num(rec.get("first_seen"), now)
            d.ever_seen = True
    return _prune(records)


def _prune(records: dict[str, Record]) -> dict[str, Record]:
    """Keep only the most-recently-seen MAX_RECORDS entries."""
    if len(records) <= MAX_RECORDS:
        return records
    keep = sorted(records.items(), key=lambda kv: _num(kv[1].get("last_seen"), 0.0),
                  reverse=True)[:MAX_RECORDS]
    return dict(keep)
