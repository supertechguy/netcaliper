# SPDX-License-Identifier: GPL-3.0-only
"""Read-only view of the kiosk session settings (/etc/netcaliper/kiosk.env, written by the installer).

The session (swayidle) owns blanking; the UI only mirrors the effective timeout so the input that
wakes a blanked screen is swallowed instead of triggering an action.
"""

from __future__ import annotations

from pathlib import Path


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def on_ac(sysfs: Path = Path("/sys")) -> bool:
    """Mirrors kiosk-display: mains/USB supply online → AC; no battery at all → AC."""
    supplies = list((sysfs / "class/power_supply").glob("*"))
    has_battery = False
    for ps in supplies:
        try:
            kind = (ps / "type").read_text().strip()
        except OSError:
            continue
        if kind == "Battery":
            has_battery = True
        elif kind == "Mains" or kind.startswith("USB"):
            try:
                if (ps / "online").read_text().strip() == "1":
                    return True
            except OSError:
                pass
    return not has_battery


def _int(v: str | None) -> int:
    try:
        return max(0, int(v or 0))
    except ValueError:
        return 0


def blank_after_s(env: dict[str, str], ac: bool) -> int:
    """Effective inactivity timeout before the backlight goes off (0 = never)."""
    if not env:
        return 0  # no kiosk on this host (dev/mock): nothing to mirror
    blank = _int(env.get("KIOSK_BLANK_S", "600"))
    battery = _int(env.get("KIOSK_BLANK_S_BATTERY"))
    if not ac and blank and 0 < battery < blank:
        return battery
    return blank
