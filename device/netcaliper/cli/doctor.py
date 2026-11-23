# SPDX-License-Identifier: GPL-3.0-only
"""`netcaliper doctor`: every detected device, capability, missing dependency and service status."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..core.config import Settings
from ..drivers.detect import Inventory
from ..drivers.snapshot import SystemSnapshot

Level = Literal["ok", "warn", "fail", "info"]

# tool -> (feature, required)
TOOL_FEATURES: dict[str, tuple[str, bool]] = {
    "ip": ("core networking", True),
    "iw": ("Wi-Fi", True),
    "ethtool": ("wired link", True),
    "nft": ("self-protection firewall", True),
    "wpa_supplicant": ("802.1X / Wi-Fi connect", False),
    "nmap": ("security scans", False),
    "arp-scan": ("discovery", False),
    "tcpdump": ("capture", False),
    "tshark": ("capture decode", False),
    "iperf3": ("performance", False),
    "rtl_433": ("sub-GHz inventory", False),
    "rtl_power": ("RF sweep", False),
    "bluetoothctl": ("BLE", False),
    "cage": ("kiosk", False),
}
UNITS = (
    "netcaliper-netns",
    "netcaliper-helper",
    "netcaliper-agent",
    "netcaliper-core",
    "netcaliper-kiosk",
    "netcaliper-sync.timer",
)


class Check(BaseModel):
    area: str
    level: Level
    message: str


class DoctorReport(BaseModel):
    source: str
    inventory: Inventory
    checks: list[Check] = Field(default_factory=list)
    services: dict[str, str] = Field(default_factory=dict)

    @property
    def worst(self) -> Level:
        levels = {c.level for c in self.checks}
        return "fail" if "fail" in levels else "warn" if "warn" in levels else "ok"


def _service_states(real: bool) -> dict[str, str]:
    if not real or not shutil.which("systemctl"):
        return {u: "n/a" for u in UNITS}
    out: dict[str, str] = {}
    for u in UNITS:
        r = subprocess.run(
            ["systemctl", "is-active", u], capture_output=True, text=True, check=False, timeout=5
        )
        out[u] = r.stdout.strip() or "unknown"
    return out


def build_report(settings: Settings, snap: SystemSnapshot, inv: Inventory) -> DoctorReport:
    real = snap.source == "real"
    checks: list[Check] = []
    py = snap.platform.python or sys.version.split()[0]
    major, minor = (int(x) for x in py.split(".")[:2])
    checks.append(
        Check(
            area="python",
            level="ok" if (major, minor) >= (3, 11) else "fail",
            message=f"Python {py} (need ≥ 3.11)",
        )
    )
    for tool, (feature, required) in TOOL_FEATURES.items():
        if not snap.tools.get(tool):
            checks.append(
                Check(
                    area="dependency",
                    level="fail" if required else "warn",
                    message=f"{tool} not found — {feature} unavailable",
                )
            )
    if not (snap.tools.get("chromium") or snap.tools.get("chromium-browser")):
        checks.append(
            Check(area="dependency", level="warn", message="chromium not found — kiosk/PDF unavailable")
        )
    for w in inv.warnings:
        checks.append(Check(area="hardware", level="warn", message=w))
    for d in inv.devices:
        for cap, st in d.capabilities.items():
            if st.state == "degraded":
                checks.append(
                    Check(
                        area="hardware", level="info", message=f"{d.name}: {cap.value} degraded — {st.reason}"
                    )
                )
    if real:
        netns = Path("/run/netns") / settings.test_netns
        checks.append(
            Check(
                area="isolation",
                level="ok" if netns.exists() else "warn",
                message=f"test netns {settings.test_netns} "
                + ("present" if netns.exists() else "missing (installer creates it)"),
            )
        )
        data = settings.data_dir
        writable = data.exists() and os.access(data, os.W_OK)
        checks.append(
            Check(
                area="storage",
                level="ok" if writable else "warn",
                message=f"data dir {data} {'writable' if writable else 'missing or not writable'}",
            )
        )
    return DoctorReport(source=snap.source, inventory=inv, checks=checks, services=_service_states(real))


# ---------------------------------------------------------------- rendering

G, DIM, Y, R, B, RST = "\033[92m", "\033[2;32m", "\033[93m", "\033[91m", "\033[1m", "\033[0m"


def render_text(rep: DoctorReport, color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{RST}" if color else s

    mark = {"ok": c(G, "✓"), "warn": c(Y, "!"), "fail": c(R, "✗"), "info": c(DIM, "·")}
    st = {"ok": c(G, "ok"), "degraded": c(Y, "degraded"), "absent": c(DIM, "absent")}
    inv = rep.inventory
    lines = [c(B + G, "netcaliper doctor") + c(DIM, f"  [{rep.source}]"), ""]
    p = inv.platform
    lines.append(f"{c(B, 'Platform')}  {p.name}  {c(DIM, f'({p.id}; {p.os}; Python {p.python})')}")
    for n in p.notes:
        lines.append(f"  {mark['info']} {n}")
    if p.battery_percent is not None:
        lines.append(f"  battery {p.battery_percent}%")
    lines += ["", c(B, "Devices")]
    for d in inv.devices:
        where = " ".join(x for x in (d.ifname, d.phy, d.usb_id) if x)
        role = (f"  role={d.role}" if d.role else "") + (f"  [netns {d.netns}]" if d.netns else "")
        lines.append(f"  {c(G, d.name)}  {c(DIM, where)}{role}")
        lines.append(f"    {c(DIM, 'id ' + d.id)}")
        for cap, s in d.capabilities.items():
            reason = f" — {s.reason}" if s.reason else ""
            lines.append(f"    {cap.value:<20} {st[s.state]}{c(DIM, reason)}")
        for n in d.notes:
            lines.append(f"    {mark['info']} {n}")
    for m in inv.missing:
        lines.append(f"  {c(DIM, m.name + ': not detected — ' + m.hint)}")
    lines += ["", c(B, "Services")]
    for u, s in rep.services.items():
        lines.append(f"  {u:<24} {c(G if s == 'active' else DIM, s)}")
    lines += ["", c(B, "Checks")]
    for ch in rep.checks:
        lines.append(f"  {mark[ch.level]} [{ch.area}] {ch.message}")
    lines += ["", f"overall: {mark[rep.worst]} {rep.worst}"]
    return "\n".join(lines)


def render_json(rep: DoctorReport) -> str:
    data: dict[str, Any] = rep.model_dump(mode="json")
    data["overall"] = rep.worst
    return json.dumps(data, indent=2)
