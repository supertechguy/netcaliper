# SPDX-License-Identifier: GPL-3.0-only
"""Home tiles / top-level sections."""

from __future__ import annotations

from dataclasses import dataclass

from ..drivers.base import Capability as C


@dataclass(frozen=True)
class Section:
    slug: str
    title: str
    hotkey: str
    blurb: str
    phase: int
    needs: tuple[C, ...] = ()


SECTIONS: tuple[Section, ...] = (
    Section("autotest", "AutoTest", "a", "Run a profile end to end", 2, (C.WIRED_TEST,)),
    Section("wired", "Wired", "w", "Link · LLDP/CDP · DHCP · VLAN · 802.1X", 2, (C.WIRED_TEST,)),
    Section("wifi", "Wi-Fi", "f", "Scan · channels · connect · roam · locate", 3, (C.WIFI_SCAN,)),
    Section("discovery", "Discovery", "d", "Hosts · SNMP · topology · problems", 5, (C.WIRED_TEST,)),
    Section("security", "Security", "s", "Engagements · nmap · policy · rogues", 6),
    Section("airmapper", "AirMapper", "m", "Site survey heatmaps", 7, (C.WIFI_SCAN,)),
    Section("rf", "RF", "r", "BLE · 2.4 GHz sweep · sub-GHz · MouseJack", 8),
    Section("tools", "Tools", "t", "Hardware · capture · iperf · blink", 0),
    Section("results", "Results", "l", "Runs, reports, sync status", 2),
    Section("settings", "Settings", ",", "Roles · profiles · sync · engagement", 1),
)

BY_SLUG = {s.slug: s for s in SECTIONS}
