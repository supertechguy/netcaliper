# SPDX-License-Identifier: GPL-3.0-only
"""Capability vocabulary and the hardware device model."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Capability(StrEnum):
    WIRED_TEST = "wired.test"
    WIRED_CABLE_TEST = "wired.cable_test"
    WIRED_MULTIGIG = "wired.multigig"
    WIFI_SCAN = "wifi.scan"
    WIFI_CONNECT = "wifi.connect"
    WIFI_MONITOR = "wifi.monitor"
    WIFI_BAND_24 = "wifi.band.2g4"
    WIFI_BAND_5 = "wifi.band.5"
    WIFI_BAND_6 = "wifi.band.6"
    WIFI_AC = "wifi.ac"
    WIFI_AX = "wifi.ax"
    BLE_SCAN = "ble.scan"
    SDR_SUBGHZ = "sdr.subghz"
    SPECTRUM_2G4 = "spectrum.2g4"
    SPECTRUM_WIDEBAND = "spectrum.wideband"
    HID_RF_DETECT = "hid_rf.detect"
    PROBE_WIREMAP = "probe.wiremap"
    PROBE_TONE = "probe.tone"
    PROBE_LENGTH = "probe.length"
    POE_MEASURE = "poe.measure"
    GPS = "gps"
    BATTERY = "platform.battery"


DeviceKind = Literal["nic", "wifi", "ble", "sdr", "nrf24", "wideband_sdr", "probe", "poe", "gps", "platform"]
Role = Literal["test-wired", "test-wifi", "monitor", "mgmt", "unused"]


class CapState(BaseModel):
    state: Literal["ok", "degraded", "absent"]
    reason: str = ""

    @classmethod
    def ok(cls) -> CapState:
        return cls(state="ok")

    @classmethod
    def degraded(cls, reason: str) -> CapState:
        return cls(state="degraded", reason=reason)

    @classmethod
    def absent(cls, reason: str) -> CapState:
        return cls(state="absent", reason=reason)


class HardwareDevice(BaseModel):
    id: str  # stable across reboots/renames (MAC- or serial-based); used for role config
    kind: DeviceKind
    name: str
    driver: str | None = None
    usb_id: str | None = None  # "vvvv:pppp"
    bus: str | None = None
    bus_path: str | None = None
    ifname: str | None = None  # display/plumbing only — never select devices by it
    phy: str | None = None
    mac: str | None = None
    serial: str | None = None
    capabilities: dict[Capability, CapState] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    role: Role | None = None

    def has(self, cap: Capability, allow_degraded: bool = False) -> bool:
        st = self.capabilities.get(cap)
        if st is None:
            return False
        return st.state == "ok" or (allow_degraded and st.state == "degraded")


class ExpectedHardware(BaseModel):
    """A device class we know about but didn't find (shown as 'not detected')."""

    kind: DeviceKind
    name: str
    provides: list[Capability]
    hint: str = ""
