# SPDX-License-Identifier: GPL-3.0-only
"""Known hardware (USB IDs) and driver quirks. Detection never *requires* an entry here —
unknown NICs/radios are still classified from sysfs/nl80211 — but entries add names and quirks."""

from __future__ import annotations

from dataclasses import dataclass

from .base import Capability, DeviceKind, ExpectedHardware


@dataclass(frozen=True)
class KnownUsb:
    kind: DeviceKind
    name: str
    note: str = ""


KNOWN_USB: dict[str, KnownUsb] = {
    "0b95:1790": KnownUsb("nic", "ASIX AX88179 USB 3.0 Gigabit Ethernet"),
    "0bda:8156": KnownUsb("nic", "Realtek RTL8156/RTL8156B 2.5 GbE"),
    "0bda:8153": KnownUsb("nic", "Realtek RTL8153 Gigabit Ethernet"),
    "0e8d:7610": KnownUsb("wifi", "MediaTek MT7610U 802.11ac"),
    "0e8d:7961": KnownUsb("wifi", "MediaTek MT7921AU Wi-Fi 6E"),
    "0bda:8176": KnownUsb("wifi", "Realtek RTL8188CUS 802.11n"),
    "0bda:8178": KnownUsb("wifi", "Realtek RTL8192CU 802.11n"),
    "0bda:2838": KnownUsb("sdr", "RTL-SDR (RTL2832U)"),
    "0bda:2832": KnownUsb("sdr", "RTL-SDR (RTL2832U)"),
    "1915:0102": KnownUsb("nrf24", "nRF24LU1+ (RFStorm research firmware)"),
    "1915:7777": KnownUsb(
        "nrf24",
        "Crazyradio PA (stock firmware)",
        "flash RFStorm/MouseJack research firmware for sweep + HID detection",
    ),
    "1d50:6089": KnownUsb("wideband_sdr", "HackRF One"),
}

# USB devices that identify the host platform.
PLATFORM_USB: dict[str, str] = {"1eaf:0024": "uconsole"}  # uConsole keyboard/trackball MCU

# NICs that exist in the kernel but have no physical jack on a given platform.
NO_JACK: dict[str, set[str]] = {"uconsole": {"bcmgenet"}}

# netcaliper's own boards identify by USB product string (USB CDC, JSON lines — see hardware/).
PRODUCT_STRINGS: dict[str, DeviceKind] = {"netcaliper-probe": "probe", "netcaliper-poe": "poe"}

DVB_MODULES = ("dvb_usb_rtl28xxu", "rtl2832", "rtl2832_sdr")

# (driver, capability) -> reason; capability is downgraded to "degraded" when advertised.
DEGRADED: dict[tuple[str, Capability], str] = {
    ("rtl8192cu", Capability.WIFI_MONITOR): "in-kernel rtl8192cu monitor mode is unreliable",
}
# (driver, capability) -> reason; capability removed (absent) even if advertised.
ABSENT: dict[tuple[str, Capability], str] = {
    ("brcmfmac", Capability.WIFI_MONITOR): "stock Broadcom firmware has no usable monitor mode",
}

# Drivers where a radio is board-internal (good default for mgmt, never moved into the test netns
# by default).
INTERNAL_WIFI_DRIVERS = {"brcmfmac"}

EXPECTED: list[ExpectedHardware] = [
    ExpectedHardware(
        kind="probe",
        name="netcaliper probe (RP2040/ESP32)",
        provides=[Capability.PROBE_WIREMAP, Capability.PROBE_TONE, Capability.PROBE_LENGTH],
        hint="future board — see hardware/probe",
    ),
    ExpectedHardware(
        kind="poe",
        name="netcaliper PoE / TruePower module",
        provides=[Capability.POE_MEASURE],
        hint="future board — see hardware/poe",
    ),
    ExpectedHardware(
        kind="wideband_sdr",
        name="Wideband SDR (e.g. HackRF)",
        provides=[Capability.SPECTRUM_WIDEBAND],
        hint="needed for 5/6 GHz spectrum",
    ),
    ExpectedHardware(kind="gps", name="GPS receiver", provides=[Capability.GPS], hint="outdoor AirMapper"),
]
