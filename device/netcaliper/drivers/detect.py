# SPDX-License-Identifier: GPL-3.0-only
"""Pure detection: SystemSnapshot -> Inventory (devices, capabilities, suggested roles)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .base import Capability as C
from .base import CapState, ExpectedHardware, HardwareDevice, Role
from .iwparse import parse_iw_phy_info
from .known import (
    ABSENT,
    DEGRADED,
    DVB_MODULES,
    EXPECTED,
    INTERNAL_WIFI_DRIVERS,
    KNOWN_USB,
    PRODUCT_STRINGS,
)
from .snapshot import NetInterface, SystemSnapshot, UsbDevice


class PlatformSummary(BaseModel):
    id: str  # rpi-cm4, rpi-cm5, rpi-4, rpi-5, x86, arm64-generic
    name: str
    is_uconsole: bool = False
    usb3: bool | None = None
    os: str = ""
    python: str = ""
    battery_percent: int | None = None
    notes: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    source: str
    platform: PlatformSummary
    devices: list[HardwareDevice]
    missing: list[ExpectedHardware] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def by_capability(self, cap: C, allow_degraded: bool = False) -> list[HardwareDevice]:
        return [d for d in self.devices if d.has(cap, allow_degraded)]

    def by_role(self, role: Role) -> list[HardwareDevice]:
        return [d for d in self.devices if d.role == role]

    def get(self, device_id: str) -> HardwareDevice | None:
        return next((d for d in self.devices if d.id == device_id), None)


# ---------------------------------------------------------------- platform


def detect_platform(snap: SystemSnapshot) -> PlatformSummary:
    p = snap.platform
    model = p.model
    notes: list[str] = []
    if "Compute Module 4" in model:
        pid, usb3 = "rpi-cm4", False
        notes.append("CM4 has USB 2.0 only: USB NICs cap around 300 Mb/s")
    elif "Compute Module 5" in model:
        pid, usb3 = "rpi-cm5", True
    elif "Raspberry Pi 5" in model:
        pid, usb3 = "rpi-5", True
    elif "Raspberry Pi 4" in model:
        pid, usb3 = "rpi-4", True
    elif p.arch in ("x86_64", "amd64", "i686"):
        pid, usb3 = "x86", None
    else:
        pid, usb3 = f"{p.arch or 'unknown'}-generic", None
    # uConsole heuristic: ClockworkPi compatible string, or a CM board with a DSI panel + battery PMIC.
    # Refine with real device-tree data from the reference image.
    compat = " ".join(p.compatible).lower()
    has_dsi = any(c.name.startswith("DSI") and c.status == "connected" for c in p.drm)
    has_axp = any("axp" in ps.name.lower() for ps in snap.power_supplies)
    is_uconsole = (
        "clockwork" in compat or "uconsole" in compat or (pid.startswith("rpi-cm") and has_dsi and has_axp)
    )
    battery = next((ps.capacity for ps in snap.power_supplies if ps.type == "Battery"), None)
    name = model or p.dmi_product or p.arch
    if is_uconsole:
        name = f"ClockworkPi uConsole ({model})"
    return PlatformSummary(
        id=pid,
        name=name,
        is_uconsole=is_uconsole,
        usb3=usb3,
        os=p.os_release.get("PRETTY_NAME", ""),
        python=p.python,
        battery_percent=battery,
        notes=notes,
    )


# ---------------------------------------------------------------- per-kind detectors


def _usb_by_path(snap: SystemSnapshot) -> dict[str, UsbDevice]:
    return {u.path: u for u in snap.usb}


def _usb_note(u: UsbDevice | None, kind: str) -> list[str]:
    if u and kind == "nic" and u.speed_mbps is not None and u.speed_mbps <= 480:
        return [f"USB link is {u.speed_mbps} Mb/s (USB 2.0): throughput capped around 300 Mb/s"]
    return []


def _wired(iface: NetInterface, usb: UsbDevice | None) -> HardwareDevice:
    known = KNOWN_USB.get(f"{usb.vid}:{usb.pid}") if usb else None
    caps: dict[C, CapState] = {C.WIRED_TEST: CapState.ok()}
    if iface.has_phydev:
        caps[C.WIRED_CABLE_TEST] = CapState(
            state="ok", reason="phylib PHY present; PHY support confirmed at test time"
        )
    else:
        caps[C.WIRED_CABLE_TEST] = CapState.absent(
            "no phylib PHY (no cable diagnostics) — requires netcaliper probe"
        )
    if any(m.startswith(("2500base", "5000base", "10000base")) for m in iface.link_modes):
        caps[C.WIRED_MULTIGIG] = CapState.ok()
    return HardwareDevice(
        id=f"nic:{iface.mac}",
        kind="nic",
        name=known.name if known else f"Ethernet ({iface.driver or 'unknown'})",
        driver=iface.driver,
        usb_id=f"{usb.vid}:{usb.pid}" if usb else None,
        bus=iface.bus,
        bus_path=iface.usb_path,
        ifname=iface.name,
        mac=iface.mac,
        capabilities=caps,
        notes=_usb_note(usb, "nic"),
    )


def _wifi(iface: NetInterface, usb: UsbDevice | None, iw_text: str | None) -> HardwareDevice:
    known = KNOWN_USB.get(f"{usb.vid}:{usb.pid}") if usb else None
    drv = iface.driver or ""
    caps: dict[C, CapState] = {}
    notes: list[str] = []
    if iw_text:
        info = parse_iw_phy_info(iw_text)
        if "managed" in info.iftypes:
            caps[C.WIFI_SCAN] = CapState.ok()
            caps[C.WIFI_CONNECT] = CapState.ok()
        if "monitor" in info.iftypes:
            caps[C.WIFI_MONITOR] = CapState.ok()
        band_caps = {"2g4": C.WIFI_BAND_24, "5": C.WIFI_BAND_5, "6": C.WIFI_BAND_6}
        for b in sorted(info.bands):
            caps[band_caps[b]] = CapState.ok()
        if info.vht:
            caps[C.WIFI_AC] = CapState.ok()
        if info.he:
            caps[C.WIFI_AX] = CapState.ok()
    else:
        notes.append("no nl80211 wiphy data (radio may be in another netns)")
    for (qdrv, cap), reason in DEGRADED.items():
        if qdrv == drv and cap in caps:
            caps[cap] = CapState.degraded(reason)
    for (qdrv, cap), reason in ABSENT.items():
        if qdrv == drv:
            caps[cap] = CapState.absent(reason)
    return HardwareDevice(
        id=f"wifi:{iface.mac}",
        kind="wifi",
        name=known.name if known else f"Wi-Fi ({drv or 'unknown'})",
        driver=iface.driver,
        usb_id=f"{usb.vid}:{usb.pid}" if usb else None,
        bus=iface.bus,
        bus_path=iface.usb_path,
        ifname=iface.name,
        phy=iface.phy,
        mac=iface.mac,
        capabilities=caps,
        notes=notes,
    )


def _usb_only(u: UsbDevice, loaded_modules: set[str]) -> HardwareDevice | None:
    usb_id = f"{u.vid}:{u.pid}"
    known = KNOWN_USB.get(usb_id)
    kind = PRODUCT_STRINGS.get(u.product) or (known.kind if known else None)
    if kind not in ("sdr", "nrf24", "wideband_sdr", "probe", "poe"):
        return None
    name = known.name if known else u.product or usb_id
    ident = f"{kind}:{u.serial}" if u.serial and u.serial not in ("00000001", "0") else f"{kind}:usb-{u.path}"
    caps: dict[C, CapState] = {}
    notes: list[str] = []
    if kind == "sdr":
        bound = [d for d in u.interface_drivers if d in DVB_MODULES]
        if bound:
            caps[C.SDR_SUBGHZ] = CapState.degraded(
                f"kernel DVB driver {bound[0]} has claimed it — blacklist {', '.join(DVB_MODULES)}"
            )
        else:
            caps[C.SDR_SUBGHZ] = CapState.ok()
        notes.append("tuner type (E4000/R820T) identified when opened via librtlsdr")
        if u.serial in ("", "00000001"):
            notes.append("default serial — set unique serials with rtl_eeprom when using several SDRs")
    elif kind == "nrf24":
        if known and known.note:
            caps[C.SPECTRUM_2G4] = CapState.degraded(known.note)
            caps[C.HID_RF_DETECT] = CapState.degraded(known.note)
        else:
            caps[C.SPECTRUM_2G4] = CapState.ok()
            caps[C.HID_RF_DETECT] = CapState.ok()
        notes.append("2.4 GHz sweep is activity-only (RPD threshold ~-64 dBm), not calibrated dBm")
    elif kind == "wideband_sdr":
        caps[C.SPECTRUM_WIDEBAND] = CapState.degraded("driver not implemented yet")
    elif kind == "probe":
        caps |= {
            c: CapState.degraded("driver not implemented yet")
            for c in (C.PROBE_WIREMAP, C.PROBE_TONE, C.PROBE_LENGTH)
        }
    elif kind == "poe":
        caps[C.POE_MEASURE] = CapState.degraded("driver not implemented yet")
    return HardwareDevice(
        id=ident,
        kind=kind,
        name=name,
        usb_id=usb_id,
        bus="usb",
        bus_path=u.path,
        serial=u.serial or None,
        driver=",".join(u.interface_drivers) or None,
        capabilities=caps,
        notes=notes,
    )


# ---------------------------------------------------------------- roles


def _wifi_score(d: HardwareDevice) -> int:
    s = 0
    if d.has(C.WIFI_MONITOR):
        s += 100
    elif d.has(C.WIFI_MONITOR, allow_degraded=True):
        s += 10
    s += 20 * sum(d.has(b) for b in (C.WIFI_BAND_24, C.WIFI_BAND_5, C.WIFI_BAND_6))
    s += 5 * d.has(C.WIFI_AC) + 10 * d.has(C.WIFI_AX)
    return s


def assign_roles(devices: list[HardwareDevice], snap: SystemSnapshot, overrides: dict[str, Role]) -> None:
    by_if = {n.name: n for n in snap.net}
    netdevs = [d for d in devices if d.kind in ("nic", "wifi")]
    for d in netdevs:
        if d.id in overrides:
            d.role = overrides[d.id]

    def free(kind: str) -> list[HardwareDevice]:
        return [d for d in netdevs if d.kind == kind and d.role is None]

    # mgmt: explicit override wins; else the interface holding the default route; else internal Wi-Fi.
    if not any(d.role == "mgmt" for d in netdevs):
        mgmt = next(
            (d for d in netdevs if d.role is None and d.ifname and by_if[d.ifname].default_route), None
        )
        mgmt = mgmt or next((d for d in free("wifi") if d.driver in INTERNAL_WIFI_DRIVERS), None)
        if mgmt:
            mgmt.role = "mgmt"

    # test-wired: prefer multi-gig, then USB-attached adapters.
    if not any(d.role == "test-wired" for d in netdevs):
        wired = sorted(free("nic"), key=lambda d: (not d.has(C.WIRED_MULTIGIG), d.bus != "usb"))
        if wired:
            wired[0].role = "test-wired"
    for d in free("nic"):
        d.role = "unused"

    # Internal (PCI/SDIO) radios are often the user's own connectivity: leave them alone when USB
    # radios exist.
    radios = free("wifi")
    if any(r.bus == "usb" for r in radios):
        for r in radios:
            if r.bus != "usb":
                r.role = "unused"
        radios = [r for r in radios if r.bus == "usb"]
    if not any(d.role == "monitor" for d in netdevs):
        monitor_capable = [r for r in radios if r.has(C.WIFI_MONITOR)]
        if monitor_capable and (len(radios) > 1 or not any(d.role == "test-wifi" for d in netdevs)):
            best = max(monitor_capable, key=_wifi_score)
            best.role = "monitor"
            radios.remove(best)
    for r in radios:
        r.role = "test-wifi"


# ---------------------------------------------------------------- entry point


def detect(snap: SystemSnapshot, role_overrides: dict[str, Role] | None = None) -> Inventory:
    usb = _usb_by_path(snap)
    iw = {w.name: w.iw_info for w in snap.wiphys}
    modules = set(snap.kernel_modules)
    devices: list[HardwareDevice] = []

    for n in snap.net:
        if n.bus == "virtual" or n.name == "lo" or n.bus == "other":
            continue
        u = usb.get(n.usb_path) if n.usb_path else None
        devices.append(_wifi(n, u, iw.get(n.phy) if n.phy else None) if n.wireless else _wired(n, u))

    for u in snap.usb:
        dev = _usb_only(u, modules)
        if dev:
            devices.append(dev)

    for bt in snap.bluetooth:
        devices.append(
            HardwareDevice(
                id=f"ble:{bt.driver or 'unknown'}:{bt.usb_path or bt.bus}",
                kind="ble",
                name=f"Bluetooth {bt.name} ({bt.driver or 'unknown'})",
                driver=bt.driver,
                bus=bt.bus,
                bus_path=bt.usb_path,
                capabilities={C.BLE_SCAN: CapState.ok()},
            )
        )

    plat = detect_platform(snap)
    if plat.battery_percent is not None:
        devices.append(
            HardwareDevice(
                id="platform:battery",
                kind="platform",
                name="Battery",
                capabilities={C.BATTERY: CapState.ok()},
            )
        )

    assign_roles(devices, snap, role_overrides or {})

    present = {d.kind for d in devices}
    missing = [e for e in EXPECTED if e.kind not in present]
    warnings: list[str] = []
    loaded_dvb = sorted(modules & set(DVB_MODULES))
    if loaded_dvb and any(d.kind == "sdr" for d in devices):
        warnings.append(
            f"DVB kernel modules loaded ({', '.join(loaded_dvb)}): RTL-SDR unusable until blacklisted"
        )
    if not any(d.role == "mgmt" for d in devices):
        warnings.append("no management interface: cloud sync and remote UI unavailable")
    if not any(d.role == "test-wired" for d in devices):
        warnings.append("no wired test interface detected")
    return Inventory(source=snap.source, platform=plat, devices=devices, missing=missing, warnings=warnings)
