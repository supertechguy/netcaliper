# SPDX-License-Identifier: GPL-3.0-only
"""SystemSnapshot: everything detection needs, gathered from the real system or a YAML fixture.

Detection is a pure function of a snapshot, so a fixture recorded on real hardware
(`netcaliper doctor --record FILE`) replays exactly on any laptop.
"""

from __future__ import annotations

import os
import platform as _platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

TOOLS = (
    "iw",
    "ip",
    "ethtool",
    "wpa_supplicant",
    "nmap",
    "arp-scan",
    "tcpdump",
    "tshark",
    "iperf3",
    "nft",
    "rtl_433",
    "rtl_power",
    "rtl_test",
    "bluetoothctl",
    "cage",
    "chromium",
    "chromium-browser",
)


class UsbDevice(BaseModel):
    path: str  # sysfs bus path, e.g. "1-1.2"
    vid: str
    pid: str
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    speed_mbps: int | None = None
    interface_drivers: list[str] = Field(default_factory=list)


class NetInterface(BaseModel):
    name: str
    mac: str = ""
    driver: str | None = None
    bus: str = "other"  # usb | pci | sdio | platform | virtual | other
    usb_path: str | None = None
    wireless: bool = False
    phy: str | None = None
    has_phydev: bool = False
    operstate: str = "unknown"
    default_route: bool = False
    link_modes: list[str] = Field(default_factory=list)


class Wiphy(BaseModel):
    name: str
    iw_info: str


class BtAdapter(BaseModel):
    name: str
    driver: str | None = None
    bus: str = "other"
    usb_path: str | None = None


class PowerSupply(BaseModel):
    name: str
    type: str
    capacity: int | None = None
    status: str | None = None


class DrmConnector(BaseModel):
    name: str
    status: str
    modes: list[str] = Field(default_factory=list)


class PlatformInfo(BaseModel):
    model: str = ""  # device-tree model (ARM boards)
    compatible: list[str] = Field(default_factory=list)
    dmi_product: str = ""
    arch: str = ""
    kernel: str = ""
    os_release: dict[str, str] = Field(default_factory=dict)
    python: str = ""
    drm: list[DrmConnector] = Field(default_factory=list)


class SystemSnapshot(BaseModel):
    source: str = "real"
    platform: PlatformInfo = Field(default_factory=PlatformInfo)
    usb: list[UsbDevice] = Field(default_factory=list)
    net: list[NetInterface] = Field(default_factory=list)
    wiphys: list[Wiphy] = Field(default_factory=list)
    bluetooth: list[BtAdapter] = Field(default_factory=list)
    power_supplies: list[PowerSupply] = Field(default_factory=list)
    kernel_modules: list[str] = Field(default_factory=list)
    tools: dict[str, str | None] = Field(default_factory=dict)


# ---------------------------------------------------------------- real collection


def _read(p: Path) -> str | None:
    try:
        return p.read_text(errors="replace").strip("\x00\n ")
    except OSError:
        return None


# Debian/Pi OS keep iw, ethtool, nft, wpa_supplicant in /usr/sbin, which is not on an unprivileged
# user's PATH — and our services run unprivileged. Always search the sbin dirs too.
_SBIN = ("/usr/local/sbin", "/usr/sbin", "/sbin")


def which(tool: str) -> str | None:
    path = os.pathsep.join([os.environ.get("PATH", ""), *_SBIN])
    return shutil.which(tool, path=path)


def _run(argv: list[str], timeout: float = 5.0) -> str:
    exe = which(argv[0])
    if exe is None:
        return ""
    try:
        return subprocess.run(
            [exe, *argv[1:]], capture_output=True, text=True, timeout=timeout, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _driver_of(dev: Path) -> str | None:
    link = dev / "driver"
    return os.path.basename(os.readlink(link)) if link.is_symlink() else None


def _bus_of(realpath: str) -> tuple[str, str | None]:
    """Classify a sysfs device path; for USB return the device (not interface) bus path."""
    if "/virtual/" in realpath:
        return "virtual", None
    parts = realpath.split("/")
    usb_iface = next((p for p in reversed(parts) if re.fullmatch(r"\d+-[\d.]+:\d+\.\d+", p)), None)
    if usb_iface:
        return "usb", usb_iface.split(":")[0]
    if "/mmc" in realpath:
        return "sdio", None
    if "/pci" in realpath:
        return "pci", None
    if "/platform/" in realpath or "/soc/" in realpath:
        return "platform", None
    return "other", None


def _default_route_ifaces() -> set[str]:
    out: set[str] = set()
    text = _read(Path("/proc/net/route")) or ""
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) > 2 and cols[1] == "00000000":
            out.add(cols[0])
    return out


def _link_modes(ifname: str) -> list[str]:
    text = _run(["ethtool", ifname])
    modes: list[str] = []
    grab = False
    for line in text.splitlines():
        if "Supported link modes:" in line:
            grab = True
            line = line.split(":", 1)[1]
        elif grab and ":" in line:
            break
        if grab:
            modes += [m for m in line.split() if m != "Not"]
    return modes


def collect_real(sysfs: Path = Path("/sys")) -> SystemSnapshot:
    snap = SystemSnapshot(source="real")

    # platform
    osr: dict[str, str] = {}
    for line in (_read(Path("/etc/os-release")) or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            osr[k] = v.strip('"')
    drm = []
    for c in sorted((sysfs / "class/drm").glob("card*-*")):
        st = _read(c / "status")
        if st is not None:
            drm.append(
                DrmConnector(
                    name=c.name.split("-", 1)[1], status=st, modes=(_read(c / "modes") or "").split()
                )
            )
    snap.platform = PlatformInfo(
        model=_read(Path("/proc/device-tree/model")) or "",
        compatible=[c for c in (_read(Path("/proc/device-tree/compatible")) or "").split("\x00") if c],
        dmi_product=_read(sysfs / "class/dmi/id/product_name") or "",
        arch=_platform.machine(),
        kernel=_platform.release(),
        os_release={k: osr[k] for k in ("ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME") if k in osr},
        python=sys.version.split()[0],
        drm=drm,
    )

    # usb
    for d in sorted((sysfs / "bus/usb/devices").glob("*")):
        if ":" in d.name or d.name.startswith("usb"):
            continue
        vid, pid = _read(d / "idVendor"), _read(d / "idProduct")
        if not vid or not pid:
            continue
        speed = _read(d / "speed")
        ifdrv = sorted({drv for i in d.glob(f"{d.name}:*") if (drv := _driver_of(i))})
        snap.usb.append(
            UsbDevice(
                path=d.name,
                vid=vid,
                pid=pid,
                manufacturer=_read(d / "manufacturer") or "",
                product=_read(d / "product") or "",
                serial=_read(d / "serial") or "",
                speed_mbps=int(float(speed)) if speed else None,
                interface_drivers=ifdrv,
            )
        )

    # net
    defroutes = _default_route_ifaces()
    for n in sorted((sysfs / "class/net").glob("*")):
        dev = n / "device"
        real = os.path.realpath(dev) if dev.exists() else os.path.realpath(n)
        bus, usb_path = _bus_of(real)
        phy = _read(n / "phy80211/name")
        wireless = phy is not None or (n / "wireless").exists()
        iface = NetInterface(
            name=n.name,
            mac=_read(n / "address") or "",
            driver=_driver_of(dev) if dev.exists() else None,
            bus=bus,
            usb_path=usb_path,
            wireless=wireless,
            phy=phy,
            has_phydev=(n / "phydev").exists(),
            operstate=_read(n / "operstate") or "unknown",
            default_route=n.name in defroutes,
        )
        if bus not in ("virtual",) and not wireless and n.name != "lo":
            iface.link_modes = _link_modes(n.name)
        snap.net.append(iface)

    # wiphys
    for p in sorted((sysfs / "class/ieee80211").glob("*")):
        snap.wiphys.append(Wiphy(name=p.name, iw_info=_run(["iw", "phy", p.name, "info"])))

    # bluetooth
    for h in sorted((sysfs / "class/bluetooth").glob("hci*")):
        if ":" in h.name:
            continue
        dev = h / "device"
        bus, usb_path = _bus_of(os.path.realpath(dev)) if dev.exists() else ("other", None)
        snap.bluetooth.append(
            BtAdapter(
                name=h.name, driver=_driver_of(dev) if dev.exists() else None, bus=bus, usb_path=usb_path
            )
        )

    # power
    for ps in sorted((sysfs / "class/power_supply").glob("*")):
        cap = _read(ps / "capacity")
        snap.power_supplies.append(
            PowerSupply(
                name=ps.name,
                type=_read(ps / "type") or "",
                capacity=int(cap) if cap and cap.isdigit() else None,
                status=_read(ps / "status"),
            )
        )

    snap.kernel_modules = sorted(
        line.split()[0] for line in (_read(Path("/proc/modules")) or "").splitlines() if line.strip()
    )
    snap.tools = {t: which(t) for t in TOOLS}
    return snap


# ---------------------------------------------------------------- fixtures

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def fixture_path(name_or_path: str) -> Path:
    p = Path(name_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return p
    cand = FIXTURE_DIR / f"{name_or_path}.yaml"
    if not cand.exists():
        available = ", ".join(sorted(f.stem for f in FIXTURE_DIR.glob("*.yaml")))
        raise FileNotFoundError(f"unknown hardware fixture {name_or_path!r} (available: {available})")
    return cand


def load_fixture(name_or_path: str) -> SystemSnapshot:
    path = fixture_path(name_or_path)
    data: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    for w in data.get("wiphys", []):
        if "iw_info_file" in w:
            w["iw_info"] = (path.parent / w.pop("iw_info_file")).read_text()
    data.setdefault("source", f"fixture:{path.stem}")
    return SystemSnapshot.model_validate(data)


def dump_snapshot(snap: SystemSnapshot) -> str:
    class _Literal(str):
        pass

    def _repr(dumper: yaml.SafeDumper, s: _Literal) -> yaml.ScalarNode:
        return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|")

    yaml.SafeDumper.add_representer(_Literal, _repr)
    data = snap.model_dump(mode="json")
    for w in data["wiphys"]:
        w["iw_info"] = _Literal(w["iw_info"])
    return yaml.safe_dump(data, sort_keys=False)


def anonymize(snap: SystemSnapshot, salt: str = "netcaliper") -> SystemSnapshot:
    """Scrub identifiers before sharing a recorded fixture: keep MAC OUIs (vendor lookup still works),
    replace the NIC-specific half and all USB serials with stable hashes."""
    import hashlib

    def h(value: str, n: int) -> str:
        return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:n]

    def mac(m: str) -> str:
        if len(m.split(":")) != 6:
            return m
        tail = h(m, 6)
        return ":".join([*m.split(":")[:3], tail[0:2], tail[2:4], tail[4:6]])

    s = snap.model_copy(deep=True)
    for n in s.net:
        new = mac(n.mac)
        old_hex, new_hex = n.mac.replace(":", "").lower(), new.replace(":", "")
        if old_hex and old_hex in n.name.lower():  # enx<mac>/wlx<mac> predictable names embed the MAC
            n.name = n.name.lower().replace(old_hex, new_hex)
        n.mac = new
    for u in s.usb:
        if u.serial:
            u.serial = h(u.serial, 8).upper()
    s.platform.dmi_product = "x86 dev box" if s.platform.dmi_product else ""
    for w in s.wiphys:
        w.iw_info = re.sub(r"(?im)^(\s*Wiphy\s+\S+).*$", r"\1", w.iw_info)
    return s
