# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import re
from pathlib import Path

import pytest

from netcaliper.drivers.base import Capability as C
from netcaliper.drivers.detect import detect
from netcaliper.drivers.iwparse import parse_iw_phy_info
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.drivers.snapshot import FIXTURE_DIR, anonymize, dump_snapshot, load_fixture

IW = FIXTURE_DIR / "iw"


def test_iw_parser_on_real_captures() -> None:
    mt = parse_iw_phy_info((IW / "iw_phy_mt76x0u.txt").read_text())
    assert "monitor" in mt.iftypes and mt.bands == {"2g4", "5"} and mt.vht and not mt.he
    rtl = parse_iw_phy_info((IW / "iw_phy_rtl8192cu.txt").read_text())
    assert rtl.bands == {"2g4"} and rtl.ht and not rtl.vht
    ax = parse_iw_phy_info((IW / "iw_phy_iwlwifi.txt").read_text())
    assert ax.he and "5" in ax.bands
    e6 = parse_iw_phy_info((IW / "iw_phy_mt7921u.txt").read_text())
    assert e6.bands == {"2g4", "5", "6"} and e6.he


def test_disabled_channels_ignored() -> None:
    info = parse_iw_phy_info((IW / "iw_phy_brcmfmac.txt").read_text())
    assert 2484.0 not in info.freqs_mhz


def _by_name(inv, part):  # type: ignore[no-untyped-def]
    return next(d for d in inv.devices if part in d.name)


def test_uconsole_roles_and_quirks() -> None:
    inv = detect(load_fixture("uconsole-cm4-full"))
    assert inv.platform.is_uconsole and inv.platform.id == "rpi-cm4" and inv.platform.battery_percent == 100
    assert _by_name(inv, "brcmfmac").role == "mgmt"
    assert _by_name(inv, "brcmfmac").capabilities[C.WIFI_MONITOR].state == "absent"
    assert _by_name(inv, "AX88179").role == "test-wired"
    assert _by_name(inv, "AX88179").capabilities[C.WIRED_CABLE_TEST].state == "absent"
    assert any("USB 2.0" in n for n in _by_name(inv, "AX88179").notes)
    assert _by_name(inv, "MT7610U").role == "monitor"
    rtl = _by_name(inv, "RTL8188CUS")
    assert rtl.role == "test-wifi" and rtl.capabilities[C.WIFI_MONITOR].state == "degraded"
    assert (
        inv.by_capability(C.SDR_SUBGHZ)
        and inv.by_capability(C.HID_RF_DETECT)
        and inv.by_capability(C.BLE_SCAN)
    )
    assert {m.kind for m in inv.missing} == {"probe", "poe", "wideband_sdr", "gps"}
    assert inv.warnings == []


def test_real_uconsole_recording() -> None:
    inv = detect(load_fixture("uconsole-cm4"))
    assert inv.platform.is_uconsole and inv.platform.os.startswith("Debian GNU/Linux 13")
    eth = _by_name(inv, "bcmgenet")
    assert eth.role == "unused" and "no Ethernet jack" in " ".join(eth.notes)
    assert _by_name(inv, "brcmfmac").role == "mgmt"
    assert "no wired test interface detected" in inv.warnings


def test_real_uconsole_with_dongles() -> None:
    # Recorded with AX88179 + MT7610U + RTL8188CUS attached. NetworkManager had DHCP'd the AX88179,
    # giving it the lowest-metric default route — it must still become test-wired, not mgmt.
    inv = detect(load_fixture("uconsole-cm4-dongles"))
    assert _by_name(inv, "brcmfmac").role == "mgmt"
    assert _by_name(inv, "AX88179").role == "test-wired"
    assert _by_name(inv, "MT7610U").role == "monitor"
    assert _by_name(inv, "RTL8188CUS").role == "test-wifi"
    assert _by_name(inv, "bcmgenet").role == "unused"
    assert "no wired test interface detected" not in inv.warnings


def test_future_hardware_autodetected() -> None:
    inv = detect(load_fixture("uconsole-cm4-future"))
    assert _by_name(inv, "MT7921AU").role == "monitor"
    assert _by_name(inv, "MT7921AU").has(C.WIFI_BAND_6) and _by_name(inv, "MT7921AU").has(C.WIFI_AX)
    assert _by_name(inv, "RTL8156").role == "test-wired" and _by_name(inv, "RTL8156").has(C.WIRED_MULTIGIG)
    assert {d.kind for d in inv.devices} >= {"probe", "poe"}


def test_devbox_recording() -> None:
    inv = detect(load_fixture("devbox-jer"))
    assert inv.platform.id == "x86"
    assert _by_name(inv, "AX88179").role == "test-wired"
    assert _by_name(inv, "iwlwifi").role == "unused"  # internal radio left alone when USB radios exist
    assert _by_name(inv, "MT7610U").role == "monitor"
    assert any("DVB" in w for w in inv.warnings)
    assert len([d for d in inv.devices if d.kind == "sdr"]) == 2


def test_role_override_by_stable_id() -> None:
    snap = load_fixture("uconsole-cm4-full")
    rtl_id = _by_name(detect(snap), "RTL8188CUS").id
    inv = detect(snap, {rtl_id: "monitor"})
    assert _by_name(inv, "RTL8188CUS").role == "monitor"
    assert _by_name(inv, "MT7610U").role == "test-wifi"


def test_dvb_bound_sdr_degraded() -> None:
    snap = load_fixture("uconsole-cm4-full")
    next(u for u in snap.usb if u.pid == "2838").interface_drivers = ["dvb_usb_rtl28xxu"]
    sdr = next(d for d in detect(snap).devices if d.kind == "sdr")
    assert sdr.capabilities[C.SDR_SUBGHZ].state == "degraded"


def test_empty_fixture() -> None:
    inv = detect(load_fixture("empty"))
    assert inv.devices == [] and len(inv.warnings) == 2


def test_anonymize_roundtrip(tmp_path: Path) -> None:
    snap = load_fixture("uconsole-cm4-full")
    anon = anonymize(snap)
    ax = next(n for n in anon.net if n.driver == "ax88179_178a")
    assert ax.mac.startswith("00:24:9b:") and ax.mac != "00:24:9b:2f:0c:4a"
    assert "2f0c4a" not in ax.name
    f = tmp_path / "x.yaml"
    f.write_text(dump_snapshot(anon))
    again = detect(load_fixture(str(f)))
    assert [d.role for d in again.devices] == [d.role for d in detect(snap).devices]


def test_unknown_fixture_message() -> None:
    with pytest.raises(FileNotFoundError, match="available"):
        load_fixture("nope")


async def test_registry_find() -> None:
    reg = HardwareRegistry.from_mode("mock:uconsole-cm4-full")
    await reg.refresh()
    assert [d.name for d in reg.find(C.WIFI_MONITOR, role="monitor")] == ["MediaTek MT7610U 802.11ac"]
    assert reg.missing({C.PROBE_WIREMAP, C.WIRED_TEST}) == {C.PROBE_WIREMAP}


IFNAME = re.compile(r"""["'](eth\d|wlan\d|enp\d\w*|wlo\d|wlx[0-9a-f]{12}|enx[0-9a-f]{12})["']""")


def test_no_hardcoded_interface_names() -> None:
    root = Path(__file__).resolve().parents[1] / "netcaliper"
    offenders = [
        f"{p.relative_to(root)}:{i}"
        for p in root.rglob("*.py")
        for i, line in enumerate(p.read_text().splitlines(), 1)
        if IFNAME.search(line)
    ]
    assert offenders == []
