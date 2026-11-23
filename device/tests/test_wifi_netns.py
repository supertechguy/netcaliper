# SPDX-License-Identifier: GPL-3.0-only
"""Wi-Fi end to end over mac80211_hwsim: two hostapd APs on one SSID (one bridge, one DHCP server)
and a client namespace that runs the *agent's* module handlers (scan → connect → DHCP → gateway →
roam → monitor) exactly as on the device. Needs root, the mac80211_hwsim module, hostapd,
wpa_supplicant, dnsmasq and iw; skips otherwise. Simulated radios only — nothing is transmitted.

    ns AP:  wlanA (ch 1) ─┐
            wlanB (ch 6) ─┴─ br0 10.88.0.1/24  dnsmasq        (hostapd: SSID ncal-roam, WPA2-PSK)
    ns CL:  wlanC (test-wifi)  wlanD (monitor)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from netcaliper.drivers.snapshot import which

pytestmark = pytest.mark.netns

IP = which("ip") or "ip"
TOOLS = {t: which(t) for t in ("hostapd", "wpa_supplicant", "dnsmasq", "iw", "modprobe")}
SSID, PSK = "ncal-roam", "ncal-roam-pass"

CLIENT = """
import asyncio, json, sys
from pathlib import Path
from netcaliper.agent.server import make_handlers
from netcaliper.core.rpc import Peer

async def main():
    ifname, radios, steps = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
    h = make_handlers("client", Path("/sys"))
    session, out = {}, {}
    for key, mod, cfg in steps:
        params = {"module": mod, "config": cfg, "ifname": ifname, "session": session, "radios": radios}
        r = await h["module.run"](params, Peer(0, 0, 0))
        session = r["session"]
        out[key] = r["result"]
    await h["wifi.end"]({"ifname": ifname}, Peer(0, 0, 0))
    print(json.dumps(out))

asyncio.run(main())
"""


def sh(*argv: str, ns: str | None = None, check: bool = True) -> str:
    cmd = [IP, "netns", "exec", ns, *argv] if ns else [which(argv[0]) or argv[0], *argv[1:]]
    return subprocess.run(cmd, check=check, capture_output=True, text=True).stdout


def hwsim_phys() -> set[str]:
    out = set()
    for p in Path("/sys/class/ieee80211").glob("*"):
        drv = p / "device" / "driver"
        if drv.exists() and drv.resolve().name == "mac80211_hwsim":
            out.add(p.name)
    return out


def iface_of(ns: str, phy: str) -> str:
    return sh("ls", f"/sys/class/ieee80211/{phy}/device/net", ns=ns).split()[0]


@pytest.fixture
def air(tmp_path: Path) -> Iterator[dict[str, Any]]:
    missing = [t for t, p in TOOLS.items() if not p]
    if missing:
        pytest.skip("needs " + ", ".join(missing))
    if Path("/sys/module/mac80211_hwsim").exists():
        pytest.skip("mac80211_hwsim already loaded by someone else")
    if (
        subprocess.run(
            [TOOLS["modprobe"] or "modprobe", "mac80211_hwsim", "radios=4"], capture_output=True
        ).returncode
        != 0
    ):
        pytest.skip("mac80211_hwsim not available in this kernel")
    n = os.getpid() % 10000
    ap, cl = f"ncal-wap{n}", f"ncal-wcl{n}"
    procs: list[subprocess.Popen[bytes]] = []
    try:
        time.sleep(1)
        phys = sorted(hwsim_phys(), key=lambda p: int(p.removeprefix("phy")))
        assert len(phys) == 4, phys
        for ns in (ap, cl):
            sh(IP, "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for phy, ns in zip(phys, (ap, ap, cl, cl), strict=True):
            sh("iw", "phy", phy, "set", "netns", "name", ns)
        wa, wb = iface_of(ap, phys[0]), iface_of(ap, phys[1])
        wc, wd = iface_of(cl, phys[2]), iface_of(cl, phys[3])
        sh("ip", "link", "add", "br0", "type", "bridge", ns=ap)
        sh("ip", "addr", "add", "10.88.0.1/24", "dev", "br0", ns=ap)
        sh("ip", "link", "set", "br0", "up", ns=ap)
        confs = []
        for w, ch in ((wa, 1), (wb, 6)):
            c = tmp_path / f"{w}.conf"
            c.write_text(
                f"interface={w}\nbridge=br0\ndriver=nl80211\nssid={SSID}\nhw_mode=g\nchannel={ch}\n"
                f"wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={PSK}\nieee80211w=1\n"
            )
            confs.append(str(c))
        log = tmp_path / "hostapd.log"
        procs.append(
            subprocess.Popen(
                [IP, "netns", "exec", ap, TOOLS["hostapd"] or "hostapd", *confs],
                stdout=log.open("wb"),
                stderr=subprocess.STDOUT,
            )
        )
        procs.append(
            subprocess.Popen(
                [
                    IP,
                    "netns",
                    "exec",
                    ap,
                    TOOLS["dnsmasq"] or "dnsmasq",
                    "-k",
                    "--no-ping",
                    "--port=0",
                    "--interface=br0",
                    "--bind-interfaces",
                    "--dhcp-range=10.88.0.50,10.88.0.99,1h",
                    f"--dhcp-leasefile={tmp_path / 'leases'}",
                    "--dhcp-option=3,10.88.0.1",
                ],
                stdout=(tmp_path / "dnsmasq.log").open("wb"),
                stderr=subprocess.STDOUT,
            )
        )
        for _ in range(50):
            if log.read_text().count("AP-ENABLED") >= 2:
                break
            time.sleep(0.2)
        else:
            pytest.fail("hostapd did not start: " + log.read_text()[-2000:])
        yield {
            "cl": cl,
            "wc": wc,
            "wd": wd,
            "ap_macs": {sh("cat", f"/sys/class/net/{w}/address", ns=ap).strip() for w in (wa, wb)},
            "log": log,
        }
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns in (ap, cl):
            subprocess.run([IP, "netns", "del", ns], capture_output=True)
        time.sleep(0.5)
        subprocess.run([which("rmmod") or "rmmod", "mac80211_hwsim"], capture_output=True)


def run(air: dict[str, Any], steps: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
    radios = {"test-wifi": air["wc"], "monitor": air["wd"]}
    p = subprocess.run(
        [
            IP,
            "netns",
            "exec",
            air["cl"],
            sys.executable,
            "-c",
            CLIENT,
            air["wc"],
            json.dumps(radios),
            json.dumps(steps),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert p.returncode == 0, p.stderr[-3000:]
    out: dict[str, Any] = json.loads(p.stdout.strip().splitlines()[-1])
    return out


def test_wifi_scan_connect_dhcp_roam_monitor(air: dict[str, Any]) -> None:
    r = run(
        air,
        [
            ("scan", "wifi.scan", {"expect_ssids": [SSID], "channels": [1, 6, 11]}),
            ("channels", "wifi.channels", {"ssid": SSID}),
            ("wrong", "wifi.connect", {"ssid": SSID, "passphrase": "not-the-pass"}),
            ("missing", "wifi.connect", {"ssid": "ncal-nowhere", "passphrase": PSK, "timeout_s": 60}),
            ("connect", "wifi.connect", {"ssid": SSID, "passphrase": PSK}),
            ("dhcp", "wifi.dhcp", {}),
            ("gateway", "net.gateway", {}),
            ("roam", "wifi.roam", {"min_signal_dbm": -100}),
            ("clients", "wifi.clients", {"duration_s": 4, "channels": [1, 6]}),
        ],
    )
    scan = r["scan"]
    assert scan["status"] == "pass", scan["message"]
    ours = [b for b in scan["details"]["bss"] if b["ssid"] == SSID]
    assert {b["bssid"] for b in ours} == air["ap_macs"]
    assert all(b["security"] == "WPA2-Personal" and b["pmf"] == "capable" for b in ours)
    assert {b["channel"] for b in ours} == {1, 6}
    assert r["channels"]["metrics"]["max_cochannel"] == 0
    assert r["wrong"]["status"] == "fail" and r["wrong"]["metrics"]["reason"] == "WRONG_KEY"
    assert r["missing"]["status"] == "fail" and r["missing"]["metrics"]["reason"] == "NETWORK_NOT_FOUND"
    c = r["connect"]
    assert c["status"] == "pass", c["message"]
    assert c["metrics"]["bssid"] in air["ap_macs"] and c["metrics"]["security"] == "WPA2-PSK"
    assert c["metrics"]["connect_ms"] > 0 and c["metrics"]["assoc_ms"] is not None
    assert r["dhcp"]["status"] == "pass" and r["dhcp"]["metrics"]["router"] == "10.88.0.1"
    assert r["gateway"]["status"] == "pass", r["gateway"]["message"]
    roam = r["roam"]
    assert roam["status"] == "pass", roam
    assert roam["metrics"]["roams"] == 2 and roam["metrics"]["failed"] == 0  # there and back
    assert roam["metrics"]["roam_worst_ms"] < 5000 and roam["metrics"]["gap_worst_ms"] is not None
    clients = r["clients"]
    assert clients["status"] in ("pass", "warn"), clients["message"]
    assert set(clients["details"]["aps"]) >= air["ap_macs"]
