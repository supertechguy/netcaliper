# SPDX-License-Identifier: GPL-3.0-only
"""Wi-Fi: IE decoder (incl. anonymised real beacons), nl80211 attribute parsing, monitor-frame
accounting, wpa_supplicant config safety, channel analysis, modules on MockNet, agent RPCs, web."""

from __future__ import annotations

import json
import struct
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from netcaliper.agent.server import make_handlers
from netcaliper.core.audit import AuditLog
from netcaliper.core.certs import CertError, CertStore
from netcaliper.core.config import Settings
from netcaliper.core.db import Database
from netcaliper.core.repo import Repository
from netcaliper.core.rpc import Peer, RpcError
from netcaliper.core.secrets import SecretStore
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.modules.autotest import AutoTest, Profile, load_profiles
from netcaliper.modules.registry import all_modules
from netcaliper.modules.runner import ModuleRunner, ModuleStep
from netcaliper.modules.wifi import analyse, radios, relation, same_radio
from netcaliper.net import dot1x, dot11, ie, nl80211, wpa
from netcaliper.net.base import TlsFiles
from netcaliper.net.mock import MockNet
from netcaliper.net.wifi import _account, mark_reported, merge, resolve_security
from netcaliper.net.wifi_base import Bss, MonitorResult, WifiCreds, freq_to_channel
from netcaliper.net.wifi_mock import BAD_PASSPHRASE
from netcaliper.web.app import create_app
from netcaliper.web.icons import ICONS, icon, wordmark
from netcaliper.web.sections import SECTIONS
from netcaliper.web.wifi import WIFI_TESTS, resolve_wifi


def _at(db: Database, registry: HardwareRegistry, net: Any, **kw: Any) -> tuple[AutoTest, Repository]:
    repo = Repository(db)
    return AutoTest(ModuleRunner(all_modules(), repo, AuditLog(db)), registry, repo, net=net, **kw), repo


def by_module(run: Any) -> dict[str, Any]:
    return {s.module: s for s in run.steps}


PEER = Peer(pid=1, uid=0, gid=0)
FIXTURE = Path(__file__).parent / "fixtures" / "ies_real.json"


# ---------------------------------------------------------------- IE decoder


@pytest.mark.parametrize("entry", json.loads(FIXTURE.read_text()), ids=lambda e: e["bssid"])
def test_decoder_on_real_beacons(entry: dict[str, Any]) -> None:
    """Beacons captured on the uConsole (MT7610U), SSIDs/BSSIDs anonymised, neighbour lists removed."""
    b = ie.decode(entry["bssid"], entry["freq"], bytes.fromhex(entry["ies"]), capability=entry["capability"])
    assert {k: getattr(b, k) for k in entry["expect"]} == entry["expect"]


def test_real_beacons_cover_the_interesting_cases() -> None:
    got = {
        (e["expect"]["security"], e["expect"]["width_mhz"], "be" in e["expect"]["standards"])
        for e in json.loads(FIXTURE.read_text())
    }
    assert ("WPA/WPA2-Personal", 20, True) in got  # WPA1 + RSN on a Wi-Fi 7 AP
    assert ("WPA2/WPA3-Personal", 80, True) in got  # VHT 80 MHz
    assert any(s == "Open" for s, _, _ in got) and any(w == 40 for _, w, _ in got)
    ent = next(e for e in json.loads(FIXTURE.read_text()) if e["expect"]["width_mhz"] == 80)
    assert ent["expect"]["center_channel"] == 42


def _beacon(*elems: bytes) -> bytes:
    return ie.ie(0, b"lab") + b"".join(elems)


def test_security_labels() -> None:
    cases = {
        "WPA3-Personal": ie.rsn_ie([8], mfpc=True, mfpr=True),
        "WPA2/WPA3-Personal": ie.rsn_ie([2, 8], mfpc=True),
        "WPA2-Enterprise": ie.rsn_ie([1]),
        "WPA2/WPA3-Enterprise": ie.rsn_ie([1, 5], mfpc=True),
        "WPA3-Enterprise": ie.rsn_ie([5], mfpc=True, mfpr=True),
        "WPA3-Enterprise 192-bit": ie.rsn_ie([12], (9,), 9, True, True),
        "OWE": ie.rsn_ie([18], mfpc=True, mfpr=True),
    }
    for label, rsn in cases.items():
        assert ie.decode("02:00:00:00:00:01", 5180, _beacon(rsn)).security == label, label
    owe_tr = ie.ie(221, ie.OUI_WFA + b"\x1c" + b"\x00" * 6)
    assert ie.decode("02:00:00:00:00:01", 2412, _beacon(owe_tr)).security == "Open (OWE transition)"
    assert ie.decode("02:00:00:00:00:01", 2412, _beacon(), capability=0x10).security == "WEP"
    tkip = ie.decode("02:00:00:00:00:01", 2412, _beacon(ie.rsn_ie([2], (2, 4), 2)))
    assert tkip.pairwise == ["tkip", "ccmp"] and tkip.group == "tkip" and tkip.pmf == "no"


def test_hidden_wps_qbss_and_capabilities() -> None:
    wps = struct.pack(">HHB", 0x1044, 1, 1) + struct.pack(">HHB", 0x1057, 1, 1)
    wps += struct.pack(">HH", 0x1011, 6) + b"Router"
    elems = (
        ie.ie(0, b"\x00\x00\x00")
        + ie.ie(11, struct.pack("<HBH", 9, 128, 0))
        + ie.ie(54, b"\x01\x02\x00")
        + ie.ie(70, b"\x02\x00\x00\x00\x00")
        + ie.ie(127, b"\x00\x00\x08\x00")
        + ie.ie(221, ie.OUI_MS + b"\x04" + wps)
    )
    b = ie.decode("02:00:00:00:00:01", 2437, elems)
    assert b.hidden and b.ssid == "" and b.channel == 6
    assert (b.stations, b.utilization_pct) == (9, 50.2)
    assert (b.k, b.v, b.r) == (True, True, True)
    assert (b.wps, b.wps_state, b.wps_locked, b.wps_device) == (True, "unconfigured", True, "Router")


def test_channel_width_from_ht_vht_he() -> None:
    ht40_below = ie.ie(61, bytes([40, 0x07]) + b"\x00" * 20)
    b = ie.decode("02:00:00:00:00:01", 5200, ie.ie(45, b"\x00" * 26) + ht40_below)
    assert (b.width_mhz, b.center_channel) == (40, 38)
    vht160 = ie.ie(192, bytes([1, 42, 50, 0, 0]))
    assert ie.decode("02:00:00:00:00:01", 5180, vht160).width_mhz == 160
    # HE operation with 6 GHz info: 80 MHz, centre 7 (primary 1)
    params = (1 << 17).to_bytes(3, "little")
    he_op = bytes([36]) + params + b"\x00" + b"\x00\x00" + bytes([1, 0x02, 7, 0, 0])
    b6 = ie.decode("02:00:00:00:00:01", 5955, ie.ie(255, bytes([35]) + b"\x00" * 20) + ie.ie(255, he_op))
    assert (b6.band, b6.channel, b6.width_mhz, b6.center_channel) == ("6", 1, 80, 7)
    assert "ax" in b6.standards


def test_ie_parsing_is_tolerant() -> None:
    assert ie.iter_ies(b"\x00\x05ab") == []  # truncated
    assert ie.iter_ies(ie.ie(0, b"x") + b"\xdd\x09\x00") == [(0, None, b"x")]
    assert ie.parse_rsn(b"\x01") == {"group": None, "pairwise": [], "akms": [], "mfpr": False, "mfpc": False}
    b = ie.decode("02:00:00:00:00:01", 2412, b"\x30\x02\x01\x00" + ie.ie(0, b"\xff\xfe"))
    assert b.ssid == "��"


def test_freq_channel_mapping() -> None:
    assert [freq_to_channel(f) for f in (2412, 2484, 5180, 5825, 5955, 7115)] == [1, 14, 36, 165, 1, 233]


# ---------------------------------------------------------------- nl80211


def test_nl80211_attribute_roundtrip_and_bss() -> None:
    bss = b"".join(
        [
            nl80211.nla(nl80211.BSS_BSSID, bytes.fromhex("020000000001")),
            nl80211.nla(nl80211.BSS_FREQUENCY, struct.pack("=I", 2437)),
            nl80211.nla(nl80211.BSS_CAPABILITY, struct.pack("=H", 0x431)),
            nl80211.nla(nl80211.BSS_BEACON_INTERVAL, struct.pack("=H", 100)),
            nl80211.nla(nl80211.BSS_SIGNAL_MBM, struct.pack("=i", -6100)),
            nl80211.nla(nl80211.BSS_STATUS, struct.pack("=I", 1)),
            nl80211.nla(nl80211.BSS_INFORMATION_ELEMENTS, ie.ie(0, b"lab")),
        ]
    )
    attrs = nl80211.parse_attrs(nl80211.nla_nested(nl80211.ATTR_BSS, [bss]))
    r = nl80211._bss(attrs)
    assert r is not None
    assert (r["bssid"], r["freq"], r["signal_dbm"], r["associated"]) == (
        "02:00:00:00:00:01",
        2437,
        -61.0,
        True,
    )
    assert (r["capability"], r["beacon_interval"], r["ies"]) == (0x431, 100, ie.ie(0, b"lab"))
    assert nl80211._bss({}) is None
    assert nl80211.parse_attr_list(nl80211.nla(1, b"a") + nl80211.nla(2, b"bc")) == [b"a", b"bc"]


# ---------------------------------------------------------------- monitor frames

AP = bytes.fromhex("020000000a01")
STA = bytes.fromhex("3c0000000001")
RAND = bytes.fromhex("da0000000002")
BCAST = b"\xff" * 6


def _frames() -> list[bytes]:
    rt = dot11.radiotap(2437, -40)
    beacon = dot11.mgmt(dot11.ST_BEACON, BCAST, AP, AP, b"\x00" * 12 + ie.ie(0, b"lab"))
    probe = dot11.mgmt(dot11.ST_PROBE_REQ, BCAST, RAND, BCAST, ie.ie(0, b"HomeNet"))
    up = dot11.data(True, AP, STA, BCAST) + b"SECRET-PAYLOAD"
    down = dot11.data(False, STA, AP, AP) + b"SECRET-PAYLOAD"
    deauth = dot11.mgmt(dot11.ST_DEAUTH, STA, AP, AP, b"\x07\x00")
    return [rt + f for f in (beacon, probe, up, down, deauth, deauth)]


def test_radiotap_and_header_parsing_drop_payloads() -> None:
    frames = [dot11.parse(p) for p in _frames()]
    assert all(f is not None and f.freq == 2437 and f.signal_dbm == -40 for f in frames)
    data = frames[2]
    assert data is not None and data.ftype == dot11.T_DATA and data.body == b""  # payload never kept
    assert dot11.data_roles(data) == (dot11.mac_str(STA), dot11.mac_str(AP))
    assert dot11.parse(b"\x01\x00") is None and dot11.parse(b"\x00\x00\x08\x00\x00\x00\x00\x00") is None


def test_monitor_accounting() -> None:
    res, clients = MonitorResult(), {}
    for p in _frames():
        f = dot11.parse(p)
        assert f is not None
        _account(f, res, clients)
    sta, rnd = clients[dot11.mac_str(STA)], clients[dot11.mac_str(RAND)]
    assert res.aps == {dot11.mac_str(AP): "lab"} and res.deauth == {dot11.mac_str(AP): 2}
    assert sta.bssid == dot11.mac_str(AP) and sta.frames == 2 and sta.freq == 2437 and not sta.randomized
    assert rnd.randomized and rnd.probes == ["HomeNet"] and rnd.bssid is None
    assert "SECRET" not in json.dumps([c.model_dump() for c in clients.values()]) + res.model_dump_json()


# ---------------------------------------------------------------- wpa_supplicant config


def test_network_block_safety() -> None:
    c = WifiCreds(ssid='evil"\n}\nnetwork={', passphrase="correct horse")
    block = wpa.network_block(c, "psk")
    assert block.startswith("network={\n\tdisabled=1\n") and "\tssid=" + c.ssid.encode().hex() in block
    assert block.count("network={") == 1 and block.count("}") == 1
    for bad in ('pass"word1', "pass\\word1", "pass\nword1"):
        with pytest.raises(wpa.ConfigError):
            wpa.network_block(WifiCreds(ssid="x", passphrase=bad), "psk")
    with pytest.raises(wpa.ConfigError):
        wpa.network_block(WifiCreds(ssid="x", passphrase="short"), "sae")
    with pytest.raises(wpa.ConfigError):
        wpa.network_block(WifiCreds(ssid="x", bssid="zz"), "open")
    sae = wpa.network_block(WifiCreds(ssid="x", passphrase="12345678"), "sae")
    assert "key_mgmt=SAE" in sae and "ieee80211w=2" in sae
    with pytest.raises(wpa.ConfigError):
        wpa.network_block(WifiCreds(ssid="x", security="eap", eap_method="tls", identity="me"), "eap")
    tls = wpa.network_block(
        WifiCreds(ssid="x", eap_method="tls", identity="me", client_cert="/c.pem", private_key="/k.pem"),
        "eap",
    )
    assert "eap=TLS" in tls and 'client_cert="/c.pem"' in tls and "password=" not in tls


def test_reported_entries_lose_their_copied_signal() -> None:
    def raw(bssid: str, freq: int, parent: str | None = None) -> dict[str, Any]:
        return {"bssid": bssid, "freq": freq, "reported_by": parent, "mld": None}

    rows = [
        raw("02:00:00:00:00:01", 2462),
        raw("02:00:00:00:00:01", 5180, "02:00:00:00:00:01"),
        raw("06:00:00:00:00:01", 2462, "02:00:00:00:00:01"),
        raw("0a:00:00:00:00:01", 5180, "02:00:00:00:00:01"),
    ]
    bss = [
        Bss(
            bssid=r["bssid"],
            freq=r["freq"],
            channel=freq_to_channel(r["freq"]),
            band="2.4" if r["freq"] < 3000 else "5",
            signal_dbm=-40,
        )
        for r in rows
    ]
    mark_reported(bss, rows)
    assert [b.signal_dbm for b in bss] == [-40, None, -40, None]  # MBSSID on the same channel keeps it
    assert bss[3].reported_by == "02:00:00:00:00:01" and bss[0].reported_by is None


def test_resolve_security_and_merge() -> None:
    def bss(akms: list[str], ssid: str = "lab") -> Bss:
        return Bss(bssid="02:00:00:00:00:01", ssid=ssid, freq=2412, channel=1, band="2.4", akms=akms)

    creds = WifiCreds(ssid="lab", passphrase="12345678")
    assert resolve_security(creds, [bss(["psk", "sae"])]) == "psk-sae"
    assert resolve_security(creds, [bss(["sae"])]) == "sae"
    assert resolve_security(creds, [bss(["8021x"])]) == "eap"
    assert resolve_security(creds, [bss([])]) == "open"
    assert resolve_security(creds, []) == "psk"  # not seen: fall back on what we were given
    a = Bss(bssid="02:00:00:00:00:01", freq=2412, channel=1, band="2.4", signal_dbm=-70)
    b = a.model_copy(update={"signal_dbm": -50})
    c = a.model_copy(update={"freq": 5180, "channel": 36, "band": "5"})  # same BSSID, other band (MLO)
    m = merge({"wlan1": [a], "wlan2": [b, c]})
    assert len(m) == 2 and m[0].signal_dbm == -50 and m[0].radios == ["wlan1", "wlan2"]


def test_dot1x_tls_config() -> None:
    conf = dot1x.config(
        "tls", "dev01", "ignored", TlsFiles(client_cert="/c", private_key="/k", ca_cert="/ca")
    )
    assert "eap=TLS" in conf and 'client_cert="/c"' in conf and 'ca_cert="/ca"' in conf
    assert "password=" not in conf
    with pytest.raises(ValueError):
        dot1x.config("tls", "dev01", None)
    with pytest.raises(ValueError):
        dot1x.config("peap", "dev01", "pw", TlsFiles(ca_cert='/x"\n'))


# ---------------------------------------------------------------- channel analysis


def _b(
    ch: int, sig: float, bssid: str = "02:00:00:00:00:01", width: int = 20, cc: int | None = None, **kw: Any
) -> Bss:
    f = 2407 + 5 * ch if ch <= 14 else 5000 + 5 * ch
    return Bss(
        bssid=bssid,
        freq=f,
        channel=ch,
        band="2.4" if ch <= 14 else "5",
        signal_dbm=sig,
        width_mhz=width,
        center_channel=cc or ch,
        **kw,
    )


def test_channel_relations() -> None:
    assert relation(_b(6, -50), _b(6, -60)) == "co"
    assert relation(_b(6, -50), _b(4, -60)) == "adjacent"
    assert relation(_b(6, -50), _b(11, -60)) is None and relation(_b(1, -50), _b(6, -60)) is None
    assert relation(_b(36, -50, width=80, cc=42), _b(44, -60)) == "co"  # inside the 80 MHz span: contends
    assert relation(_b(36, -50, width=40, cc=38), _b(44, -60, width=40, cc=46)) is None
    assert relation(_b(36, -50, width=80, cc=42), _b(48, -60, width=40, cc=46)) == "co"
    assert relation(_b(6, -50), _b(36, -50)) is None
    assert same_radio(_b(6, -50, "8c:30:66:80:7c:55"), _b(6, -50, "92:30:66:80:7c:55"))
    assert same_radio(_b(6, -50, "44:d9:e7:10:00:01"), _b(6, -50, "44:d9:e7:10:00:03"))
    assert not same_radio(_b(6, -50, "44:d9:e7:10:00:01"), _b(11, -50, "44:d9:e7:10:00:02"))


def test_analyse_recommends_quiet_channels() -> None:
    bss = [
        _b(1, -45, "02:00:00:00:01:01", ssid="lab"),
        _b(1, -55, "02:00:00:00:02:01"),
        _b(3, -60, "02:00:00:00:03:01"),
        _b(6, -50, "02:00:00:00:04:01"),
        _b(11, -90, "02:00:00:00:05:01"),  # below the floor: ignored
        _b(36, -50, "02:00:00:00:06:01", width=80, cc=42),
    ]
    a = analyse(bss, "lab", -82)
    assert a["best_24"] == 11 and a["off_plan_24"] == [3] and a["radios"] == 5
    assert not a["best_5"].startswith("36")
    t = a["target"][0]
    assert (t["cochannel"], t["adjacent"]) == (1, 1)
    assert len(radios(bss)) == 6


# ---------------------------------------------------------------- modules on MockNet


def _resolver(tmp_path: Path, **saved: str) -> Any:
    secrets = SecretStore(tmp_path / "secrets.json")
    if saved:
        secrets.put("wifi", saved)
    certs = CertStore(tmp_path / "certs")
    return lambda s: resolve_wifi(s, secrets, certs)


async def test_wifi_profile_end_to_end(db: Database, registry: HardwareRegistry, tmp_path: Path) -> None:
    resolve = _resolver(tmp_path, ssid="CorpNet", passphrase="correct-horse")
    at, repo = _at(db, registry, MockNet(), resolve=resolve)
    at.start(load_profiles()["wifi"])
    run = await at.wait()
    assert run is not None and run.interface == "wlx0013ef000001"  # the test-wifi role, not the mgmt radio
    m = by_module(run)
    assert all(s.status in ("pass", "warn") for s in run.steps), [
        (s.module, s.status, s.message) for s in run.steps
    ]
    assert (
        m["wifi.connect"].metrics["bssid"] == "44:d9:e7:10:00:01"
        and m["wifi.connect"].metrics["snr_db"] == 47
    )
    assert m["wifi.dhcp"].status == "pass" and m["wifi.roam"].metrics["roams"] == 4
    assert m["wifi.clients"].metrics["clients"] > 0
    results = {r.module_id: r for r in await repo.results(run.run_id)}
    blob = json.dumps([r.model_dump(mode="json") for r in results.values()])
    assert "correct-horse" not in blob  # credentials never reach results (or the outbox)
    macs = [c["mac"] for c in results["wifi.clients"].details["clients"]]
    assert macs and all(len(x) == 17 for x in macs)  # client MACs are kept in the report
    findings = await repo.findings(run.run_id)
    assert {"wifi.open", "wifi.wps", "wifi.tkip"} <= {f.rule_id for f in findings}
    assert at.net._assoc == {}  # left the network at the end of the run


async def test_wifi_wrong_key_skips_link_steps(
    db: Database, registry: HardwareRegistry, tmp_path: Path
) -> None:
    resolve = _resolver(tmp_path, ssid="CorpNet", passphrase=BAD_PASSPHRASE)
    at, _ = _at(db, registry, MockNet(deauth_flood=True), resolve=resolve)
    at.start(load_profiles()["wifi"])
    run = await at.wait()
    assert run is not None
    m = by_module(run)
    assert m["wifi.connect"].status == "fail" and "wrong passphrase" in m["wifi.connect"].message
    for mod in ("wifi.dhcp", "net.dns", "net.gateway", "wifi.roam"):
        assert (m[mod].status, m[mod].message) == ("skipped", "not associated")
    assert m["wifi.scan"].status == "pass" and m["wifi.clients"].status == "warn"  # deauth flood seen
    assert run.status == "fail"


async def test_wifi_without_saved_network(db: Database, registry: HardwareRegistry, tmp_path: Path) -> None:
    at, _ = _at(db, registry, MockNet(), resolve=_resolver(tmp_path))
    at.start(
        Profile(
            id="w",
            name="w",
            interface="test-wifi",
            steps=[ModuleStep(module="wifi.connect"), ModuleStep(module="wifi.dhcp")],
        )
    )
    run = await at.wait()
    assert run is not None and [s.status for s in run.steps] == ["skipped", "skipped"]
    assert "Wi-Fi screen" in run.steps[0].message


async def test_wifi_profile_needs_a_test_radio(db: Database, tmp_path: Path) -> None:
    reg = HardwareRegistry.from_mode("mock:uconsole-cm4-full", {})
    await reg.refresh()
    for d in reg.inventory.by_role("test-wifi"):
        d.role = "unused"
    at, _ = _at(db, reg, MockNet(), resolve=_resolver(tmp_path, ssid="CorpNet", passphrase="correct-horse"))
    at.start(load_profiles()["wifi"])
    run = await at.wait()
    assert run is not None and all(s.status == "skipped" for s in run.steps)
    assert run.steps[0].message == "no test-wifi radio"


def test_resolve_wifi_fills_saved_network_and_certs(tmp_path: Path) -> None:
    secrets, certs = SecretStore(tmp_path / "s.json"), CertStore(tmp_path / "certs")
    pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    certs.put("corp", "ca", pem)
    certs.put("dev", "cert", pem)
    certs.put("dev", "key", b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
    secrets.put(
        "wifi",
        {
            "ssid": "Corp",
            "security": "eap",
            "eap_method": "tls",
            "identity": "me",
            "ca_cert": "corp",
            "client_cert": "dev",
            "private_key": "dev",
        },
    )
    cfg = resolve_wifi(ModuleStep(module="wifi.connect"), secrets, certs).config
    assert cfg["ssid"] == "Corp" and cfg["ca_cert"] == str(tmp_path / "certs/corp.ca.pem")
    assert cfg["client_cert"].endswith("dev.crt.pem") and cfg["private_key"].endswith("dev.key.pem")
    other = resolve_wifi(ModuleStep(module="wifi.connect", config={"ssid": "Other"}), secrets, certs).config
    assert other == {"ssid": "Other"}  # saved credentials only go to the saved network
    assert resolve_wifi(ModuleStep(module="wifi.channels"), secrets, certs).config == {"ssid": "Corp"}
    step = ModuleStep(module="net.dns")
    assert resolve_wifi(step, secrets, certs) is step


def test_cert_store(tmp_path: Path) -> None:
    s = CertStore(tmp_path / "certs")
    with pytest.raises(CertError):
        s.put("../x", "ca", b"-----BEGIN CERTIFICATE-----")
    with pytest.raises(CertError):
        s.put("x", "ca", b"#!/bin/sh\n")
    with pytest.raises(CertError):
        s.put("x", "key", b"-----BEGIN CERTIFICATE-----")
    p = s.put("x", "ca", b"0\x82\x01\x00")  # DER
    assert p.stat().st_mode & 0o777 == 0o600 and (tmp_path / "certs").stat().st_mode & 0o777 == 0o700
    assert s.list() == {"x": ["ca"]} and s.path("x", "key") is None
    s.delete("x")
    assert s.list() == {}


# ---------------------------------------------------------------- agent


@pytest.fixture
def sysfs(tmp_path: Path) -> Path:
    (tmp_path / "class/net/eth1").mkdir(parents=True)
    (tmp_path / "class/net/wlan1/phy80211").mkdir(parents=True)
    (tmp_path / "class/net/wlan2/phy80211").mkdir(parents=True)
    return tmp_path


async def test_agent_wifi_rpcs(sysfs: Path) -> None:
    net = MockNet()
    h = make_handlers("ncal-test", sysfs, net=net)
    radios = {"test-wifi": "wlan1", "monitor": "wlan2"}
    r = await h["module.run"]({"module": "wifi.scan", "ifname": "wlan1", "radios": radios}, PEER)
    assert r["result"]["status"] == "pass" and r["session"]["wifi_scan"]
    assert set(r["result"]["metrics"]["radios"].split(",")) == {"wlan1", "wlan2"}
    for bad in ({"test-wifi": "eth1"}, {"monitor": "../x"}, {"monitor": "wlan9"}, ["wlan1"]):
        with pytest.raises(RpcError):
            await h["module.run"]({"module": "wifi.scan", "ifname": "wlan1", "radios": bad}, PEER)
    s = await h["wifi.sample"]({"ifname": "wlan2", "mac": "44:D9:E7:10:00:01", "freq": 2412}, PEER)
    assert s and all(-60 < x["signal_dbm"] < -40 for x in s)
    for bad_params in (
        {"ifname": "eth1", "mac": "44:d9:e7:10:00:01", "freq": 2412},
        {"ifname": "wlan2", "mac": "nope", "freq": 2412},
        {"ifname": "wlan2", "mac": "44:d9:e7:10:00:01", "freq": 900},
    ):
        with pytest.raises(RpcError):
            await h["wifi.sample"](bad_params, PEER)
    await net.wifi_connect("wlan1", WifiCreds(ssid="CorpGuest"))
    assert (await h["wifi.end"]({"ifname": "wlan1"}, PEER)) == {"ok": True} and net._assoc == {}


# ---------------------------------------------------------------- web


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, test_net=MockNet())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.app = app  # type: ignore[attr-defined]
            yield c


async def test_wifi_screen_scan_and_view(client: httpx.AsyncClient) -> None:
    page = await client.get("/s/wifi")
    assert page.status_code == 200 and all(f"/wifi/run/{k}" in page.text for k in WIFI_TESTS)
    assert "Save a network first" in (await client.post("/wifi/run/connect")).text
    r = await client.post("/wifi/run/scan")
    assert "Wi-Fi Scan" in r.text
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    assert run.status in ("pass", "warn") and run.interface == "wlx0013ef000001"
    final = (await client.get(f"/partials/run/{run.run_id}")).text
    assert f"/partials/wifi/view/{run.run_id}" in final
    view = (await client.get(f"/partials/wifi/view/{run.run_id}")).text
    assert "CorpNet" in view and "/s/wifi/locate?mac=44:d9:e7:10:00:01&freq=2412" in view
    loc = await client.get(
        "/s/wifi/locate", params={"mac": "44:d9:e7:10:00:01", "freq": 2412, "label": "CorpNet"}
    )
    assert loc.status_code == 200 and "locate.js" in loc.text
    s = (await client.get("/api/v1/wifi/sample", params={"mac": "44:d9:e7:10:00:01", "freq": 2412})).json()
    assert s["samples"] == 5 and -60 < s["signal_dbm"] < -40
    assert (await client.get("/api/v1/wifi/sample", params={"mac": "x", "freq": 2412})).status_code == 400


async def test_wifi_network_credentials_local_only(client: httpx.AsyncClient, settings: Settings) -> None:
    bad = await client.post("/wifi/network", data={"ssid": "Corp", "passphrase": 'a"b\ncdefgh'})
    assert "No quotes" in bad.text
    assert "8-63" in (await client.post("/wifi/network", data={"ssid": "Corp", "passphrase": "short"})).text
    ok = await client.post("/wifi/network", data={"ssid": "CorpNet", "passphrase": "correct-horse"})
    assert "Saved CorpNet" in ok.text
    page = (await client.get("/s/wifi")).text
    assert "correct-horse" not in page and "(unchanged)" in page
    # re-saving the same network without retyping keeps the passphrase
    await client.post("/wifi/network", data={"ssid": "CorpNet", "security": "psk"})
    saved = SecretStore(settings.data_dir / "secrets.json").get("wifi") or {}
    assert (
        saved["passphrase"] == "correct-horse"
        and (settings.data_dir / "secrets.json").stat().st_mode & 0o777 == 0o600
    )
    await client.post("/wifi/run/connect")
    run = await client.app.state.autotest.wait()  # type: ignore[attr-defined]
    assert by_module(run)["wifi.connect"].status == "pass"
    tls = await client.post("/wifi/network", data={"ssid": "X", "security": "eap", "eap_method": "tls"})
    assert "client certificate" in tls.text
    assert "removed" in (await client.post("/wifi/network/clear")).text


async def test_cert_upload(client: httpx.AsyncClient, settings: Settings) -> None:
    pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    r = await client.post("/certs", data={"name": "corp-ca", "kind": "ca"}, files={"file": ("ca.pem", pem)})
    assert "Imported ca corp-ca" in r.text
    assert (
        "not a PEM"
        in (
            await client.post("/certs", data={"name": "y", "kind": "ca"}, files={"file": ("x", b"hello")})
        ).text
    )
    page = (await client.get("/s/wifi")).text
    assert "<option>corp-ca</option>" in page
    assert "Removed" in (await client.post("/certs/corp-ca/delete")).text
    assert not (settings.data_dir / "certs/corp-ca.ca.pem").exists()


# ---------------------------------------------------------------- icons


def test_icons_are_square_pixel_grids() -> None:
    for name, rows in ICONS.items():
        assert len(rows) == 12 and all(len(r) == 12 and set(r) <= {".", "#"} for r in rows), name
        assert any("#" in r for r in rows), name
    assert all(s.slug in ICONS for s in SECTIONS) and all(k in ICONS for k in WIFI_TESTS)
    svg = str(icon("wifi"))
    assert svg.startswith("<svg") and 'fill="currentColor"' in svg and 'height=".78"' in svg  # scanlines
    assert str(icon("nope")) == ""
    assert 'aria-label="netcaliper"' in str(wordmark())


async def test_pages_render_icons(client: httpx.AsyncClient) -> None:
    for path in ("/", "/s/wifi", "/s/wired", "/s/autotest", "/s/results", "/s/tools"):
        page = await client.get(path)
        assert page.status_code == 200 and '<svg class="ico' in page.text, path
    assert 'class="wordmark"' in (await client.get("/partials/status")).text
