# SPDX-License-Identifier: GPL-3.0-only
"""802.11 information-element decoder (beacons / probe responses / nl80211 scan results).

Our own: every field we report comes from the raw IEs, so results are identical whether the BSS was
seen by an nl80211 scan or a monitor-mode beacon. All multi-byte IE fields are little-endian.
"""

from __future__ import annotations

import struct
from typing import Any

from .wifi_base import Bss, band_of, freq_to_channel

AKM = {
    1: "8021x",
    2: "psk",
    3: "ft-8021x",
    4: "ft-psk",
    5: "8021x-sha256",
    6: "psk-sha256",
    8: "sae",
    9: "ft-sae",
    11: "8021x-suite-b",
    12: "8021x-suite-b-192",
    13: "ft-8021x-sha384",
    18: "owe",
    24: "sae-ext",
    25: "ft-sae-ext",
}
CIPHER = {
    1: "wep40",
    2: "tkip",
    4: "ccmp",
    5: "wep104",
    6: "bip-cmac",
    8: "gcmp",
    9: "gcmp-256",
    10: "ccmp-256",
    11: "bip-gmac-128",
    12: "bip-gmac-256",
    13: "bip-cmac-256",
}
OUI_IEEE = b"\x00\x0f\xac"
OUI_MS = b"\x00\x50\xf2"
OUI_WFA = b"\x50\x6f\x9a"


def iter_ies(data: bytes) -> list[tuple[int, int | None, bytes]]:
    """[(id, ext_id or None, body)] — tolerant of truncation (stops at the first broken element)."""
    out: list[tuple[int, int | None, bytes]] = []
    i = 0
    while i + 2 <= len(data):
        eid, ln = data[i], data[i + 1]
        body = data[i + 2 : i + 2 + ln]
        if len(body) < ln:
            break
        if eid == 255 and body:
            out.append((255, body[0], body[1:]))
        else:
            out.append((eid, None, body))
        i += 2 + ln
    return out


def _suites(b: bytes, i: int, oui: bytes, table: dict[int, str]) -> tuple[list[str], int]:
    if i + 2 > len(b):
        return [], i
    n = struct.unpack_from("<H", b, i)[0]
    i += 2
    out = []
    for _ in range(n):
        s = b[i : i + 4]
        if len(s) < 4:
            break
        out.append(table.get(s[3], f"{s[:3].hex()}:{s[3]}") if s[:3] == oui else f"{s[:3].hex()}:{s[3]}")
        i += 4
    return out, i


def parse_rsn(b: bytes, oui: bytes = OUI_IEEE, wpa1: bool = False) -> dict[str, Any]:
    r: dict[str, Any] = {"group": None, "pairwise": [], "akms": [], "mfpr": False, "mfpc": False}
    if len(b) < 2:
        return r
    i = 2  # version
    if i + 4 <= len(b):
        g = b[i : i + 4]
        r["group"] = CIPHER.get(g[3], g.hex()) if g[:3] == oui else g.hex()
        i += 4
    r["pairwise"], i = _suites(b, i, oui, CIPHER)
    r["akms"], i = _suites(b, i, oui, AKM if not wpa1 else {1: "8021x", 2: "psk"})
    if not wpa1 and i + 2 <= len(b):
        caps = struct.unpack_from("<H", b, i)[0]
        r["mfpr"], r["mfpc"] = bool(caps & 0x40), bool(caps & 0x80)
    return r


def parse_wps(b: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    i = 0
    while i + 4 <= len(b):
        t, ln = struct.unpack_from(">HH", b, i)  # WPS TLVs are big-endian
        v = b[i + 4 : i + 4 + ln]
        i += 4 + ln
        if t == 0x1044 and v:
            out["state"] = {1: "unconfigured", 2: "configured"}.get(v[0], str(v[0]))
        elif t == 0x1057 and v:
            out["locked"] = bool(v[0])
        elif t == 0x1011:
            out["device"] = v.decode("utf-8", "replace").strip("\x00").strip() or None
    return out


def security_label(
    akms: list[str], wpa1: bool, privacy: bool, owe_transition: bool, pmf_required: bool
) -> str:
    a = set(akms)
    ent = {x for x in a if "8021x" in x}
    if "8021x-suite-b-192" in a:
        return "WPA3-Enterprise 192-bit"
    if ent:
        if pmf_required and "8021x" not in ent:  # only SHA-256/FT AKMs + PMF required
            return "WPA3-Enterprise"
        if "8021x-sha256" in ent:
            return "WPA2/WPA3-Enterprise"
        return "WPA/WPA2-Enterprise" if wpa1 else "WPA2-Enterprise"
    sae = bool(a & {"sae", "ft-sae", "sae-ext", "ft-sae-ext"})
    psk = bool(a & {"psk", "ft-psk", "psk-sha256"})
    if sae and psk:
        return "WPA2/WPA3-Personal"
    if sae:
        return "WPA3-Personal"
    if psk:
        return "WPA/WPA2-Personal" if wpa1 and a else "WPA2-Personal"
    if "owe" in a:
        return "OWE"
    if wpa1:
        return "WPA-Personal"
    if owe_transition:
        return "Open (OWE transition)"
    return "WEP" if privacy else "Open"


def _ht_streams(htcap: bytes) -> int:
    mcs = htcap[3:7] if len(htcap) >= 7 else b""
    return sum(1 for x in mcs if x)


def _vht_streams(vhtcap: bytes) -> int:
    if len(vhtcap) < 6:
        return 0
    m = struct.unpack_from("<H", vhtcap, 4)[0]
    return sum(1 for s in range(8) if (m >> (2 * s)) & 3 != 3)


def decode(
    bssid: str,
    freq: int,
    ies: bytes,
    *,
    capability: int | None = None,
    signal_dbm: float | None = None,
    beacon_interval: int | None = None,
    seen_ms_ago: int | None = None,
    associated: bool = False,
) -> Bss:
    channel = freq_to_channel(freq)
    b = Bss(
        bssid=bssid,
        freq=freq,
        channel=channel,
        band=band_of(freq),
        signal_dbm=signal_dbm,
        beacon_interval=beacon_interval,
        seen_ms_ago=seen_ms_ago,
        associated=associated,
    )
    privacy = bool(capability is not None and capability & 0x10)
    rsn: dict[str, Any] | None = None
    wpa: dict[str, Any] | None = None
    owe_transition = False
    ofdm = False
    std: set[str] = set()
    streams = 0
    ht_sec_offset, ht_any_width = 0, False
    vht_op: bytes | None = None
    he_6g: bytes | None = None
    for eid, ext, body in iter_ies(ies):
        if eid == 0:
            b.ssid = body.decode("utf-8", "replace")
            b.hidden = not body or all(c == 0 for c in body)
            if b.hidden:
                b.ssid = ""
        elif eid in (1, 50):
            if any((r & 0x7F) > 22 for r in body):  # rates above 11 Mb/s (units of 500 kb/s) = OFDM
                ofdm = True
        elif eid == 3 and body:
            ch = body[0]
            if ch and b.band == "2.4" and ch != channel:
                b.channel = ch  # DS parameter set is authoritative on 2.4 GHz
        elif eid == 7 and len(body) >= 2:
            b.country = body[:2].decode("ascii", "replace")
        elif eid == 11 and len(body) >= 3:
            b.stations = struct.unpack_from("<H", body, 0)[0]
            b.utilization_pct = round(body[2] * 100 / 255, 1)
        elif eid == 45:
            std.add("n")
            streams = max(streams, _ht_streams(body))
        elif eid == 61 and len(body) >= 2:
            ht_sec_offset, ht_any_width = body[1] & 0x03, bool(body[1] & 0x04)
        elif eid == 48:
            rsn = parse_rsn(body)
        elif eid == 54:
            b.r = True
        elif eid == 70:
            b.k = True
        elif eid == 127 and len(body) >= 3:
            b.v = bool(body[2] & 0x08)  # bit 19: BSS transition
        elif eid == 191:
            std.add("ac")
            streams = max(streams, _vht_streams(body))
        elif eid == 192:
            vht_op = body
        elif eid == 221 and len(body) >= 4:
            oui, t = body[:3], body[3]
            if oui == OUI_MS and t == 1:
                wpa = parse_rsn(body[4:], OUI_MS, wpa1=True)
            elif oui == OUI_MS and t == 4:
                w = parse_wps(body[4:])
                b.wps, b.wps_state, b.wps_locked, b.wps_device = (
                    True,
                    w.get("state"),
                    w.get("locked"),
                    w.get("device"),
                )
            elif oui == OUI_WFA and t == 0x1C:
                owe_transition = True
        elif eid == 255 and ext == 35:
            std.add("ax")
        elif eid == 255 and ext == 36:
            he_6g = _he_6ghz_info(body)
        elif eid == 255 and ext == 108:
            std.add("be")

    # standards
    if b.band == "2.4":
        std.add("g" if ofdm else "b")
        if ofdm:
            std.add("b")  # 2.4 GHz OFDM APs nearly always keep DSSS rates too
    elif b.band == "5":
        std.add("a")
    order = ["b", "g", "a", "n", "ac", "ax", "be"]
    b.standards = [s for s in order if s in std]
    b.streams = streams or None

    # channel width / centre
    b.width_mhz, b.center_channel = 20, b.channel
    if ht_any_width and ht_sec_offset in (1, 3):
        b.width_mhz = 40
        b.center_channel = b.channel + (2 if ht_sec_offset == 1 else -2)
    if vht_op is not None and len(vht_op) >= 3 and vht_op[0] >= 1:
        c0, c1 = vht_op[1], vht_op[2]
        if c1 == 0:
            b.width_mhz, b.center_channel = 80, c0
        elif abs(c1 - c0) == 8:
            b.width_mhz, b.center_channel = 160, c1
        else:
            b.width_mhz, b.center_channel = 160, c0  # 80+80: report as 160 total
    if he_6g is not None and b.band == "6":
        width = {0: 20, 1: 40, 2: 80, 3: 160}.get(he_6g[1] & 0x03, 20)
        c0, c1 = he_6g[2], he_6g[3]
        b.width_mhz = width
        b.center_channel = c1 if width == 160 and c1 else c0

    # security
    akms = (rsn or {}).get("akms", []) + [f"wpa:{a}" for a in (wpa or {}).get("akms", [])]
    b.akms = list(dict.fromkeys(a.removeprefix("wpa:") for a in akms))
    b.pairwise = list(dict.fromkeys((rsn or {}).get("pairwise", []) + (wpa or {}).get("pairwise", [])))
    b.group = (rsn or wpa or {}).get("group")
    if rsn:
        b.pmf = "required" if rsn["mfpr"] else "capable" if rsn["mfpc"] else "no"
    b.security = security_label(b.akms, wpa is not None, privacy, owe_transition, b.pmf == "required")
    return b


def _he_6ghz_info(body: bytes) -> bytes | None:
    """6 GHz Operation Information from the HE Operation element, if present."""
    if len(body) < 6:
        return None
    params = body[0] | body[1] << 8 | body[2] << 16
    i = 3 + 1 + 2  # params, BSS colour, basic HE-MCS/NSS
    if params & (1 << 14):
        i += 3  # VHT Operation Information
    if params & (1 << 15):
        i += 1  # max co-hosted BSSID indicator
    if params & (1 << 17) and len(body) >= i + 5:
        return body[i : i + 5]
    return None


# ---------------------------------------------------------------- builders (tests, mocks)


def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


def rsn_ie(
    akms: list[int], pairwise: tuple[int, ...] = (4,), group: int = 4, mfpc: bool = False, mfpr: bool = False
) -> bytes:
    body = struct.pack("<H", 1) + OUI_IEEE + bytes([group])
    body += struct.pack("<H", len(pairwise)) + b"".join(OUI_IEEE + bytes([p]) for p in pairwise)
    body += struct.pack("<H", len(akms)) + b"".join(OUI_IEEE + bytes([a]) for a in akms)
    body += struct.pack("<H", (0x40 if mfpr else 0) | (0x80 if mfpc else 0))
    return ie(48, body)
