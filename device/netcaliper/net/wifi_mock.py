# SPDX-License-Identifier: GPL-3.0-only
"""Simulated Wi-Fi environment for MockNet. BSSes are built as raw information elements and run
through the real decoder, so mock scans exercise the same parsing as hardware scans."""

from __future__ import annotations

import asyncio
import random
import struct
from dataclasses import dataclass

from . import ie
from .wifi_base import (
    Client,
    MonitorResult,
    RoamAttempt,
    Sample,
    ScanResult,
    SurveyChannel,
    WifiConnectResult,
    WifiCreds,
    WifiEvent,
    freq_to_channel,
)


def _freq(ch: int) -> int:
    return 2407 + 5 * ch if ch <= 13 else 5000 + 5 * ch


@dataclass
class MockAp:
    bssid: str
    ssid: str
    channel: int
    signal: int
    akms: tuple[int, ...] = (2,)  # IEEE AKM suite numbers; () = open
    mfpc: bool = False
    mfpr: bool = False
    width: int = 20
    wps: bool = False
    stations: int = 3
    util: int = 40  # /255
    tkip: bool = False
    k: bool = True
    v: bool = True

    def ies(self) -> bytes:
        out = ie.ie(0, self.ssid.encode())
        out += ie.ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))
        if self.channel <= 14:
            out += ie.ie(3, bytes([self.channel]))
        out += ie.ie(7, b"US\x20" + bytes([1, 11, 30]))
        out += ie.ie(11, struct.pack("<HBH", self.stations, self.util, 0))
        out += ie.ie(45, b"\xef\x01\x1b" + b"\xff\xff\x00\x00" + b"\x00" * 19)
        sec = 1 if self.width >= 40 else 0
        out += ie.ie(61, bytes([self.channel, (0x04 | sec) if self.width >= 40 else 0]) + b"\x00" * 20)
        if self.akms:
            out += ie.rsn_ie(
                list(self.akms), (2, 4) if self.tkip else (4,), 2 if self.tkip else 4, self.mfpc, self.mfpr
            )
        if self.k:
            out += ie.ie(70, b"\x02\x00\x00\x00\x00")
        out += ie.ie(127, b"\x00\x00\x08\x00" if self.v else b"\x00\x00\x00\x00")
        if self.channel > 14:
            out += ie.ie(191, b"\x00" * 4 + struct.pack("<H", 0xFFFA) + b"\x00" * 6)
            c0 = self.channel + 6 if self.width == 80 else self.channel
            out += ie.ie(192, bytes([1 if self.width >= 80 else 0, c0, 0]) + b"\x00\x00")
        out += ie.ie(255, bytes([35]) + b"\x00" * 6)
        if self.wps:
            tlv = struct.pack(">HHB", 0x1044, 1, 2) + struct.pack(">HH", 0x1011, 5) + b"Mock1"
            out += ie.ie(221, ie.OUI_MS + b"\x04" + tlv)
        return out


DEFAULT_APS = [
    MockAp("44:d9:e7:10:00:01", "CorpNet", 1, -48, (2, 8), mfpc=True, stations=7, util=60),
    MockAp("44:d9:e7:10:00:02", "CorpNet", 36, -55, (2, 8), mfpc=True, width=80, stations=12, util=30),
    MockAp("44:d9:e7:20:00:01", "CorpNet", 6, -63, (2, 8), mfpc=True, stations=4, util=90),
    MockAp("44:d9:e7:20:00:02", "CorpNet", 149, -66, (2, 8), mfpc=True, width=80, stations=2, util=20),
    MockAp("46:d9:e7:10:00:01", "CorpGuest", 1, -49, (), stations=3, util=60),
    MockAp("44:d9:e7:30:00:01", "Corp-802.1X", 44, -58, (1, 5), mfpc=True, width=40, stations=5),
    MockAp("a0:63:91:5a:11:20", "NETGEAR-5G", 3, -71, (2,), wps=True, tkip=True, util=120, k=False, v=False),
    MockAp("a0:63:91:5a:11:21", "", 11, -77, (2,), k=False, v=False),
    MockAp("f2:9c:12:00:00:44", "Printer-Setup", 6, -80, (), k=False, v=False),
]
BAD_PASSPHRASE = "wrong-password"  # noqa: S105 - the mock's "wrong key" trigger


class WifiMock:
    """Mixin for MockNet. Expects `self.rnd`, `self._wait()`."""

    rnd: random.Random
    wifi_aps: list[MockAp]
    _assoc: dict[str, MockAp]

    def _wifi_init(self, aps: list[MockAp] | None = None, deauth_flood: bool = False) -> None:
        self.wifi_aps = list(aps if aps is not None else DEFAULT_APS)
        self._assoc = {}
        self.deauth_flood = deauth_flood

    async def _wait(self) -> None: ...  # provided by MockNet

    def _jitter(self, s: int) -> float:
        return float(s + self.rnd.randint(-3, 3))

    async def wifi_scan(
        self, ifnames: list[str], timeout_s: float = 25.0, freqs: list[int] | None = None
    ) -> ScanResult:
        await self._wait()
        bss = []
        for ap in self.wifi_aps:
            if freqs and _freq(ap.channel) not in freqs:
                continue
            b = ie.decode(
                ap.bssid,
                _freq(ap.channel),
                ap.ies(),
                capability=0x0431 if ap.akms else 0x0421,
                signal_dbm=self._jitter(ap.signal),
                beacon_interval=100,
                seen_ms_ago=120,
            )
            # the first radio (the 2.4 GHz-only test adapter in the default fixture) misses 5 GHz
            b.radios = [i for k, i in enumerate(ifnames) if ap.channel <= 14 or k == len(ifnames) - 1]
            b.associated = any(a.bssid == ap.bssid for a in self._assoc.values())
            if b.radios:
                bss.append(b)
        chans = sorted({ap.channel for ap in self.wifi_aps})
        survey = [
            SurveyChannel(
                freq=_freq(c),
                channel=c,
                noise_dbm=-95 if c <= 14 else -101,
                busy_pct=round(sum(a.util for a in self.wifi_aps if a.channel == c) / 3.5, 1),
                radio=ifnames[0] if ifnames else "",
            )
            for c in chans
        ]
        bss.sort(key=lambda b: -(b.signal_dbm or -999))
        return ScanResult(
            bss=bss,
            survey=survey,
            radios=dict.fromkeys(ifnames, "ok"),
            duration_ms=round(self.rnd.uniform(2500, 4500), 1),
        )

    async def wifi_connect(self, ifname: str, creds: WifiCreds, timeout_s: float = 30.0) -> WifiConnectResult:
        await self._wait()
        aps = sorted(
            (
                a
                for a in self.wifi_aps
                if a.ssid == creds.ssid and (not creds.bssid or a.bssid == creds.bssid)
            ),
            key=lambda a: -a.signal,
        )
        res = WifiConnectResult(ok=False, ssid=creds.ssid)
        if not aps:
            res.reason = res.error = "NETWORK_NOT_FOUND"
            return res
        ap = aps[0]
        eap = 1 in ap.akms or 5 in ap.akms
        if ap.akms and not eap and creds.passphrase in (None, "", BAD_PASSPHRASE):
            res.reason = res.error = "WRONG_KEY"
            res.events = [WifiEvent(t_ms=2100, event="CTRL-EVENT-SSID-TEMP-DISABLED id=0 reason=WRONG_KEY")]
            return res
        if eap and (not creds.identity or creds.password == BAD_PASSPHRASE):
            res.reason = res.error = "EAP_FAILURE"
            return res
        scan, auth, assoc = self.rnd.uniform(900, 1800), self.rnd.uniform(2, 8), self.rnd.uniform(3, 12)
        eap_ms = self.rnd.uniform(120, 400) if eap else None
        key = self.rnd.uniform(8, 30)
        connect = auth + assoc + (eap_ms or 0) + key
        self._assoc[ifname] = ap
        return WifiConnectResult(
            ok=True,
            ssid=ap.ssid,
            bssid=ap.bssid,
            freq=_freq(ap.channel),
            channel=ap.channel,
            key_mgmt="WPA2-EAP" if eap else "SAE" if 8 in ap.akms else "WPA2-PSK" if ap.akms else "NONE",
            pairwise="CCMP" if ap.akms else None,
            generation="6",
            scan_ms=round(scan, 1),
            auth_ms=round(auth, 1),
            assoc_ms=round(assoc, 1),
            eap_ms=round(eap_ms, 1) if eap_ms else None,
            key_ms=round(key, 1),
            connect_ms=round(connect, 1),
            total_ms=round(scan + connect, 1),
            signal_dbm=ap.signal,
            noise_dbm=-95 if ap.channel <= 14 else -101,
            tx_rate_mbps=144.4 if ap.channel <= 14 else 433.3,
            width=f"{ap.width} MHz",
        )

    async def wifi_roam(
        self, ifname: str, bssid: str, gateway: str | None, timeout_s: float = 10.0
    ) -> RoamAttempt:
        await self._wait()
        cur = self._assoc.get(ifname)
        if cur is None:
            return RoamAttempt(from_bssid="", to_bssid=bssid, ok=False, error="not connected")
        tgt = next((a for a in self.wifi_aps if a.bssid == bssid and a.ssid == cur.ssid), None)
        if tgt is None:
            return RoamAttempt(from_bssid=cur.bssid, to_bssid=bssid, ok=False, error="target not found")
        ms = self.rnd.uniform(25, 80) + (40 if tgt.channel > 14 and cur.channel <= 14 else 0)
        self._assoc[ifname] = tgt
        sent = int((ms + 1500) / 20)
        lost = int(ms / 20)
        return RoamAttempt(
            from_bssid=cur.bssid,
            to_bssid=bssid,
            ok=True,
            ms=round(ms, 1),
            gap_ms=round(ms + 20, 1) if gateway else None,
            sent=sent if gateway else None,
            lost=lost if gateway else None,
        )

    async def wifi_disconnect(self, ifname: str) -> None:
        self._assoc.pop(ifname, None)

    async def wifi_monitor(
        self, ifname: str, duration_s: float, freqs: list[int] | None = None
    ) -> MonitorResult:
        await self._wait()
        chans = [freq_to_channel(f) for f in freqs] if freqs else sorted({a.channel for a in self.wifi_aps})
        aps = {a.bssid: a.ssid for a in self.wifi_aps if a.channel in chans}
        clients = []
        for i, ap in enumerate(a for a in self.wifi_aps if a.channel in chans and a.stations):
            for j in range(min(ap.stations, 3)):
                local = (i + j) % 3 == 0
                mac = f"{'da' if local else '3c'}:22:fb:{i:02x}:{j:02x}:{(i * 7 + j) % 256:02x}"
                clients.append(
                    Client(
                        mac=mac,
                        bssid=ap.bssid,
                        ssid=ap.ssid or None,
                        signal_dbm=ap.signal - 6 - 3 * j,
                        freq=_freq(ap.channel),
                        frames=40 + 11 * j,
                        randomized=local,
                    )
                )
        clients.append(
            Client(
                mac="ee:41:07:aa:bb:cc",
                signal_dbm=-70,
                frames=4,
                randomized=True,
                probes=["CorpNet", "HomeWiFi"],
            )
        )
        deauth = {"44:d9:e7:10:00:01": 2}
        if self.deauth_flood:
            deauth["66:66:66:00:00:01"] = 480
        clients.sort(key=lambda c: -(c.signal_dbm or -999))
        return MonitorResult(
            clients=clients,
            aps=aps,
            deauth=deauth,
            channels=chans,
            frames=1200 + 80 * len(clients),
            duration_ms=duration_s * 1000,
        )

    async def wifi_sample(self, ifname: str, mac: str, freq: int, duration_s: float = 0.5) -> list[Sample]:
        await asyncio.sleep(min(duration_s, 0.2))
        ap = next((a for a in self.wifi_aps if a.bssid == mac.lower()), None)
        base = ap.signal if ap else -65
        return [Sample(t_ms=k * 100.0, signal_dbm=float(base + self.rnd.randint(-4, 4))) for k in range(5)]
