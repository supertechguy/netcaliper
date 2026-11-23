# SPDX-License-Identifier: GPL-3.0-only
"""Real Wi-Fi measurements (runs in the agent, inside the test netns).

- scan: nl80211 scans on every given radio in parallel, merged per (BSSID, frequency) — Wi-Fi 7
  APs reuse one BSSID across bands — plus survey dumps for per-channel busy time / noise.
- connect / roam: wpa_supplicant; timings from its control-socket events.
- monitor / sample: monitor mode on the monitor radio, headers only (see dot11.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import re
import socket
import time
from pathlib import Path
from typing import Any

from ..drivers.iwparse import parse_iw_phy_info
from . import dot11, ie, ip4, link, nl80211, wpa
from .packets import ETH_P_ALL, RawSocket, now_ms
from .wifi_base import (
    Bss,
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

_EV = {
    "auth": re.compile(r"SME: Trying to authenticate with ([0-9a-f:]{17})"),
    "assoc_try": re.compile(r"Trying to associate with ([0-9a-f:]{17})"),
    "associated": re.compile(r"Associated with ([0-9a-f:]{17})"),
    "eap_start": re.compile(r"CTRL-EVENT-EAP-STARTED"),
    "eap_ok": re.compile(r"CTRL-EVENT-EAP-SUCCESS"),
    "eap_fail": re.compile(r"CTRL-EVENT-EAP-FAILURE"),
    "key": re.compile(r"WPA: Key negotiation completed with ([0-9a-f:]{17})"),
    "connected": re.compile(r"CTRL-EVENT-CONNECTED - Connection to ([0-9a-f:]{17})"),
    "temp_disabled": re.compile(r"CTRL-EVENT-SSID-TEMP-DISABLED .*reason=(\w+)"),
    "assoc_reject": re.compile(r"CTRL-EVENT-ASSOC-REJECT bssid=(\S+) status_code=(\d+)"),
    "auth_reject": re.compile(
        r"CTRL-EVENT-AUTH-REJECT (\S+) auth_type=\d+ auth_transaction=\d+ status_code=(\d+)"
    ),
    "not_found": re.compile(r"CTRL-EVENT-NETWORK-NOT-FOUND"),
}


def resolve_security(creds: WifiCreds, seen: list[Bss]) -> str:
    if creds.security != "auto":
        return creds.security
    akms = {a for b in seen if b.ssid == creds.ssid for a in b.akms}
    if any("8021x" in a for a in akms):
        return "eap"
    sae, psk = bool(akms & {"sae", "ft-sae", "sae-ext"}), bool(akms & {"psk", "ft-psk", "psk-sha256"})
    if sae and psk:
        return "psk-sae"
    if sae:
        return "sae"
    if psk:
        return "psk"
    if "owe" in akms:
        return "owe"
    if seen and any(b.ssid == creds.ssid for b in seen):
        return "open"
    return "psk" if creds.passphrase else "eap" if creds.identity else "open"


def mark_reported(bss: list[Bss], raw: list[dict[str, Any]]) -> None:
    """Entries cfg80211 built from *another channel's* frame (Wi-Fi 7 multi-link / reduced neighbour
    report) carry that frame's signal, which says nothing about this BSS: flag them, drop the signal.
    Multi-BSSID profiles share their parent's beacon on the same channel, so their signal is real."""
    heard = {(r["bssid"], r["freq"]) for r in raw if not r.get("reported_by")}
    for b, r in zip(bss, raw, strict=True):
        b.mld = r.get("mld")
        parent = r.get("reported_by")
        if parent and (parent, b.freq) not in heard:
            b.reported_by, b.signal_dbm = parent, None


def merge(results: dict[str, list[Bss]]) -> list[Bss]:
    out: dict[tuple[str, int], Bss] = {}
    for radio, bsss in results.items():
        for b in bsss:
            key = (b.bssid, b.freq)
            cur = out.get(key)
            if cur is None:
                b.radios = [radio]
                out[key] = b
                continue
            if radio not in cur.radios:
                cur.radios.append(radio)
            if (b.signal_dbm or -999) > (cur.signal_dbm or -999):
                b.radios = cur.radios
                out[key] = b
    return sorted(out.values(), key=lambda b: -(b.signal_dbm or -999))


def _sys(ifname: str, attr: str) -> str | None:
    try:
        return Path(f"/sys/class/net/{ifname}/{attr}").read_text().strip()
    except OSError:
        return None


class WifiReal:
    def __init__(self) -> None:
        self._sup: dict[str, wpa.Supplicant] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._freq: dict[str, int] = {}  # monitor iface -> current frequency
        self.country: str | None = None

    def _lock(self, ifname: str) -> asyncio.Lock:
        return self._locks.setdefault(ifname, asyncio.Lock())

    # ------------------------------------------------------------ mode / channel

    async def _iftype(self, ifname: str) -> str:
        out = await link.must("iw", "dev", ifname, "info")
        m = re.search(r"^\s*type (\S+)", out, re.M)
        return m.group(1) if m else "unknown"

    async def _ensure_mode(self, ifname: str, mode: str) -> None:
        if await self._iftype(ifname) != mode:
            await link.must("ip", "link", "set", "dev", ifname, "down")
            await link.must("iw", "dev", ifname, "set", "type", mode)
            self._freq.pop(ifname, None)
        if _sys(ifname, "operstate") in ("down", None) or not int(_sys(ifname, "flags") or "0", 16) & 1:
            await link.must("ip", "link", "set", "dev", ifname, "up")

    async def _set_freq(self, ifname: str, freq: int) -> None:
        if self._freq.get(ifname) != freq:
            await link.must("iw", "dev", ifname, "set", "freq", str(freq))
            self._freq[ifname] = freq

    async def _freqs(self, ifname: str) -> list[int]:
        phy = (await asyncio.to_thread(Path(f"/sys/class/net/{ifname}/phy80211/name").read_text)).strip()
        info = parse_iw_phy_info(await link.must("iw", "phy", phy, "info"))
        return sorted({int(f) for f in info.freqs_mhz if f < 5925})  # 6 GHz needs passive-only handling

    # ------------------------------------------------------------ scan

    async def _scan_one(
        self, ifname: str, timeout_s: float, freqs: list[int] | None = None
    ) -> tuple[list[Bss], list[SurveyChannel]]:
        async with self._lock(ifname):
            if ifname not in self._sup:
                await self._ensure_mode(ifname, "managed")
            idx = socket.if_nametoindex(ifname)
            try:
                raw = await nl80211.scan(idx, freqs, timeout_s=timeout_s)
            except nl80211.NlError as e:
                if e.errno != errno.ECANCELED:
                    raise
                raw = await nl80211.scan(
                    idx, freqs, timeout_s=timeout_s
                )  # aborted (e.g. by a mode change): once more
            bss = [
                ie.decode(
                    r["bssid"],
                    r["freq"],
                    r["ies"],
                    capability=r["capability"],
                    signal_dbm=r["signal_dbm"],
                    beacon_interval=r["beacon_interval"],
                    seen_ms_ago=r["seen_ms_ago"],
                    associated=r["associated"],
                )
                for r in raw
            ]
            mark_reported(bss, raw)
            try:
                sv = await nl80211.survey(idx)
            except OSError:
                sv = []
        survey = [
            SurveyChannel(
                freq=s["freq"],
                channel=freq_to_channel(s["freq"]),
                noise_dbm=s["noise_dbm"],
                busy_pct=s["busy_pct"],
                in_use=s["in_use"],
                radio=ifname,
            )
            for s in sv
        ]
        return bss, survey

    async def wifi_scan(
        self, ifnames: list[str], timeout_s: float = 25.0, freqs: list[int] | None = None
    ) -> ScanResult:
        t0 = now_ms()
        res = await asyncio.gather(
            *(self._scan_one(i, timeout_s, freqs) for i in ifnames), return_exceptions=True
        )
        radios: dict[str, str] = {}
        per: dict[str, list[Bss]] = {}
        survey: list[SurveyChannel] = []
        for ifname, r in zip(ifnames, res, strict=True):
            if isinstance(r, BaseException):
                radios[ifname] = f"{type(r).__name__}: {r}"[:160]
                continue
            radios[ifname] = "ok"
            per[ifname], sv = r
            survey += sv
        return ScanResult(bss=merge(per), survey=survey, radios=radios, duration_ms=round(now_ms() - t0, 1))

    # ------------------------------------------------------------ connect

    async def wifi_connect(self, ifname: str, creds: WifiCreds, timeout_s: float = 30.0) -> WifiConnectResult:
        await self.wifi_disconnect(ifname)
        res = WifiConnectResult(ok=False, ssid=creds.ssid)
        async with self._lock(ifname):
            await self._ensure_mode(ifname, "managed")
            seen: list[Bss] = []
            if creds.security == "auto":
                with contextlib.suppress(Exception):
                    raw = await nl80211.scan(socket.if_nametoindex(ifname), creds.freqs or None)
                    seen = [
                        ie.decode(r["bssid"], r["freq"], r["ies"], capability=r["capability"]) for r in raw
                    ]
            security = resolve_security(creds, seen)
            try:
                sup = await wpa.start(ifname, wpa.network_block(creds, security), self.country)
            except (wpa.ConfigError, RuntimeError) as e:
                res.error = str(e)
                return res
        t0 = time.monotonic()
        marks: dict[str, float] = {}
        not_found = 0

        def ms(a: str, b: str) -> float | None:
            return round((marks[b] - marks[a]) * 1000, 1) if a in marks and b in marks else None

        try:
            await sup.ctrl.request("SELECT_NETWORK 0")
            deadline = t0 + timeout_s
            while (left := deadline - time.monotonic()) > 0:
                ev = await sup.mon.event(left)
                if ev is None:
                    break
                t = time.monotonic()
                for name, rx in _EV.items():
                    m = rx.search(ev)
                    if not m:
                        continue
                    res.events.append(WifiEvent(t_ms=round((t - t0) * 1000, 1), event=ev[:160]))
                    marks.setdefault(name, t)
                    if name == "temp_disabled":
                        res.reason = m.group(1)
                    elif name == "assoc_reject":
                        res.reason = f"ASSOC_REJECT status={m.group(2)}"
                    elif name == "auth_reject":
                        res.reason = f"AUTH_REJECT status={m.group(2)}"
                        if security in ("sae", "psk-sae") and m.group(2) == "1":
                            res.reason = "WRONG_KEY"  # SAE: the AP rejects a commit/confirm it can't verify
                    elif name == "eap_fail":
                        res.reason = "EAP_FAILURE"
                    elif name == "not_found":
                        not_found += 1
                        if not_found >= 2:  # two complete scans without it
                            res.reason = "NETWORK_NOT_FOUND"
                    break
                if "connected" in marks or res.reason:
                    break
            if "connected" not in marks:
                res.error = res.reason or f"not connected within {timeout_s:.0f} s"
                await sup.stop()
                return res
            first = marks.get("auth", marks.get("assoc_try"))
            res.ok = True
            res.scan_ms = round((first - t0) * 1000, 1) if first else None
            res.auth_ms = ms("auth", "assoc_try")
            res.assoc_ms = ms("assoc_try", "associated")
            res.eap_ms = ms("eap_start", "eap_ok")
            res.key_ms = ms("eap_ok" if "eap_ok" in marks else "associated", "key")
            res.connect_ms = round((marks["connected"] - first) * 1000, 1) if first else None
            res.total_ms = round((marks["connected"] - t0) * 1000, 1)
            st = wpa.kv(await sup.ctrl.request("STATUS"))
            sig = wpa.kv(await sup.ctrl.request("SIGNAL_POLL"))
            res.bssid, res.key_mgmt, res.pairwise = (
                st.get("bssid"),
                st.get("key_mgmt"),
                st.get("pairwise_cipher"),
            )
            res.generation = st.get("wifi_generation")
            if f := st.get("freq"):
                res.freq, res.channel = int(f), freq_to_channel(int(f))
            rssi = sig.get("RSSI", "")
            res.signal_dbm = int(rssi) if rssi.lstrip("-").isdigit() and int(rssi) < 0 else None
            if res.signal_dbm is None:  # some drivers (rtl8192cu) report nonsense: use the BSS entry
                with contextlib.suppress(Exception):
                    dump = await nl80211.scan_dump(socket.if_nametoindex(ifname))
                    hit = next((b for b in dump if b["bssid"] == res.bssid and b["signal_dbm"]), None)
                    res.signal_dbm = round(hit["signal_dbm"]) if hit else None
            noise = sig.get("NOISE", "")
            res.noise_dbm = int(noise) if noise.lstrip("-").isdigit() and int(noise) < 0 else None
            res.tx_rate_mbps = float(sig["LINKSPEED"]) if sig.get("LINKSPEED", "").isdigit() else None
            res.width = sig.get("WIDTH")
            self._sup[ifname] = sup
            return res
        except BaseException:
            await sup.stop()
            raise

    async def wifi_disconnect(self, ifname: str) -> None:
        sup = self._sup.pop(ifname, None)
        if sup is not None:
            with contextlib.suppress(Exception):
                await sup.ctrl.request("DISCONNECT", timeout=2)
            await sup.stop()

    # ------------------------------------------------------------ roam

    async def wifi_roam(
        self, ifname: str, bssid: str, gateway: str | None, timeout_s: float = 10.0
    ) -> RoamAttempt:
        sup = self._sup.get(ifname)
        if sup is None:
            return RoamAttempt(from_bssid="", to_bssid=bssid, ok=False, error="not connected")
        cur = wpa.kv(await sup.ctrl.request("STATUS")).get("bssid", "")
        att = RoamAttempt(from_bssid=cur, to_bssid=bssid, ok=False)
        stop = asyncio.Event()
        pinger = (
            asyncio.create_task(ip4.ping_stream(ifname, gateway, timeout_s + 2, 0.02, stop))
            if gateway
            else None
        )
        try:
            await asyncio.sleep(0.5)  # baseline before the roam
            t0 = time.monotonic()
            reply = (await sup.ctrl.request(f"ROAM {bssid}")).strip()
            if reply != "OK":
                att.error = f"ROAM refused: {reply}"
                return att
            deadline = t0 + timeout_s
            while (left := deadline - time.monotonic()) > 0:
                ev = await sup.mon.event(left)
                if ev is None:
                    break
                m = _EV["connected"].search(ev)
                if m and m.group(1).lower() == bssid.lower():
                    att.ok, att.ms = True, round((time.monotonic() - t0) * 1000, 1)
                    break
                if "CTRL-EVENT-DISCONNECTED" in ev and "locally_generated=1" not in ev:
                    att.error = ev[:120]
            if not att.ok:
                att.error = att.error or f"not roamed within {timeout_s:.0f} s"
            await asyncio.sleep(1.0)  # let pings recover / show the gap
        finally:
            stop.set()
            if pinger:
                sent, recv, gap = await pinger
                att.sent, att.lost, att.gap_ms = sent, sent - recv, gap
        return att

    # ------------------------------------------------------------ monitor

    async def wifi_monitor(
        self, ifname: str, duration_s: float, freqs: list[int] | None = None
    ) -> MonitorResult:
        async with self._lock(ifname):
            await self._ensure_mode(ifname, "monitor")
            hop = freqs or await self._freqs(ifname)
            dwell = max(0.15, min(1.0, duration_s / max(1, len(hop))))
            res = MonitorResult(channels=[freq_to_channel(f) for f in hop])
            clients: dict[str, Client] = {}
            t0 = now_ms()
            try:
                with RawSocket(ifname, ETH_P_ALL) as sock:
                    end = time.monotonic() + duration_s
                    i = 0
                    while time.monotonic() < end:
                        with contextlib.suppress(RuntimeError):  # e.g. a DFS channel the driver refuses
                            await self._set_freq(ifname, hop[i % len(hop)])
                        i += 1
                        for _, pkt in await sock.collect(
                            min(dwell, max(0.0, end - time.monotonic())), lambda p: True
                        ):
                            f = dot11.parse(pkt)
                            if f is not None:
                                res.frames += 1
                                _account(f, res, clients)
            finally:
                await self._ensure_mode(ifname, "managed")
        for c in clients.values():
            c.ssid = res.aps.get(c.bssid or "") or None
        res.clients = sorted(clients.values(), key=lambda c: -(c.signal_dbm or -999))
        res.duration_ms = round(now_ms() - t0, 1)
        return res

    async def wifi_sample(self, ifname: str, mac: str, freq: int, duration_s: float = 0.5) -> list[Sample]:
        mac = mac.lower()
        async with self._lock(ifname):
            await self._ensure_mode(ifname, "monitor")  # stays in monitor while locating
            await self._set_freq(ifname, freq)
            t0 = now_ms()
            out: list[Sample] = []
            with RawSocket(ifname, ETH_P_ALL) as sock:
                for t, pkt in await sock.collect(duration_s, lambda p: True):
                    f = dot11.parse(pkt)
                    if f and f.addr2 == mac and f.signal_dbm is not None:
                        out.append(Sample(t_ms=round(t - t0, 1), signal_dbm=f.signal_dbm))
        return out


def _account(f: dot11.Frame, res: MonitorResult, clients: dict[str, Client]) -> None:
    if f.ftype == dot11.T_MGMT:
        if f.subtype in (dot11.ST_BEACON, dot11.ST_PROBE_RESP) and f.addr3 and len(f.body) >= 12:
            ssid = next((b.decode("utf-8", "replace") for e, _, b in ie.iter_ies(f.body[12:]) if e == 0), "")
            if ssid.strip("\x00"):
                res.aps[f.addr3] = ssid
            else:
                res.aps.setdefault(f.addr3, "")
        elif f.subtype == dot11.ST_PROBE_REQ and dot11.is_unicast(f.addr2) and f.addr2:
            c = clients.setdefault(f.addr2, Client(mac=f.addr2, randomized=dot11.is_local(f.addr2)))
            ssid = next((b.decode("utf-8", "replace") for e, _, b in ie.iter_ies(f.body) if e == 0), "")
            if ssid and ssid not in c.probes and len(c.probes) < 20:
                c.probes.append(ssid)
            _seen(c, f)
        elif f.subtype in (dot11.ST_DEAUTH, dot11.ST_DISASSOC) and f.addr2:
            res.deauth[f.addr2] = res.deauth.get(f.addr2, 0) + 1
        elif f.subtype == dot11.ST_ASSOC_REQ and dot11.is_unicast(f.addr2) and f.addr2:
            c = clients.setdefault(f.addr2, Client(mac=f.addr2, randomized=dot11.is_local(f.addr2)))
            c.bssid = f.addr1
            _seen(c, f)
    elif f.ftype == dot11.T_DATA:
        sta, bssid = dot11.data_roles(f)
        if sta and bssid and dot11.is_unicast(sta) and sta != bssid:
            c = clients.setdefault(sta, Client(mac=sta, randomized=dot11.is_local(sta)))
            c.bssid = bssid
            if f.addr2 == sta:
                _seen(c, f)
            else:
                c.frames += 1


def _seen(c: Client, f: dot11.Frame) -> None:
    c.frames += 1
    c.freq = f.freq or c.freq
    if f.signal_dbm is not None:
        c.signal_dbm = (
            f.signal_dbm if c.signal_dbm is None else round(0.7 * c.signal_dbm + 0.3 * f.signal_dbm, 1)
        )
