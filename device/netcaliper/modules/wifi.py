# SPDX-License-Identifier: GPL-3.0-only
"""Wi-Fi modules (Phase 3). All run in the test netns and are PASSIVE: scanning, associating as an
ordinary client, roaming between APs of a network we were given credentials for, and listening in
monitor mode (headers only). Nothing here transmits on behalf of anyone else: no deauth, no
injection, no credential guessing.

Radios are chosen by role in core (`ctx.radios`: "test-wifi", "monitor"); `ctx.ifname` is the
test-wifi radio for Wi-Fi profiles.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from ..core.records import Finding, Status
from ..drivers.base import Capability as C
from ..net.wifi_base import Bss, RoamAttempt, TestWifi, WifiCreds
from .base import ModuleConfig, ModuleResult, RunContext, TestModule
from .registry import register
from .thresholds import worst
from .wired import DhcpConfig, WiredDhcp


def wifi(ctx: RunContext, role: str = "test-wifi") -> tuple[TestWifi, str]:
    net = ctx.net
    ifname = ctx.radios.get(role) or (ctx.ifname if role == "test-wifi" else None)
    if net is None or not isinstance(net, TestWifi):
        raise RuntimeError("no Wi-Fi test plane")
    if ifname is None:
        raise LookupError(f"no {role} radio")
    return net, ifname


def scan_radios(ctx: RunContext) -> list[str]:
    """Every test-plane radio (test-wifi first), deduplicated — never the mgmt radio."""
    out = [r for r in (ctx.radios.get("test-wifi") or ctx.ifname, ctx.radios.get("monitor")) if r]
    return list(dict.fromkeys(out))


def _scan_from_session(ctx: RunContext) -> list[Bss] | None:
    raw = ctx.session.get("wifi_scan")
    return [Bss.model_validate(b) for b in raw] if raw else None


# ---------------------------------------------------------------- channel analysis (pure)

_24_PLAN = (1, 6, 11)
_5_BLOCKS_80 = {42: False, 58: True, 106: True, 122: True, 138: True, 155: False}  # centre -> DFS


def chan_freq(ch: int) -> int:
    if ch == 14:
        return 2484
    return 2407 + 5 * ch if ch <= 13 else 5000 + 5 * ch


def span(b: Bss) -> tuple[float, float]:
    centre = (
        chan_freq(b.center_channel or b.channel)
        if b.band != "6"
        else 5950 + 5 * (b.center_channel or b.channel)
    )
    half = 11.0 if b.band == "2.4" and b.width_mhz == 20 else b.width_mhz / 2  # DSSS masks are 22 MHz
    return centre - half, centre + half


def same_radio(a: Bss, b: Bss) -> bool:
    """Virtual BSSIDs of one AP radio: same frequency, MACs differing only in the first octet
    (locally-administered variants) or only in the low nibble of the last octet."""
    return a.freq == b.freq and (a.bssid[3:] == b.bssid[3:] or a.bssid[:16] == b.bssid[:16])


def radios(bss: list[Bss]) -> list[list[Bss]]:
    groups: list[list[Bss]] = []
    for b in sorted(bss, key=lambda x: -(x.signal_dbm or -999)):
        g = next((g for g in groups if same_radio(g[0], b)), None)
        if g is None:
            groups.append([b])
        else:
            g.append(b)
    return groups


def relation(t: Bss, o: Bss) -> Literal["co", "adjacent", "overlap", None]:
    """How radio `o` affects BSS `t`:
    - "co": contends with it on its primary channel (shares airtime);
    - "adjacent": 2.4 GHz only — partially overlapping 20 MHz channels: noise, not polite contention;
    - "overlap": 5/6 GHz bonded channels sharing only secondary 20 MHz channels (reduces usable width);
    - None: no overlap."""
    if t.band != o.band:
        return None
    lo_t, hi_t = span(t)
    lo_o, hi_o = span(o)
    if hi_o <= lo_t or hi_t <= lo_o:
        return None
    if t.band == "2.4":
        return "co" if o.channel == t.channel else "adjacent"

    def primary(b: Bss) -> int:
        return chan_freq(b.channel) if b.band != "6" else 5950 + 5 * b.channel

    if lo_o < primary(t) < hi_o or lo_t < primary(o) < hi_t:
        return "co"
    return "overlap"


def analyse(bss: list[Bss], ssid: str | None, min_signal: float) -> dict[str, Any]:
    audible = [b for b in bss if (b.signal_dbm or -999) >= min_signal]
    rad = radios(audible)
    heads = [g[0] for g in rad]

    def weight(b: Bss) -> float:  # louder neighbours hurt more: 1.0 at -50 dBm, ~0.1 at -82
        return max(0.05, min(1.0, 10 ** (((b.signal_dbm or -90) + 50) / 32)))

    def cost(probe: Bss) -> float:
        c = 0.0
        for o in heads:
            r = relation(probe, o)
            if r:
                c += weight(o) * {"co": 1.0, "adjacent": 0.6, "overlap": 0.4}[r]
                c += (o.utilization_pct or 0) / 100 * weight(o)
        return round(c, 2)

    channels: dict[int, dict[str, Any]] = {}
    for g in rad:
        h = g[0]
        row = channels.setdefault(
            h.channel,
            {
                "channel": h.channel,
                "band": h.band,
                "radios": 0,
                "bss": 0,
                "strongest": None,
                "utilization_pct": None,
                "ssids": [],
            },
        )
        row["radios"] += 1
        row["bss"] += len(g)
        row["strongest"] = max(filter(None, [row["strongest"], h.signal_dbm]), default=None)
        if h.utilization_pct is not None:
            row["utilization_pct"] = max(row["utilization_pct"] or 0, h.utilization_pct)
        for b in g:
            if b.ssid and b.ssid not in row["ssids"]:
                row["ssids"].append(b.ssid)

    def probe(band: Literal["2.4", "5"], ch: int, width: int, centre: int) -> Bss:
        return Bss(
            bssid="00:00:00:00:00:00",
            freq=chan_freq(ch),
            channel=ch,
            band=band,
            width_mhz=width,
            center_channel=centre,
        )

    rec24 = sorted((cost(probe("2.4", c, 20, c)), c) for c in _24_PLAN)
    rec5 = sorted((cost(probe("5", cc - 6, 80, cc)), cc) for cc in _5_BLOCKS_80)
    out: dict[str, Any] = {
        "channels": sorted(channels.values(), key=lambda r: (r["band"] != "2.4", r["channel"])),
        "radios": len(rad),
        "off_plan_24": sorted({h.channel for h in heads if h.band == "2.4" and h.channel not in _24_PLAN}),
        "best_24": rec24[0][1],
        "best_5": f"{rec5[0][1] - 6}-{rec5[0][1] + 6}" + (" (DFS)" if _5_BLOCKS_80[rec5[0][1]] else ""),
        "scores_24": {c: s for s, c in rec24},
        "scores_5": {f"{cc - 6}-{cc + 6}": s for s, cc in rec5},
        "target": [],
    }
    if ssid:
        for g in rad:
            for t in (b for b in g if b.ssid == ssid):
                co = [o for o in heads if o is not g[0] and relation(t, o) == "co"]
                adj = [o for o in heads if o is not g[0] and relation(t, o) == "adjacent"]
                ovl = [o for o in heads if o is not g[0] and relation(t, o) == "overlap"]
                out["target"].append(
                    {
                        "bssid": t.bssid,
                        "channel": t.channel,
                        "width_mhz": t.width_mhz,
                        "signal_dbm": t.signal_dbm,
                        "cochannel": len(co),
                        "adjacent": len(adj),
                        "overlap": len(ovl),
                        "cochannel_loudest": max((o.signal_dbm or -999 for o in co), default=None),
                        "adjacent_loudest": max((o.signal_dbm or -999 for o in adj), default=None),
                        "utilization_pct": t.utilization_pct,
                    }
                )
    return out


# ---------------------------------------------------------------- scan


class ScanConfig(ModuleConfig):
    timeout_s: float = Field(25.0, gt=0, le=60)  # 6 GHz passive dwell makes full scans slow
    channels: list[int] = Field(default_factory=list, max_length=64)  # default: every supported channel
    expect_ssids: list[str] = Field(default_factory=list)  # fail if any is not heard
    min_signal_dbm: float = Field(-75.0, ge=-100, le=0)  # expected networks weaker than this warn


@register
class WifiScan(TestModule[ScanConfig]):
    id = "wifi.scan"
    title = "Wi-Fi scan"
    requires = frozenset({C.WIFI_SCAN})
    executor = "test-ns"
    Config = ScanConfig
    needs_link = False
    timeout_s = 60.0

    async def run(self, ctx: RunContext, cfg: ScanConfig) -> ModuleResult:
        net, _ = wifi(ctx)
        radios_ = scan_radios(ctx)
        res = await net.wifi_scan(radios_, cfg.timeout_s, [chan_freq(c) for c in cfg.channels] or None)
        failed = {r: e for r, e in res.radios.items() if e != "ok"}
        if len(failed) == len(res.radios):
            return ModuleResult(
                status="error", message="scan failed: " + "; ".join(f"{r}: {e}" for r, e in failed.items())
            )
        bss = res.bss
        ctx.session["wifi_scan"] = [b.model_dump() for b in bss]
        ssids = {b.ssid for b in bss if b.ssid}
        band = {k: sum(1 for b in bss if b.band == k) for k in ("2.4", "5", "6")}
        findings: list[Finding] = []
        status: Status = "pass"
        notes = [
            f"{len(bss)} BSSIDs, {len(ssids)} SSIDs ({band['2.4']} on 2.4 GHz, {band['5']} on 5 GHz"
            + (f", {band['6']} on 6 GHz" if band["6"] else "")
            + ")"
        ]

        def finding(sev: Any, rule: str, title: str, sel: list[Bss]) -> None:
            if sel:
                findings.append(
                    Finding(
                        severity=sev,
                        rule_id=rule,
                        title=title,
                        evidence={
                            "suspects": sorted({f"{b.ssid or '<hidden>'} ({b.bssid})" for b in sel})[:20]
                        },
                    )
                )

        finding(
            "medium", "wifi.wep", "WEP network (broken encryption)", [b for b in bss if b.security == "WEP"]
        )
        finding("medium", "wifi.tkip", "Network allows TKIP", [b for b in bss if "tkip" in b.pairwise])
        finding(
            "low", "wifi.wps", "WPS enabled and not locked", [b for b in bss if b.wps and not b.wps_locked]
        )
        finding(
            "info",
            "wifi.open",
            "Open (unencrypted) network",
            [b for b in bss if b.security in ("Open", "Open (OWE transition)")],
        )
        missing = [s for s in cfg.expect_ssids if s not in ssids]
        weak = [
            s
            for s in cfg.expect_ssids
            if s in ssids and max(b.signal_dbm or -999 for b in bss if b.ssid == s) < cfg.min_signal_dbm
        ]
        if missing:
            status = "fail"
            notes.append("not heard: " + ", ".join(missing))
        if weak:
            status = worst(status, "warn")
            notes.append(f"weaker than {cfg.min_signal_dbm:.0f} dBm: " + ", ".join(weak))
        if failed:
            status = worst(status, "warn")
            notes.append("radio errors: " + ", ".join(failed))
        metrics: dict[str, Any] = {
            "bssids": len(bss),
            "ssids": len(ssids),
            "bss_24": band["2.4"],
            "bss_5": band["5"],
            "bss_6": band["6"],
            "hidden": sum(1 for b in bss if b.hidden),
            "open": sum(1 for b in bss if b.security.startswith("Open")),
            "wpa3": sum(1 for b in bss if "WPA3" in b.security),
            "strongest_dbm": max((b.signal_dbm for b in bss if b.signal_dbm is not None), default=None),
            "radios": ",".join(radios_),
            "scan_ms": res.duration_ms,
        }
        return ModuleResult(
            status=status,
            message="; ".join(notes),
            metrics=metrics,
            findings=findings,
            details={
                "bss": ctx.session["wifi_scan"],
                "survey": [s.model_dump() for s in res.survey],
                "radios": res.radios,
            },
        )


# ---------------------------------------------------------------- channels


class ChannelsConfig(ModuleConfig):
    ssid: str | None = None  # the network under test; analysis covers all channels regardless
    min_signal_dbm: float = Field(-82.0, ge=-100, le=0)  # weaker neighbours are ignored (≈ CCA threshold)


@register
class WifiChannels(TestModule[ChannelsConfig]):
    id = "wifi.channels"
    title = "Channels & interference"
    requires = frozenset({C.WIFI_SCAN})
    executor = "test-ns"
    Config = ChannelsConfig
    needs_link = False
    timeout_s = 60.0

    async def run(self, ctx: RunContext, cfg: ChannelsConfig) -> ModuleResult:
        bss = _scan_from_session(ctx)
        survey: list[dict[str, Any]] = []
        if bss is None:
            net, _ = wifi(ctx)
            res = await net.wifi_scan(scan_radios(ctx))
            bss, survey = res.bss, [s.model_dump() for s in res.survey]
        a = analyse(bss, cfg.ssid, cfg.min_signal_dbm)
        status: Status = "pass"
        notes = [f"best 2.4 GHz channel {a['best_24']}, best 5 GHz 80 MHz block {a['best_5']}"]
        metrics: dict[str, Any] = {
            "radios": a["radios"],
            "off_plan_24": len(a["off_plan_24"]),
            "best_24": a["best_24"],
            "best_5": a["best_5"],
        }
        if a["off_plan_24"]:
            notes.append("2.4 GHz radios off 1/6/11: channel " + ", ".join(map(str, a["off_plan_24"])))
        if cfg.ssid:
            t = a["target"]
            if not t:
                return ModuleResult(
                    status="fail",
                    message=f"{cfg.ssid} not heard above {cfg.min_signal_dbm:.0f} dBm",
                    metrics=metrics,
                    details=a,
                )
            metrics |= {
                "max_cochannel": max(x["cochannel"] for x in t),
                "max_adjacent": max(x["adjacent"] for x in t),
                "max_overlap": max(x["overlap"] for x in t),
                "max_utilization_pct": max((x["utilization_pct"] or 0 for x in t), default=None),
            }
            if metrics["max_adjacent"]:
                status = "warn"
                notes.append(
                    f"{cfg.ssid}: adjacent-channel overlap on "
                    + ", ".join(sorted({str(x["channel"]) for x in t if x["adjacent"]}))
                )
            notes.append(f"{cfg.ssid}: up to {metrics['max_cochannel']} co-channel radio(s)")
            if metrics["max_overlap"]:
                notes.append(f"{metrics['max_overlap']} bonded-channel overlap(s) on 5/6 GHz")
        if survey:
            a["survey"] = survey
        return ModuleResult(status=status, message="; ".join(notes), metrics=metrics, details=a)


# ---------------------------------------------------------------- connect


class ConnectConfig(ModuleConfig):
    ssid: str = Field("", max_length=32)  # empty: core fills in the network saved on the Wi-Fi screen
    security: Literal["auto", "open", "owe", "psk", "sae", "psk-sae", "eap"] = "auto"
    passphrase: str | None = Field(None, repr=False)
    eap_method: Literal["peap", "ttls", "tls"] = "peap"
    identity: str | None = None
    password: str | None = Field(None, repr=False)
    ca_cert: str | None = None  # paths — core resolves cert-store names to paths
    client_cert: str | None = None
    private_key: str | None = None
    private_key_password: str | None = Field(None, repr=False)
    bssid: str | None = None
    timeout_s: float = Field(30.0, gt=0, le=90)


@register
class WifiConnect(TestModule[ConnectConfig]):
    id = "wifi.connect"
    title = "Wi-Fi connect"
    requires = frozenset({C.WIFI_CONNECT})
    executor = "test-ns"
    Config = ConnectConfig
    timeout_s = 120.0

    async def run(self, ctx: RunContext, cfg: ConnectConfig) -> ModuleResult:
        net, ifname = wifi(ctx)
        if not cfg.ssid:
            return ModuleResult(
                status="skipped", message="no network configured (save one on the Wi-Fi screen)"
            )
        creds = WifiCreds.model_validate(cfg.model_dump(exclude={"timeout_s"}))
        creds.freqs = sorted({b.freq for b in _scan_from_session(ctx) or [] if b.ssid == cfg.ssid})
        r = await net.wifi_connect(ifname, creds, cfg.timeout_s)
        details = r.model_dump(exclude={"events"})
        details["events"] = [e.model_dump() for e in r.events][-40:]
        if not r.ok:
            hint = {
                "WRONG_KEY": "wrong passphrase",
                "NETWORK_NOT_FOUND": "SSID not found",
                "EAP_FAILURE": "802.1X/EAP authentication rejected",
            }.get(r.reason or "", r.error or "failed")
            return ModuleResult(
                status="fail", message=f"{cfg.ssid}: {hint}", details=details, metrics={"reason": r.reason}
            )
        ctx.session["wifi"] = {"ssid": r.ssid, "bssid": r.bssid, "freq": r.freq}
        snr = r.signal_dbm - r.noise_dbm if r.signal_dbm is not None and r.noise_dbm is not None else None
        metrics: dict[str, Any] = {
            "bssid": r.bssid,
            "channel": r.channel,
            "security": r.key_mgmt,
            "connect_ms": r.connect_ms,
            "auth_ms": r.auth_ms,
            "assoc_ms": r.assoc_ms,
            "eap_ms": r.eap_ms,
            "key_ms": r.key_ms,
            "scan_ms": r.scan_ms,
            "signal_dbm": r.signal_dbm,
            "noise_dbm": r.noise_dbm,
            "snr_db": snr,
            "tx_rate_mbps": r.tx_rate_mbps,
            "wifi_generation": r.generation,
        }
        msg = f"{r.ssid} via {r.bssid} ch {r.channel}, {r.connect_ms or '?'} ms"
        if r.signal_dbm is not None:
            msg += f", {r.signal_dbm} dBm"
        return ModuleResult(status="pass", message=msg, metrics=metrics, details=details)


@register
class WifiDhcp(WiredDhcp):
    """DHCP over the Wi-Fi association (same measurement as wired.dhcp)."""

    id = "wifi.dhcp"
    title = "DHCP (Wi-Fi)"
    requires = frozenset({C.WIFI_CONNECT})
    Config = DhcpConfig

    async def run(self, ctx: RunContext, cfg: DhcpConfig) -> ModuleResult:
        if "wifi" not in ctx.session:
            return ModuleResult(status="skipped", message="not associated")
        return await super().run(ctx, cfg)


# ---------------------------------------------------------------- roam


class RoamConfig(ModuleConfig):
    max_aps: int = Field(4, ge=1, le=16)
    min_signal_dbm: float = Field(-75.0, ge=-100, le=0)  # don't roam to APs we can barely hear
    return_to_first: bool = True
    timeout_s: float = Field(10.0, gt=0, le=30)


@register
class WifiRoam(TestModule[RoamConfig]):
    id = "wifi.roam"
    title = "Roaming"
    requires = frozenset({C.WIFI_CONNECT})
    executor = "test-ns"
    Config = RoamConfig
    timeout_s = 300.0

    async def run(self, ctx: RunContext, cfg: RoamConfig) -> ModuleResult:
        net, ifname = wifi(ctx)
        cur = ctx.session.get("wifi")
        if not cur:
            return ModuleResult(status="skipped", message="not associated")
        lease = ctx.session.get("lease") or {}
        gateway = lease.get("router")
        known = sorted({b.freq for b in _scan_from_session(ctx) or [] if b.ssid == cur["ssid"]})
        res = await net.wifi_scan([ifname], freqs=known or None)
        cands = [
            b
            for b in res.bss
            if b.ssid == cur["ssid"]
            and b.bssid != cur["bssid"]
            and (b.signal_dbm or -999) >= cfg.min_signal_dbm
        ]
        cands = cands[: cfg.max_aps]
        if not cands:
            return ModuleResult(
                status="skipped",
                message=f"no other {cur['ssid']} AP above {cfg.min_signal_dbm:.0f} dBm",
                metrics={"candidates": 0},
            )
        plan = [b.bssid for b in cands] + ([cur["bssid"]] if cfg.return_to_first else [])
        attempts: list[RoamAttempt] = []
        for target in plan:
            await ctx.progress(len(attempts) / len(plan) * 100, f"roaming to {target}", None)
            a = await net.wifi_roam(ifname, target, gateway, cfg.timeout_s)
            attempts.append(a)
            if a.ok:
                ctx.session["wifi"] = {**cur, "bssid": target}
        ok = [a for a in attempts if a.ok]
        times = [a.ms for a in ok if a.ms is not None]
        gaps = [a.gap_ms for a in ok if a.gap_ms is not None]
        metrics: dict[str, Any] = {
            "candidates": len(cands),
            "roams": len(attempts),
            "failed": len(attempts) - len(ok),
            "roam_avg_ms": round(sum(times) / len(times), 1) if times else None,
            "roam_worst_ms": max(times, default=None),
            "gap_worst_ms": max(gaps, default=None),
            "lost": sum(a.lost or 0 for a in attempts) if gateway else None,
        }
        status: Status = "pass" if len(ok) == len(attempts) else "fail" if not ok else "warn"
        msg = f"{len(ok)}/{len(attempts)} roams"
        if times:
            msg += f", worst {metrics['roam_worst_ms']} ms"
        if gaps:
            msg += f", longest outage {metrics['gap_worst_ms']} ms"
        return ModuleResult(
            status=status,
            message=msg,
            metrics=metrics,
            details={"attempts": [a.model_dump() for a in attempts]},
        )


# ---------------------------------------------------------------- clients (monitor)


class ClientsConfig(ModuleConfig):
    duration_s: float = Field(20.0, gt=0, le=300)
    channels: list[int] = Field(default_factory=list)  # default: every channel the radio supports
    deauth_alert: int = Field(30, ge=1)  # deauth/disassoc frames from one transmitter → finding


@register
class WifiClients(TestModule[ClientsConfig]):
    id = "wifi.clients"
    title = "Wi-Fi clients"
    requires = frozenset({C.WIFI_MONITOR})
    executor = "test-ns"
    Config = ClientsConfig
    needs_link = False
    timeout_s = 330.0

    async def run(self, ctx: RunContext, cfg: ClientsConfig) -> ModuleResult:
        try:
            net, ifname = wifi(ctx, "monitor")
        except LookupError:
            return ModuleResult(status="skipped", message="no monitor radio assigned")
        freqs = [chan_freq(c) for c in cfg.channels] or None
        m = await net.wifi_monitor(ifname, cfg.duration_s, freqs)
        assoc = [c for c in m.clients if c.bssid]
        findings = (
            [
                Finding(
                    severity="medium",
                    rule_id="wifi.deauth_flood",
                    title="Deauthentication/disassociation flood",
                    evidence={
                        "suspects": [
                            f"{t} ({n} frames)" for t, n in m.deauth.items() if n >= cfg.deauth_alert
                        ]
                    },
                )
            ]
            if any(n >= cfg.deauth_alert for n in m.deauth.values())
            else []
        )
        metrics: dict[str, Any] = {
            "clients": len(m.clients),
            "associated": len(assoc),
            "probing": len(m.clients) - len(assoc),
            "randomized": sum(1 for c in m.clients if c.randomized),
            "aps": len(m.aps),
            "deauth_frames": sum(m.deauth.values()),
            "frames": m.frames,
            "channels": len(m.channels),
        }
        status: Status = "warn" if findings else "pass"
        msg = f"{len(m.clients)} clients ({len(assoc)} associated) on {len(m.aps)} APs"
        msg += f" over {len(m.channels)} channels"
        return ModuleResult(
            status=status,
            message=msg,
            metrics=metrics,
            findings=findings,
            details={
                "clients": [c.model_dump() for c in m.clients],
                "aps": m.aps,
                "deauth": m.deauth,
                "channels": m.channels,
            },
        )
