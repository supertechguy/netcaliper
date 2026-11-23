# SPDX-License-Identifier: GPL-3.0-only
"""Wired AutoTest modules (Phase 2). All run in the test netns (executor "test-ns") and are PASSIVE
in the CyberScope sense: they measure the network as an ordinary client would, they don't scan.

Status policy here is only for clear-cut cases (no link, no lease, every DNS server dead, more than
one DHCP server); numeric pass/warn/fail comes from profile thresholds on the metrics.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field

from ..core.records import Finding, Status
from ..drivers.base import Capability as C
from ..net.base import Lease
from .base import ModuleConfig, ModuleResult, RunContext, TestModule
from .registry import register
from .thresholds import worst

_MODE = re.compile(r"^(\d+)base\w*/(Full|Half)$")


def best_common_mode(a: list[str], b: list[str]) -> tuple[int, str] | None:
    """Highest speed/duplex both ends advertise, e.g. (1000, 'Full')."""
    modes = set(a) & set(b)
    parsed = [(int(m.group(1)), m.group(2)) for x in modes if (m := _MODE.match(x))]
    return max(parsed, key=lambda p: (p[0], p[1] == "Full")) if parsed else None


def _lease(ctx: RunContext) -> Lease | None:
    raw = ctx.session.get("lease")
    return Lease.model_validate(raw) if raw else None


# ---------------------------------------------------------------- link


class LinkConfig(ModuleConfig):
    timeout_s: float = Field(10.0, gt=0, le=60)
    min_speed_mbps: int | None = None  # warn below this negotiated speed


@register
class WiredLink(TestModule[LinkConfig]):
    id = "wired.link"
    title = "Link"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = LinkConfig
    timeout_s = 75.0

    async def run(self, ctx: RunContext, cfg: LinkConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        st = await net.link_up(ifname, cfg.timeout_s)
        metrics: dict[str, Any] = {
            "carrier": st.carrier,
            "speed_mbps": st.speed_mbps,
            "duplex": st.duplex,
            "autoneg": st.autoneg,
            "link_up_ms": st.link_up_ms,
            "carrier_changes": st.carrier_changes,
        }
        details = st.model_dump()
        if not st.carrier:
            return ModuleResult(
                status="fail", message="no link (no carrier)", metrics=metrics, details=details
            )
        status: Status = "pass"
        notes = [f"{st.speed_mbps or '?'} Mb/s {st.duplex}"]
        best = best_common_mode(st.advertised, st.partner_advertised)
        if best:
            details["best_common"] = f"{best[0]} {best[1]}"
            if st.speed_mbps and st.speed_mbps < best[0]:
                status = "warn"
                notes.append(f"both ends support {best[0]} Mb/s — check the cable (downshift)")
        if st.duplex == "half":
            status = "warn"
            notes.append("half duplex (duplex mismatch?)")
        if cfg.min_speed_mbps and st.speed_mbps and st.speed_mbps < cfg.min_speed_mbps:
            status = "warn"
            notes.append(f"below expected {cfg.min_speed_mbps} Mb/s")
        return ModuleResult(status=status, message="; ".join(notes), metrics=metrics, details=details)


# ---------------------------------------------------------------- switch (LLDP/CDP/EDP)


class SwitchConfig(ModuleConfig):
    listen_s: float = Field(35.0, gt=0, le=180)  # LLDP default interval is 30 s, CDP 60 s
    require: bool = False  # fail when nothing is heard (e.g. a port that must report LLDP)


@register
class SwitchInfo(TestModule[SwitchConfig]):
    id = "wired.switchinfo"
    title = "Switch (LLDP/CDP/EDP)"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    background = True
    Config = SwitchConfig
    timeout_s = 200.0

    async def run(self, ctx: RunContext, cfg: SwitchConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        neighbors = await net.listen_neighbors(ifname, cfg.listen_s)
        if not neighbors:
            return ModuleResult(
                status="fail" if cfg.require else "pass",
                message=f"no LLDP/CDP/EDP heard in {cfg.listen_s:.0f} s",
                metrics={"neighbors": 0},
            )
        pref = {"lldp": 0, "cdp": 1, "edp": 2}  # the standard first
        ordered = sorted(neighbors, key=lambda n: pref.get(n.protocol, 9))
        first = ordered[0]

        def pick(attr: str) -> Any:
            return next((getattr(n, attr) for n in ordered if getattr(n, attr)), None)

        metrics: dict[str, Any] = {
            "neighbors": len(neighbors),
            "protocols": ",".join(sorted({n.protocol for n in neighbors})),
            "switch": pick("system_name"),
            "port": pick("port_id"),
            "native_vlan": pick("native_vlan"),
            "voice_vlan": pick("voice_vlan"),
        }
        msg = f"{metrics['switch'] or first.chassis_id} port {metrics['port'] or '?'}"
        if metrics["native_vlan"]:
            msg += f", VLAN {metrics['native_vlan']}"
        if metrics["voice_vlan"]:
            msg += f", voice {metrics['voice_vlan']}"
        others = sorted(
            {
                f"{n.system_name or n.chassis_id} ({n.protocol})"
                for n in ordered
                if (n.system_name or n.chassis_id) != (first.system_name or first.chassis_id)
            }
        )
        if others:
            # e.g. CDP from a router flooded through a switch that doesn't speak CDP
            msg += "; also heard: " + ", ".join(others)
        return ModuleResult(
            status="pass",
            message=msg,
            metrics=metrics,
            details={"neighbors": [n.model_dump() for n in neighbors]},
        )


# ---------------------------------------------------------------- DHCP


class DhcpConfig(ModuleConfig):
    collect_s: float = Field(2.0, ge=0, le=10)  # keep listening for more offers (rogue servers)
    timeout_s: float = Field(10.0, gt=0, le=60)
    expected_servers: list[str] = Field(default_factory=list)  # authorised server IDs; others = rogue


@register
class WiredDhcp(TestModule[DhcpConfig]):
    id = "wired.dhcp"
    title = "DHCP"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = DhcpConfig
    timeout_s = 90.0

    async def run(self, ctx: RunContext, cfg: DhcpConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        await net.release(ifname)
        try:
            lease = await net.dhcp(ifname, cfg.collect_s, cfg.timeout_s)
        except Exception as e:
            return ModuleResult(status="fail", message=f"no lease: {e}", metrics={"offers": 0})
        await net.apply_lease(ifname, lease)
        ctx.session["lease"] = lease.model_dump()
        servers = {o.server_id for o in lease.offers}
        metrics: dict[str, Any] = {
            "ip": f"{lease.ip}/{lease.prefixlen}",
            "offer_ms": lease.discover_to_offer_ms,
            "ack_ms": lease.request_to_ack_ms,
            "offers": len(lease.offers),  # total_ms (incl. the rogue-collection window) stays in details
            "servers": len(servers),
            "lease_s": lease.lease_s,
            "router": lease.router,
            "dns": ", ".join(lease.dns),
        }
        status: Status = "pass"
        msg = (
            f"{lease.ip}/{lease.prefixlen} from {lease.server_id}"
            f" (offer {lease.discover_to_offer_ms:.0f} ms, ack {lease.request_to_ack_ms:.0f} ms)"
        )
        findings: list[Finding] = []
        rogue = sorted(servers - set(cfg.expected_servers)) if cfg.expected_servers else []
        if len(servers) > 1 or rogue:
            status = "warn"
            suspects = rogue or sorted(servers)
            msg += f"; {len(servers)} DHCP servers answered: {', '.join(sorted(servers))}"
            findings.append(
                Finding(
                    severity="high",
                    rule_id="dhcp.multiple_servers",
                    title="Multiple / unauthorised DHCP servers",
                    evidence={"offers": [o.model_dump() for o in lease.offers], "suspects": suspects},
                )
            )
        if not lease.router:
            status = worst(status, "warn")
            msg += "; no default gateway offered"
        return ModuleResult(
            status=status, message=msg, metrics=metrics, details=lease.model_dump(), findings=findings
        )


# ---------------------------------------------------------------- DNS


class DnsConfig(ModuleConfig):
    names: list[str] = Field(default_factory=lambda: ["example.com"], min_length=1, max_length=10)
    servers: list[str] = Field(default_factory=list)  # default: the DHCP-supplied servers
    timeout_s: float = Field(3.0, gt=0, le=15)


@register
class NetDns(TestModule[DnsConfig]):
    id = "net.dns"
    title = "DNS"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = DnsConfig

    async def run(self, ctx: RunContext, cfg: DnsConfig) -> ModuleResult:
        net, _ = self.net(ctx)
        lease = _lease(ctx)
        servers = cfg.servers or (lease.dns if lease else [])
        if not servers:
            return ModuleResult(
                status="skipped", message="no DNS servers (no DHCP lease and none configured)"
            )
        results = [await net.dns(s, n, timeout_s=cfg.timeout_s) for s in servers for n in cfg.names]
        ok = [r for r in results if r.ok]
        times = [r.ms for r in ok if r.ms is not None]
        dead = sorted({r.server for r in results} - {r.server for r in ok})
        metrics: dict[str, Any] = {
            "servers": len(servers),
            "failed_servers": len(dead),
            "lookup_ms": max(times) if times else None,  # worst successful lookup
            "lookup_avg_ms": round(sum(times) / len(times), 2) if times else None,
        }
        if not ok:
            status: Status = "fail"
            msg = "no DNS server answered"
        elif dead:
            status, msg = "warn", f"not answering: {', '.join(dead)}"
        else:
            status, msg = "pass", f"{len(servers)} server(s), worst {max(times):.0f} ms"
        return ModuleResult(
            status=status,
            message=msg,
            metrics=metrics,
            details={"results": [r.model_dump() for r in results]},
        )


# ---------------------------------------------------------------- gateway


class GatewayConfig(ModuleConfig):
    count: int = Field(5, ge=1, le=50)


@register
class NetGateway(TestModule[GatewayConfig]):
    id = "net.gateway"
    title = "Gateway"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = GatewayConfig

    async def run(self, ctx: RunContext, cfg: GatewayConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        lease = _lease(ctx)
        if not lease or not lease.router:
            return ModuleResult(status="skipped", message="no gateway known (no DHCP lease)")
        a = await net.arp(ifname, lease.router)
        p = await net.ping(ifname, lease.router, count=cfg.count)
        metrics: dict[str, Any] = {
            "arp_ms": a.ms,
            "mac": a.mac,
            "loss_pct": round(p.loss_pct, 1),
            "rtt_avg_ms": p.rtt_avg,
            "rtt_max_ms": p.rtt_max,
            "jitter_ms": p.jitter,
        }
        if a.mac is None:
            return ModuleResult(
                status="fail", message=f"gateway {lease.router} does not answer ARP", metrics=metrics
            )
        if p.received == 0:
            # Some gateways drop ICMP; ARP proves it's alive.
            return ModuleResult(
                status="warn", message=f"{lease.router} ({a.mac}) answers ARP but not ping", metrics=metrics
            )
        status: Status = "warn" if p.loss_pct else "pass"
        msg = f"{lease.router} ({a.mac}) {p.rtt_avg} ms avg, {p.loss_pct:.0f}% loss"
        return ModuleResult(
            status=status,
            message=msg,
            metrics=metrics,
            details={"arp": a.model_dump(), "ping": p.model_dump()},
        )


# ---------------------------------------------------------------- targets


class Probe(ModuleConfig):
    kind: Literal["ping", "tcp", "http", "ftp"]
    target: str = Field(min_length=1, max_length=253)
    port: int | None = Field(None, ge=1, le=65535)
    user: str = "anonymous"
    password: str = ""


class TargetsConfig(ModuleConfig):
    probes: list[Probe] = Field(
        default_factory=lambda: [
            Probe(kind="ping", target="1.1.1.1"),
            Probe(kind="tcp", target="1.1.1.1", port=443),
            Probe(kind="http", target="https://example.com/"),
        ],
        max_length=20,
    )
    count: int = Field(5, ge=1, le=50)


@register
class NetTargets(TestModule[TargetsConfig]):
    id = "net.targets"
    title = "Targets"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = TargetsConfig
    timeout_s = 240.0

    async def run(self, ctx: RunContext, cfg: TargetsConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        lease = _lease(ctx)
        dns = lease.dns if lease else []
        rows: list[dict[str, Any]] = []
        for t in cfg.probes:
            if t.kind == "ping":
                r = await net.ping(ifname, t.target, count=cfg.count)
                ms = r.rtt_avg
                rows.append(
                    {
                        "kind": "ping",
                        "target": t.target,
                        "ok": r.received > 0,
                        "ms": ms,
                        "loss_pct": round(r.loss_pct, 1),
                        "detail": r.model_dump(),
                    }
                )
            else:
                if t.kind == "tcp":
                    c = await net.tcp(t.target, t.port or 80, dns)
                elif t.kind == "http":
                    c = await net.http(t.target, dns)
                else:
                    c = await net.ftp(t.target, dns, t.user, t.password)
                rows.append(
                    {
                        "kind": t.kind,
                        "target": t.target,
                        "ok": c.ok,
                        "ms": c.total_ms,
                        "detail": c.model_dump(),
                    }
                )
        failed = [r for r in rows if not r["ok"]]
        times = [r["ms"] for r in rows if r["ok"] and r["ms"] is not None]
        metrics: dict[str, Any] = {
            "targets": len(rows),
            "failed": len(failed),
            "worst_ms": max(times) if times else None,
        }
        for i, row in enumerate(rows):
            metrics[f"t{i + 1}_ms"] = row["ms"]
        if failed and len(failed) == len(rows):
            status: Status = "fail"
        elif failed:
            status = "warn"
        else:
            status = "pass"
        msg = f"{len(rows) - len(failed)}/{len(rows)} reachable"
        if failed:
            msg += "; failed: " + ", ".join(f"{r['kind']} {r['target']}" for r in failed)
        return ModuleResult(status=status, message=msg, metrics=metrics, details={"targets": rows})


# ---------------------------------------------------------------- IPv6


class Ipv6Config(ModuleConfig):
    expect: bool = False  # fail when the network has no IPv6 routers
    timeout_s: float = Field(4.0, gt=0, le=20)


@register
class WiredIpv6(TestModule[Ipv6Config]):
    id = "wired.ipv6"
    title = "IPv6"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = Ipv6Config

    async def run(self, ctx: RunContext, cfg: Ipv6Config) -> ModuleResult:
        net, ifname = self.net(ctx)
        ras = await net.router_solicit(ifname, cfg.timeout_s)
        d6 = await net.dhcp6(ifname, cfg.timeout_s) if any(r.managed or r.other for r in ras) else None
        # Rogue-RA risk = more than one *default* router (lifetime > 0). Lifetime-0 advertisers only
        # announce prefixes/routes — e.g. Thread/Matter border routers (HomePod, Nest) — and are normal.
        default = [r for r in ras if r.lifetime_s > 0]
        metrics: dict[str, Any] = {
            "routers": len(default),
            "advertisers": len(ras),
            "ra_ms": min((r.ms for r in ras if r.ms is not None), default=None),
            "prefixes": ", ".join(sorted({p for r in ras for p in r.prefixes})),
            "dhcp6": d6.ok if d6 else None,
            "dhcp6_ms": d6.advertise_ms if d6 else None,
        }
        details = {"routers": [r.model_dump() for r in ras], "dhcp6": d6.model_dump() if d6 else None}
        if not default:
            what = (
                "no IPv6 routers"
                if not ras
                else f"no IPv6 default router ({len(ras)} prefix-only advertisers)"
            )
            return ModuleResult(
                status="fail" if cfg.expect else "pass",
                message=what + (f", prefixes {metrics['prefixes']}" if metrics["prefixes"] else ""),
                metrics=metrics,
                details=details,
            )
        findings: list[Finding] = []
        status: Status = "pass"
        msg = f"{len(default)} default router(s), prefixes {metrics['prefixes'] or 'none'}"
        if len(ras) > len(default):
            msg += f" (+{len(ras) - len(default)} prefix-only advertisers)"
        if len({r.router_mac or r.router for r in default}) > 1:
            status = "warn"
            msg += " — more than one default router (rogue RA?)"
            findings.append(
                Finding(
                    severity="medium",
                    rule_id="ipv6.multiple_routers",
                    title="Multiple IPv6 default routers advertising",
                    evidence={"routers": [r.model_dump() for r in default]},
                )
            )
        if d6 is not None and not d6.ok:
            status = worst(status, "warn")
            msg += "; RA asks for DHCPv6 but no server answered"
        elif d6 is not None and d6.servers > 1:
            status = worst(status, "warn")
            msg += f"; {d6.servers} DHCPv6 servers"
        return ModuleResult(status=status, message=msg, metrics=metrics, details=details, findings=findings)


# ---------------------------------------------------------------- VLAN


class VlanConfig(ModuleConfig):
    vlans: list[int] = Field(min_length=1, max_length=16)
    collect_s: float = Field(1.0, ge=0, le=10)
    timeout_s: float = Field(8.0, gt=0, le=60)


@register
class WiredVlan(TestModule[VlanConfig]):
    id = "wired.vlan"
    title = "VLANs"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = VlanConfig
    timeout_s = 300.0

    async def run(self, ctx: RunContext, cfg: VlanConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        rows: list[dict[str, Any]] = []
        for vid in cfg.vlans:
            if not 1 <= vid <= 4094:
                rows.append({"vlan": vid, "ok": False, "error": "invalid VLAN id"})
                continue
            sub = await net.vlan_add(ifname, vid)
            try:
                lease = await net.dhcp(sub, cfg.collect_s, cfg.timeout_s)
                rows.append(
                    {
                        "vlan": vid,
                        "ok": True,
                        "ip": f"{lease.ip}/{lease.prefixlen}",
                        "router": lease.router,
                        "ms": lease.total_ms,
                        "servers": len(lease.offers),
                    }
                )
            except Exception as e:
                rows.append({"vlan": vid, "ok": False, "error": str(e)[:120]})
            finally:
                await net.vlan_del(sub)
        failed = [r["vlan"] for r in rows if not r["ok"]]
        metrics: dict[str, Any] = {"vlans": len(rows), "failed": len(failed)}
        status: Status = "fail" if len(failed) == len(rows) else "warn" if failed else "pass"
        msg = f"{len(rows) - len(failed)}/{len(rows)} VLANs got a lease"
        if failed:
            msg += f"; failed: {', '.join(map(str, failed))}"
        return ModuleResult(status=status, message=msg, metrics=metrics, details={"vlans": rows})


# ---------------------------------------------------------------- 802.1X


class Dot1xConfig(ModuleConfig):
    method: Literal["peap", "ttls", "md5"] = "peap"
    identity: str = Field(min_length=1, max_length=128)
    password: str | None = Field(None, max_length=256, repr=False)  # resolved from secrets by core
    timeout_s: float = Field(30.0, gt=0, le=120)


@register
class WiredDot1x(TestModule[Dot1xConfig]):
    id = "wired.dot1x"
    title = "802.1X"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = Dot1xConfig
    timeout_s = 150.0

    async def run(self, ctx: RunContext, cfg: Dot1xConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        r = await net.dot1x(ifname, cfg.method, cfg.identity, cfg.password, cfg.timeout_s)
        metrics: dict[str, Any] = {"ok": r.ok, "auth_ms": r.auth_ms, "state": r.state}
        msg = (
            f"{cfg.method.upper()} as {cfg.identity}: authenticated in {r.auth_ms:.0f} ms"
            if r.ok
            else f"{cfg.method.upper()} as {cfg.identity}: {r.error or r.state}"
        )
        return ModuleResult(
            status="pass" if r.ok else "fail", message=msg, metrics=metrics, details=r.model_dump()
        )


# ---------------------------------------------------------------- port blink / cable


class BlinkConfig(ModuleConfig):
    times: int = Field(10, ge=1, le=60)
    period_s: float = Field(1.0, ge=0.2, le=5)


@register
class WiredBlink(TestModule[BlinkConfig]):
    """Find the switch port: toggle link so its LED blinks. Disruptive by nature — tool action, not
    part of the default AutoTest."""

    id = "wired.blink"
    title = "Port blink"
    requires = frozenset({C.WIRED_TEST})
    executor = "test-ns"
    Config = BlinkConfig
    timeout_s = 330.0

    async def run(self, ctx: RunContext, cfg: BlinkConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        n = await net.link_bounce(ifname, cfg.times, cfg.period_s)
        return ModuleResult(status="pass", message=f"blinked the port {n} times", metrics={"cycles": n})


@register
class WiredCable(TestModule[ModuleConfig]):
    id = "wired.cable"
    title = "Cable test"
    requires = frozenset({C.WIRED_TEST, C.WIRED_CABLE_TEST})
    executor = "test-ns"
    timeout_s = 90.0

    async def run(self, ctx: RunContext, cfg: ModuleConfig) -> ModuleResult:
        net, ifname = self.net(ctx)
        r = await net.cable_test(ifname)
        if not r.supported:
            return ModuleResult(status="skipped", message=r.error or "cable diagnostics not supported")
        bad = [p for p in r.pairs if str(p.get("code", "")).upper() not in ("OK", "")]
        return ModuleResult(
            status="warn" if bad else "pass",
            message=f"{len(r.pairs)} pairs, {len(bad)} faults" if r.pairs else "no pair data",
            metrics={"pairs": len(r.pairs), "faults": len(bad)},
            details=r.model_dump(),
        )
