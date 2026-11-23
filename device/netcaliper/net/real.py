# SPDX-License-Identifier: GPL-3.0-only
"""RealNet: TestNet on real interfaces. Runs inside the agent (test netns, NET_RAW + NET_ADMIN)."""

from __future__ import annotations

from . import app, discovery, dot1x, ip4, ipv6, link
from . import dhcp as dhcp4
from .base import (
    ArpResult,
    CableResult,
    ConnectResult,
    Dhcp6Result,
    DnsResult,
    Dot1xResult,
    Lease,
    LinkStatus,
    Neighbor,
    PingResult,
    RouterAdvert,
    TlsFiles,
)
from .packets import iface_mac
from .wifi import WifiReal


class RealNet(WifiReal):
    def __init__(self) -> None:
        super().__init__()
        self._addr: dict[str, str] = {}  # ifname -> IPv4 we configured (ARP source)

    async def link_status(self, ifname: str) -> LinkStatus:
        return await link.status(ifname)

    async def link_up(self, ifname: str, timeout_s: float = 10.0) -> LinkStatus:
        return await link.up(ifname, timeout_s)

    async def link_bounce(self, ifname: str, times: int, period_s: float) -> int:
        return await link.bounce(ifname, times, period_s)

    async def dhcp(self, ifname: str, collect_s: float = 2.0, timeout_s: float = 10.0) -> Lease:
        return await dhcp4.acquire(ifname, iface_mac(ifname), collect_s, timeout_s)

    async def apply_lease(self, ifname: str, lease: Lease) -> None:
        await link.apply_lease(ifname, lease.ip, lease.prefixlen, lease.router)
        self._addr[ifname] = lease.ip

    async def release(self, ifname: str) -> None:
        await link.release(ifname)
        self._addr.pop(ifname, None)

    async def dns(self, server: str, name: str, rtype: str = "A", timeout_s: float = 3.0) -> DnsResult:
        return await ip4.dns_query(server, name, rtype, timeout_s)

    async def arp(self, ifname: str, ip: str, timeout_s: float = 2.0) -> ArpResult:
        src = self._addr.get(ifname, "0.0.0.0")  # noqa: S104 - ARP-probe source, not a bind
        return await ip4.arp(ifname, iface_mac(ifname), src, ip, timeout_s)

    async def ping(
        self, ifname: str, target: str, count: int = 5, interval_s: float = 0.2, timeout_s: float = 1.0
    ) -> PingResult:
        return await ip4.ping(ifname, target, count, interval_s, timeout_s)

    async def tcp(self, target: str, port: int, dns: list[str], timeout_s: float = 5.0) -> ConnectResult:
        return await app.tcp(target, port, dns, timeout_s)

    async def http(self, url: str, dns: list[str], timeout_s: float = 10.0) -> ConnectResult:
        return await app.http(url, dns, timeout_s)

    async def ftp(
        self,
        target: str,
        dns: list[str],
        user: str = "anonymous",
        password: str = "",
        timeout_s: float = 10.0,
    ) -> ConnectResult:
        return await app.ftp(target, dns, user, password, timeout_s)

    async def listen_neighbors(self, ifname: str, duration_s: float) -> list[Neighbor]:
        return await discovery.listen(ifname, duration_s)

    async def router_solicit(self, ifname: str, timeout_s: float = 4.0) -> list[RouterAdvert]:
        return await ipv6.router_solicit(ifname, timeout_s)

    async def dhcp6(self, ifname: str, timeout_s: float = 5.0) -> Dhcp6Result:
        return await ipv6.dhcp6_probe(ifname, iface_mac(ifname), timeout_s)

    async def vlan_add(self, ifname: str, vid: int) -> str:
        return await link.vlan_add(ifname, vid)

    async def vlan_del(self, ifname: str) -> None:
        await link.vlan_del(ifname)

    async def dot1x(
        self,
        ifname: str,
        method: str,
        identity: str,
        password: str | None,
        timeout_s: float = 30.0,
        tls: TlsFiles | None = None,
    ) -> Dot1xResult:
        return await dot1x.authenticate(ifname, method, identity, password, timeout_s, tls)

    async def cable_test(self, ifname: str) -> CableResult:
        return await link.cable_test(ifname)
