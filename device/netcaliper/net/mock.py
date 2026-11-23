# SPDX-License-Identifier: GPL-3.0-only
"""MockNet: a plausible simulated network so the full AutoTest runs on x86 without hardware.

Scenario knobs (constructor) let tests drive the failure paths: rogue DHCP server, no DHCP,
dead gateway, DNS failure, no neighbors, IPv6 absent, 802.1X rejection.
"""

from __future__ import annotations

import asyncio
import itertools
import random

from .base import (
    ArpResult,
    CableResult,
    ConnectResult,
    Dhcp6Result,
    DhcpOffer,
    DnsResult,
    Dot1xResult,
    Lease,
    LinkStatus,
    Neighbor,
    PingResult,
    RouterAdvert,
)

GBE = ["10baseT/Half", "10baseT/Full", "100baseT/Half", "100baseT/Full", "1000baseT/Full"]


class MockNet:
    def __init__(
        self,
        *,
        seed: int = 7,
        rogue_dhcp: bool = False,
        no_dhcp: bool = False,
        dead_gateway: bool = False,
        dns_fail: bool = False,
        neighbors: bool = True,
        ipv6: bool = True,
        dot1x_ok: bool = True,
        rogue_ra: bool = False,
        thread_brs: int = 0,  # lifetime-0 prefix advertisers (Thread/Matter border routers)
        speed: int = 1000,
        delay: float = 0.0,
    ) -> None:
        self.rnd = random.Random(seed)  # noqa: S311 - simulation, not crypto
        self.rogue_dhcp, self.no_dhcp, self.dead_gateway, self.dns_fail = (
            rogue_dhcp,
            no_dhcp,
            dead_gateway,
            dns_fail,
        )
        self.neighbors, self.ipv6, self.dot1x_ok, self.speed, self.delay = (
            neighbors,
            ipv6,
            dot1x_ok,
            speed,
            delay,
        )
        self.rogue_ra, self.thread_brs = rogue_ra, thread_brs
        self.vlans: set[str] = set()
        self.applied: dict[str, Lease] = {}

    def _ms(self, lo: float, hi: float) -> float:
        return round(self.rnd.uniform(lo, hi), 2)

    async def _wait(self) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)

    async def link_status(self, ifname: str) -> LinkStatus:
        return LinkStatus(
            ifname=ifname,
            carrier=True,
            speed_mbps=self.speed,
            duplex="full",
            autoneg=True,
            advertised=GBE,
            partner_advertised=GBE,
            supported=GBE,
            carrier_changes=2,
            mtu=1500,
            mac="00:05:1b:00:00:01",
        )

    async def link_up(self, ifname: str, timeout_s: float = 10.0) -> LinkStatus:
        await self._wait()
        st = await self.link_status(ifname)
        st.link_up_ms = self._ms(1800, 3200)  # typical GbE autoneg
        return st

    async def link_bounce(self, ifname: str, times: int, period_s: float) -> int:
        return times

    async def dhcp(self, ifname: str, collect_s: float = 2.0, timeout_s: float = 10.0) -> Lease:
        await self._wait()
        if self.no_dhcp:
            raise TimeoutError(f"no DHCPOFFER within {timeout_s:.0f} s")
        offers = [
            DhcpOffer(
                server_id="192.168.1.1",
                server_mac="74:ac:b9:00:00:01",
                yiaddr="192.168.1.57",
                offer_ms=self._ms(4, 30),
            )
        ]
        if self.rogue_dhcp:
            offers.append(
                DhcpOffer(
                    server_id="10.99.0.1",
                    server_mac="b8:27:eb:00:00:99",
                    yiaddr="10.99.0.23",
                    offer_ms=self._ms(30, 60),
                )
            )
        o = offers[0]
        req = self._ms(2, 15)
        return Lease(
            ip=o.yiaddr,
            prefixlen=24,
            router="192.168.1.1",
            dns=["192.168.1.1", "1.1.1.1"],
            domain="lan",
            lease_s=86400,
            server_id=o.server_id,
            server_mac=o.server_mac,
            offers=offers,
            discover_to_offer_ms=o.offer_ms,
            request_to_ack_ms=req,
            total_ms=round(o.offer_ms + collect_s * 1000 + req, 2),
            options={"ntp": "192.168.1.1"},
        )

    async def apply_lease(self, ifname: str, lease: Lease) -> None:
        self.applied[ifname] = lease

    async def release(self, ifname: str) -> None:
        self.applied.pop(ifname, None)

    async def dns(self, server: str, name: str, rtype: str = "A", timeout_s: float = 3.0) -> DnsResult:
        if self.dns_fail:
            return DnsResult(server=server, name=name, rtype=rtype, ok=False, error="timeout")
        return DnsResult(
            server=server,
            name=name,
            rtype=rtype,
            ok=True,
            answers=["93.184.215.14"],
            rcode="NOERROR",
            ms=self._ms(3, 40),
        )

    async def arp(self, ifname: str, ip: str, timeout_s: float = 2.0) -> ArpResult:
        if self.dead_gateway:
            return ArpResult(ip=ip, mac=None, ms=None)
        return ArpResult(ip=ip, mac="74:ac:b9:00:00:01", ms=self._ms(0.4, 2))

    async def ping(
        self, ifname: str, target: str, count: int = 5, interval_s: float = 0.2, timeout_s: float = 1.0
    ) -> PingResult:
        if self.dead_gateway:
            return PingResult(target=target, sent=count, received=0)
        rtts = [self._ms(0.5, 3) if target.startswith("192.168.") else self._ms(9, 25) for _ in range(count)]
        return PingResult(
            target=target,
            sent=count,
            received=count,
            rtt_min=min(rtts),
            rtt_avg=round(sum(rtts) / len(rtts), 3),
            rtt_max=max(rtts),
            jitter=round(sum(abs(a - b) for a, b in itertools.pairwise(rtts)) / (count - 1), 3)
            if count > 1
            else None,
        )

    async def _connect(self, target: str, port: int, tls: bool, status: int | None) -> ConnectResult:
        if self.dns_fail:
            return ConnectResult(target=target, port=port, ok=False, error="DNS resolution failed")
        d, c = self._ms(3, 30), self._ms(8, 30)
        t = self._ms(20, 60) if tls else None
        fb = self._ms(20, 120)
        return ConnectResult(
            target=target,
            ip="93.184.215.14",
            port=port,
            ok=True,
            dns_ms=d,
            connect_ms=c,
            tls_ms=t,
            first_byte_ms=fb,
            total_ms=round(d + c + (t or 0) + fb + 5, 2),
            status=status,
        )

    async def tcp(self, target: str, port: int, dns: list[str], timeout_s: float = 5.0) -> ConnectResult:
        return await self._connect(target, port, False, None)

    async def http(self, url: str, dns: list[str], timeout_s: float = 10.0) -> ConnectResult:
        return await self._connect(url, 443 if url.startswith("https") else 80, url.startswith("https"), 200)

    async def ftp(
        self,
        target: str,
        dns: list[str],
        user: str = "anonymous",
        password: str = "",
        timeout_s: float = 10.0,
    ) -> ConnectResult:
        r = await self._connect(target, 21, False, 230)
        r.detail = "230 Login successful."
        return r

    async def listen_neighbors(self, ifname: str, duration_s: float) -> list[Neighbor]:
        await self._wait()
        if not self.neighbors:
            return []
        return [
            Neighbor(
                protocol="lldp",
                src_mac="74:ac:b9:00:10:07",
                chassis_id="74:ac:b9:00:10:00",
                system_name="idf2-access-sw1",
                system_description="Simulated switch 48P PoE+",
                port_id="gi1/0/7",
                port_description="Desk 2-114",
                mgmt_addresses=["192.168.1.2"],
                native_vlan=10,
                voice_vlan=20,
                capabilities=["bridge", "router"],
                poe={"class": "4", "allocated_w": "30.0"},
                ttl_s=120,
            ),
            Neighbor(
                protocol="cdp",
                src_mac="74:ac:b9:00:10:07",
                system_name="idf2-access-sw1",
                port_id="GigabitEthernet1/0/7",
                platform="Simulated",
                native_vlan=10,
                voice_vlan=20,
                duplex="full",
                capabilities=["switch", "igmp"],
                ttl_s=180,
            ),
        ]

    async def router_solicit(self, ifname: str, timeout_s: float = 4.0) -> list[RouterAdvert]:
        if not self.ipv6:
            return []
        ras = [
            RouterAdvert(
                router="fe80::76ac:b9ff:fe00:1",
                router_mac="74:ac:b9:00:00:01",
                lifetime_s=1800,
                managed=False,
                other=True,
                prefixes=["2001:db8:10::/64"],
                rdnss=["2001:db8:10::1"],
                mtu=1500,
                ms=self._ms(2, 20),
            )
        ]
        if self.rogue_ra:
            ras.append(
                RouterAdvert(
                    router="fe80::ba27:ebff:fe00:99",
                    router_mac="b8:27:eb:00:00:99",
                    lifetime_s=600,
                    managed=False,
                    other=False,
                    prefixes=["2001:db8:bad::/64"],
                    ms=self._ms(20, 40),
                )
            )
        for k in range(self.thread_brs):
            ras.append(
                RouterAdvert(
                    router=f"fe80::c4f7:c1ff:fe00:{k + 1:x}",
                    router_mac=f"c4:f7:c1:00:00:{k + 1:02x}",
                    lifetime_s=0,
                    managed=False,
                    other=False,
                    prefixes=["fd10:24:3734:1869::/64"],
                    ms=self._ms(5, 30),
                )
            )
        return ras

    async def dhcp6(self, ifname: str, timeout_s: float = 5.0) -> Dhcp6Result:
        if not self.ipv6:
            return Dhcp6Result(ok=False, error="no DHCPv6 Advertise")
        return Dhcp6Result(
            ok=True,
            server_duid="000300017 4acb9000001".replace(" ", ""),
            dns=["2001:db8:10::1"],
            advertise_ms=self._ms(5, 40),
            servers=1,
        )

    async def vlan_add(self, ifname: str, vid: int) -> str:
        name = f"{ifname[:9]}.{vid}"
        self.vlans.add(name)
        return name

    async def vlan_del(self, ifname: str) -> None:
        self.vlans.discard(ifname)

    async def dot1x(
        self, ifname: str, method: str, identity: str, password: str | None, timeout_s: float = 30.0
    ) -> Dot1xResult:
        if self.dot1x_ok:
            return Dot1xResult(ok=True, method=method, state="AUTHENTICATED", auth_ms=self._ms(150, 900))
        return Dot1xResult(
            ok=False, method=method, state="HELD", auth_ms=self._ms(150, 900), error="authentication rejected"
        )

    async def cable_test(self, ifname: str) -> CableResult:
        return CableResult(supported=False, error="PHY has no cable diagnostics (simulated AX88179)")
