# SPDX-License-Identifier: GPL-3.0-only
"""Test-plane primitives: what wired/net modules may do on a test interface.

`RealNet` implements this inside the agent (test netns) with our own packet code; `MockNet`
simulates it so the whole AutoTest runs on x86 without hardware. Modules only orchestrate these
calls and report metrics — thresholds and pass/fail policy live in profiles.

All durations are milliseconds (float). Interfaces are passed by name *within the test netns*;
callers resolve them from the hardware registry by role/capability, never hard-code them.
"""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, Field


class LinkStatus(BaseModel):
    ifname: str
    carrier: bool
    speed_mbps: int | None = None
    duplex: Literal["full", "half", "unknown"] = "unknown"
    autoneg: bool | None = None
    advertised: list[str] = Field(default_factory=list)
    partner_advertised: list[str] = Field(default_factory=list)
    supported: list[str] = Field(default_factory=list)
    carrier_changes: int | None = None  # kernel flap counter since the device appeared
    link_up_ms: float | None = None  # time from admin-up to carrier (when we brought it up)
    mtu: int | None = None
    mac: str = ""


class DhcpOffer(BaseModel):
    server_id: str
    server_mac: str = ""
    yiaddr: str
    offer_ms: float


class Lease(BaseModel):
    ip: str
    prefixlen: int
    router: str | None = None
    dns: list[str] = Field(default_factory=list)
    domain: str | None = None
    lease_s: int | None = None
    server_id: str
    server_mac: str = ""
    offers: list[DhcpOffer] = Field(default_factory=list)  # every offer seen (rogue detection)
    discover_to_offer_ms: float
    request_to_ack_ms: float
    total_ms: float
    options: dict[str, str] = Field(default_factory=dict)  # raw-ish extras (ntp, mtu, …) for display


class DnsResult(BaseModel):
    server: str
    name: str
    rtype: str = "A"
    ok: bool
    answers: list[str] = Field(default_factory=list)
    rcode: str = ""
    ms: float | None = None
    error: str | None = None


class PingResult(BaseModel):
    target: str
    sent: int
    received: int
    rtt_min: float | None = None
    rtt_avg: float | None = None
    rtt_max: float | None = None
    jitter: float | None = None  # mean absolute difference of consecutive RTTs

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - self.received) / self.sent if self.sent else 100.0


class ArpResult(BaseModel):
    ip: str
    mac: str | None
    ms: float | None


class ConnectResult(BaseModel):
    target: str
    ip: str | None = None
    port: int
    ok: bool
    dns_ms: float | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    first_byte_ms: float | None = None
    total_ms: float | None = None
    status: int | None = None  # HTTP status / FTP reply code
    detail: str = ""
    error: str | None = None


class Neighbor(BaseModel):
    """A switch/neighbor announced via LLDP, CDP or EDP."""

    protocol: Literal["lldp", "cdp", "edp"]
    src_mac: str
    chassis_id: str | None = None
    system_name: str | None = None
    system_description: str | None = None
    port_id: str | None = None
    port_description: str | None = None
    platform: str | None = None
    mgmt_addresses: list[str] = Field(default_factory=list)
    native_vlan: int | None = None
    voice_vlan: int | None = None
    vlans: list[int] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    poe: dict[str, str] = Field(default_factory=dict)  # LLDP-MED / 802.3at power, CDP power
    duplex: str | None = None
    ttl_s: int | None = None


class RouterAdvert(BaseModel):
    router: str  # link-local source
    router_mac: str = ""
    lifetime_s: int
    managed: bool  # M flag → DHCPv6 for addresses
    other: bool  # O flag → DHCPv6 for other config
    prefixes: list[str] = Field(default_factory=list)
    rdnss: list[str] = Field(default_factory=list)
    mtu: int | None = None
    ms: float | None = None


class Dhcp6Result(BaseModel):
    ok: bool
    server_duid: str | None = None
    addresses: list[str] = Field(default_factory=list)
    dns: list[str] = Field(default_factory=list)
    advertise_ms: float | None = None
    servers: int = 0
    error: str | None = None


class Dot1xResult(BaseModel):
    ok: bool
    method: str
    state: str  # final EAP/supplicant state
    auth_ms: float | None = None
    error: str | None = None


class CableResult(BaseModel):
    supported: bool
    pairs: list[dict[str, str | float | None]] = Field(default_factory=list)
    error: str | None = None


class TestNet(Protocol):
    """Implemented by RealNet (agent) and MockNet. See module docstring."""

    async def link_status(self, ifname: str) -> LinkStatus: ...
    async def link_up(self, ifname: str, timeout_s: float = 10.0) -> LinkStatus: ...
    async def link_bounce(self, ifname: str, times: int, period_s: float) -> int: ...
    async def dhcp(self, ifname: str, collect_s: float = 2.0, timeout_s: float = 10.0) -> Lease: ...
    async def apply_lease(self, ifname: str, lease: Lease) -> None: ...
    async def release(self, ifname: str) -> None: ...
    async def dns(self, server: str, name: str, rtype: str = "A", timeout_s: float = 3.0) -> DnsResult: ...
    async def arp(self, ifname: str, ip: str, timeout_s: float = 2.0) -> ArpResult: ...
    async def ping(
        self, ifname: str, target: str, count: int = 5, interval_s: float = 0.2, timeout_s: float = 1.0
    ) -> PingResult: ...
    async def tcp(self, target: str, port: int, dns: list[str], timeout_s: float = 5.0) -> ConnectResult: ...
    async def http(self, url: str, dns: list[str], timeout_s: float = 10.0) -> ConnectResult: ...
    async def ftp(
        self,
        target: str,
        dns: list[str],
        user: str = "anonymous",
        password: str = "",
        timeout_s: float = 10.0,
    ) -> ConnectResult: ...
    async def listen_neighbors(self, ifname: str, duration_s: float) -> list[Neighbor]: ...
    async def router_solicit(self, ifname: str, timeout_s: float = 4.0) -> list[RouterAdvert]: ...
    async def dhcp6(self, ifname: str, timeout_s: float = 5.0) -> Dhcp6Result: ...
    async def vlan_add(self, ifname: str, vid: int) -> str: ...
    async def vlan_del(self, ifname: str) -> None: ...
    async def dot1x(
        self, ifname: str, method: str, identity: str, password: str | None, timeout_s: float = 30.0
    ) -> Dot1xResult: ...
    async def cable_test(self, ifname: str) -> CableResult: ...
