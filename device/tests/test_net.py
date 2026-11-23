# SPDX-License-Identifier: GPL-3.0-only
"""Protocol code (no sockets): builders ↔ parsers, server replies built with dpkt."""

from __future__ import annotations

import socket
import struct

import dpkt
import pytest

from netcaliper.modules.wired import best_common_mode
from netcaliper.net import dhcp, discovery, dot1x, ip4, ipv6
from netcaliper.net.packets import mac_bytes

SW = "74:ac:b9:00:10:07"
CLIENT = "02:00:00:00:00:01"


# ---------------------------------------------------------------- discovery


def test_lldp_roundtrip_with_vlans_and_mgmt() -> None:
    f = discovery.build_lldp(
        SW,
        "idf2-sw1",
        "gi1/0/7",
        port_description="Desk 2-114",
        native_vlan=10,
        voice_vlan=20,
        mgmt_ip="192.0.2.2",
        caps=("bridge", "router"),
    )
    n = discovery.parse_lldp(f)
    assert n is not None and n.protocol == "lldp"
    assert (n.system_name, n.port_id, n.port_description) == ("idf2-sw1", "gi1/0/7", "Desk 2-114")
    assert n.chassis_id == SW and n.src_mac == SW and n.ttl_s == 120
    assert (n.native_vlan, n.voice_vlan) == (10, 20)
    assert n.mgmt_addresses == ["192.0.2.2"]
    assert set(n.capabilities) == {"bridge", "router"}
    assert discovery.parse_any(f) == n


def test_cdp_roundtrip() -> None:
    f = discovery.build_cdp(
        SW,
        "core-sw",
        "GigabitEthernet1/0/7",
        platform="cisco WS-C3850",
        native_vlan=30,
        voice_vlan=31,
        mgmt_ip="192.0.2.9",
    )
    n = discovery.parse_cdp(f)
    assert n is not None and n.protocol == "cdp"
    assert (n.system_name, n.port_id, n.platform) == ("core-sw", "GigabitEthernet1/0/7", "cisco WS-C3850")
    assert (n.native_vlan, n.voice_vlan, n.duplex) == (30, 31, "full")
    assert n.mgmt_addresses == ["192.0.2.9"] and "switch" in n.capabilities
    assert discovery.parse_lldp(f) is None  # protocol dispatch is strict


def test_edp_roundtrip() -> None:
    n = discovery.parse_edp(discovery.build_edp(SW, "x440", slot=1, port=12, vlans=(5, 6)))
    assert n is not None and n.protocol == "edp"
    assert (n.system_name, n.port_id, n.chassis_id) == ("x440", "1:12", SW)
    assert n.vlans == [5, 6]


@pytest.mark.parametrize("cut", [0, 5, 14, 20, 40])
def test_parsers_survive_truncation(cut: int) -> None:
    for f in (
        discovery.build_lldp(SW, "a", "b", native_vlan=1),
        discovery.build_cdp(SW, "a", "b"),
        discovery.build_edp(SW, "a", 1, 1),
    ):
        discovery.parse_any(f[:cut])  # must not raise
        discovery.parse_any(f[: len(f) - cut])


# ---------------------------------------------------------------- DHCP


def _reply(
    xid: int, mt: int, server: str, yiaddr: str, smac: str = SW, dns: tuple[str, ...] = ("192.0.2.1",)
) -> bytes:
    opts = [
        (dpkt.dhcp.DHCP_OPT_MSGTYPE, bytes([mt])),
        (dpkt.dhcp.DHCP_OPT_SERVER_ID, socket.inet_aton(server)),
        (dpkt.dhcp.DHCP_OPT_NETMASK, socket.inet_aton("255.255.255.0")),
        (dpkt.dhcp.DHCP_OPT_ROUTER, socket.inet_aton(server)),
        (dpkt.dhcp.DHCP_OPT_DNS_SVRS, b"".join(socket.inet_aton(x) for x in dns)),
        (dpkt.dhcp.DHCP_OPT_LEASE_SEC, struct.pack("!I", 3600)),
        (dpkt.dhcp.DHCP_OPT_DOMAIN, b"lab"),
    ]
    msg = dpkt.dhcp.DHCP(
        op=dpkt.dhcp.DHCP_OP_REPLY,
        xid=xid,
        chaddr=mac_bytes(CLIENT) + bytes(10),
        yiaddr=struct.unpack("!I", socket.inet_aton(yiaddr))[0],
        opts=opts,
    )
    udp = dpkt.udp.UDP(sport=67, dport=68, data=bytes(msg))
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(server), dst=b"\xff" * 4, p=17, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(dst=b"\xff" * 6, src=mac_bytes(smac), type=0x0800, data=ip))


def test_dhcp_discover_is_well_formed() -> None:
    eth = dpkt.ethernet.Ethernet(dhcp.build(CLIENT, 0x1234, dpkt.dhcp.DHCPDISCOVER))
    msg = dpkt.dhcp.DHCP(eth.data.data.data)
    opts = dict(msg.opts)
    assert msg.xid == 0x1234 and msg.flags & 0x8000
    assert opts[dpkt.dhcp.DHCP_OPT_MSGTYPE] == bytes([dpkt.dhcp.DHCPDISCOVER])
    assert eth.data.data.dport == 67


def test_dhcp_reply_parsing_and_lease() -> None:
    f = _reply(7, dpkt.dhcp.DHCPACK, "192.0.2.1", "192.0.2.50", dns=("192.0.2.1", "192.0.2.53"))
    r = dhcp.parse_reply(f, 7)
    assert r is not None and r[1] == dpkt.dhcp.DHCPACK and r[2] == SW
    lease = dhcp.lease_from(r[0], r[3], r[2])
    assert lease["ip"] == "192.0.2.50" and lease["prefixlen"] == 24 and lease["router"] == "192.0.2.1"
    assert (
        lease["dns"] == ["192.0.2.1", "192.0.2.53"] and lease["lease_s"] == 3600 and lease["domain"] == "lab"
    )
    assert dhcp.parse_reply(f, 8) is None  # other transaction


def test_dhcp_offer_collection_dedupes_per_server() -> None:
    offers: list = []
    for srv, mac in (("192.0.2.1", SW), ("192.0.2.1", SW), ("10.9.9.1", "b8:27:eb:00:00:99")):
        dhcp._collect_offer(_reply(9, dpkt.dhcp.DHCPOFFER, srv, "192.0.2.77", smac=mac), 9, 0.0, offers)
    assert [o.server_id for o, _, _ in offers] == ["192.0.2.1", "10.9.9.1"]


# ---------------------------------------------------------------- DNS / ICMP / ARP


def test_icmp_checksum_verifies() -> None:
    pkt = ip4.echo_request(0x4242, 3, b"netcaliper")
    assert ip4._checksum(pkt) == 0  # a correct checksum sums to zero


def test_arp_request_frame() -> None:
    eth = dpkt.ethernet.Ethernet(ip4.arp_request(CLIENT, "192.0.2.50", "192.0.2.1"))
    assert eth.dst == b"\xff" * 6 and eth.type == 0x0806
    assert eth.data.op == dpkt.arp.ARP_OP_REQUEST and socket.inet_ntoa(eth.data.tpa) == "192.0.2.1"


async def test_dns_query_against_local_udp_server() -> None:
    import asyncio

    loop = asyncio.get_running_loop()

    class Srv(asyncio.DatagramProtocol):
        def connection_made(self, t: asyncio.BaseTransport) -> None:
            self.t = t

        def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
            q = dpkt.dns.DNS(data)
            q.op = dpkt.dns.DNS_RA | dpkt.dns.DNS_QR
            q.qr = dpkt.dns.DNS_R
            q.an = [
                dpkt.dns.DNS.RR(
                    name=q.qd[0].name, type=1, cls=1, ttl=60, rdata=socket.inet_aton("192.0.2.80")
                )
            ]
            self.t.sendto(bytes(q), addr)  # type: ignore[attr-defined]

    t, _ = await loop.create_datagram_endpoint(Srv, local_addr=("127.0.0.1", 0))
    port = t.get_extra_info("sockname")[1]
    orig = loop.create_datagram_endpoint

    async def patched(factory, remote_addr=None, **kw):  # type: ignore[no-untyped-def]
        return await orig(factory, remote_addr=(remote_addr[0], port), **kw)

    loop.create_datagram_endpoint = patched  # type: ignore[method-assign]
    try:
        r = await ip4.dns_query("127.0.0.1", "example.test")
        ip, ms = await ip4.resolve("example.test", ["127.0.0.1"])
    finally:
        loop.create_datagram_endpoint = orig  # type: ignore[method-assign]
        t.close()
    assert r.ok and r.answers == ["192.0.2.80"] and r.rcode == "NOERROR" and r.ms is not None
    assert ip == "192.0.2.80" and ms is not None
    assert await ip4.resolve("192.0.2.9", []) == ("192.0.2.9", 0.0)


# ---------------------------------------------------------------- IPv6


def test_router_advert_parsing() -> None:
    prefix = (
        bytes([3, 4, 64, 0xC0])
        + struct.pack("!II", 86400, 14400)
        + bytes(4)
        + socket.inet_pton(socket.AF_INET6, "2001:db8:10::")
    )
    rdnss = (
        bytes([25, 3, 0, 0]) + struct.pack("!I", 600) + socket.inet_pton(socket.AF_INET6, "2001:db8:10::53")
    )
    sll = bytes([1, 1]) + mac_bytes(SW)
    mtu = bytes([5, 1, 0, 0]) + struct.pack("!I", 1500)
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0x40, 1800, 0, 0) + sll + prefix + mtu + rdnss
    r = ipv6.parse_ra(ra, "fe80::1", 3.5)
    assert r is not None and r.router == "fe80::1" and r.router_mac == SW
    assert (r.lifetime_s, r.managed, r.other, r.mtu) == (1800, False, True, 1500)
    assert r.prefixes == ["2001:db8:10::/64"] and r.rdnss == ["2001:db8:10::53"]
    assert ipv6.parse_ra(b"\x87" + bytes(20), "fe80::1") is None  # not an RA


def test_dhcp6_solicit_and_advertise() -> None:
    sol = ipv6.build_solicit(0xABCDEF, b"\x00\x03\x00\x01" + mac_bytes(CLIENT))
    assert sol[0] == 1 and sol[1:4] == b"\xab\xcd\xef"
    iaaddr = (
        struct.pack("!HH", 5, 24)
        + socket.inet_pton(socket.AF_INET6, "2001:db8::77")
        + struct.pack("!II", 1, 2)
    )
    ia = struct.pack("!III", 1, 0, 0) + iaaddr
    adv = (
        bytes([2])
        + (0xABCDEF).to_bytes(3, "big")
        + struct.pack("!HH", 2, 4)
        + b"\x00\x01\x02\x03"
        + struct.pack("!HH", 3, len(ia))
        + ia
        + struct.pack("!HH", 23, 16)
        + socket.inet_pton(socket.AF_INET6, "2001:db8::53")
    )
    assert ipv6.parse_advertise(adv, 0xABCDEF) == ("00010203", ["2001:db8::77"], ["2001:db8::53"])
    assert ipv6.parse_advertise(adv, 1) is None


# ---------------------------------------------------------------- 802.1X / link


def test_dot1x_config_escapes_and_rejects_injection() -> None:
    c = dot1x.config("peap", "alice", "s3cret")
    assert 'identity="alice"' in c and "key_mgmt=IEEE8021X" in c and "MSCHAPV2" in c
    for bad in ('a"\n}\nnetwork={', "x\\y", "line\nbreak"):
        with pytest.raises(ValueError):
            dot1x.config("peap", bad, "p")
        with pytest.raises(ValueError):
            dot1x.config("peap", "u", bad)
    with pytest.raises(ValueError):
        dot1x.config("tls", "u", None)


def test_best_common_mode_detects_downshift() -> None:
    a = ["10baseT/Full", "100baseT/Full", "1000baseT/Full"]
    assert best_common_mode(a, ["10baseT/Half", "100baseT/Full"]) == (100, "Full")
    assert best_common_mode(a, a) == (1000, "Full")
    assert best_common_mode(a, []) is None
