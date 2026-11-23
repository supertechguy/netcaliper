# SPDX-License-Identifier: GPL-3.0-only
"""IPv6: Router Solicitation → Router Advertisements (all routers answering = rogue-RA check) and a
DHCPv6 Solicit → Advertise probe. The test netns keeps accept_ra/autoconf off: we observe, the
kernel doesn't configure itself from what it hears."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import time

from .base import Dhcp6Result, RouterAdvert
from .packets import mac_str, now_ms

ALL_ROUTERS = "ff02::2"
ALL_DHCP = "ff02::1:2"


def parse_ra(data: bytes, src: str, t_ms: float | None = None) -> RouterAdvert | None:
    """`data` is the ICMPv6 message (raw ICMPv6 sockets strip the IPv6 header)."""
    if len(data) < 16 or data[0] != 134:
        return None
    flags = data[5]
    ra = RouterAdvert(
        router=src,
        lifetime_s=struct.unpack("!H", data[6:8])[0],
        managed=bool(flags & 0x80),
        other=bool(flags & 0x40),
        ms=t_ms,
    )
    i = 16
    while i + 2 <= len(data):
        typ, ln = data[i], data[i + 1] * 8
        if ln == 0:
            break
        opt = data[i : i + ln]
        i += ln
        if typ == 1 and len(opt) >= 8:
            ra.router_mac = mac_str(opt[2:8])
        elif typ == 3 and len(opt) >= 32:
            plen = opt[2]
            ra.prefixes.append(f"{socket.inet_ntop(socket.AF_INET6, opt[16:32])}/{plen}")
        elif typ == 5 and len(opt) >= 8:
            ra.mtu = struct.unpack("!I", opt[4:8])[0]
        elif typ == 25 and len(opt) >= 24:
            ra.rdnss += [
                socket.inet_ntop(socket.AF_INET6, opt[j : j + 16]) for j in range(8, len(opt) - 15, 16)
            ]
    return ra


async def router_solicit(ifname: str, timeout_s: float = 4.0) -> list[RouterAdvert]:
    loop = asyncio.get_running_loop()
    idx = socket.if_nametoindex(ifname)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    # Receive RAs: join all-nodes is implicit; just make sure we see type 134.
    found: dict[str, RouterAdvert] = {}
    try:
        t0 = now_ms()
        rs = struct.pack("!BBHI", 133, 0, 0, 0)  # kernel fills the ICMPv6 checksum
        await loop.sock_sendto(sock, rs, (ALL_ROUTERS, 0, 0, idx))
        deadline = time.monotonic() + timeout_s
        while (left := deadline - time.monotonic()) > 0:
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), left)
            except TimeoutError:
                break
            src = str(addr[0]).split("%")[0]
            ra = parse_ra(data, src, round(now_ms() - t0, 2))
            if ra and src not in found:
                found[src] = ra
    finally:
        sock.close()
    return list(found.values())


def _opt(code: int, value: bytes) -> bytes:
    return struct.pack("!HH", code, len(value)) + value


def build_solicit(xid: int, duid: bytes) -> bytes:
    ia_na = struct.pack("!III", 1, 0, 0)  # IAID, T1, T2
    return (
        bytes([1])
        + xid.to_bytes(3, "big")
        + _opt(1, duid)  # client id
        + _opt(3, ia_na)
        + _opt(6, struct.pack("!HH", 23, 24))  # ORO: DNS servers, domain list
        + _opt(8, b"\x00\x00")  # elapsed time
    )


def parse_advertise(data: bytes, xid: int) -> tuple[str | None, list[str], list[str]] | None:
    if len(data) < 4 or data[0] != 2 or int.from_bytes(data[1:4], "big") != xid:
        return None
    server, addrs, dns = None, [], []
    i = 4
    while i + 4 <= len(data):
        code, ln = struct.unpack("!HH", data[i : i + 4])
        v = data[i + 4 : i + 4 + ln]
        i += 4 + ln
        if code == 2:
            server = v.hex()
        elif code == 3 and len(v) >= 12:
            j = 12
            while j + 4 <= len(v):
                sc, sl = struct.unpack("!HH", v[j : j + 4])
                if sc == 5 and sl >= 24:
                    addrs.append(socket.inet_ntop(socket.AF_INET6, v[j + 4 : j + 20]))
                j += 4 + sl
        elif code == 23:
            dns += [socket.inet_ntop(socket.AF_INET6, v[k : k + 16]) for k in range(0, len(v) - 15, 16)]
    return server, addrs, dns


async def dhcp6_probe(ifname: str, mac: str, timeout_s: float = 5.0) -> Dhcp6Result:
    loop = asyncio.get_running_loop()
    idx = socket.if_nametoindex(ifname)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    xid = int.from_bytes(os.urandom(3), "big")
    duid = b"\x00\x03\x00\x01" + bytes.fromhex(mac.replace(":", ""))  # DUID-LL
    servers: dict[str, tuple[list[str], list[str], float]] = {}
    try:
        sock.bind(("::", 546, 0, idx))
        t0 = now_ms()
        await loop.sock_sendto(sock, build_solicit(xid, duid), (ALL_DHCP, 547, 0, idx))
        deadline = time.monotonic() + timeout_s
        while (left := deadline - time.monotonic()) > 0:
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 4096), left)
            except TimeoutError:
                break
            r = parse_advertise(data, xid)
            if r and r[0] and r[0] not in servers:
                servers[r[0]] = (r[1], r[2], round(now_ms() - t0, 2))
                if len(servers) == 1:
                    deadline = min(deadline, time.monotonic() + 1.0)  # brief window for more servers
    except OSError as e:
        return Dhcp6Result(ok=False, error=str(e))
    finally:
        sock.close()
    if not servers:
        return Dhcp6Result(ok=False, error="no DHCPv6 Advertise")
    sid, (addrs, dns, ms) = next(iter(servers.items()))
    return Dhcp6Result(
        ok=True, server_duid=sid, addresses=addrs, dns=dns, advertise_ms=ms, servers=len(servers)
    )
