# SPDX-License-Identifier: GPL-3.0-only
"""DHCPv4 client over AF_PACKET: precise timing and *every* offer collected (rogue detection).

Never touches system config: the lease is applied separately (see RealNet.apply_lease) and only
inside the test netns.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct

import dpkt
from dpkt import dhcp as d

from .base import DhcpOffer, Lease
from .packets import BROADCAST, ETH_P_IP, RawSocket, mac_bytes, mac_str, now_ms

PARAMS = bytes([1, 3, 6, 15, 26, 28, 42, 51, 54, 58, 59, 119])  # mask router dns domain mtu bcast ntp …


class DhcpError(Exception):
    pass


def _ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", i))


def build(mac: str, xid: int, msgtype: int, extra: list[tuple[int, bytes]] | None = None) -> bytes:
    opts: list[tuple[int, bytes]] = [
        (d.DHCP_OPT_MSGTYPE, bytes([msgtype])),
        (d.DHCP_OPT_PARAM_REQ, PARAMS),
        (d.DHCP_OPT_CLIENT_ID, b"\x01" + mac_bytes(mac)),
        (d.DHCP_OPT_VENDOR_ID, b"netcaliper"),
        *(extra or []),
    ]
    msg = d.DHCP(op=d.DHCP_OP_REQUEST, chaddr=mac_bytes(mac) + b"\x00" * 10, xid=xid, flags=0x8000, opts=opts)
    udp = dpkt.udp.UDP(sport=68, dport=67, data=bytes(msg))
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=b"\x00" * 4, dst=b"\xff" * 4, p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(dst=BROADCAST, src=mac_bytes(mac), type=ETH_P_IP, data=ip))


def parse_reply(frame: bytes, xid: int) -> tuple[d.DHCP, int, str, dict[int, bytes]] | None:
    """(dhcp, msgtype, server MAC, options) if `frame` is a DHCP reply for our transaction."""
    try:
        eth = dpkt.ethernet.Ethernet(frame)
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.udp.UDP) or ip.data.dport != 68:
            return None
        msg = d.DHCP(ip.data.data)
    except (dpkt.UnpackError, struct.error, ValueError):
        return None
    if msg.xid != xid or msg.op != d.DHCP_OP_REPLY:
        return None
    opts = dict(msg.opts)
    mt = opts.get(d.DHCP_OPT_MSGTYPE)
    if not mt:
        return None
    return msg, mt[0], mac_str(eth.src), opts


def _ips(b: bytes | None) -> list[str]:
    return [socket.inet_ntoa(b[i : i + 4]) for i in range(0, len(b or b"") - 3, 4)] if b else []


def lease_from(msg: d.DHCP, opts: dict[int, bytes], server_mac: str) -> dict[str, object]:
    mask = opts.get(d.DHCP_OPT_NETMASK)
    prefix = ipaddress.IPv4Network(f"0.0.0.0/{socket.inet_ntoa(mask)}").prefixlen if mask else 24
    routers = _ips(opts.get(d.DHCP_OPT_ROUTER))
    lease_b = opts.get(d.DHCP_OPT_LEASE_SEC)
    extras: dict[str, str] = {}
    if v := opts.get(d.DHCP_OPT_MTUSIZE):
        extras["mtu"] = str(struct.unpack("!H", v)[0])
    if v := opts.get(42):
        extras["ntp"] = ", ".join(_ips(v))
    if v := opts.get(d.DHCP_OPT_BROADCASTADDR):
        extras["broadcast"] = socket.inet_ntoa(v)
    return {
        "ip": _ip(msg.yiaddr),
        "prefixlen": prefix,
        "router": routers[0] if routers else None,
        "dns": _ips(opts.get(d.DHCP_OPT_DNS_SVRS)),
        "domain": (opts.get(d.DHCP_OPT_DOMAIN) or b"").decode(errors="replace").strip("\x00") or None,
        "lease_s": struct.unpack("!I", lease_b)[0] if lease_b else None,
        "server_id": socket.inet_ntoa(opts[d.DHCP_OPT_SERVER_ID]) if d.DHCP_OPT_SERVER_ID in opts else "",
        "server_mac": server_mac,
        "options": extras,
    }


async def acquire(ifname: str, mac: str, collect_s: float = 2.0, timeout_s: float = 10.0) -> Lease:
    """DISCOVER → collect OFFERs for `collect_s` after the first → REQUEST the first → ACK."""
    xid = random.getrandbits(32)
    with RawSocket(ifname, ETH_P_IP) as sock:
        offers: list[tuple[DhcpOffer, d.DHCP, dict[int, bytes]]] = []
        t0 = now_ms()
        sock.send(build(mac, xid, d.DHCPDISCOVER))
        resent = False
        while not offers:
            elapsed = (now_ms() - t0) / 1000
            if elapsed >= timeout_s:
                raise DhcpError(f"no DHCPOFFER within {timeout_s:.0f} s")
            if not resent and elapsed >= 3.0:  # one retransmit, like real clients
                sock.send(build(mac, xid, d.DHCPDISCOVER))
                resent = True
            frame = await sock.recv(min(timeout_s - elapsed, 3.0 if not resent else timeout_s))
            if frame is not None:
                _collect_offer(frame, xid, t0, offers)
        # More offers within the window = more than one DHCP server answering (rogue candidates).
        for _, frame in await sock.collect(collect_s, lambda f: parse_reply(f, xid) is not None):
            _collect_offer(frame, xid, t0, offers)

        chosen, cmsg, copts = offers[0]
        req_extra = [
            (d.DHCP_OPT_REQ_IP, struct.pack("!I", cmsg.yiaddr)),
            (d.DHCP_OPT_SERVER_ID, copts[d.DHCP_OPT_SERVER_ID]),
        ]
        t1 = now_ms()
        sock.send(build(mac, xid, d.DHCPREQUEST, req_extra))
        while True:
            left = timeout_s - (now_ms() - t1) / 1000
            if left <= 0:
                raise DhcpError("no DHCPACK")
            frame = await sock.recv(left)
            if frame is None:
                raise DhcpError("no DHCPACK")
            r = parse_reply(frame, xid)
            if r is None:
                continue
            msg, mt, smac, opts = r
            if opts.get(d.DHCP_OPT_SERVER_ID) not in (None, copts[d.DHCP_OPT_SERVER_ID]):
                continue  # another server's reply (e.g. a rogue NAKing a REQUEST that wasn't for it)
            if mt == d.DHCPNAK:
                raise DhcpError(f"DHCPNAK from {chosen.server_id}")
            if mt == d.DHCPACK:
                t2 = now_ms()
                return Lease.model_validate(
                    {
                        **lease_from(msg, opts, smac),
                        "offers": [o for o, _, _ in offers],
                        "discover_to_offer_ms": round(chosen.offer_ms, 2),
                        "request_to_ack_ms": round(t2 - t1, 2),
                        "total_ms": round(t2 - t0, 2),
                    }
                )


def _collect_offer(
    frame: bytes, xid: int, t0: float, offers: list[tuple[DhcpOffer, d.DHCP, dict[int, bytes]]]
) -> None:
    r = parse_reply(frame, xid)
    if r is None or r[1] != d.DHCPOFFER or d.DHCP_OPT_SERVER_ID not in r[3]:
        return
    msg, _, smac, opts = r
    sid = socket.inet_ntoa(opts[d.DHCP_OPT_SERVER_ID])
    if any(o.server_id == sid and o.server_mac == smac for o, _, _ in offers):
        return
    offers.append(
        (
            DhcpOffer(
                server_id=sid, server_mac=smac, yiaddr=_ip(msg.yiaddr), offer_ms=round(now_ms() - t0, 2)
            ),
            msg,
            opts,
        )
    )
