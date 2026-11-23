# SPDX-License-Identifier: GPL-3.0-only
"""DNS, ICMP echo and ARP — our own packets, so timings are ours and nothing uses the host's
resolver (inside the test netns /etc/resolv.conf belongs to the management network)."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import os
import random
import socket
import statistics
import struct
import time

import dpkt

from .base import ArpResult, DnsResult, PingResult
from .packets import BROADCAST, ETH_P_ARP, RawSocket, mac_bytes, mac_str, now_ms

RTYPES = {"A": dpkt.dns.DNS_A, "AAAA": dpkt.dns.DNS_AAAA, "MX": dpkt.dns.DNS_MX, "TXT": dpkt.dns.DNS_TXT}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


# ---------------------------------------------------------------- DNS


class _Udp(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.q: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        self.q.put_nowait(data)


async def dns_query(server: str, name: str, rtype: str = "A", timeout_s: float = 3.0) -> DnsResult:
    qid = random.getrandbits(16)
    q = dpkt.dns.DNS(id=qid, op=dpkt.dns.DNS_RD, qd=[dpkt.dns.DNS.Q(name=name, type=RTYPES.get(rtype, 1))])
    loop = asyncio.get_running_loop()
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    transport, proto = await loop.create_datagram_endpoint(_Udp, remote_addr=(server, 53), family=fam)
    try:
        t0 = now_ms()
        transport.sendto(bytes(q))
        deadline = time.monotonic() + timeout_s
        while (left := deadline - time.monotonic()) > 0:
            try:
                data = await asyncio.wait_for(proto.q.get(), left)
            except TimeoutError:
                break
            try:
                r = dpkt.dns.DNS(data)
            except (dpkt.UnpackError, struct.error):
                continue
            if r.id != qid:
                continue
            ms = round(now_ms() - t0, 2)
            answers = []
            for rr in r.an:
                if rr.type == dpkt.dns.DNS_A:
                    answers.append(socket.inet_ntop(socket.AF_INET, rr.rdata))
                elif rr.type == dpkt.dns.DNS_AAAA:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rr.rdata))
                elif rr.type == dpkt.dns.DNS_CNAME:
                    answers.append(f"CNAME {rr.cname}")
            rcode = RCODES.get(r.rcode, str(r.rcode))
            return DnsResult(
                server=server,
                name=name,
                rtype=rtype,
                ok=rcode == "NOERROR" and bool(answers),
                answers=answers,
                rcode=rcode,
                ms=ms,
            )
        return DnsResult(server=server, name=name, rtype=rtype, ok=False, error="timeout")
    except OSError as e:
        return DnsResult(server=server, name=name, rtype=rtype, ok=False, error=str(e))
    finally:
        transport.close()


async def resolve(name: str, dns: list[str], timeout_s: float = 3.0) -> tuple[str | None, float | None]:
    """First A record via the test network's DNS servers. Literal IPs pass straight through."""
    with contextlib.suppress(OSError):
        socket.inet_pton(socket.AF_INET, name)
        return name, 0.0
    for server in dns:
        r = await dns_query(server, name, "A", timeout_s)
        ips = [a for a in r.answers if not a.startswith("CNAME")]
        if r.ok and ips:
            return ips[0], r.ms
    return None, None


# ---------------------------------------------------------------- ICMP


def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return int(~s & 0xFFFF)


def echo_request(ident: int, seq: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), ident, seq) + payload


async def ping(
    ifname: str, target: str, count: int = 5, interval_s: float = 0.2, timeout_s: float = 1.0
) -> PingResult:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
    sock.setblocking(False)
    ident = (os.getpid() ^ random.getrandbits(16)) & 0xFFFF
    rtts: list[float] = []
    sent_at: dict[int, float] = {}
    try:
        for seq in range(1, count + 1):
            sent_at[seq] = now_ms()
            await loop.sock_sendto(sock, echo_request(ident, seq, b"netcaliper" + bytes(22)), (target, 0))
            deadline = time.monotonic() + timeout_s
            while (left := deadline - time.monotonic()) > 0:
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 2048), left)
                except TimeoutError:
                    break
                ihl = (data[0] & 0x0F) * 4
                typ, _, _, rid, rseq = struct.unpack("!BBHHH", data[ihl : ihl + 8])
                if typ == 0 and rid == ident and rseq == seq:
                    rtts.append(round(now_ms() - sent_at[seq], 3))
                    break
            if seq < count:
                await asyncio.sleep(interval_s)
    finally:
        sock.close()
    jitter = statistics.fmean(abs(a - b) for a, b in itertools.pairwise(rtts)) if len(rtts) > 1 else None
    return PingResult(
        target=target,
        sent=count,
        received=len(rtts),
        rtt_min=min(rtts) if rtts else None,
        rtt_avg=round(statistics.fmean(rtts), 3) if rtts else None,
        rtt_max=max(rtts) if rtts else None,
        jitter=round(jitter, 3) if jitter is not None else None,
    )


# ---------------------------------------------------------------- ARP


def arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    arp = dpkt.arp.ARP(
        op=dpkt.arp.ARP_OP_REQUEST,
        sha=mac_bytes(src_mac),
        spa=socket.inet_aton(src_ip),
        tha=b"\x00" * 6,
        tpa=socket.inet_aton(target_ip),
    )
    return bytes(dpkt.ethernet.Ethernet(dst=BROADCAST, src=mac_bytes(src_mac), type=ETH_P_ARP, data=arp))


async def arp(ifname: str, src_mac: str, src_ip: str, target_ip: str, timeout_s: float = 2.0) -> ArpResult:
    tpa = socket.inet_aton(target_ip)

    def is_reply(frame: bytes) -> bool:
        try:
            a = dpkt.ethernet.Ethernet(frame).data
        except (dpkt.UnpackError, struct.error):
            return False
        return isinstance(a, dpkt.arp.ARP) and a.op == dpkt.arp.ARP_OP_REPLY and a.spa == tpa

    with RawSocket(ifname, ETH_P_ARP) as sock:
        t0 = now_ms()
        sock.send(arp_request(src_mac, src_ip, target_ip))
        got = await sock.collect(timeout_s, is_reply, stop_after=1)
    if not got:
        return ArpResult(ip=target_ip, mac=None, ms=None)
    t, frame = got[0]
    return ArpResult(ip=target_ip, mac=mac_str(dpkt.ethernet.Ethernet(frame).data.sha), ms=round(t - t0, 2))
