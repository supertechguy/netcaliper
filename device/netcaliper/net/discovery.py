# SPDX-License-Identifier: GPL-3.0-only
"""LLDP / CDP / EDP: passive parsers + frame builders (builders drive the netns integration tests,
standing in for a switch). Listening is purely passive — nothing is transmitted."""

from __future__ import annotations

import asyncio
import socket
import struct

from .base import Neighbor
from .packets import ETH_P_802_2, ETH_P_LLDP, RawSocket, mac_bytes, mac_str

LLDP_MCAST = ["01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00"]
CDP_MCAST = "01:00:0c:cc:cc:cc"
EDP_MCAST = "00:e0:2b:00:00:00"
_SNAP_CDP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
_SNAP_EDP = b"\xaa\xaa\x03\x00\xe0\x2b\x00\xbb"

LLDP_CAPS = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"]
CDP_CAPS = {
    0x01: "router",
    0x02: "bridge",
    0x04: "sr-bridge",
    0x08: "switch",
    0x10: "host",
    0x20: "igmp",
    0x40: "repeater",
    0x80: "phone",
}


def _text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace").strip("\x00").strip()


# ---------------------------------------------------------------- LLDP


def _id(subtype: int, v: bytes) -> str:
    if subtype in (3, 4) and len(v) == 6:  # MAC address
        return mac_str(v)
    if subtype == 5 and v[:1] == b"\x01" and len(v) == 5:  # network address, IPv4
        return socket.inet_ntoa(v[1:])
    return _text(v)


def parse_lldp(frame: bytes) -> Neighbor | None:
    if len(frame) < 16 or frame[12:14] != b"\x88\xcc":
        return None
    n = Neighbor(protocol="lldp", src_mac=mac_str(frame[6:12]))
    i, data = 0, frame[14:]
    while i + 2 <= len(data):
        hdr = struct.unpack("!H", data[i : i + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = data[i + 2 : i + 2 + ln]
        i += 2 + ln
        if t == 0:
            break
        if t == 1 and v:
            n.chassis_id = _id(v[0], v[1:])
        elif t == 2 and v:
            n.port_id = _id(v[0], v[1:])
        elif t == 3 and len(v) >= 2:
            n.ttl_s = struct.unpack("!H", v[:2])[0]
        elif t == 4:
            n.port_description = _text(v)
        elif t == 5:
            n.system_name = _text(v)
        elif t == 6:
            n.system_description = _text(v)
        elif t == 7 and len(v) >= 4:
            enabled = struct.unpack("!H", v[2:4])[0]
            n.capabilities = [c for b, c in enumerate(LLDP_CAPS) if enabled & (1 << b)]
        elif t == 8 and len(v) >= 2:
            alen = v[0]
            if v[1] == 1 and alen == 5:
                n.mgmt_addresses.append(socket.inet_ntoa(v[2:6]))
            elif v[1] == 2 and alen == 17:
                n.mgmt_addresses.append(socket.inet_ntop(socket.AF_INET6, v[2:18]))
        elif t == 127 and len(v) >= 4:
            _lldp_org(n, v[:3], v[3], v[4:])
    return n


def _lldp_org(n: Neighbor, oui: bytes, sub: int, v: bytes) -> None:
    if oui == b"\x00\x80\xc2":  # IEEE 802.1
        if sub == 1 and len(v) >= 2:
            n.native_vlan = struct.unpack("!H", v[:2])[0] or None
        elif sub == 3 and len(v) >= 2:
            vid = struct.unpack("!H", v[:2])[0]
            if vid not in n.vlans:
                n.vlans.append(vid)
    elif oui == b"\x00\x12\x0f":  # IEEE 802.3
        if sub == 1 and len(v) >= 5:
            mau = struct.unpack("!H", v[3:5])[0]
            n.duplex = "full" if mau in (16, 30, 54, 110) else n.duplex  # common *-FD MAU types
        elif sub == 2 and len(v) >= 3:
            n.poe["class"] = str(max(0, v[2] - 1))
            if len(v) >= 12:
                n.poe["requested_w"] = f"{struct.unpack('!H', v[8:10])[0] / 10:.1f}"
                n.poe["allocated_w"] = f"{struct.unpack('!H', v[10:12])[0] / 10:.1f}"
    elif oui == b"\x00\x12\xbb":  # LLDP-MED
        if sub == 2 and len(v) >= 4:
            app, policy = v[0], int.from_bytes(v[1:4], "big")
            vid = (policy >> 9) & 0xFFF
            if app == 1 and vid:
                n.voice_vlan = vid
        elif sub == 4 and len(v) >= 3:
            n.poe["med_w"] = f"{struct.unpack('!H', v[1:3])[0] / 10:.1f}"


def _tlv(t: int, v: bytes) -> bytes:
    return struct.pack("!H", (t << 9) | len(v)) + v


def build_lldp(
    src_mac: str,
    system_name: str,
    port_id: str,
    *,
    port_description: str = "",
    native_vlan: int | None = None,
    voice_vlan: int | None = None,
    mgmt_ip: str | None = None,
    ttl: int = 120,
    caps: tuple[str, ...] = ("bridge",),
) -> bytes:
    capbits = sum(1 << LLDP_CAPS.index(c) for c in caps)
    body = (
        _tlv(1, b"\x04" + mac_bytes(src_mac))
        + _tlv(2, b"\x05" + port_id.encode())
        + _tlv(3, struct.pack("!H", ttl))
        + (_tlv(4, port_description.encode()) if port_description else b"")
        + _tlv(5, system_name.encode())
        + _tlv(7, struct.pack("!HH", capbits, capbits))
    )
    if mgmt_ip:
        body += _tlv(8, b"\x05\x01" + socket.inet_aton(mgmt_ip) + b"\x02\x00\x00\x00\x00\x00")
    if native_vlan:
        body += _tlv(127, b"\x00\x80\xc2\x01" + struct.pack("!H", native_vlan))
    if voice_vlan:
        body += _tlv(127, b"\x00\x12\xbb\x02\x01" + (voice_vlan << 9 | 5 << 6 | 46).to_bytes(3, "big"))
    return mac_bytes(LLDP_MCAST[0]) + mac_bytes(src_mac) + b"\x88\xcc" + body + _tlv(0, b"")


# ---------------------------------------------------------------- CDP


def _cdp_addrs(v: bytes) -> list[str]:
    out: list[str] = []
    if len(v) < 4:
        return out
    count, i = struct.unpack("!I", v[:4])[0], 4
    for _ in range(count):
        if i + 2 > len(v):
            break
        plen = v[i + 1]
        proto = v[i + 2 : i + 2 + plen]
        i += 2 + plen
        alen = struct.unpack("!H", v[i : i + 2])[0]
        addr = v[i + 2 : i + 2 + alen]
        i += 2 + alen
        if proto == b"\xcc" and alen == 4:
            out.append(socket.inet_ntoa(addr))
    return out


def parse_cdp(frame: bytes) -> Neighbor | None:
    if frame[:6] != mac_bytes(CDP_MCAST) or frame[14:22] != _SNAP_CDP:
        return None
    n = Neighbor(protocol="cdp", src_mac=mac_str(frame[6:12]))
    length = struct.unpack("!H", frame[12:14])[0]
    data = frame[22 : 14 + length] if 0 < length <= len(frame) - 14 else frame[22:]
    if len(data) < 4:
        return None
    n.ttl_s = data[1]
    i = 4
    while i + 4 <= len(data):
        t, ln = struct.unpack("!HH", data[i : i + 4])
        if ln < 4:
            break
        v = data[i + 4 : i + ln]
        i += ln
        if t == 0x01:
            n.system_name = _text(v)
            n.chassis_id = n.system_name
        elif t == 0x02:
            n.mgmt_addresses += [a for a in _cdp_addrs(v) if a not in n.mgmt_addresses]
        elif t == 0x03:
            n.port_id = _text(v)
        elif t == 0x04 and len(v) >= 4:
            bits = struct.unpack("!I", v[:4])[0]
            n.capabilities = [name for b, name in CDP_CAPS.items() if bits & b]
        elif t == 0x05:
            n.system_description = _text(v)
        elif t == 0x06:
            n.platform = _text(v)
        elif t == 0x0A and len(v) >= 2:
            n.native_vlan = struct.unpack("!H", v[:2])[0]
        elif t == 0x0B and v:
            n.duplex = "full" if v[0] else "half"
        elif t == 0x0E and len(v) >= 3:
            n.voice_vlan = struct.unpack("!H", v[1:3])[0]
        elif t == 0x10 and len(v) >= 2:
            n.poe["consumption_w"] = f"{struct.unpack('!H', v[:2])[0] / 1000:.1f}"
        elif t == 0x16:
            n.mgmt_addresses += [a for a in _cdp_addrs(v) if a not in n.mgmt_addresses]
    return n


def _cdp_tlv(t: int, v: bytes) -> bytes:
    return struct.pack("!HH", t, len(v) + 4) + v


def build_cdp(
    src_mac: str,
    device_id: str,
    port_id: str,
    *,
    platform: str = "",
    native_vlan: int | None = None,
    voice_vlan: int | None = None,
    mgmt_ip: str | None = None,
    ttl: int = 180,
) -> bytes:
    body = _cdp_tlv(0x01, device_id.encode()) + _cdp_tlv(0x03, port_id.encode())
    body += _cdp_tlv(0x04, struct.pack("!I", 0x08 | 0x20))
    if platform:
        body += _cdp_tlv(0x06, platform.encode())
    if mgmt_ip:
        body += _cdp_tlv(0x02, struct.pack("!I", 1) + b"\x01\x01\xcc\x00\x04" + socket.inet_aton(mgmt_ip))
    if native_vlan:
        body += _cdp_tlv(0x0A, struct.pack("!H", native_vlan))
    body += _cdp_tlv(0x0B, b"\x01")
    if voice_vlan:
        body += _cdp_tlv(0x0E, b"\x01" + struct.pack("!H", voice_vlan))
    cdp = bytes([2, ttl]) + b"\x00\x00" + body
    payload = _SNAP_CDP + cdp
    return mac_bytes(CDP_MCAST) + mac_bytes(src_mac) + struct.pack("!H", len(payload)) + payload


# ---------------------------------------------------------------- EDP (Extreme)


def parse_edp(frame: bytes) -> Neighbor | None:
    if frame[:6] != mac_bytes(EDP_MCAST) or frame[14:22] != _SNAP_EDP or len(frame) < 22 + 16:
        return None
    n = Neighbor(protocol="edp", src_mac=mac_str(frame[6:12]))
    hdr = frame[22:38]
    n.chassis_id = mac_str(hdr[10:16])
    i, data = 0, frame[38:]
    while i + 4 <= len(data) and data[i] == 0x99:
        t, ln = data[i + 1], struct.unpack("!H", data[i + 2 : i + 4])[0]
        if ln < 4:
            break
        v = data[i + 4 : i + ln]
        i += ln
        if t == 0:
            break
        if t == 1:
            n.system_name = _text(v)
        elif t == 2 and len(v) >= 4:
            slot, port = struct.unpack("!HH", v[:4])
            n.port_id = f"{slot + 1}:{port + 1}"
            if len(v) >= 16:
                n.system_description = "ExtremeXOS " + ".".join(str(b) for b in v[12:16])
        elif t == 5 and len(v) >= 12:
            vid = struct.unpack("!H", v[2:4])[0]
            if vid not in n.vlans:
                n.vlans.append(vid)
            ip = v[8:12]
            if ip != b"\x00\x00\x00\x00" and socket.inet_ntoa(ip) not in n.mgmt_addresses:
                n.mgmt_addresses.append(socket.inet_ntoa(ip))
    return n


def build_edp(src_mac: str, name: str, slot: int, port: int, vlans: tuple[int, ...] = ()) -> bytes:
    tlvs = bytes([0x99, 1]) + struct.pack("!H", len(name) + 5) + name.encode() + b"\x00"
    info = struct.pack("!HH", slot - 1, port - 1) + bytes(8) + bytes([30, 1, 0, 0])
    tlvs += bytes([0x99, 2]) + struct.pack("!H", len(info) + 4) + info
    for vid in vlans:
        v = b"\x00\x00" + struct.pack("!H", vid) + bytes(8)
        tlvs += bytes([0x99, 5]) + struct.pack("!H", len(v) + 4) + v
    tlvs += bytes([0x99, 0, 0, 4])
    hdr = (
        bytes([1, 0])
        + struct.pack("!H", 16 + len(tlvs))
        + b"\x00\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + mac_bytes(src_mac)
    )
    payload = _SNAP_EDP + hdr + tlvs
    return mac_bytes(EDP_MCAST) + mac_bytes(src_mac) + struct.pack("!H", len(payload)) + payload


# ---------------------------------------------------------------- listener


def parse_any(frame: bytes) -> Neighbor | None:
    return parse_lldp(frame) or parse_cdp(frame) or parse_edp(frame)


async def listen(ifname: str, duration_s: float) -> list[Neighbor]:
    """Collect announcements for `duration_s` (LLDP: 30 s default interval; CDP: 60 s). Returns
    early once both LLDP and CDP have been heard. Newest announcement per (protocol, sender) wins."""
    found: dict[tuple[str, str], Neighbor] = {}
    done = asyncio.Event()

    async def run(sock: RawSocket) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration_s
        while not done.is_set() and (left := deadline - loop.time()) > 0:
            frame = await sock.recv(left)
            if frame is None:
                break
            n = parse_any(frame)
            if n is not None:
                found[(n.protocol, n.src_mac)] = n
                if {"lldp", "cdp"} <= {p for p, _ in found}:
                    done.set()

    with (
        RawSocket(ifname, ETH_P_LLDP, multicast=LLDP_MCAST) as a,
        RawSocket(ifname, ETH_P_802_2, multicast=[CDP_MCAST, EDP_MCAST]) as b,
    ):
        await asyncio.gather(run(a), run(b))
    return sorted(found.values(), key=lambda n: (n.protocol, n.src_mac))
