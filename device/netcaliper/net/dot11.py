# SPDX-License-Identifier: GPL-3.0-only
"""Monitor-mode frames: radiotap + 802.11 header parsing. Headers only — we never look into frame
bodies except the information elements of beacons/probes (what APs broadcast to everyone) and the
SSID a client probes for. Data payloads are not read, kept or forwarded."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .packets import mac_str

# (size, alignment) for radiotap fields 0..14, in bit order
_RT_FIELDS = [
    (8, 8),
    (1, 1),
    (1, 1),
    (4, 2),
    (2, 1),
    (1, 1),
    (1, 1),
    (2, 2),
    (2, 2),
    (2, 2),
    (1, 1),
    (1, 1),
    (1, 1),
    (1, 1),
    (2, 2),
]
T_MGMT, T_CTRL, T_DATA = 0, 1, 2
ST_ASSOC_REQ, ST_PROBE_REQ, ST_PROBE_RESP, ST_BEACON, ST_DISASSOC, ST_DEAUTH = 0, 4, 5, 8, 10, 12


@dataclass
class Frame:
    freq: int | None = None
    signal_dbm: int | None = None
    ftype: int = 0
    subtype: int = 0
    to_ds: bool = False
    from_ds: bool = False
    addr1: str | None = None
    addr2: str | None = None  # transmitter, when present
    addr3: str | None = None
    body: bytes = field(default=b"", repr=False)  # mgmt frame body only (IEs live here)


def parse_radiotap(pkt: bytes) -> tuple[int, int | None, int | None, bool] | None:
    """(header length, freq MHz, dBm signal, has FCS)."""
    if len(pkt) < 8 or pkt[0] != 0:
        return None
    hlen = struct.unpack_from("<H", pkt, 2)[0]
    if hlen > len(pkt):
        return None
    present = [struct.unpack_from("<I", pkt, 4)[0]]
    off = 8
    while present[-1] & 0x80000000 and off + 4 <= hlen:
        present.append(struct.unpack_from("<I", pkt, off)[0])
        off += 4
    p = present[0]
    freq = signal = None
    fcs = False
    for bit, (size, align) in enumerate(_RT_FIELDS):
        if not p & (1 << bit):
            continue
        off = (off + align - 1) & ~(align - 1)
        if off + size > hlen:
            break
        if bit == 1:
            fcs = bool(pkt[off] & 0x10)
        elif bit == 3:
            freq = struct.unpack_from("<H", pkt, off)[0]
        elif bit == 5:
            signal = struct.unpack_from("<b", pkt, off)[0]
        off += size
        if bit >= 6:
            break
    return hlen, freq, signal, fcs


def parse(pkt: bytes) -> Frame | None:
    rt = parse_radiotap(pkt)
    if rt is None:
        return None
    hlen, freq, signal, fcs = rt
    d = pkt[hlen : len(pkt) - 4] if fcs else pkt[hlen:]
    if len(d) < 10:
        return None
    fc0, fc1 = d[0], d[1]
    f = Frame(
        freq=freq,
        signal_dbm=signal,
        ftype=(fc0 >> 2) & 3,
        subtype=(fc0 >> 4) & 0xF,
        to_ds=bool(fc1 & 1),
        from_ds=bool(fc1 & 2),
        addr1=mac_str(d[4:10]),
    )
    if f.ftype == T_CTRL:
        # RTS (11), PS-Poll (10), BlockAck(Req) (8/9) carry a transmitter address; CTS/ACK don't.
        if f.subtype in (8, 9, 10, 11) and len(d) >= 16:
            f.addr2 = mac_str(d[10:16])
        return f
    if len(d) < 24:
        return None
    f.addr2, f.addr3 = mac_str(d[10:16]), mac_str(d[16:22])
    if f.ftype == T_MGMT:
        f.body = d[24:]
    return f


def is_unicast(mac: str | None) -> bool:
    return mac is not None and not int(mac[:2], 16) & 1


def is_local(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 2)


def data_roles(f: Frame) -> tuple[str | None, str | None]:
    """(client, bssid) for a data frame, by the DS bits; (None, None) for WDS/IBSS."""
    if f.to_ds and not f.from_ds:
        return f.addr2, f.addr1
    if f.from_ds and not f.to_ds:
        return f.addr1, f.addr2
    return None, None


# ---------------------------------------------------------------- builders (tests / emulation)


def radiotap(freq: int, signal: int) -> bytes:
    """Minimal header: flags, channel, dBm signal."""
    present = (1 << 1) | (1 << 3) | (1 << 5)
    body = bytes([0]) + b"\x00" + struct.pack("<HH", freq, 0x00A0) + struct.pack("<b", signal)
    return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + body


def mgmt(subtype: int, da: bytes, sa: bytes, bssid: bytes, body: bytes) -> bytes:
    return bytes([subtype << 4, 0]) + b"\x00\x00" + da + sa + bssid + b"\x00\x00" + body


def data(to_ds: bool, a1: bytes, a2: bytes, a3: bytes) -> bytes:
    fc1 = 1 if to_ds else 2
    return bytes([0x08, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00"
