# SPDX-License-Identifier: GPL-3.0-only
"""Minimal nl80211 client over generic netlink: trigger scan, dump scan results (with raw IEs), survey.

Own code on a raw NETLINK_GENERIC socket (no pyroute2): we only need a handful of commands, and the
raw information elements — `iw` prints a lossy human rendering of them. Constants from
<linux/nl80211.h>. Mode/channel changes go through `iw` (rare, and simpler to audit).
"""

from __future__ import annotations

import asyncio
import errno
import itertools
import os
import socket
import struct
import time
from typing import Any

NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_DUMP = 0x1, 0x2, 0x4, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
GENL_ID_CTRL, CTRL_CMD_GETFAMILY = 0x10, 3
CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_MCAST_GROUPS = 1, 2, 7

CMD_GET_SCAN, CMD_TRIGGER_SCAN, CMD_NEW_SCAN_RESULTS, CMD_SCAN_ABORTED, CMD_GET_SURVEY = 32, 33, 34, 35, 50
ATTR_IFINDEX, ATTR_SCAN_FREQUENCIES, ATTR_SCAN_SSIDS, ATTR_BSS, ATTR_SURVEY_INFO = 3, 44, 45, 47, 84
BSS_BSSID, BSS_FREQUENCY, BSS_BEACON_INTERVAL, BSS_CAPABILITY = 1, 2, 4, 5
BSS_INFORMATION_ELEMENTS, BSS_SIGNAL_MBM, BSS_STATUS, BSS_SEEN_MS_AGO, BSS_BEACON_IES = 6, 7, 9, 10, 11
BSS_PARENT_BSSID, BSS_MLD_ADDR = 18, 22
SURVEY_FREQUENCY, SURVEY_NOISE, SURVEY_IN_USE, SURVEY_TIME, SURVEY_TIME_BUSY = 1, 2, 3, 4, 5


class NlError(OSError):
    pass


def nla(t: int, payload: bytes) -> bytes:
    ln = 4 + len(payload)
    return struct.pack("=HH", ln, t) + payload + b"\x00" * ((4 - ln % 4) % 4)


def nla_nested(t: int, items: list[bytes]) -> bytes:
    return nla(t | 0x8000, b"".join(items))


def parse_attrs(data: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(data):
        ln, t = struct.unpack_from("=HH", data, i)
        if ln < 4:
            break
        out[t & 0x3FFF] = data[i + 4 : i + ln]
        i += (ln + 3) & ~3
    return out


def parse_attr_list(data: bytes) -> list[bytes]:
    """Nested arrays: the attribute types are indices, keep order."""
    out: list[bytes] = []
    i = 0
    while i + 4 <= len(data):
        ln, _ = struct.unpack_from("=HH", data, i)
        if ln < 4:
            break
        out.append(data[i + 4 : i + ln])
        i += (ln + 3) & ~3
    return out


def u32(b: bytes | None) -> int | None:
    return struct.unpack("=I", b[:4])[0] if b and len(b) >= 4 else None


def u64(b: bytes | None) -> int | None:
    return struct.unpack("=Q", b[:8])[0] if b and len(b) >= 8 else None


class GenlSocket:
    _seq = itertools.count(int(time.time()) & 0xFFFF)

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.sock.bind((0, 0))
        self.sock.setblocking(False)

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> GenlSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def join(self, group: int) -> None:
        self.sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)

    def send(self, family: int, cmd: int, attrs: bytes, flags: int) -> int:
        seq = next(self._seq)
        payload = struct.pack("=BBH", cmd, 1, 0) + attrs
        hdr = struct.pack("=IHHII", 16 + len(payload), family, flags | NLM_F_REQUEST, seq, 0)
        self.sock.send(hdr + payload)
        return seq

    async def recv(self, timeout: float) -> list[tuple[int, int, int, bytes]]:
        """[(type, flags, seq, payload)] from one datagram."""
        loop = asyncio.get_running_loop()
        data = await asyncio.wait_for(loop.sock_recv(self.sock, 1 << 18), timeout)
        out = []
        i = 0
        while i + 16 <= len(data):
            ln, typ, flags, seq, _ = struct.unpack_from("=IHHII", data, i)
            if ln < 16:
                break
            out.append((typ, flags, seq, data[i + 16 : i + ln]))
            i += (ln + 3) & ~3
        return out

    async def request(
        self, family: int, cmd: int, attrs: bytes = b"", dump: bool = False, timeout: float = 5.0
    ) -> list[tuple[int, dict[int, bytes]]]:
        """Send and collect replies: [(genl cmd, attrs)]. Raises NlError on a netlink error."""
        seq = self.send(family, cmd, attrs, (NLM_F_DUMP if dump else 0) | NLM_F_ACK)
        out: list[tuple[int, dict[int, bytes]]] = []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("netlink request timed out")
            for typ, flags, rseq, payload in await self.recv(left):
                if rseq != seq:
                    continue
                if typ == NLMSG_ERROR:
                    err = struct.unpack_from("=i", payload)[0]
                    if err:
                        raise NlError(-err, os.strerror(-err))
                    return out  # ACK
                if typ == NLMSG_DONE:
                    return out
                if len(payload) >= 4:
                    out.append((payload[0], parse_attrs(payload[4:])))
                if not dump and not flags & NLM_F_MULTI:
                    continue  # the ACK follows


_family: dict[str, tuple[int, dict[str, int]]] = {}


async def family(name: str = "nl80211") -> tuple[int, dict[str, int]]:
    if name in _family:
        return _family[name]
    with GenlSocket() as s:
        replies = await s.request(
            GENL_ID_CTRL, CTRL_CMD_GETFAMILY, nla(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\x00")
        )
    if not replies:
        raise NlError(errno.ENOENT, f"generic netlink family {name} not found")
    attrs = replies[0][1]
    fid = struct.unpack("=H", attrs[CTRL_ATTR_FAMILY_ID][:2])[0]
    groups: dict[str, int] = {}
    for g in parse_attr_list(attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")):
        ga = parse_attrs(g)
        if 1 in ga and 2 in ga:
            groups[ga[1].rstrip(b"\x00").decode()] = u32(ga[2]) or 0
    _family[name] = (fid, groups)
    return fid, groups


def _bss(attrs: dict[int, bytes]) -> dict[str, Any] | None:
    raw = attrs.get(ATTR_BSS)
    if raw is None:
        return None
    b = parse_attrs(raw)
    mac = b.get(BSS_BSSID)
    freq = u32(b.get(BSS_FREQUENCY))
    if not mac or not freq:
        return None
    sig = b.get(BSS_SIGNAL_MBM)
    status = u32(b.get(BSS_STATUS))
    return {
        "bssid": ":".join(f"{x:02x}" for x in mac[:6]),
        "freq": freq,
        "ies": b.get(BSS_INFORMATION_ELEMENTS) or b.get(BSS_BEACON_IES) or b"",
        "capability": struct.unpack("=H", b[BSS_CAPABILITY][:2])[0] if BSS_CAPABILITY in b else None,
        "beacon_interval": struct.unpack("=H", b[BSS_BEACON_INTERVAL][:2])[0]
        if BSS_BEACON_INTERVAL in b
        else None,
        "signal_dbm": struct.unpack("=i", sig[:4])[0] / 100 if sig else None,
        "seen_ms_ago": u32(b.get(BSS_SEEN_MS_AGO)),
        "associated": status == 1,
        # set when cfg80211 built this entry from another AP's frame (multi-BSSID, Wi-Fi 7
        # multi-link / reduced neighbour report): we did not hear it ourselves
        "reported_by": _mac(b.get(BSS_PARENT_BSSID)),
        "mld": _mac(b.get(BSS_MLD_ADDR)),
    }


def _mac(v: bytes | None) -> str | None:
    return ":".join(f"{x:02x}" for x in v[:6]) if v and len(v) >= 6 else None


async def scan_dump(ifindex: int) -> list[dict[str, Any]]:
    fid, _ = await family()
    with GenlSocket() as s:
        replies = await s.request(fid, CMD_GET_SCAN, nla(ATTR_IFINDEX, struct.pack("=I", ifindex)), dump=True)
    return [b for _, a in replies if (b := _bss(a))]


async def scan(ifindex: int, freqs: list[int] | None = None, timeout_s: float = 25.0) -> list[dict[str, Any]]:
    """Trigger an (active, wildcard) scan and return the dump once the kernel reports results."""
    fid, groups = await family()
    with GenlSocket() as s:
        s.join(groups["scan"])
        attrs = nla(ATTR_IFINDEX, struct.pack("=I", ifindex)) + nla_nested(ATTR_SCAN_SSIDS, [nla(1, b"")])
        if freqs:
            attrs += nla_nested(
                ATTR_SCAN_FREQUENCIES, [nla(i + 1, struct.pack("=I", f)) for i, f in enumerate(freqs)]
            )
        try:
            await s.request(fid, CMD_TRIGGER_SCAN, attrs)
        except NlError as e:
            if e.errno != errno.EBUSY:  # someone else's scan is running: wait for it instead
                raise
        deadline = time.monotonic() + timeout_s
        done = False
        while not done:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"scan did not finish within {timeout_s:.0f} s")
            try:
                msgs = await s.recv(left)
            except TimeoutError:
                raise TimeoutError(f"scan did not finish within {timeout_s:.0f} s") from None
            for typ, _, _, payload in msgs:
                if typ != fid or len(payload) < 4:
                    continue
                a = parse_attrs(payload[4:])
                if u32(a.get(ATTR_IFINDEX)) != ifindex:
                    continue
                if payload[0] == CMD_NEW_SCAN_RESULTS:
                    done = True
                elif payload[0] == CMD_SCAN_ABORTED:
                    raise NlError(errno.ECANCELED, "scan aborted")
    return await scan_dump(ifindex)


async def survey(ifindex: int) -> list[dict[str, Any]]:
    fid, _ = await family()
    with GenlSocket() as s:
        replies = await s.request(
            fid, CMD_GET_SURVEY, nla(ATTR_IFINDEX, struct.pack("=I", ifindex)), dump=True
        )
    out = []
    for _, a in replies:
        info = parse_attrs(a.get(ATTR_SURVEY_INFO, b""))
        freq = u32(info.get(SURVEY_FREQUENCY))
        if not freq:
            continue
        noise = info.get(SURVEY_NOISE)
        t, busy = u64(info.get(SURVEY_TIME)), u64(info.get(SURVEY_TIME_BUSY))
        out.append(
            {
                "freq": freq,
                "noise_dbm": struct.unpack("=b", noise[:1])[0] if noise else None,
                "in_use": SURVEY_IN_USE in info,
                "busy_pct": round(busy * 100 / t, 1) if t and busy is not None else None,
            }
        )
    return out
