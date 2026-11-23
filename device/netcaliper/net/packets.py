# SPDX-License-Identifier: GPL-3.0-only
"""AF_PACKET sockets for asyncio (needs CAP_NET_RAW; the agent has it inside the test netns)."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

ETH_P_ALL = 0x0003
ETH_P_802_2 = 0x0004  # 802.3 frames with an LLC header (CDP, EDP)
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_LLDP = 0x88CC
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
BROADCAST = b"\xff" * 6


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6])


def iface_mac(ifname: str) -> str:
    return Path(f"/sys/class/net/{ifname}/address").read_text().strip()


def now_ms() -> float:
    return time.monotonic() * 1000.0


class RawSocket:
    """Non-blocking AF_PACKET socket bound to one interface and ethertype."""

    def __init__(self, ifname: str, proto: int = ETH_P_ALL, multicast: list[str] | None = None) -> None:
        self.ifname = ifname
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
        self.sock.bind((ifname, proto))
        self.sock.setblocking(False)
        self.ifindex = socket.if_nametoindex(ifname)
        for mac in multicast or []:
            # Per-socket membership: removed automatically when the socket closes.
            mreq = struct.pack("iHH8s", self.ifindex, PACKET_MR_MULTICAST, 6, mac_bytes(mac))
            self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

    def send(self, frame: bytes) -> None:
        self.sock.send(frame)

    async def recv(self, timeout_s: float) -> bytes | None:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(loop.sock_recv(self.sock, 65535), timeout_s)
        except TimeoutError:
            return None

    async def collect(
        self, duration_s: float, match: Callable[[bytes], bool], stop_after: int | None = None
    ) -> list[tuple[float, bytes]]:
        """Frames matching `match` within `duration_s`, as (monotonic ms, frame)."""
        out: list[tuple[float, bytes]] = []
        deadline = time.monotonic() + duration_s
        while (left := deadline - time.monotonic()) > 0:
            frame = await self.recv(left)
            if frame is None:
                break
            if match(frame):
                out.append((now_ms(), frame))
                if stop_after and len(out) >= stop_after:
                    break
        return out

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()

    def __enter__(self) -> RawSocket:
        return self

    def __exit__(
        self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()
