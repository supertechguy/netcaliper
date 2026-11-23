# SPDX-License-Identifier: GPL-3.0-only
"""Application-layer reachability with a timing breakdown: TCP connect, HTTP(S), FTP.
Names resolve through the test network's DNS (ip4.resolve), never the host resolver."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from urllib.parse import urlsplit

from .base import ConnectResult
from .ip4 import resolve
from .packets import now_ms


async def tcp(target: str, port: int, dns: list[str], timeout_s: float = 5.0) -> ConnectResult:
    t0 = now_ms()
    ip, dns_ms = await resolve(target, dns)
    if ip is None:
        return ConnectResult(target=target, port=port, ok=False, error="DNS resolution failed")
    t1 = now_ms()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout_s)
    except (OSError, TimeoutError) as e:
        return ConnectResult(target=target, ip=ip, port=port, ok=False, dns_ms=dns_ms, error=type(e).__name__)
    connect_ms = round(now_ms() - t1, 2)
    w.close()
    with contextlib.suppress(Exception):
        await w.wait_closed()
    return ConnectResult(
        target=target,
        ip=ip,
        port=port,
        ok=True,
        dns_ms=dns_ms,
        connect_ms=connect_ms,
        total_ms=round(now_ms() - t0, 2),
    )


async def http(url: str, dns: list[str], timeout_s: float = 10.0) -> ConnectResult:
    u = urlsplit(url if "://" in url else f"http://{url}")
    host = u.hostname or ""
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    t0 = now_ms()
    ip, dns_ms = await resolve(host, dns)
    if ip is None:
        return ConnectResult(target=url, port=port, ok=False, error="DNS resolution failed")
    res = ConnectResult(target=url, ip=ip, port=port, ok=False, dns_ms=dns_ms)
    try:
        async with asyncio.timeout(timeout_s):
            t1 = now_ms()
            r, w = await asyncio.open_connection(ip, port)
            res.connect_ms = round(now_ms() - t1, 2)
            if tls:
                t2 = now_ms()
                await w.start_tls(ssl.create_default_context(), server_hostname=host)
                res.tls_ms = round(now_ms() - t2, 2)
            t3 = now_ms()
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netcaliper\r\nConnection: close\r\n\r\n"
            )
            w.write(req.encode())
            await w.drain()
            line = await r.readline()
            res.first_byte_ms = round(now_ms() - t3, 2)
            parts = line.decode(errors="replace").split()
            res.status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            res.detail = line.decode(errors="replace").strip()[:80]
            await r.read(256 * 1024)  # drain (bounded) so total time includes the body
            w.close()
    except (OSError, TimeoutError, ssl.SSLError) as e:
        res.error = f"{type(e).__name__}: {e}"[:200]
        return res
    res.total_ms = round(now_ms() - t0, 2)
    res.ok = res.status is not None and res.status < 400
    return res


async def ftp(
    target: str, dns: list[str], user: str = "anonymous", password: str = "", timeout_s: float = 10.0
) -> ConnectResult:
    """Banner + login timing (control channel only; no data transfer)."""
    t0 = now_ms()
    ip, dns_ms = await resolve(target, dns)
    if ip is None:
        return ConnectResult(target=target, port=21, ok=False, error="DNS resolution failed")
    res = ConnectResult(target=target, ip=ip, port=21, ok=False, dns_ms=dns_ms)

    async def reply(r: asyncio.StreamReader) -> tuple[int, str]:
        line = await r.readline()
        text = line.decode(errors="replace")
        while len(text) > 3 and text[3] == "-":  # multi-line reply
            line = await r.readline()
            text = line.decode(errors="replace")
        return (int(text[:3]) if text[:3].isdigit() else 0), text.strip()

    try:
        async with asyncio.timeout(timeout_s):
            t1 = now_ms()
            r, w = await asyncio.open_connection(ip, 21)
            res.connect_ms = round(now_ms() - t1, 2)
            code, text = await reply(r)
            res.first_byte_ms = round(now_ms() - t1, 2)
            if code == 220:
                w.write(f"USER {user}\r\n".encode())
                code, text = await reply(r)
                if code == 331:
                    w.write(f"PASS {password or 'netcaliper@'}\r\n".encode())
                    code, text = await reply(r)
                w.write(b"QUIT\r\n")
            res.status, res.detail = code, text[:80]
            w.close()
    except (OSError, TimeoutError) as e:
        res.error = type(e).__name__
        return res
    res.total_ms = round(now_ms() - t0, 2)
    res.ok = res.status == 230
    return res
