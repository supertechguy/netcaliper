# SPDX-License-Identifier: GPL-3.0-only
"""Minimal async HTTP/1.1 client for the cloud sync (no extra dependency). TLS with certificate and
hostname verification against the system CAs; plain http:// only to loopback (local `wrangler dev`).
Bounded: overall timeout and a response size cap."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .. import __version__

USER_AGENT = f"netcaliper/{__version__}"
MAX_RESPONSE = 4 * 1024 * 1024


class HttpsError(OSError):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> str:
    """Normalised base URL, or ValueError: https://host[:port] (http only for loopback)."""
    u = urlsplit(url.strip())
    if u.scheme not in ("https", "http") or not u.hostname:
        raise ValueError("server URL must be https://host")
    if u.scheme == "http" and not is_loopback(u.hostname):
        raise ValueError("plain http is only allowed to localhost")
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("server URL must be just https://host[:port]")
    return f"{u.scheme}://{u.netloc}"


async def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    timeout: float = 30.0,
    max_response: int = MAX_RESPONSE,
    ssl_context: ssl.SSLContext | None = None,
) -> Response:
    return await asyncio.wait_for(
        _request(method, url, headers or {}, body, max_response, ssl_context), timeout=timeout
    )


async def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    max_response: int,
    ssl_context: ssl.SSLContext | None,
) -> Response:
    u = urlsplit(url)
    host = u.hostname or ""
    if u.scheme == "https":
        tls: ssl.SSLContext | None = ssl_context or ssl.create_default_context()
        port = u.port or 443
    elif u.scheme == "http" and is_loopback(host):
        tls, port = None, u.port or 80
    else:
        raise HttpsError(f"refusing {u.scheme}:// to {host}")
    reader, writer = await asyncio.open_connection(host, port, ssl=tls, server_hostname=host if tls else None)
    try:
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        hdrs = {
            "Host": u.netloc,
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Connection": "close",
            **headers,
        }
        if body or method in ("POST", "PUT"):
            hdrs["Content-Length"] = str(len(body))
        head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        if any(c in head[:-4] for c in "\x00") or "\r\n\r\n" in head[:-4]:
            raise HttpsError("bad header")
        writer.write(head.encode("latin-1") + body)
        await writer.drain()

        status_line = (await reader.readline()).decode("latin-1").strip()
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit():
            raise HttpsError(f"bad status line: {status_line[:80]!r}")
        status = int(parts[1])
        rh: dict[str, str] = {}
        while True:
            line = (await reader.readline()).decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            k, _, v = line.partition(":")
            rh[k.strip().lower()] = v.strip()
            if len(rh) > 100:
                raise HttpsError("too many response headers")
        if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return Response(status, rh)
        if "chunked" in rh.get("transfer-encoding", "").lower():
            data = bytearray()
            while True:
                size_line = (await reader.readline()).decode("latin-1").split(";")[0].strip()
                size = int(size_line or "0", 16)
                if size == 0:
                    await reader.readline()
                    break
                if len(data) + size > max_response:
                    raise HttpsError("response too large")
                data += await reader.readexactly(size)
                await reader.readexactly(2)
            return Response(status, rh, bytes(data))
        if "content-length" in rh:
            n = int(rh["content-length"])
            if n > max_response:
                raise HttpsError("response too large")
            return Response(status, rh, await reader.readexactly(n))
        rest = await reader.read(max_response + 1)
        if len(rest) > max_response:
            raise HttpsError("response too large")
        return Response(status, rh, rest)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
