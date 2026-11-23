# SPDX-License-Identifier: GPL-3.0-only
"""Tiny JSON-lines RPC over unix sockets, shared by core↔helper and core↔agent.

Request:  {"id": 1, "method": "ping", "params": {...}}
Response: {"id": 1, "ok": true, "result": ...} | {"id": 1, "ok": false, "error": {"code", "message"}}

Servers check the peer's uid with SO_PEERCRED before reading anything.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import os
import socket
import struct
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MAX_LINE = 1 << 20  # 1 MiB: a full snapshot fits; anything bigger is a bug or abuse
Handler = Callable[[dict[str, Any], "Peer"], Awaitable[Any]]


class RpcError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Peer:
    def __init__(self, pid: int, uid: int, gid: int) -> None:
        self.pid, self.uid, self.gid = pid, uid, gid

    def __repr__(self) -> str:
        return f"Peer(pid={self.pid}, uid={self.uid})"


def peer_of(sock: socket.socket) -> Peer:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return Peer(pid, uid, gid)


class RpcServer:
    def __init__(
        self,
        path: Path,
        handlers: dict[str, Handler],
        allowed_uids: set[int],
        mode: int = 0o660,
        gid: int | None = None,
        public_methods: frozenset[str] = frozenset(),
    ) -> None:
        self.path = path
        self.handlers = handlers
        self.allowed_uids = allowed_uids
        self.mode = mode
        self.gid = gid
        # Read-only methods any peer that can open the socket may call (socket mode/group
        # still restricts who that is). Everything else requires an allowed uid.
        self.public_methods = public_methods
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        old = os.umask(0o177)  # never expose the socket, even briefly, before chmod
        try:
            self._server = await asyncio.start_unix_server(self._client, path=str(self.path), limit=MAX_LINE)
        finally:
            os.umask(old)
        if self.gid is not None:
            os.chown(self.path, -1, self.gid)
        os.chmod(self.path, self.mode)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        peer = peer_of(sock)
        if peer.uid not in self.allowed_uids and not self.public_methods:
            log.warning("rejecting %r: uid not allowed", peer)
            await _send(writer, {"id": None, "ok": False, "error": {"code": "denied", "message": "uid"}})
            writer.close()
            return
        try:
            while line := await reader.readline():
                await _send(writer, await self._dispatch(line, peer))
        except (asyncio.LimitOverrunError, ValueError):
            await _send(writer, _err(None, "too_large", "request exceeds limit"))
        except ConnectionError:
            pass
        finally:
            writer.close()

    async def _dispatch(self, line: bytes, peer: Peer) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return _err(None, "bad_json", "invalid JSON")
        if not isinstance(req, dict):
            return _err(None, "bad_request", "request must be an object")
        rid = req.get("id")
        method, params = req.get("method"), req.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return _err(rid, "bad_request", "method must be a string, params an object")
        if peer.uid not in self.allowed_uids and method not in self.public_methods:
            log.warning("rejecting %s from %r: uid not allowed", method, peer)
            return _err(rid, "denied", "uid")
        handler = self.handlers.get(method)
        if handler is None:
            return _err(rid, "unknown_method", method)
        try:
            return {"id": rid, "ok": True, "result": await handler(params, peer)}
        except RpcError as e:
            return _err(rid, e.code, e.message)
        except Exception as e:  # contain: one bad call must not kill a privileged daemon
            log.exception("handler %s failed", method)
            return _err(rid, "internal", type(e).__name__)


def _err(rid: Any, code: str, message: str) -> dict[str, Any]:
    return {"id": rid, "ok": False, "error": {"code": code, "message": message}}


async def _send(writer: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
    writer.write(json.dumps(obj, separators=(",", ":"), default=str).encode() + b"\n")
    await writer.drain()


class RpcClient:
    """One connection per call: calls are rare and this survives server restarts for free."""

    def __init__(self, path: Path, timeout: float = 30.0) -> None:
        self.path = path
        self.timeout = timeout
        self._ids = itertools.count(1)

    async def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> Any:
        return await asyncio.wait_for(self._call(method, params or {}), timeout or self.timeout)

    async def _call(self, method: str, params: dict[str, Any]) -> Any:
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.path), limit=MAX_LINE)
        except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
            raise RpcError("unreachable", f"{self.path}: {type(e).__name__}") from e
        try:
            rid = next(self._ids)
            req = {"id": rid, "method": method, "params": params}
            writer.write(json.dumps(req, separators=(",", ":")).encode() + b"\n")
            await writer.drain()
            line = await reader.readline()
            if not line:
                raise RpcError("closed", "connection closed without a response")
            resp = json.loads(line)
            if not resp.get("ok"):
                err = resp.get("error") or {}
                raise RpcError(str(err.get("code", "error")), str(err.get("message", "")))
            return resp.get("result")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
