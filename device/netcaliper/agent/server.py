# SPDX-License-Identifier: GPL-3.0-only
"""Agent RPC surface. Phase 1: identity + namespace snapshot. Module execution lands in Phase 2."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from ..core.rpc import Handler, Peer, RpcServer
from ..drivers.snapshot import collect_net


def make_handlers(netns: str, sysfs: Path = Path("/sys")) -> dict[str, Handler]:
    async def ping(params: dict[str, Any], peer: Peer) -> Any:
        return {"pid": os.getpid(), "uid": os.getuid(), "netns": netns}

    async def snapshot_net(params: dict[str, Any], peer: Peer) -> Any:
        net, wiphys = await asyncio.to_thread(collect_net, sysfs)
        return {
            "netns": netns,
            "net": [n.model_dump() for n in net],
            "wiphys": [w.model_dump() for w in wiphys],
        }

    return {"ping": ping, "snapshot.net": snapshot_net}


def build_server(netns: str, socket_path: Path) -> RpcServer:
    # Same uid as core (both run as the service user); root for diagnostics.
    return RpcServer(
        socket_path,
        make_handlers(netns),
        {0, os.getuid()},
        mode=0o660,
        public_methods=frozenset({"ping", "snapshot.net"}),  # read-only: lets `doctor` show the netns
    )
