# SPDX-License-Identifier: GPL-3.0-only
"""Agent RPC surface: identity, namespace snapshot, and execution of test-ns modules.

`module.run` only runs PASSIVE test-ns modules. ACTIVE modules are authorized by the runner in core
against the engagement; until there is a signed authorization to hand across, the agent refuses
them so it can never become a path around the scope guard.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..core.engagement import ScopeGuard
from ..core.rpc import Handler, Peer, RpcError, RpcServer
from ..drivers.registry import HardwareRegistry
from ..drivers.snapshot import collect_net, collect_real
from ..net.base import TestNet


def make_handlers(netns: str, sysfs: Path = Path("/sys"), net: TestNet | None = None) -> dict[str, Handler]:
    from ..modules.base import Activity, ModuleResult, RunContext
    from ..modules.registry import all_modules

    modules = all_modules()
    if net is None:
        from ..net.real import RealNet

        net = RealNet()
    test_net = net

    async def ping(params: dict[str, Any], peer: Peer) -> Any:
        return {"pid": os.getpid(), "uid": os.getuid(), "netns": netns}

    async def snapshot_net(params: dict[str, Any], peer: Peer) -> Any:
        net, wiphys = await asyncio.to_thread(collect_net, sysfs)
        return {
            "netns": netns,
            "net": [n.model_dump() for n in net],
            "wiphys": [w.model_dump() for w in wiphys],
        }

    async def module_run(params: dict[str, Any], peer: Peer) -> Any:
        mid = params.get("module")
        cls = modules.get(mid) if isinstance(mid, str) else None
        if cls is None or cls.executor != "test-ns":
            raise RpcError("bad_request", f"not a test-ns module: {mid!r}")
        if cls.activity is not Activity.PASSIVE:
            raise RpcError("forbidden", f"{cls.id} is ACTIVE; active modules are not run by the agent")
        ifname = params.get("ifname")
        if not isinstance(ifname, str) or "/" in ifname or not (sysfs / "class/net" / ifname).exists():
            raise RpcError("bad_request", f"no such interface in {netns}: {ifname!r}")
        try:
            cfg = cls.Config.model_validate(params.get("config") or {})
        except ValidationError as e:
            raise RpcError("bad_request", f"invalid config: {e.error_count()} errors") from e
        session = params.get("session")
        ctx = RunContext(
            run_id=str(params.get("run_id") or ""),
            hardware=HardwareRegistry(collect_real),  # not refreshed; capability checks happen in core
            guard=ScopeGuard(None),  # deny-all
            net=test_net,
            ifname=ifname,
            session=dict(session) if isinstance(session, dict) else {},
        )
        try:
            result = await asyncio.wait_for(cls().run(ctx, cfg), cls.timeout_s)
        except TimeoutError:
            result = ModuleResult(status="error", message=f"timed out after {cls.timeout_s:.0f} s")
        except Exception as e:  # report, don't kill the connection
            result = ModuleResult(status="error", message=f"{type(e).__name__}: {e}")
        return {"result": result.model_dump(mode="json"), "session": ctx.session}

    return {"ping": ping, "snapshot.net": snapshot_net, "module.run": module_run}


def build_server(netns: str, socket_path: Path) -> RpcServer:
    # Same uid as core (both run as the service user); root for diagnostics.
    return RpcServer(
        socket_path,
        make_handlers(netns),
        {0, os.getuid()},
        mode=0o660,
        public_methods=frozenset({"ping", "snapshot.net"}),  # read-only: lets `doctor` show the netns
    )
