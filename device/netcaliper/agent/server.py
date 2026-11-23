# SPDX-License-Identifier: GPL-3.0-only
"""Agent RPC surface: identity, namespace snapshot, and execution of test-ns modules.

`module.run` only runs PASSIVE test-ns modules. ACTIVE modules are authorized by the runner in core
against the engagement; until there is a signed authorization to hand across, the agent refuses
them so it can never become a path around the scope guard.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..core.engagement import ScopeGuard
from ..core.rpc import Handler, Peer, RpcError, RpcServer
from ..drivers.registry import HardwareRegistry
from ..drivers.snapshot import collect_net, collect_real
from ..net.base import TestNet
from ..net.wifi_base import TestWifi

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


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

    def _iface(name: Any, wireless: bool = False) -> str:
        """An interface that exists in this namespace (and is a Wi-Fi radio, if asked)."""
        path = sysfs / "class/net" / name if isinstance(name, str) and name and "/" not in name else None
        if path is None or not path.exists() or (wireless and not (path / "phy80211").exists()):
            raise RpcError(
                "bad_request", f"no such {'radio' if wireless else 'interface'} in {netns}: {name!r}"
            )
        return str(name)

    async def wifi_sample(params: dict[str, Any], peer: Peer) -> Any:
        """Locate: signal samples of one transmitter on one channel (monitor mode, headers only)."""
        ifname = _iface(params.get("ifname"), wireless=True)
        mac, freq = params.get("mac"), params.get("freq")
        if not isinstance(mac, str) or not _MAC.match(mac.lower()):
            raise RpcError("bad_request", "invalid mac")
        if not isinstance(freq, int) or not 2400 <= freq <= 7125:
            raise RpcError("bad_request", "invalid freq")
        dur = float(params.get("duration_s") or 0.5)
        samples = await wifi_net().wifi_sample(ifname, mac, freq, max(0.1, min(dur, 2.0)))
        return [s.model_dump() for s in samples]

    async def wifi_end(params: dict[str, Any], peer: Peer) -> Any:
        """End of a Wi-Fi run: leave the network and drop the address."""
        ifname = _iface(params.get("ifname"), wireless=True)
        net = wifi_net()
        await net.wifi_disconnect(ifname)
        await test_net.release(ifname)
        return {"ok": True}

    def wifi_net() -> TestWifi:
        if not isinstance(test_net, TestWifi):
            raise RpcError("unavailable", "no Wi-Fi support in this test plane")
        return test_net

    async def module_run(params: dict[str, Any], peer: Peer) -> Any:
        mid = params.get("module")
        cls = modules.get(mid) if isinstance(mid, str) else None
        if cls is None or cls.executor != "test-ns":
            raise RpcError("bad_request", f"not a test-ns module: {mid!r}")
        if cls.activity is not Activity.PASSIVE:
            raise RpcError("forbidden", f"{cls.id} is ACTIVE; active modules are not run by the agent")
        ifname = _iface(params.get("ifname"))
        raw_radios = params.get("radios") or {}
        if not isinstance(raw_radios, dict) or len(raw_radios) > 4:
            raise RpcError("bad_request", "invalid radios")
        radios = {str(role): _iface(v, wireless=True) for role, v in raw_radios.items()}
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
            radios=radios,
        )
        try:
            result = await asyncio.wait_for(cls().run(ctx, cfg), cls.timeout_s)
        except TimeoutError:
            result = ModuleResult(status="error", message=f"timed out after {cls.timeout_s:.0f} s")
        except Exception as e:  # report, don't kill the connection
            result = ModuleResult(status="error", message=f"{type(e).__name__}: {e}")
        return {"result": result.model_dump(mode="json"), "session": ctx.session}

    return {
        "ping": ping,
        "snapshot.net": snapshot_net,
        "module.run": module_run,
        "wifi.sample": wifi_sample,
        "wifi.end": wifi_end,
    }


def build_server(netns: str, socket_path: Path) -> RpcServer:
    # Same uid as core (both run as the service user); root for diagnostics.
    return RpcServer(
        socket_path,
        make_handlers(netns),
        {0, os.getuid()},
        mode=0o660,
        public_methods=frozenset({"ping", "snapshot.net"}),  # read-only: lets `doctor` show the netns
    )
