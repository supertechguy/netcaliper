# SPDX-License-Identifier: GPL-3.0-only
"""Test plane: keep test-role interfaces inside the test netns, everything else out of it.

Pure decision logic (`plan`) + an executor that asks the root helper to do each step and records
every move in the audit log. Hotplug is a cheap polling signature (USB + netdev listings) — no
udev dependency, works the same on every distro.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from ..drivers.base import HardwareDevice
from ..drivers.detect import Inventory
from .audit import AuditLog
from .rpc import RpcError

log = logging.getLogger(__name__)

TEST_ROLES = frozenset({"test-wired", "test-wifi", "monitor"})


class Caller(Protocol):
    async def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> Any: ...


@dataclass(frozen=True)
class Step:
    op: Literal["plane.move_in", "plane.move_out"]
    device_id: str
    mac: str
    name: str


@dataclass
class Plan:
    unmanaged_macs: list[str]
    steps: list[Step] = field(default_factory=list)


@dataclass
class Outcome:
    step: Step
    ok: bool
    detail: dict[str, Any]


def _netdevs(inv: Inventory) -> list[HardwareDevice]:
    return [d for d in inv.devices if d.kind in ("nic", "wifi") and d.mac]


def plan(inv: Inventory, netns: str) -> Plan:
    devs = _netdevs(inv)
    p = Plan(unmanaged_macs=sorted({d.mac for d in devs if d.role in TEST_ROLES and d.mac}))
    for d in devs:
        assert d.mac
        if d.role in TEST_ROLES and d.netns is None:
            p.steps.append(Step("plane.move_in", d.id, d.mac, d.name))
        elif d.role not in TEST_ROLES and d.netns == netns:
            p.steps.append(Step("plane.move_out", d.id, d.mac, d.name))
    return p


async def apply(p: Plan, helper: Caller, audit: AuditLog | None, nm_done: bool = False) -> list[Outcome]:
    # NetworkManager first, so it never races us for a link we're about to move.
    if not nm_done:
        await helper.call("nm.set_unmanaged", {"macs": p.unmanaged_macs})
    out: list[Outcome] = []
    for s in p.steps:
        try:
            res = await helper.call(s.op, {"mac": s.mac})
            o = Outcome(s, True, res if isinstance(res, dict) else {"result": res})
        except RpcError as e:
            o = Outcome(s, False, {"error": e.code, "message": e.message})
        out.append(o)
        if audit is not None:
            await audit.append(
                "system",
                s.op if o.ok else f"{s.op}.failed",
                {"device_id": s.device_id, "mac": s.mac, "name": s.name, **o.detail},
            )
        log.info("%s %s (%s): %s", s.op, s.name, s.mac, "ok" if o.ok else o.detail)
    return out


class TestPlane:
    """Stateful wrapper used by core: skips the helper entirely when nothing changed."""

    __test__ = False

    def __init__(self, helper: Caller, netns: str, audit: AuditLog | None = None) -> None:
        self.helper = helper
        self.netns = netns
        self.audit = audit
        self._nm_macs: list[str] | None = None
        self.last_error: str | None = None

    async def reconcile(self, inv: Inventory) -> list[Outcome]:
        p = plan(inv, self.netns)
        if not p.steps and p.unmanaged_macs == self._nm_macs:
            return []
        try:
            out = await apply(p, self.helper, self.audit, nm_done=p.unmanaged_macs == self._nm_macs)
        except RpcError as e:
            self.last_error = f"helper: {e.code} {e.message}"
            log.warning("test plane reconcile failed: %s", self.last_error)
            return []
        self._nm_macs = p.unmanaged_macs
        failed = [o for o in out if not o.ok]
        self.last_error = (
            "; ".join(f"{o.step.name}: {o.detail.get('error')}" for o in failed) if failed else None
        )
        return out


def hotplug_signature(sysfs: Path = Path("/sys")) -> tuple[str, ...]:
    """Changes whenever a USB device or a root-namespace netdev appears or disappears."""
    usb = sorted(p.name for p in (sysfs / "bus/usb/devices").glob("*") if ":" not in p.name)
    net = sorted(p.name for p in (sysfs / "class/net").glob("*"))
    return (*usb, "|", *net)


async def watch_hotplug(
    on_change: Callable[[], Awaitable[None]],
    interval: float,
    signature: Callable[[], tuple[str, ...]] = hotplug_signature,
    settle: float = 2.0,
) -> None:
    """Poll `signature` every `interval` s; after a change, wait `settle` s (drivers finish probing,
    interfaces get renamed) and call `on_change` once. Runs until cancelled."""
    last = await asyncio.to_thread(signature)
    while True:
        await asyncio.sleep(interval)
        cur = await asyncio.to_thread(signature)
        if cur == last:
            continue
        await asyncio.sleep(settle)
        last = await asyncio.to_thread(signature)
        try:
            await on_change()
        except Exception:
            log.exception("hotplug handler failed")
