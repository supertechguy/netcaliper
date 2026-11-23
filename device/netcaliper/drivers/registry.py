# SPDX-License-Identifier: GPL-3.0-only
"""HardwareRegistry: the single place modules ask "who provides capability X?"."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any, Protocol

from .base import Capability, HardwareDevice, Role
from .detect import Inventory, detect
from .snapshot import NetInterface, SystemSnapshot, Wiphy, collect_real, load_fixture, merge_netns

log = logging.getLogger(__name__)
SnapshotSource = Callable[[], SystemSnapshot]


class NetnsView(Protocol):
    """The test-plane agent (or a fake): returns what it sees inside the test netns."""

    async def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> Any: ...


def source_for_mode(mode: str) -> SnapshotSource:
    """mode: "real" or "mock:<fixture name or path>"."""
    if mode == "real":
        return collect_real
    if mode.startswith("mock"):
        _, _, name = mode.partition(":")
        fixture = name or "uconsole-cm4-full"
        return lambda: load_fixture(fixture)
    raise ValueError(f"unknown hardware mode {mode!r} (use 'real' or 'mock:<fixture>')")


class HardwareRegistry:
    def __init__(
        self,
        source: SnapshotSource,
        role_overrides: dict[str, Role] | None = None,
        agent: NetnsView | None = None,
    ) -> None:
        self._source = source
        self._overrides = role_overrides or {}
        self.agent = agent
        self._inventory: Inventory | None = None
        self.snapshot: SystemSnapshot | None = None
        self._lock = asyncio.Lock()
        self.is_mock = source is not collect_real

    @classmethod
    def from_mode(cls, mode: str, role_overrides: dict[str, Role] | None = None) -> HardwareRegistry:
        return cls(source_for_mode(mode), role_overrides)

    async def refresh(self) -> Inventory:
        async with self._lock:
            snap = await asyncio.to_thread(self._source)
            agent_error = None
            if self.agent is not None:
                try:
                    view = await self.agent.call("snapshot.net", timeout=15)
                    snap = merge_netns(
                        snap,
                        str(view["netns"]),
                        [NetInterface.model_validate(n) for n in view["net"]],
                        [Wiphy.model_validate(w) for w in view["wiphys"]],
                    )
                except Exception as e:  # agent down must never take the UI down
                    agent_error = f"test-plane agent unreachable ({e}); test-netns devices not shown"
                    log.warning("%s", agent_error)
            self.snapshot = snap
            self._inventory = detect(snap, self._overrides)
            if agent_error:
                self._inventory.warnings.append(agent_error)
            return self._inventory

    @property
    def inventory(self) -> Inventory:
        if self._inventory is None:
            raise RuntimeError("HardwareRegistry.refresh() has not run")
        return self._inventory

    def find(
        self, cap: Capability, role: Role | None = None, allow_degraded: bool = False
    ) -> list[HardwareDevice]:
        devs = self.inventory.by_capability(cap, allow_degraded)
        return [d for d in devs if role is None or d.role == role]

    def missing(self, caps: set[Capability]) -> set[Capability]:
        return {c for c in caps if not self.inventory.by_capability(c)}
