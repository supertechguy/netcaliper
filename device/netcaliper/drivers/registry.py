# SPDX-License-Identifier: GPL-3.0-only
"""HardwareRegistry: the single place modules ask "who provides capability X?"."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from .base import Capability, HardwareDevice, Role
from .detect import Inventory, detect
from .snapshot import SystemSnapshot, collect_real, load_fixture

SnapshotSource = Callable[[], SystemSnapshot]


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
    def __init__(self, source: SnapshotSource, role_overrides: dict[str, Role] | None = None) -> None:
        self._source = source
        self._overrides = role_overrides or {}
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
            self.snapshot = snap
            self._inventory = detect(snap, self._overrides)
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
