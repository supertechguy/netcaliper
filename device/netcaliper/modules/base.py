# SPDX-License-Identifier: GPL-3.0-only
"""Test module contract. See docs/ARCHITECTURE.md §4."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Generic, Literal, Protocol, TypeVar

from pydantic import BaseModel, Field

from ..core.engagement import ScopeGuard
from ..core.records import Finding, Status
from ..drivers.base import Capability
from ..drivers.registry import HardwareRegistry
from ..net.base import TestNet


class Activity(StrEnum):
    PASSIVE = "passive"  # always allowed
    ACTIVE = "active"  # requires an engagement covering every target (enforced by the runner)


class ModuleConfig(BaseModel):
    """Base for module configs. ACTIVE modules must expose their targets via `targets()`."""

    def targets(self) -> list[str]:
        return []


class ModuleResult(BaseModel):
    status: Status
    message: str = ""
    metrics: dict[str, float | int | str | bool | None] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


ProgressFn = Callable[[float, str, dict[str, Any] | None], Awaitable[None]]


async def _no_progress(pct: float, msg: str, data: dict[str, Any] | None = None) -> None:
    return None


class Caller(Protocol):
    async def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> Any: ...


@dataclass
class RunContext:
    run_id: str
    hardware: HardwareRegistry
    guard: ScopeGuard
    progress: ProgressFn = _no_progress
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    # Test-plane execution (executor = "test-ns"):
    net: TestNet | None = None  # RealNet in the agent, MockNet in mock mode
    ifname: str | None = None  # the test interface *inside the test netns*, resolved by role
    session: dict[str, Any] = field(default_factory=dict)  # per-run shared state (e.g. the DHCP lease)
    agent: Caller | None = None  # set in core when test-ns modules must run in the agent
    radios: dict[str, str] = field(default_factory=dict)  # role ("test-wifi", "monitor") -> ifname


C = TypeVar("C", bound=ModuleConfig)


class TestModule(ABC, Generic[C]):
    __test__ = False
    id: ClassVar[str]
    version: ClassVar[str] = "1"
    title: ClassVar[str]
    requires: ClassVar[frozenset[Capability]] = frozenset()
    optional: ClassVar[frozenset[Capability]] = frozenset()
    activity: ClassVar[Activity] = Activity.PASSIVE
    executor: ClassVar[Literal["test-ns", "root"]] = "root"
    # Background modules (passive listeners) start when reached and are collected at the end of a run.
    background: ClassVar[bool] = False
    timeout_s: ClassVar[float] = 120.0  # hard ceiling for one run of this module
    needs_link: ClassVar[bool] = True  # False: still useful when the association failed (scan, monitor)
    Config: ClassVar[type[ModuleConfig]] = ModuleConfig

    def net(self, ctx: RunContext) -> tuple[TestNet, str]:
        """The TestNet and test interface; raises if this module was dispatched without them."""
        if ctx.net is None or ctx.ifname is None:
            raise RuntimeError(f"{self.id}: no test interface (test plane not available)")
        return ctx.net, ctx.ifname

    @abstractmethod
    async def run(self, ctx: RunContext, cfg: C) -> ModuleResult: ...
