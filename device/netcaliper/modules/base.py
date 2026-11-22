# SPDX-License-Identifier: GPL-3.0-only
"""Test module contract. See docs/ARCHITECTURE.md §4."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Generic, Literal, TypeVar

from pydantic import BaseModel, Field

from ..core.engagement import ScopeGuard
from ..core.records import Finding, Status
from ..drivers.base import Capability
from ..drivers.registry import HardwareRegistry


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


@dataclass
class RunContext:
    run_id: str
    hardware: HardwareRegistry
    guard: ScopeGuard
    progress: ProgressFn = _no_progress
    cancel: asyncio.Event = field(default_factory=asyncio.Event)


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
    Config: ClassVar[type[ModuleConfig]] = ModuleConfig

    @abstractmethod
    async def run(self, ctx: RunContext, cfg: C) -> ModuleResult: ...
