# SPDX-License-Identifier: GPL-3.0-only
"""Driver interfaces. Each feature phase adds a real implementation and a mock behind these ABCs;
modules only ever see these types (resolved from the registry by capability).

Phase 0 defines the contracts; method sets grow with the phases listed in docs/ROADMAP.md.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from .base import HardwareDevice


class Driver(ABC):  # noqa: B024 - marker base; subclasses define the abstract API
    def __init__(self, device: HardwareDevice) -> None:
        self.device = device


class WiredNic(Driver):  # phase 2
    @abstractmethod
    async def link_state(self) -> dict[str, Any]: ...
    @abstractmethod
    async def blink(self, seconds: float) -> None: ...
    @abstractmethod
    async def cable_test(self) -> dict[str, Any]: ...


class WifiRadio(Driver):  # phase 3
    @abstractmethod
    async def scan(self) -> list[dict[str, Any]]: ...
    @abstractmethod
    def monitor(self, channels: list[int]) -> AsyncIterator[dict[str, Any]]: ...


class BleAdapter(Driver):  # phase 8
    @abstractmethod
    def scan(self) -> AsyncIterator[dict[str, Any]]: ...


class SubGhzSdr(Driver):  # phase 8
    @abstractmethod
    def ism_decode(self, freq_hz: int) -> AsyncIterator[dict[str, Any]]: ...
    @abstractmethod
    async def power_sweep(self, start_hz: int, stop_hz: int, bin_hz: int) -> list[tuple[int, float]]: ...


class Nrf24Radio(Driver):  # phase 8 — detection/sweep only, never transmit keystrokes
    @abstractmethod
    async def channel_activity(self, dwell_ms: int) -> list[tuple[int, float]]: ...
    @abstractmethod
    def hid_scan(self) -> AsyncIterator[dict[str, Any]]: ...


class WidebandSdr(Driver):  # slot for HackRF-class hardware (5/6 GHz spectrum)
    @abstractmethod
    async def sweep(self, start_hz: int, stop_hz: int, bin_hz: int) -> list[tuple[int, float]]: ...


class WiremapProbe(Driver):  # phase 10 — netcaliper probe (USB CDC, JSON lines)
    @abstractmethod
    async def wiremap(self) -> dict[str, Any]: ...
    @abstractmethod
    async def cable_length_m(self) -> float: ...
    @abstractmethod
    async def tone(self, on: bool) -> None: ...


class PoeModule(Driver):  # phase 10 — INA226 + switchable load
    @abstractmethod
    async def measure(self, load_w: float | None = None) -> dict[str, Any]: ...
