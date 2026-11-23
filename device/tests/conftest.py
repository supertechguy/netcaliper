# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from netcaliper.core.config import Settings
from netcaliper.core.db import Database
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.drivers.snapshot import which

os.environ.setdefault("NETCALIPER_HW", "mock:uconsole-cm4-full")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data", config_dir=tmp_path / "etc")
    s.hardware.mode = "mock:uconsole-cm4-full"
    return s


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    async with Database(tmp_path / "t.db") as d:
        yield d


@pytest.fixture
async def registry() -> HardwareRegistry:
    r = HardwareRegistry.from_mode("mock:uconsole-cm4-full")
    await r.refresh()
    return r


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    hw = os.environ.get("NETCALIPER_HW", "")
    for item in items:
        if "hw" in item.keywords and not hw.startswith("real"):
            item.add_marker(pytest.mark.skip(reason="hardware test: set NETCALIPER_HW=real"))
        if "netns" in item.keywords and (os.geteuid() != 0 or not which("ip")):
            item.add_marker(pytest.mark.skip(reason="netns test: needs root and iproute2"))
