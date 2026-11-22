# SPDX-License-Identifier: GPL-3.0-only
"""Configuration: TOML file (/etc/netcaliper/netcaliper.toml) overlaid by NETCALIPER_* env vars."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

Role = Literal["test-wired", "test-wifi", "monitor", "mgmt", "unused"]

DEFAULT_CONFIG_FILE = Path("/etc/netcaliper/netcaliper.toml")


class WebSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080


class SyncSettings(BaseModel):
    enabled: bool = False
    server_url: str = "https://netcaliper.supertechguy.net"
    allow_over_test_port: bool = False


class HardwareSettings(BaseModel):
    # "real", or "mock:<fixture>" (a bundled fixture name or a path to a fixture YAML).
    mode: str = "real"
    # Role overrides keyed by stable device id (see drivers.base.HardwareDevice.id).
    roles: dict[str, Role] = Field(default_factory=dict)


class Settings(BaseModel):
    data_dir: Path = Path("/var/lib/netcaliper")
    config_dir: Path = Path("/etc/netcaliper")
    test_netns: str = "ncal-test"
    web: WebSettings = Field(default_factory=WebSettings)
    sync: SyncSettings = Field(default_factory=SyncSettings)
    hardware: HardwareSettings = Field(default_factory=HardwareSettings)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netcaliper.db"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"


def _env_overrides(env: dict[str, str]) -> dict[str, Any]:
    """NETCALIPER_WEB__PORT=9000 -> {"web": {"port": "9000"}}. NETCALIPER_HW is a shorthand."""
    out: dict[str, Any] = {}
    for key, value in env.items():
        if not key.startswith("NETCALIPER_"):
            continue
        name = key.removeprefix("NETCALIPER_").lower()
        if name == "hw":
            out.setdefault("hardware", {})["mode"] = value
            continue
        if name == "config":
            continue
        node = out
        parts = name.split("__")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_settings(path: Path | None = None, env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ) if env is None else env
    path = path or Path(env.get("NETCALIPER_CONFIG", str(DEFAULT_CONFIG_FILE)))
    data: dict[str, Any] = {}
    if path.is_file():
        data = tomllib.loads(path.read_text())
    _merge(data, _env_overrides(env))
    return Settings.model_validate(data)
