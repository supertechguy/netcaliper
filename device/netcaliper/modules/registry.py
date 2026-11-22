# SPDX-License-Identifier: GPL-3.0-only
"""Module discovery: built-ins plus `netcaliper.modules` entry points (plug-ins)."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from .base import TestModule

_BUILTIN: dict[str, type[TestModule[Any]]] = {}


def register(cls: type[TestModule[Any]]) -> type[TestModule[Any]]:
    if cls.id in _BUILTIN and _BUILTIN[cls.id] is not cls:
        raise ValueError(f"duplicate module id {cls.id}")
    _BUILTIN[cls.id] = cls
    return cls


def all_modules() -> dict[str, type[TestModule[Any]]]:
    from . import system  # noqa: F401  (registers built-ins)

    mods = dict(_BUILTIN)
    for ep in entry_points(group="netcaliper.modules"):
        cls = ep.load()
        mods.setdefault(cls.id, cls)
    return mods
