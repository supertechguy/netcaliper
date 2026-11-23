# SPDX-License-Identifier: GPL-3.0-only
"""Declarative pass/warn/fail thresholds, evaluated by the runner (modules only report metrics)."""

from __future__ import annotations

import operator
import re
from collections.abc import Callable, Mapping

from pydantic import BaseModel, field_validator

from ..core.records import Status

_OPS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}
_EXPR = re.compile(r"^\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")


def _check(expr: str) -> str:
    if not _EXPR.match(expr):
        raise ValueError(f"bad threshold expression {expr!r} (e.g. '> 500')")
    return expr


class Threshold(BaseModel):
    metric: str
    warn: str | None = None
    fail: str | None = None

    @field_validator("warn", "fail")
    @classmethod
    def _valid(cls, v: str | None) -> str | None:
        return _check(v) if v is not None else v

    @staticmethod
    def _hit(expr: str | None, value: float) -> bool:
        if expr is None:
            return False
        m = _EXPR.match(expr)
        assert m
        return _OPS[m.group(1)](value, float(m.group(2)))

    def evaluate(self, metrics: Mapping[str, object]) -> Status | None:
        v = metrics.get(self.metric)
        if not isinstance(v, int | float) or isinstance(v, bool):
            return None
        if self._hit(self.fail, float(v)):
            return "fail"
        if self._hit(self.warn, float(v)):
            return "warn"
        return "pass"


_RANK: dict[Status, int] = {"skipped": 0, "pass": 1, "warn": 2, "fail": 3, "error": 4}


def worst(*statuses: Status) -> Status:
    return max(statuses, key=lambda s: _RANK[s]) if statuses else "pass"
