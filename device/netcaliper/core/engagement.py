# SPDX-License-Identifier: GPL-3.0-only
"""Engagements and the scope guard.

Every ACTIVE module must have its targets authorized by `ScopeGuard.authorize` before it touches
the network; the module runner enforces this (see netcaliper.modules.runner). Hostnames are resolved
and *every* resulting address must be in scope.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from .ids import new_id, utcnow

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Awaitable[list[str]]]


class Engagement(BaseModel):
    id: str = Field(default_factory=new_id)
    name: str
    authorized_by: str
    authorized_cidrs: list[str] = Field(default_factory=list)
    excluded_cidrs: list[str] = Field(default_factory=list)
    authorized_ssids: list[str] = Field(default_factory=list)
    allowed_modules: list[str] | None = None  # None = any ACTIVE module
    starts_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime

    @field_validator("authorized_cidrs", "excluded_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(c, strict=False)) for c in v]

    def networks(self) -> list[IPNet]:
        return [ipaddress.ip_network(c) for c in self.authorized_cidrs]

    def exclusions(self) -> list[IPNet]:
        return [ipaddress.ip_network(c) for c in self.excluded_cidrs]

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        return self.starts_at <= now < self.expires_at


class ScopeError(PermissionError):
    pass


class Decision(BaseModel):
    allowed: bool
    engagement_id: str | None
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    reason: str = ""


async def _default_resolver(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


def _target_networks(target: str) -> list[IPNet] | None:
    """Return the networks a literal target covers, or None if it's a hostname."""
    try:
        return [ipaddress.ip_network(target, strict=False)]
    except ValueError:
        pass
    # nmap-style last-octet range: 10.0.0.1-20
    if "-" in target and target.count(".") == 3:
        base, _, end = target.rpartition("-")
        try:
            start = ipaddress.IPv4Address(base)
            last = ipaddress.IPv4Address(".".join([*base.split(".")[:3], end]))
        except ValueError:
            return None
        if last < start:
            raise ScopeError(f"invalid range {target}")
        return list(ipaddress.summarize_address_range(start, last))
    return None


class ScopeGuard:
    def __init__(self, engagement: Engagement | None, resolver: Resolver | None = None) -> None:
        self.engagement = engagement
        self._resolve = resolver or _default_resolver

    def _covered(self, net: IPNet) -> bool:
        assert self.engagement is not None
        if any(net.version == ex.version and net.overlaps(ex) for ex in self.engagement.exclusions()):
            return False
        return any(net.version == a.version and net.subnet_of(a) for a in self.engagement.networks())  # type: ignore[arg-type]

    async def check(self, targets: Iterable[str], module_id: str | None = None) -> Decision:
        eng = self.engagement
        if eng is None:
            return Decision(allowed=False, engagement_id=None, reason="no active engagement")
        if not eng.is_active():
            return Decision(
                allowed=False, engagement_id=eng.id, reason="engagement not active (expired or not started)"
            )
        if module_id and eng.allowed_modules is not None and module_id not in eng.allowed_modules:
            return Decision(
                allowed=False, engagement_id=eng.id, reason=f"module {module_id} not allowed by engagement"
            )
        ok: list[str] = []
        bad: list[str] = []
        targets = list(targets)
        if not targets:
            return Decision(allowed=False, engagement_id=eng.id, reason="no targets given")
        for t in targets:
            nets = _target_networks(t)
            if nets is None:
                try:
                    addrs = await self._resolve(t)
                except OSError:
                    bad.append(t)
                    continue
                nets = [ipaddress.ip_network(a) for a in addrs]
                if not nets:
                    bad.append(t)
                    continue
            (ok if all(self._covered(n) for n in nets) else bad).append(t)
        return Decision(
            allowed=not bad,
            engagement_id=eng.id,
            in_scope=ok,
            out_of_scope=bad,
            reason="" if not bad else "targets outside engagement scope",
        )

    async def authorize(self, targets: Iterable[str], module_id: str | None = None) -> Decision:
        d = await self.check(targets, module_id)
        if not d.allowed:
            raise ScopeError(f"{d.reason}: {', '.join(d.out_of_scope) or '-'}")
        return d
