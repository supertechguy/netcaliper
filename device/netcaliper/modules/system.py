# SPDX-License-Identifier: GPL-3.0-only
"""system.hardware — reports detected hardware and roles. Passive, root-ns; also a reference module."""

from __future__ import annotations

from .base import ModuleConfig, ModuleResult, RunContext, TestModule
from .registry import register


@register
class HardwareCheck(TestModule[ModuleConfig]):
    id = "system.hardware"
    title = "Hardware check"

    async def run(self, ctx: RunContext, cfg: ModuleConfig) -> ModuleResult:
        await ctx.progress(0.1, "detecting hardware", None)
        inv = await ctx.hardware.refresh()
        roles = {r: len(inv.by_role(r)) for r in ("test-wired", "test-wifi", "monitor", "mgmt")}
        await ctx.progress(1.0, "done", None)
        status = "warn" if inv.warnings else "pass"
        return ModuleResult(
            status=status,
            message="; ".join(inv.warnings) or f"{len(inv.devices)} devices detected",
            metrics={"devices": len(inv.devices), **{f"role.{k}": v for k, v in roles.items()}},
            details={
                "platform": inv.platform.model_dump(),
                "devices": [d.model_dump(mode="json") for d in inv.devices],
            },
        )
