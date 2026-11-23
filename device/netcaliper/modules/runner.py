# SPDX-License-Identifier: GPL-3.0-only
"""Module runner: capability check, engagement enforcement, audit, thresholds, persistence."""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from ..core.audit import AuditLog
from ..core.engagement import ScopeError
from ..core.ids import utcnow
from ..core.records import TestResult
from ..core.repo import Repository
from ..core.rpc import RpcError
from .base import Activity, ModuleResult, RunContext, TestModule
from .thresholds import Threshold, worst


class ModuleStep(BaseModel):
    module: str
    config: dict[str, Any] = Field(default_factory=dict)
    thresholds: list[Threshold] = Field(default_factory=list)
    continue_on_fail: bool = True


class Profile(BaseModel):
    id: str
    name: str
    steps: list[ModuleStep]


class ModuleRunner:
    def __init__(
        self, modules: dict[str, type[TestModule[Any]]], repo: Repository | None, audit: AuditLog
    ) -> None:
        self.modules = modules
        self.repo = repo
        self.audit = audit

    async def run_step(self, ctx: RunContext, step: ModuleStep) -> TestResult:
        started = utcnow()
        cls = self.modules.get(step.module)
        if cls is None:
            return await self._finish(
                ctx,
                step,
                "unknown",
                started,
                ModuleResult(status="error", message=f"unknown module {step.module}"),
            )
        try:
            cfg = cls.Config.model_validate(step.config)
        except ValidationError as e:
            return await self._finish(
                ctx,
                step,
                cls.version,
                started,
                ModuleResult(status="error", message=f"invalid config: {e.error_count()} errors"),
            )

        missing = ctx.hardware.missing(set(cls.requires))
        if missing:
            return await self._finish(
                ctx,
                step,
                cls.version,
                started,
                ModuleResult(
                    status="skipped",
                    message="missing capability: " + ", ".join(sorted(m.value for m in missing)),
                ),
            )

        if cls.activity is Activity.ACTIVE:
            try:
                decision = await ctx.guard.authorize(cfg.targets(), module_id=cls.id)
            except ScopeError as e:
                await self.audit.append(
                    "runner",
                    "active.denied",
                    {"module": cls.id, "run_id": ctx.run_id, "targets": cfg.targets(), "reason": str(e)},
                )
                return await self._finish(
                    ctx,
                    step,
                    cls.version,
                    started,
                    ModuleResult(status="skipped", message=f"not authorized: {e}"),
                )
            await self.audit.append(
                "runner",
                "active.start",
                {"module": cls.id, "run_id": ctx.run_id, "targets": decision.in_scope},
                engagement_id=decision.engagement_id,
            )
        try:
            result = await self._execute(ctx, cls, cfg)
        except TimeoutError:
            result = ModuleResult(status="error", message=f"timed out after {cls.timeout_s:.0f} s")
        except RpcError as e:
            result = ModuleResult(status="error", message=f"test-plane agent: {e.code} {e.message}")
        except Exception as e:  # a module crash must never take down the run
            result = ModuleResult(status="error", message=f"{type(e).__name__}: {e}")

        evaluated = [s for t in step.thresholds if (s := t.evaluate(result.metrics)) is not None]
        if evaluated and result.status in ("pass", "warn", "fail"):
            result.status = worst(result.status, *evaluated)
        if cls.activity is Activity.ACTIVE:
            await self.audit.append(
                "runner", "active.end", {"module": cls.id, "run_id": ctx.run_id, "status": result.status}
            )
        return await self._finish(ctx, step, cls.version, started, result)

    @staticmethod
    async def _execute(ctx: RunContext, cls: type[TestModule[Any]], cfg: Any) -> ModuleResult:
        """test-ns modules run inside the agent (real hardware) or in-process against MockNet."""
        if cls.executor == "test-ns" and ctx.agent is not None:
            raw = await ctx.agent.call(
                "module.run",
                {
                    "module": cls.id,
                    "config": cfg.model_dump(mode="json"),
                    "ifname": ctx.ifname,
                    "radios": ctx.radios,
                    "run_id": ctx.run_id,
                    "session": ctx.session,
                },
                timeout=cls.timeout_s + 10,
            )
            ctx.session.update(raw.get("session") or {})
            return ModuleResult.model_validate(raw["result"])
        return await asyncio.wait_for(cls().run(ctx, cfg), cls.timeout_s)

    async def _finish(
        self, ctx: RunContext, step: ModuleStep, version: str, started: Any, r: ModuleResult
    ) -> TestResult:
        tr = TestResult(
            run_id=ctx.run_id,
            module_id=step.module,
            module_version=version,
            status=r.status,
            started_at=started,
            finished_at=utcnow(),
            metrics=r.metrics,
            details=r.details,
            message=r.message,
        )
        if self.repo is not None:
            await self.repo.save(tr)
            for f in r.findings:
                f.run_id = ctx.run_id
                await self.repo.save(f)
        return tr
