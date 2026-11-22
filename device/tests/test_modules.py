# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

from datetime import timedelta

import pytest

from netcaliper.core.audit import AuditLog
from netcaliper.core.db import Database
from netcaliper.core.engagement import Engagement, ScopeGuard
from netcaliper.core.ids import utcnow
from netcaliper.core.outbox import Outbox
from netcaliper.core.records import TestRun
from netcaliper.core.repo import Repository
from netcaliper.drivers.base import Capability
from netcaliper.drivers.registry import HardwareRegistry
from netcaliper.modules.base import Activity, ModuleConfig, ModuleResult, RunContext, TestModule
from netcaliper.modules.registry import all_modules
from netcaliper.modules.runner import ModuleRunner, ModuleStep
from netcaliper.modules.thresholds import Threshold, worst


class TargetsCfg(ModuleConfig):
    hosts: list[str] = []

    def targets(self) -> list[str]:
        return self.hosts


class FakeActive(TestModule[TargetsCfg]):
    id = "test.active"
    title = "fake active"
    activity = Activity.ACTIVE
    Config = TargetsCfg
    ran = 0

    async def run(self, ctx: RunContext, cfg: TargetsCfg) -> ModuleResult:
        FakeActive.ran += 1
        return ModuleResult(status="pass", metrics={"latency_ms": 120})


class NeedsProbe(TestModule[ModuleConfig]):
    id = "test.probe"
    title = "needs probe"
    requires = frozenset({Capability.PROBE_WIREMAP})

    async def run(self, ctx: RunContext, cfg: ModuleConfig) -> ModuleResult:
        raise AssertionError("must not run")


class Crashes(TestModule[ModuleConfig]):
    id = "test.crash"
    title = "crash"

    async def run(self, ctx: RunContext, cfg: ModuleConfig) -> ModuleResult:
        raise RuntimeError("boom")


@pytest.fixture
async def setup(db: Database, registry: HardwareRegistry):  # type: ignore[no-untyped-def]
    mods = {**all_modules(), FakeActive.id: FakeActive, NeedsProbe.id: NeedsProbe, Crashes.id: Crashes}
    repo = Repository(db)
    run = TestRun()
    await repo.save(run)
    return ModuleRunner(mods, repo, AuditLog(db)), run, registry, db


def _eng() -> Engagement:
    return Engagement(
        name="e",
        authorized_by="jer",
        authorized_cidrs=["10.0.0.0/24"],
        expires_at=utcnow() + timedelta(hours=1),
    )


async def test_active_module_blocked_without_engagement(setup) -> None:  # type: ignore[no-untyped-def]
    runner, run, reg, db = setup
    FakeActive.ran = 0
    ctx = RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(None))
    r = await runner.run_step(ctx, ModuleStep(module="test.active", config={"hosts": ["10.0.0.5"]}))
    assert r.status == "skipped" and FakeActive.ran == 0
    async with db.conn.execute("SELECT action FROM audit_log") as cur:
        assert [row[0] async for row in cur] == ["active.denied"]


async def test_active_module_runs_in_scope_and_is_audited(setup) -> None:  # type: ignore[no-untyped-def]
    runner, run, reg, db = setup
    ctx = RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(_eng()))
    step = ModuleStep(
        module="test.active",
        config={"hosts": ["10.0.0.5"]},
        thresholds=[Threshold(metric="latency_ms", warn="> 100", fail="> 500")],
    )
    r = await runner.run_step(ctx, step)
    assert r.status == "warn"
    async with db.conn.execute("SELECT action, engagement_id FROM audit_log ORDER BY seq") as cur:
        rows = [tuple(row) async for row in cur]
    assert [a for a, _ in rows] == ["active.start", "active.end"] and rows[0][1] is not None
    out = RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(_eng()))
    assert (
        await runner.run_step(out, ModuleStep(module="test.active", config={"hosts": ["8.8.8.8"]}))
    ).status == "skipped"


async def test_missing_capability_skips(setup) -> None:  # type: ignore[no-untyped-def]
    runner, run, reg, _ = setup
    r = await runner.run_step(
        RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(None)), ModuleStep(module="test.probe")
    )
    assert r.status == "skipped" and "probe.wiremap" in r.message


async def test_crash_is_contained_and_persisted(setup) -> None:  # type: ignore[no-untyped-def]
    runner, run, reg, db = setup
    r = await runner.run_step(
        RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(None)), ModuleStep(module="test.crash")
    )
    assert r.status == "error" and "boom" in r.message
    assert await Outbox(db).pending_count() == 2  # run + result


async def test_hardware_module(setup) -> None:  # type: ignore[no-untyped-def]
    runner, run, reg, _ = setup
    r = await runner.run_step(
        RunContext(run_id=run.id, hardware=reg, guard=ScopeGuard(None)), ModuleStep(module="system.hardware")
    )
    assert r.status == "pass" and r.metrics["role.monitor"] == 1


def test_thresholds() -> None:
    t = Threshold(metric="m", warn=">= 10", fail="> 20")
    assert [t.evaluate({"m": v}) for v in (5, 10, 25)] == ["pass", "warn", "fail"]
    assert t.evaluate({"m": "x"}) is None and t.evaluate({}) is None
    assert worst("pass", "warn", "skipped") == "warn"
    with pytest.raises(ValueError):
        Threshold(metric="m", warn="bigger than 3")
