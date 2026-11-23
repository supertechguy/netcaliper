# SPDX-License-Identifier: GPL-3.0-only
"""AutoTest: run a profile end to end on the wired test interface.

Steps run in order; `background` modules (passive listeners such as LLDP/CDP) start when reached and
are collected at the end, so their listening window overlaps the rest of the run. One run at a time
(they share the test interface). Live state is kept in memory for the UI; results are persisted
through the repository (→ outbox → cloud, metadata only).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

from ..core.engagement import ScopeGuard
from ..core.ids import new_id, utcnow
from ..core.records import Status, TestRun
from ..core.repo import Repository
from ..drivers.registry import HardwareRegistry
from ..net.base import TestNet
from .base import Caller, RunContext
from .runner import ModuleRunner, ModuleStep
from .runner import Profile as _Profile
from .thresholds import worst

log = logging.getLogger(__name__)
BUILTIN_PROFILES = Path(__file__).resolve().parent.parent / "profiles"
StepStatus = Status | Literal["pending", "running"]


class Profile(_Profile):
    description: str = ""
    source: str = "builtin"


def load_profiles(extra_dir: Path | None = None) -> dict[str, Profile]:
    """Built-ins, then `extra_dir/*.yaml` (same id overrides). Broken files are logged and skipped."""
    out: dict[str, Profile] = {}
    dirs = [(BUILTIN_PROFILES, "builtin")] + ([(extra_dir, "local")] if extra_dir else [])
    for d, source in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text())
                p = Profile.model_validate({**(data or {}), "source": source})
            except (OSError, yaml.YAMLError, ValidationError) as e:
                log.warning("profile %s skipped: %s", f, e)
                continue
            out[p.id] = p
    return out


class StepState(BaseModel):
    module: str
    title: str
    background: bool = False
    status: StepStatus = "pending"
    message: str = ""
    metrics: dict[str, float | int | str | bool | None] = Field(default_factory=dict)
    result_id: str | None = None


class RunState(BaseModel):
    run_id: str
    profile_id: str
    profile_name: str
    status: StepStatus = "running"
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    interface: str | None = None
    message: str = ""
    steps: list[StepState] = Field(default_factory=list)

    @property
    def done(self) -> bool:
        return self.status not in ("pending", "running")


class Busy(Exception):
    pass


class AutoTest:
    def __init__(
        self,
        runner: ModuleRunner,
        registry: HardwareRegistry,
        repo: Repository | None,
        *,
        net: TestNet | None = None,  # in-process (mock mode)
        agent: Caller | None = None,  # real mode: test-ns modules run in the agent
        test_netns: str | None = None,
        guard_factory: Callable[[], ScopeGuard] = lambda: ScopeGuard(None),
        clock_synced: Callable[[], bool] = lambda: False,
    ) -> None:
        self.runner, self.registry, self.repo = runner, registry, repo
        self.net, self.agent, self.test_netns = net, agent, test_netns
        self.guard_factory, self.clock_synced = guard_factory, clock_synced
        self.current: RunState | None = None
        self.history: dict[str, RunState] = {}  # this boot's runs, newest last
        self._task: asyncio.Task[RunState] | None = None

    @property
    def busy(self) -> bool:
        return self._task is not None and not self._task.done()

    def _interface(self) -> tuple[str | None, str]:
        """(ifname inside the test netns, problem). Selected by role, never by name."""
        devs = self.registry.inventory.by_role("test-wired")  # by role: "unused" ports stay unused
        if not devs:
            return None, "no wired test interface"
        d = devs[0]
        if d.ifname is None:
            return None, f"{d.name}: no network interface"
        if self.agent is not None and d.netns != self.test_netns:
            return None, f"{d.name} is not in the test namespace yet"
        return d.ifname, ""

    def start(self, profile: Profile) -> RunState:
        if self.busy:
            raise Busy("a run is already in progress")
        modules = self.runner.modules
        state = RunState(
            run_id=new_id(),
            profile_id=profile.id,
            profile_name=profile.name,
            steps=[
                StepState(
                    module=s.module,
                    title=modules[s.module].title if s.module in modules else s.module,
                    background=s.module in modules and modules[s.module].background,
                )
                for s in profile.steps
            ],
        )
        self.current = state
        self.history[state.run_id] = state
        while len(self.history) > 20:
            self.history.pop(next(iter(self.history)))
        self._task = asyncio.create_task(self._run(profile, state))
        return state

    async def wait(self) -> RunState | None:
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        return self.current

    async def cancel(self) -> None:
        if self.busy and self._task is not None:
            self._task.cancel()
            await self.wait()

    async def _run(self, profile: Profile, state: RunState) -> RunState:
        run = TestRun(
            id=state.run_id,
            profile_id=profile.id,
            started_at=state.started_at,
            clock_synced=self.clock_synced(),
        )
        if self.repo:
            await self.repo.save(run)
        ifname, problem = self._interface()
        state.interface = ifname
        ctx = RunContext(
            run_id=state.run_id,
            hardware=self.registry,
            guard=self.guard_factory(),
            net=self.net,
            ifname=ifname,
            agent=self.agent,
        )
        background: list[tuple[StepState, asyncio.Task[Any]]] = []
        try:
            for step, st in zip(profile.steps, state.steps, strict=True):
                if (
                    problem
                    and self.runner.modules.get(step.module) is not None
                    and self.runner.modules[step.module].executor == "test-ns"
                ):
                    st.status, st.message = "skipped", problem
                    continue
                if st.background:
                    st.status = "running"
                    background.append((st, asyncio.create_task(self._step(ctx, step, st))))
                    continue
                await self._step(ctx, step, st)
                if st.status in ("fail", "error") and not step.continue_on_fail:
                    break
                if step.module == "wired.link" and st.status == "fail":
                    problem = "no link"  # nothing else on this interface can work
            for _, task in background:
                await task
            for st in state.steps:
                if st.status == "pending":
                    st.status, st.message = "skipped", st.message or "not reached"
        except asyncio.CancelledError:
            for _, task in background:
                task.cancel()
            for st in state.steps:
                if st.status in ("pending", "running"):
                    st.status, st.message = "skipped", "cancelled"
            state.message = "cancelled"
            raise
        finally:
            await self._finish(run, state)
        return state

    async def _step(self, ctx: RunContext, step: ModuleStep, st: StepState) -> None:
        st.status = "running"
        tr = await self.runner.run_step(ctx, step)
        st.status, st.message, st.metrics, st.result_id = tr.status, tr.message, tr.metrics, tr.id

    async def _finish(self, run: TestRun, state: RunState) -> None:
        counted = [s.status for s in state.steps if s.status not in ("pending", "running", "skipped")]
        status: Status = worst(*counted) if counted else "skipped"  # type: ignore[arg-type]
        if state.message == "cancelled":
            status = "error"
        state.status, state.finished_at = status, utcnow()
        run.status, run.finished_at = status, state.finished_at
        run.summary = {
            "profile": state.profile_name,
            "interface": state.interface,
            "counts": {
                k: sum(1 for s in state.steps if s.status == k)
                for k in ("pass", "warn", "fail", "error", "skipped")
            },
            "steps": [
                {"module": s.module, "status": s.status, "message": s.message[:200]} for s in state.steps
            ],
        }
        if self.repo:
            try:
                await asyncio.shield(self.repo.save(run))
            except Exception:
                log.exception("saving test run %s failed", run.id)
