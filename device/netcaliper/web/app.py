# SPDX-License-Identifier: GPL-3.0-only
"""FastAPI application: UI shell + JSON API."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..core.audit import AuditLog
from ..core.clock import clock_synced
from ..core.config import Settings
from ..core.db import Database
from ..core.ids import utcnow
from ..core.outbox import Outbox
from ..core.repo import Repository
from ..core.rpc import RpcClient
from ..core.testplane import TestPlane, watch_hotplug
from ..drivers.registry import HardwareRegistry
from ..modules.autotest import AutoTest, Busy, load_profiles
from ..modules.registry import all_modules
from ..modules.runner import ModuleRunner
from ..net.base import TestNet
from .kiosk import blank_after_s, on_ac, read_env
from .sections import BY_SLUG, SECTIONS

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")
log = logging.getLogger(__name__)


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _same_origin(request: Request) -> bool:
    """State-changing requests from another origin (a page the kiosk browser was sent to) are refused."""
    origin = request.headers.get("origin")
    if origin is None or origin == "null":
        return origin is None
    return origin.split("://", 1)[-1] == request.headers.get("host")


def create_app(
    settings: Settings,
    registry: HardwareRegistry | None = None,
    plane: TestPlane | None = None,
    test_net: TestNet | None = None,
) -> FastAPI:
    real = settings.hardware.mode == "real"
    if registry is None:
        registry = HardwareRegistry.from_mode(settings.hardware.mode, settings.hardware.roles)
        if real:
            registry.agent = RpcClient(settings.agent_socket)
    reg = registry
    plane_lock = asyncio.Lock()

    async def refresh_and_place() -> None:
        """Detect, move test-role devices into/out of the test netns, re-detect if anything moved."""
        async with plane_lock:
            inv = await reg.refresh()
            if app.state.plane is None or not settings.test_plane.auto_assign:
                return
            outcomes = await app.state.plane.reconcile(inv)
            if any(o.ok for o in outcomes):
                await asyncio.sleep(1.0)  # let the kernel finish re-registering moved links
                await reg.refresh()
            if app.state.plane.last_error:
                reg.inventory.warnings.append(f"test plane: {app.state.plane.last_error}")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = await Database(settings.db_path).open()
        app.state.db = db
        app.state.outbox = Outbox(db)
        app.state.repo = repo = Repository(db)
        modules = all_modules()
        net = test_net
        if net is None and not real:
            from ..net.mock import MockNet

            net = MockNet(delay=0.4)  # a little latency so the live view is watchable
        app.state.autotest = AutoTest(
            ModuleRunner(modules, repo, AuditLog(db)),
            reg,
            repo,
            net=net,
            agent=RpcClient(settings.agent_socket, timeout=300) if real else None,
            test_netns=settings.test_netns,
            clock_synced=clock_synced,
        )
        if app.state.plane is None and real:
            app.state.plane = TestPlane(RpcClient(settings.helper_socket), settings.test_netns, AuditLog(db))
        await refresh_and_place()
        watcher = None
        if real and settings.test_plane.hotplug_poll_s > 0:
            watcher = asyncio.create_task(
                watch_hotplug(refresh_and_place, settings.test_plane.hotplug_poll_s)
            )
        try:
            yield
        finally:
            await app.state.autotest.cancel()
            if watcher:
                watcher.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watcher
            await db.close()

    app = FastAPI(title="netcaliper", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.registry = registry
    app.state.plane = plane

    @app.middleware("http")
    async def local_only(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Remote (mgmt-interface) access needs login + TLS (planned alongside cloud enrollment).
        # Until then: loopback only.
        if not _is_loopback(request.client.host if request.client else None):
            return JSONResponse({"detail": "remote access requires login (not yet enabled)"}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS") and not _same_origin(request):
            return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        return await call_next(request)

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def ctx(request: Request, **extra: Any) -> dict[str, Any]:
        inv = registry.inventory
        return {
            "request": request,
            "version": __version__,
            "inv": inv,
            "mock": registry.is_mock,
            "sections": SECTIONS,
            "blank_after": blank_after_s(read_env(settings.kiosk_env), on_ac()),
            **extra,
        }

    def ready(needs: tuple[Any, ...]) -> bool:
        return all(registry.inventory.by_capability(c) for c in needs)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        tiles = [{"s": s, "ready": ready(s.needs)} for s in SECTIONS]
        return templates.TemplateResponse(request, "home.html", ctx(request, tiles=tiles))

    def profiles() -> dict[str, Any]:
        return load_profiles(settings.config_dir / "profiles")

    def wired_iface() -> Any:
        devs = registry.inventory.by_role("test-wired")
        return devs[0] if devs else None

    @app.get("/s/autotest", response_class=HTMLResponse)
    async def autotest_page(request: Request) -> HTMLResponse:
        at: AutoTest = app.state.autotest
        return templates.TemplateResponse(
            request,
            "sections/autotest.html",
            ctx(
                request,
                section=BY_SLUG["autotest"],
                profiles=list(profiles().values()),
                run=at.current,
                iface=wired_iface(),
            ),
        )

    @app.post("/autotest/start/{profile_id}", response_class=HTMLResponse)
    async def autotest_start(request: Request, profile_id: str) -> HTMLResponse:
        p = profiles().get(profile_id)
        if p is None:
            raise HTTPException(404, "unknown profile")
        at: AutoTest = app.state.autotest
        try:
            run = at.start(p)
        except Busy:
            run = at.current
        return templates.TemplateResponse(request, "partials/run.html", ctx(request, run=run))

    @app.post("/autotest/cancel")
    async def autotest_cancel() -> dict[str, Any]:
        await app.state.autotest.cancel()
        return {"ok": True}

    @app.get("/partials/run/{run_id}", response_class=HTMLResponse)
    async def run_partial(request: Request, run_id: str) -> HTMLResponse:
        run = app.state.autotest.history.get(run_id)
        if run is None:
            raise HTTPException(404)
        return templates.TemplateResponse(request, "partials/run.html", ctx(request, run=run))

    @app.get("/s/results", response_class=HTMLResponse)
    async def results_page(request: Request) -> HTMLResponse:
        runs = await app.state.repo.recent_runs(50)
        return templates.TemplateResponse(
            request, "sections/results.html", ctx(request, section=BY_SLUG["results"], runs=runs)
        )

    @app.get("/results/{run_id}", response_class=HTMLResponse)
    async def result_page(request: Request, run_id: str) -> HTMLResponse:
        repo: Repository = app.state.repo
        run = await repo.get_run(run_id)
        if run is None:
            raise HTTPException(404)
        titles = {k: v.title for k, v in all_modules().items()}
        return templates.TemplateResponse(
            request,
            "result.html",
            ctx(
                request,
                run=run,
                results=await repo.results(run_id),
                findings=await repo.findings(run_id),
                titles=titles,
            ),
        )

    # JSON API
    @app.get("/api/v1/profiles")
    async def api_profiles() -> list[dict[str, Any]]:
        return [p.model_dump() for p in profiles().values()]

    @app.post("/api/v1/autotest/{profile_id}")
    async def api_autotest(profile_id: str) -> JSONResponse:
        p = profiles().get(profile_id)
        if p is None:
            raise HTTPException(404, "unknown profile")
        try:
            run = app.state.autotest.start(p)
        except Busy as e:
            raise HTTPException(409, str(e)) from e
        return JSONResponse(run.model_dump(mode="json"), status_code=202)

    @app.get("/api/v1/runs")
    async def api_runs(limit: int = 50) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in await app.state.repo.recent_runs(min(max(limit, 1), 500))]

    @app.get("/api/v1/runs/{run_id}")
    async def api_run(run_id: str) -> dict[str, Any]:
        live = app.state.autotest.history.get(run_id)
        repo: Repository = app.state.repo
        run = await repo.get_run(run_id)
        if run is None and live is None:
            raise HTTPException(404)
        return {
            "run": run.model_dump(mode="json") if run else None,
            "live": live.model_dump(mode="json") if live else None,
            "results": [r.model_dump(mode="json") for r in await repo.results(run_id)],
            "findings": [f.model_dump(mode="json") for f in await repo.findings(run_id)],
        }

    @app.get("/s/{slug}", response_class=HTMLResponse)
    async def section(request: Request, slug: str) -> HTMLResponse:
        s = BY_SLUG.get(slug)
        if s is None:
            raise HTTPException(404)
        devices = [d for d in registry.inventory.devices if any(d.has(c, True) for c in s.needs)]
        return templates.TemplateResponse(
            request,
            f"sections/{slug}.html"
            if (HERE / "templates/sections" / f"{slug}.html").exists()
            else "sections/placeholder.html",
            ctx(request, section=s, devices=devices),
        )

    @app.get("/partials/status", response_class=HTMLResponse)
    async def status(request: Request) -> HTMLResponse:
        pending = await app.state.outbox.pending_count()
        mgmt = registry.inventory.by_role("mgmt")
        return templates.TemplateResponse(
            request,
            "partials/status.html",
            ctx(request, pending=pending, mgmt=mgmt[0] if mgmt else None, now=utcnow(), sync=settings.sync),
        )

    @app.get("/partials/hardware", response_class=HTMLResponse)
    async def hardware_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "partials/hardware.html", ctx(request))

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__, "hardware_source": registry.inventory.source}

    @app.get("/api/v1/hardware")
    async def hardware() -> dict[str, Any]:
        return registry.inventory.model_dump(mode="json")

    @app.post("/api/v1/hardware/refresh")
    async def hardware_refresh() -> dict[str, Any]:
        await refresh_and_place()
        return registry.inventory.model_dump(mode="json")

    return app
