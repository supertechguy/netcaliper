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
from ..core.config import Settings
from ..core.db import Database
from ..core.ids import utcnow
from ..core.outbox import Outbox
from ..core.rpc import RpcClient
from ..core.testplane import TestPlane, watch_hotplug
from ..drivers.registry import HardwareRegistry
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


def create_app(
    settings: Settings, registry: HardwareRegistry | None = None, plane: TestPlane | None = None
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
            **extra,
        }

    def ready(needs: tuple[Any, ...]) -> bool:
        return all(registry.inventory.by_capability(c) for c in needs)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        tiles = [{"s": s, "ready": ready(s.needs)} for s in SECTIONS]
        return templates.TemplateResponse(request, "home.html", ctx(request, tiles=tiles))

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
