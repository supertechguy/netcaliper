# SPDX-License-Identifier: GPL-3.0-only
"""FastAPI application: UI shell + JSON API."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..core.config import Settings
from ..core.db import Database
from ..core.ids import utcnow
from ..core.outbox import Outbox
from ..drivers.registry import HardwareRegistry
from .sections import BY_SLUG, SECTIONS

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_app(settings: Settings, registry: HardwareRegistry | None = None) -> FastAPI:
    registry = registry or HardwareRegistry.from_mode(settings.hardware.mode, settings.hardware.roles)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = await Database(settings.db_path).open()
        app.state.db = db
        app.state.outbox = Outbox(db)
        await registry.refresh()
        try:
            yield
        finally:
            await db.close()

    app = FastAPI(title="netcaliper", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.registry = registry

    @app.middleware("http")
    async def local_only(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Remote (mgmt-interface) access needs login + TLS, which lands in Phase 1. Until then: loopback only.
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
        return (await registry.refresh()).model_dump(mode="json")

    return app
