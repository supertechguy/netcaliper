# SPDX-License-Identifier: GPL-3.0-only
"""Settings screen: cloud enrollment + sync status, profile sources."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ..core.audit import AuditLog
from ..core.https import check_url
from ..core.sync import CloudSync, SyncError
from .auth import COOKIE, MIN_PASSWORD, SESSION_S, Auth, cert_fingerprint
from .sections import BY_SLUG


def install(
    app: FastAPI,
    templates: Jinja2Templates,
    ctx: Callable[..., dict[str, Any]],
    notice: Callable[..., HTMLResponse],
    profiles: Callable[[], dict[str, Any]],
) -> None:
    def cloud() -> CloudSync:
        sync: CloudSync = app.state.sync
        return sync

    auth: Auth = app.state.auth
    web = app.state.settings.web

    def remote_info(request: Request) -> dict[str, Any]:
        cert_ok = web.tls_cert.is_file() and web.tls_key.exists()
        return {
            "port": web.remote_port,
            "cert": cert_ok,
            "fingerprint": cert_fingerprint(str(web.tls_cert)) if cert_ok else None,
            "password": auth.configured,
            "local": request.client is not None and request.client.host in ("127.0.0.1", "::1"),
            "min": MIN_PASSWORD,
        }

    def audit() -> AuditLog:
        return AuditLog(app.state.db)

    async def cloud_ctx(request: Request, **extra: Any) -> dict[str, Any]:
        return ctx(
            request,
            cloud=cloud().status(),
            pending=await app.state.outbox.pending_count(),
            rejected=await app.state.outbox.rejected_count(),
            **extra,
        )

    @app.get("/s/settings", response_class=HTMLResponse)
    async def settings_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "sections/settings.html",
            await cloud_ctx(
                request,
                section=BY_SLUG["settings"],
                profiles=list(profiles().values()),
                remote=remote_info(request),
            ),
        )

    @app.get("/partials/cloud", response_class=HTMLResponse)
    async def cloud_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "partials/cloud.html", await cloud_ctx(request))

    @app.post("/settings/cloud/enroll", response_class=HTMLResponse)
    async def cloud_enroll(request: Request, code: str = Form(""), server: str = Form("")) -> HTMLResponse:
        try:
            base = check_url(server) if server.strip() else None
        except ValueError as e:
            return notice(request, str(e))
        if not code.strip():
            return notice(request, "Enter the code shown in the dashboard (Enroll).")
        try:
            r = await cloud().enroll(code, base)
        except SyncError as e:
            return notice(request, str(e))
        return notice(request, f"Enrolled as {r['name']} on {r['server']}. Syncing.", "ok")

    @app.post("/settings/cloud/sync", response_class=HTMLResponse)
    async def cloud_sync_now(request: Request) -> HTMLResponse:
        try:
            st = await cloud().sync_now()
        except SyncError as e:
            return notice(request, str(e))
        if st["last_error"]:
            return notice(request, st["last_error"])
        return notice(request, f"Synced; {await app.state.outbox.pending_count()} still queued.", "ok")

    @app.post("/settings/cloud/unenroll", response_class=HTMLResponse)
    async def cloud_unenroll(request: Request) -> HTMLResponse:
        await cloud().unenroll()
        return notice(request, "Token removed from this device. Revoke it in the dashboard as well.", "ok")

    # ------------------------------------------------------------ remote access

    @app.post("/settings/remote/password", response_class=HTMLResponse)
    async def remote_password(
        request: Request, password: str = Form(""), confirm: str = Form("")
    ) -> HTMLResponse:
        # loopback only (the middleware refuses /settings/remote/* from anywhere else)
        if password != confirm:
            return notice(request, "The two passwords differ.")
        try:
            await auth.set_password(password)
        except ValueError as e:
            return notice(request, f"Password: {e}.")
        await audit().append("local", "web.password_set", {})
        return notice(request, f"Password set. Remote access: https://<device>:{web.remote_port}/", "ok")

    @app.post("/settings/remote/clear", response_class=HTMLResponse)
    async def remote_clear(request: Request) -> HTMLResponse:
        auth.clear_password()
        await audit().append("local", "web.password_cleared", {})
        return notice(request, "Password removed; remote access is closed.", "ok")

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request, "login.html", ctx(request, error=None, configured=auth.configured)
        )

    @app.post("/login", response_model=None)
    async def login(request: Request, password: str = Form("")) -> Response:
        ip = request.client.host if request.client else "?"
        if auth.throttled(ip):
            return templates.TemplateResponse(
                request,
                "login.html",
                ctx(request, error="Too many attempts — wait a few minutes.", configured=auth.configured),
                status_code=429,
            )
        if not auth.configured or not await auth.check_password(password):
            auth.failed(ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                ctx(request, error="Wrong password.", configured=auth.configured),
                status_code=401,
            )
        await audit().append("remote", "web.login", {"from": ip})
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(
            COOKIE,
            auth.new_session(),
            max_age=SESSION_S,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )
        return resp

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        auth.end(request.cookies.get(COOKIE))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return resp
