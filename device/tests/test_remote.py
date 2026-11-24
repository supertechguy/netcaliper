# SPDX-License-Identifier: GPL-3.0-only
"""Remote browser access: kiosk (loopback) unaffected; remote = HTTPS + password session only."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from netcaliper.core.config import Settings
from netcaliper.web.app import create_app
from netcaliper.web.auth import COOKIE, PER_IP_FAILS

PASSWORD = "correct horse battery"


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[Any]:
    a = create_app(settings)
    async with a.router.lifespan_context(a):
        yield a


def client(app: Any, host: str, scheme: str = "https") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(host, 40000))
    return httpx.AsyncClient(transport=transport, base_url=f"{scheme}://ncal.local:8443")


async def kiosk_set_password(app: Any, pw: str = PASSWORD) -> httpx.Response:
    async with client(app, "127.0.0.1", "http") as k:
        return await k.post("/settings/remote/password", data={"password": pw, "confirm": pw})


async def test_remote_closed_until_password_set(app: Any) -> None:
    async with client(app, "192.0.2.10") as r:
        page = await r.get("/", headers={"accept": "text/html"})
        assert page.status_code == 303 and page.headers["location"] == "/login"
        assert (await r.get("/api/v1/runs")).status_code == 401
        login = await r.get("/login")
        assert "isn't set up" in login.text
        assert (await r.post("/login", data={"password": "anything-at-all"})).status_code == 401
    # the kiosk is unaffected
    async with client(app, "127.0.0.1", "http") as k:
        assert (await k.get("/")).status_code == 200


async def test_plain_http_refused_remotely(app: Any) -> None:
    async with client(app, "192.0.2.10", "http") as r:
        assert (await r.get("/login")).status_code == 403


async def test_login_session_logout(app: Any) -> None:
    assert "Password set" in (await kiosk_set_password(app)).text
    secrets = json.loads((app.state.settings.data_dir / "secrets.json").read_text())
    assert PASSWORD not in json.dumps(secrets) and secrets["web_admin"]["alg"] == "scrypt"
    async with client(app, "192.0.2.10") as r:
        bad = await r.post("/login", data={"password": "nope nope nope"})
        assert bad.status_code == 401 and COOKIE not in bad.cookies
        ok = await r.post("/login", data={"password": PASSWORD})
        assert ok.status_code == 303
        sc = ok.headers["set-cookie"].lower()
        assert "httponly" in sc and "secure" in sc and "samesite=strict" in sc
        assert (await r.get("/api/v1/runs")).status_code == 200
        assert (await r.get("/s/settings")).status_code == 200
        # password changes only at the device
        same = {"origin": "https://ncal.local:8443"}
        assert (await r.post("/settings/remote/clear", headers=same)).status_code == 403
        # cross-origin state change still refused for logged-in sessions
        evil = {"origin": "https://evil.example"}
        assert (await r.post("/autotest/cancel", headers=evil)).status_code == 403
        out = await r.post("/logout", headers=same)
        assert out.status_code == 303
        assert (await r.get("/api/v1/runs")).status_code == 401
    # a forged cookie gets nowhere
    async with client(app, "192.0.2.11") as r:
        r.cookies.set(COOKIE, "x" * 43)
        assert (await r.get("/api/v1/runs")).status_code == 401
    # audit trail
    async with client(app, "127.0.0.1", "http") as k:
        assert (await k.get("/api/v1/health")).status_code == 200
    rows = await (await app.state.db.conn.execute("SELECT action FROM audit_log ORDER BY seq")).fetchall()
    assert [r[0] for r in rows] == ["web.password_set", "web.login"]


async def test_new_password_ends_sessions_and_rules(app: Any) -> None:
    assert "at least" in (await kiosk_set_password(app, "short")).text
    await kiosk_set_password(app)
    async with client(app, "192.0.2.10") as r:
        await r.post("/login", data={"password": PASSWORD})
        assert (await r.get("/api/v1/runs")).status_code == 200
        await kiosk_set_password(app, PASSWORD + "!")
        assert (await r.get("/api/v1/runs")).status_code == 401


async def test_failed_logins_are_throttled(app: Any) -> None:
    await kiosk_set_password(app)
    async with client(app, "192.0.2.20") as r:
        for _ in range(PER_IP_FAILS):
            assert (await r.post("/login", data={"password": "wrong-wrong"})).status_code == 401
        # even the right password is refused while throttled
        assert (await r.post("/login", data={"password": PASSWORD})).status_code == 429
    async with client(app, "192.0.2.21") as other:
        assert (await other.post("/login", data={"password": PASSWORD})).status_code == 303


async def test_htmx_requests_get_redirect_header(app: Any) -> None:
    async with client(app, "192.0.2.10") as r:
        resp = await r.get("/partials/status", headers={"hx-request": "true"})
        assert resp.status_code == 401 and resp.headers["hx-redirect"] == "/login"
