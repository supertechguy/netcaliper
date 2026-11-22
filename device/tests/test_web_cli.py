# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from netcaliper.cli.main import main
from netcaliper.cli.schemas import export
from netcaliper.core.config import Settings
from netcaliper.web.app import create_app
from netcaliper.web.sections import SECTIONS


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


async def test_home_has_all_tiles_with_hotkeys(client: httpx.AsyncClient) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    for s in SECTIONS:
        assert f'href="/s/{s.slug}"' in r.text and f'data-hotkey="{s.hotkey}"' in r.text
    assert "cdn" not in r.text.lower()  # everything vendored


async def test_sections_and_partials(client: httpx.AsyncClient) -> None:
    for s in SECTIONS:
        assert (await client.get(f"/s/{s.slug}")).status_code == 200
    assert (await client.get("/s/nope")).status_code == 404
    hw = await client.get("/partials/hardware")
    assert "MT7610U" in hw.text and "not detected" in hw.text
    st = await client.get("/partials/status")
    assert "MOCK HW" in st.text and "wlan0" in st.text


async def test_api(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/health")).json()["ok"] is True
    inv = (await client.post("/api/v1/hardware/refresh")).json()
    assert inv["platform"]["is_uconsole"] is True


async def test_static_vendor_assets(client: httpx.AsyncClient) -> None:
    for path in (
        "/static/vendor/htmx-2.0.11.min.js",
        "/static/vendor/alpine-3.17.5.min.js",
        "/static/css/theme.css",
        "/static/js/nav.js",
    ):
        assert (await client.get(path)).status_code == 200


async def test_remote_clients_rejected(settings: Settings) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("192.168.1.50", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            assert (await c.get("/")).status_code == 403


def test_doctor_json_on_fixture(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["doctor", "--fixture", "uconsole-cm4-full", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["inventory"]["platform"]["id"] == "rpi-cm4"
    assert out["services"]["netcaliper-core"] == "n/a"


def test_doctor_record(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "rec.yaml"
    main(["doctor", "--fixture", "devbox-jer", "--record", str(f), "--anonymize", "--no-color"])
    assert "AX88179" in capsys.readouterr().out and f.read_text().startswith("source:")


def test_committed_schemas_current() -> None:
    schemas = Path(__file__).resolve().parents[2] / "schemas"
    assert export(schemas, check=True) == [], "run `netcaliper schemas`"
