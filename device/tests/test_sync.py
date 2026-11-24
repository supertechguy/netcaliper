# SPDX-License-Identifier: GPL-3.0-only
"""Cloud sync client against a small in-process fake of the Worker API (the real Worker has its own
tests in cloud/test; the two meet in the end-to-end check described in docs)."""

from __future__ import annotations

import asyncio
import gzip
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from netcaliper.core.audit import AuditLog
from netcaliper.core.db import Database
from netcaliper.core.https import check_url, request
from netcaliper.core.outbox import Outbox
from netcaliper.core.records import Finding, TestRun
from netcaliper.core.repo import Repository
from netcaliper.core.secrets import SecretStore
from netcaliper.core.sync import CloudSync, SyncError
from netcaliper.modules.autotest import load_profiles

TOKEN = "t" * 43


class FakeCloud:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.reject: dict[str, tuple[str, bool]] = {}
        self.backoff_s: int | None = None
        self.status_override: int | None = None
        self.revoked = False
        self.profiles: list[dict[str, Any]] = []
        self.version = 1
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode()
        method, path, _ = line.split(" ", 2)
        headers: dict[str, str] = {}
        while (h := (await reader.readline()).decode()) not in ("\r\n", ""):
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()
        body = await reader.readexactly(int(headers.get("content-length", "0")))
        self.requests.append((method, path, headers))
        status, out, extra = self.route(method, path, headers, body)
        data = json.dumps(out).encode() if out is not None else b""
        head = f"HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in extra.items())
        # chunked, like Cloudflare often answers
        writer.write(head.encode() + b"transfer-encoding: chunked\r\n\r\n")
        if data:
            writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        writer.close()

    def route(
        self, method: str, path: str, h: dict[str, str], body: bytes
    ) -> tuple[int, Any, dict[str, str]]:
        if path == "/api/v1/enroll":
            req = json.loads(body)
            if req["code"] != "ABCDE-12345":
                return 401, {"error": "invalid, used or expired enrollment code"}, {}
            return 200, {"device_id": "dev-1", "name": "bench", "token": TOKEN}, {}
        if h.get("authorization") != f"Bearer {TOKEN}" or self.revoked:
            return 401, {"error": "unknown or revoked device token"}, {}
        if self.status_override:
            return self.status_override, {"error": "boom"}, {}
        if path == "/api/v1/sync":
            assert h["content-encoding"] == "gzip"
            req = json.loads(gzip.decompress(body))
            acked, rejected = [], []
            for r in req["records"]:
                if r["id"] in self.reject:
                    reason, retry = self.reject[r["id"]]
                    rejected.append({"id": r["id"], "reason": reason, "retry": retry})
                else:
                    self.records[r["id"]] = r
                    acked.append(r["id"])
            out: dict[str, Any] = {
                "acked": acked,
                "rejected": rejected,
                "limits": {"max_records": 200, "max_bytes": 256000},
            }
            if self.backoff_s:
                out["backoff_s"] = self.backoff_s
            return 200, out, {}
        if path == "/api/v1/config":
            etag = f'"v{self.version}"'
            if h.get("if-none-match") == etag:
                return 304, None, {"etag": etag}
            return (
                200,
                {"version": self.version, "site": {"id": "s", "name": "HQ"}, "profiles": self.profiles},
                {"etag": etag},
            )
        return 404, {"error": "not found"}, {}


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    cloud = FakeCloud()
    server = await asyncio.start_server(cloud.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    db = await Database(tmp_path / "db.sqlite").open()
    secrets = SecretStore(tmp_path / "secrets.json")
    sync = CloudSync(
        Outbox(db),
        secrets,
        AuditLog(db),
        tmp_path / "cloud-profiles",
        f"http://127.0.0.1:{port}",
        known_modules=lambda: {"wired.link", "net.dhcp", "wifi.scan"},
    )
    try:
        yield {
            "cloud": cloud,
            "sync": sync,
            "db": db,
            "repo": Repository(db),
            "secrets": secrets,
            "tmp": tmp_path,
        }
    finally:
        await db.close()
        server.close()
        await server.wait_closed()


def test_server_url_rules() -> None:
    assert check_url("https://netcaliper.example.net/") == "https://netcaliper.example.net"
    assert check_url("http://127.0.0.1:8787") == "http://127.0.0.1:8787"
    for bad in (
        "http://netcaliper.example.net",
        "ftp://x",
        "https://u:p@x",
        "https://x/path",
        "https://x?q=1",
    ):
        with pytest.raises(ValueError):
            check_url(bad)


async def test_plain_http_only_to_loopback() -> None:
    with pytest.raises(OSError, match="refusing"):
        await request("GET", "http://192.0.2.1/", timeout=2)


async def test_enroll_push_and_audit_first(env: dict[str, Any]) -> None:
    sync: CloudSync = env["sync"]
    cloud: FakeCloud = env["cloud"]
    with pytest.raises(SyncError, match="invalid"):
        await sync.enroll("WRONG-00000")
    assert not sync.enrolled
    r = await sync.enroll("ABCDE-12345")
    assert r["device_id"] == "dev-1" and sync.enrolled
    stored = json.loads((env["tmp"] / "secrets.json").read_text())
    assert stored["cloud"]["token"] == TOKEN
    assert oct((env["tmp"] / "secrets.json").stat().st_mode & 0o777) == "0o600"

    run = TestRun(profile_id="wired-basic")
    await env["repo"].save(run)
    await env["repo"].save(Finding(run_id=run.id, severity="low", rule_id="x", title="t"))
    res = await sync.push_once()
    assert res == {"sent": 3, "acked": 3, "rejected": 0}  # run, finding + the enrollment audit entry
    kinds = [r["kind"] for r in cloud.records.values()]
    assert kinds[0] == "audit"  # audit log syncs first
    # the token never appears in what we send as data
    assert TOKEN not in json.dumps(list(cloud.records.values()))
    assert await Outbox(env["db"]).pending_count() == 0
    assert (await sync.push_once())["sent"] == 0


async def test_rejections_and_backoff(env: dict[str, Any]) -> None:
    sync: CloudSync = env["sync"]
    cloud: FakeCloud = env["cloud"]
    await sync.enroll("ABCDE-12345")
    bad, later = TestRun(), TestRun()
    await env["repo"].save(bad)
    await env["repo"].save(later)
    cloud.reject = {bad.id: ("bad status", False), later.id: ("schema_version 2 not supported", True)}
    cloud.backoff_s = 900
    await sync.push_once()
    ob = Outbox(env["db"])
    assert await ob.rejected_count() == 1
    assert await ob.pending_count() == 1  # the retryable one stays queued (with its own backoff)
    assert sync.backoff_until - time.monotonic() > 800

    cloud.status_override = 503
    with pytest.raises(SyncError, match="503"):
        await sync.pull_config()


async def test_cycle_backs_off_on_errors_and_stops_when_revoked(env: dict[str, Any]) -> None:
    sync: CloudSync = env["sync"]
    cloud: FakeCloud = env["cloud"]
    await sync.enroll("ABCDE-12345")
    cloud.status_override = 500
    wait = await sync._cycle()
    assert 15 <= wait <= 30 and sync.last_error and "500" in sync.last_error
    wait2 = await sync._cycle()
    assert wait2 >= 30  # exponential
    cloud.status_override = None
    cloud.revoked = True
    await sync._cycle()
    assert sync.revoked and not sync.active
    st = sync.status()
    assert st["revoked"] and "revoked" in (st["last_error"] or "")


async def test_config_pull_writes_valid_profiles(env: dict[str, Any]) -> None:
    sync: CloudSync = env["sync"]
    cloud: FakeCloud = env["cloud"]
    await sync.enroll("ABCDE-12345")
    cloud.profiles = [
        {
            "id": "branch",
            "name": "Branch",
            "interface": "test-wired",
            "steps": [{"module": "wired.link"}, {"module": "net.dhcp"}],
        },
        {"id": "broken", "name": "x"},  # no steps → invalid
        {"id": "unknown", "name": "x", "steps": [{"module": "nmap.exploit"}]},  # module we don't have
    ]
    assert await sync.pull_config() is True
    assert sync.site == "HQ"
    assert sync.profile_ids == ["branch"]
    assert any(s.startswith("unknown: unknown module") for s in sync.profiles_skipped)
    assert any(s.startswith("broken: invalid") for s in sync.profiles_skipped)
    assert await sync.pull_config() is False  # ETag → 304
    profiles = load_profiles(env["tmp"] / "local", env["tmp"] / "cloud-profiles")
    assert profiles["branch"].source == "cloud"
    # a profile removed in the dashboard disappears from the device
    cloud.profiles, cloud.version = [], 2
    assert await sync.pull_config() is True
    assert "branch" not in load_profiles(None, env["tmp"] / "cloud-profiles")


async def test_unenroll_forgets_token(env: dict[str, Any]) -> None:
    sync: CloudSync = env["sync"]
    await sync.enroll("ABCDE-12345")
    await sync.unenroll()
    assert not sync.enrolled
    assert "cloud" not in json.loads((env["tmp"] / "secrets.json").read_text())
    ok, _ = await AuditLog(env["db"]).verify()
    assert ok
